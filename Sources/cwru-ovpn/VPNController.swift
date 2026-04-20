import AppKit
import COpenVPN3Wrapper
import Darwin
import Foundation

enum VPNControllerError: LocalizedError {
    case failedToStart(String)
    case missingSession
    case unsafeSessionState(String)

    var errorDescription: String? {
        switch self {
        case .failedToStart(let message):
            return message
        case .missingSession:
            return "No active \(AppIdentity.executableName) session was found."
        case .unsafeSessionState(let message):
            return message
        }
    }
}

fileprivate final class VPNEventPayload: NSObject {
    let name: String
    let info: String
    let isError: Bool
    let isFatal: Bool

    init(name: String, info: String, isError: Bool, isFatal: Bool) {
        self.name = name
        self.info = info
        self.isError = isError
        self.isFatal = isFatal
    }
}

fileprivate final class RouteMonitorPayload: NSObject {
    let data: Data

    init(data: Data) {
        self.data = data
    }
}

fileprivate final class ReachabilityProbePayload: NSObject {
    let checkedHosts: [String]
    let reachableHost: String?
    let reason: String

    init(checkedHosts: [String], reachableHost: String?, reason: String) {
        self.checkedHosts = checkedHosts
        self.reachableHost = reachableHost
        self.reason = reason
    }
}

private struct ManagedReconnectRequest {
    let configFilePath: String?
    let tunnelMode: AppTunnelMode
    let allowSleep: Bool
    let reason: String
}

private final class RouteMonitorRelay: @unchecked Sendable {
    weak var owner: VPNController?

    func deliver(_ data: Data) {
        guard let owner else {
            return
        }

        let payload = RouteMonitorPayload(data: data)
        owner.perform(#selector(VPNController.handleRouteMonitorPayload(_:)),
                      on: Thread.main,
                      with: payload,
                      waitUntilDone: false)
    }
}

private final class ReachabilityProbeRelay: @unchecked Sendable {
    weak var owner: VPNController?

    func deliver(_ result: ReachabilityProbeResult, reason: String) {
        guard let owner else {
            return
        }

        let payload = ReachabilityProbePayload(checkedHosts: result.checkedHosts,
                                               reachableHost: result.reachableHost,
                                               reason: reason)
        owner.perform(#selector(VPNController.handleReachabilityProbePayload(_:)),
                      on: Thread.main,
                      with: payload,
                      waitUntilDone: false)
    }
}

private func vpnEventTrampoline(_ context: UnsafeMutableRawPointer?,
                                _ name: UnsafePointer<CChar>?,
                                _ info: UnsafePointer<CChar>?,
                                _ isError: Bool,
                                _ isFatal: Bool) {
    guard let context, let name else {
        return
    }

    let controller = Unmanaged<VPNController>.fromOpaque(context).takeUnretainedValue()
    let payload = VPNEventPayload(name: String(cString: name),
                                  info: info.map { String(cString: $0) } ?? "",
                                  isError: isError,
                                  isFatal: isFatal)
    controller.perform(#selector(VPNController.handleEventPayload(_:)),
                       on: Thread.main,
                       with: payload,
                       waitUntilDone: false)
}

final class VPNController: NSObject {
    private let profilePath: String
    private let configFilePath: String?
    private let ssoMethods: String
    private let verbosity: AppVerbosity
    private var tunnelMode: AppTunnelMode
    private let reachabilityProbeHosts: [String]
    private let routeManager: RouteManager
    private var menuBarController: MenuBarController?
    private var sessionState: SessionState
    private var client: OpaquePointer?
    private var signalSources: [DispatchSourceSignal] = []
    private var routeMonitorTimer: DispatchSourceTimer?
    private var routeMonitorProcess: Process?
    private var routeMonitorOutputPipe: Pipe?
    private var routeMonitorBuffer = Data()
    private let routeMonitorRelay = RouteMonitorRelay()
    private let reachabilityProbeRelay = ReachabilityProbeRelay()
    private var routeHealthCheckScheduled = false
    private let reachabilityProbeQueue = DispatchQueue(label: "cwru-ovpn.reachability-probe", qos: .utility)
    private var reachabilityProbeInFlight = false
    private var lastReachabilityProbeHealthy = true
    private var lastReachabilityFailureAt: Date?
    private var caffeinateProcess: Process?
    private var webAuthWindowController: WebAuthWindowController?
    private var externalWebAuthSession: ExternalWebAuthSession?
    private var controllerLockFD: Int32 = -1
    private var cleanupComplete = false
    private var requestedStop = false
    private var handlingConnectedEvent = false
    private var managedReconnectRequest: ManagedReconnectRequest?
    private var workspaceObserversInstalled = false
    private var disconnectingAfterWake = false
    private let allowSleep: Bool
    private let backgroundChild: Bool

    init(profilePath: String,
         configFilePath: String?,
         configuration: AppConfig,
         verbosity: AppVerbosity,
         tunnelMode: AppTunnelMode,
         allowSleep: Bool,
         backgroundChild: Bool = false) throws {
        let routeManager = RouteManager(configuration: configuration.splitTunnel)
        let physicalNetwork = try routeManager.detectPhysicalNetwork()
        let physicalDNSConfiguration = try routeManager.capturePhysicalDNSConfiguration(for: physicalNetwork.interfaceName)
        self.profilePath = URL(fileURLWithPath: profilePath).standardized.path
        self.configFilePath = configFilePath.map { URL(fileURLWithPath: $0).standardized.path }
        self.ssoMethods = AppConfig.hardcodedSSOMethods.joined(separator: ",")
        self.verbosity = verbosity
        self.tunnelMode = tunnelMode
        self.reachabilityProbeHosts = configuration.splitTunnel.effectiveReachabilityProbeHosts
        self.routeManager = routeManager
        self.allowSleep = allowSleep
        self.backgroundChild = backgroundChild
        self.sessionState = SessionState(
            pid: getpid(),
            executablePath: Self.currentExecutablePath,
            phase: .connecting,
            profilePath: self.profilePath,
            configFilePath: self.configFilePath,
            startedAt: Date(),
            lastEvent: nil,
            lastInfo: nil,
            physicalGateway: physicalNetwork.gateway,
            physicalInterface: physicalNetwork.interfaceName,
            physicalServiceName: physicalDNSConfiguration?.serviceName,
            originalDNSServers: physicalDNSConfiguration?.dnsServers,
            originalSearchDomains: physicalDNSConfiguration?.searchDomains,
            originalIPv6Mode: physicalDNSConfiguration?.ipv6Mode,
            pushedDNSServers: nil,
            pushedSearchDomains: nil,
            tunName: nil,
            vpnIPv4: nil,
            serverHost: nil,
            serverIP: nil,
            tunnelMode: tunnelMode,
            requestedTunnelMode: nil,
            fullTunnelDefaultRoutes: nil,
            fullTunnelDNSServers: nil,
            fullTunnelSearchDomains: nil,
            appliedIncludedRoutes: configuration.splitTunnel.includedRoutes,
            appliedResolverDomains: configuration.splitTunnel.effectiveResolverDomains,
            routesApplied: false,
            cleanupNeeded: false
        )
        super.init()
        self.routeMonitorRelay.owner = self
        self.reachabilityProbeRelay.owner = self
    }

    deinit {
        removeWorkspaceObservers()
        releaseControllerLock()
        if let client {
            cwru_ovpn_client_destroy(client)
        }
    }

    @MainActor
    func start() throws {
        emit("Starting VPN in \(tunnelMode.modeDescription) mode.")
        installMenuBarIfNeeded()
        updateMenuBar()

        try RuntimePaths.ensureStateDirectory()
        try acquireControllerLock()
        let removedRemoteRoutes = try routeManager.prepareForConnection(using: sessionState)
        let configContent = try String(contentsOfFile: profilePath, encoding: .utf8)
        EventLog.startSession(profilePath: profilePath)
        if removedRemoteRoutes > 0 {
            EventLog.append(note: "Removed \(removedRemoteRoutes) stale remote host routes before connect.",
                            phase: sessionState.phase)
            emit("Removed \(removedRemoteRoutes) stale remote host routes before connecting.", level: .debug)
        }
        EventLog.append(note: "Starting VPN client.", phase: sessionState.phase)
        emit("Event log: \(RuntimePaths.eventLogFile.path)", level: .debug)
        try saveState()
        startCleanupWatchdog()
        installSignalHandlers()
        installWorkspaceObservers()
        let client = cwru_ovpn_client_create()
        self.client = client

        cwru_ovpn_client_set_event_callback(client, vpnEventTrampoline, Unmanaged.passUnretained(self).toOpaque())

        var errorPointer: UnsafeMutablePointer<CChar>?
        let started = configContent.withCString { configCString in
            AppIdentity.reportedClientVersion.withCString { guiCString in
                ssoMethods.withCString { ssoCString in
                    cwru_ovpn_client_start(client, configCString, guiCString, ssoCString, &errorPointer)
                }
            }
        }

        if !started {
            let message = errorPointer.map { String(cString: $0) } ?? "OpenVPN 3 failed to start"
            if let errorPointer {
                cwru_ovpn_string_free(errorPointer)
            }
            throw VPNControllerError.failedToStart(message)
        }
    }

    static func disconnectExistingSession(force: Bool = false) throws {
        guard let session = SessionState.load() else {
            throw VPNControllerError.missingSession
        }

        let expectedExecutablePath = session.executablePath ?? currentExecutablePath

        if processExists(session.pid) {
            guard processMatchesExecutable(session.pid,
                                          expectedExecutablePath: expectedExecutablePath) else {
                throw VPNControllerError.unsafeSessionState(
                    "Refusing to signal PID \(session.pid) because it does not match the expected \(AppIdentity.executableName) executable path."
                )
            }
            kill(session.pid, SIGTERM)
            print("Disconnect requested.")
            return
        }

        if session.cleanupNeeded {
            try validateSessionForPrivilegedCleanup(session)
            let configuration = try AppConfig.load(explicitConfigPath: session.configFilePath)
            do {
                let cleanupHealthy = try RouteManager(configuration: configuration.splitTunnel).cleanup(using: session)
                if !cleanupHealthy {
                    if force {
                        print("Cleanup ran but network looks unhealthy; forcing state removal anyway.")
                    } else {
                        var recoveryState = session
                        recoveryState.markRecoveryRequired(message: "Cleanup ran, but the network still appears unhealthy.")
                        try? recoveryState.save()
                        print("Cleanup ran, but the network still appears unhealthy. State was kept so you can retry disconnect. Pass --force to drop state anyway.")
                        return
                    }
                }
            } catch {
                if force {
                    print("Cleanup raised \(error.localizedDescription); forcing state removal anyway.")
                } else {
                    var recoveryState = session
                    recoveryState.markRecoveryRequired(message: "Cleanup failed: \(error.localizedDescription)")
                    try? recoveryState.save()
                    throw error
                }
            }
        }
        SessionState.remove()
        print(session.cleanupNeeded
              ? "Removed stale state and restored network configuration."
              : "Removed stale state.")
    }

    static func handleConnectRequestForActiveSession(targetMode: AppTunnelMode,
                                                     configFilePath: String?) throws -> Bool {
        guard var session = SessionState.load() else {
            return false
        }

        let expectedExecutablePath = session.executablePath ?? currentExecutablePath
        if !processExists(session.pid) {
            if session.cleanupNeeded {
                print("Recovering stale network state from the previous session before reconnecting.")
                try disconnectExistingSession(force: true)
            } else {
                SessionState.remove()
            }
            return false
        }

        guard processMatchesExecutable(session.pid,
                                       expectedExecutablePath: expectedExecutablePath) else {
            throw VPNControllerError.unsafeSessionState(
                "Refusing to control PID \(session.pid) because it does not match the expected \(AppIdentity.executableName) executable path."
            )
        }

        if let configFilePath {
            let requestedConfigFilePath = URL(fileURLWithPath: AppConfig.expandUserPath(configFilePath)).standardized.path
            if let activeConfigFilePath = session.configFilePath,
               requestedConfigFilePath != activeConfigFilePath {
                throw VPNControllerError.failedToStart(
                    "A VPN session is already running with a different config file. Disconnect first to switch config files."
                )
            }
        }

        switch session.phase {
        case .connected:
            let activeMode = session.tunnelMode ?? targetMode
            if activeMode == targetMode {
                print("Already connected in \(activeMode.modeDescription) mode.")
                return true
            }

            session.requestedTunnelMode = targetMode
            try session.save()
            kill(session.pid, SIGUSR1)
            try waitForModeSwitch(pid: session.pid, targetMode: targetMode)
            print("Switched to \(targetMode.modeDescription) mode without reconnecting.")
            return true

        case .connecting, .authPending:
            if session.requestedTunnelMode != targetMode {
                session.requestedTunnelMode = targetMode
                try session.save()
                kill(session.pid, SIGUSR1)
            }
            print("A VPN session is already connecting. Requested \(targetMode.modeDescription) mode; it will apply after connection.")
            return true

        case .disconnecting:
            throw VPNControllerError.failedToStart("A VPN session is disconnecting. Wait a moment and retry.")

        case .disconnected, .failed:
            throw VPNControllerError.failedToStart(
                "An active VPN controller is in \(session.phase.rawValue) state. Run ovpnd, then retry."
            )
        }
    }

    private static func waitForModeSwitch(pid: Int32,
                                          targetMode: AppTunnelMode,
                                          timeout: TimeInterval = 8.0) throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            guard processExists(pid) else {
                throw VPNControllerError.failedToStart(
                    "The active VPN session exited while applying the mode switch."
                )
            }

            if let session = SessionState.load(), session.pid == pid {
                if session.phase == .failed {
                    throw VPNControllerError.failedToStart(
                        session.lastInfo ?? "Mode switch failed."
                    )
                }

                if session.phase == .connected,
                   session.tunnelMode == targetMode,
                   session.requestedTunnelMode == nil {
                    return
                }
            }

            Thread.sleep(forTimeInterval: 0.1)
        }

        throw VPNControllerError.failedToStart(
            "Timed out while waiting for mode switch to \(targetMode.modeDescription)."
        )
    }

    private static var currentExecutablePath: String {
        URL(fileURLWithPath: CommandLine.arguments[0])
            .resolvingSymlinksInPath()
            .standardized.path
    }

    private static func validateSessionForPrivilegedCleanup(_ session: SessionState) throws {
        if let tunName = session.tunName,
           !tunName.isEmpty,
           !isSafeInterfaceName(tunName) {
            throw VPNControllerError.unsafeSessionState(
                "Refusing cleanup due to an unexpected tunnel interface name in session state."
            )
        }

        if let physicalInterface = session.physicalInterface,
           !physicalInterface.isEmpty,
           !isSafeInterfaceName(physicalInterface) {
            throw VPNControllerError.unsafeSessionState(
                "Refusing cleanup due to an unexpected physical interface name in session state."
            )
        }

        if let serverIP = session.serverIP,
           !serverIP.isEmpty,
           !isSafeIPAddress(serverIP) {
            throw VPNControllerError.unsafeSessionState(
                "Refusing cleanup due to an invalid server IP in session state."
            )
        }

        if let physicalGateway = session.physicalGateway,
           !physicalGateway.isEmpty,
           !isSafeIPAddress(physicalGateway) {
            throw VPNControllerError.unsafeSessionState(
                "Refusing cleanup due to an invalid gateway in session state."
            )
        }

        if let appliedIncludedRoutes = session.appliedIncludedRoutes,
           !appliedIncludedRoutes.allSatisfy(AppConfig.SplitTunnelConfiguration.isValidCIDR) {
            throw VPNControllerError.unsafeSessionState(
                "Refusing cleanup due to invalid split-tunnel routes in session state."
            )
        }

        if let appliedResolverDomains = session.appliedResolverDomains,
           !appliedResolverDomains.allSatisfy({
               AppConfig.SplitTunnelConfiguration.isValidDomainName($0)
               && isSafeResolverDomainFileName($0)
           }) {
            throw VPNControllerError.unsafeSessionState(
                "Refusing cleanup due to invalid resolver domains in session state."
            )
        }
    }

    private static func isSafeInterfaceName(_ value: String) -> Bool {
        guard !value.isEmpty,
              !value.hasPrefix("-"),
              value.count <= 32 else {
            return false
        }

        return value.allSatisfy { character in
            character.isLetter || character.isNumber || character == "_" || character == "." || character == "-"
        }
    }

    private static func isSafeIPAddress(_ value: String) -> Bool {
        var ipv4 = in_addr()
        var ipv6 = in6_addr()

        return value.withCString { pointer in
            inet_pton(AF_INET, pointer, &ipv4) == 1 || inet_pton(AF_INET6, pointer, &ipv6) == 1
        }
    }

    private static func isSafeResolverDomainFileName(_ name: String) -> Bool {
        guard !name.isEmpty, !name.contains("/"), name != ".", name != ".." else {
            return false
        }
        return name.allSatisfy { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }
    }

    static func printStatus() {
        let session = SessionState.load()
        let configFilePath = session?.configFilePath
        let configuredVerbosity = (try? AppConfig.load(explicitConfigPath: configFilePath))?.verbosity ?? .daily

        guard let session else {
            print("Status: Disconnected")
            if configuredVerbosity == .debug {
                print("Event log: \(RuntimePaths.eventLogFile.path)")
            }
            return
        }

        let alive = processExists(session.pid)
        let recoveryNeeded = !alive && session.cleanupNeeded
        print("Status: \(statusTitle(for: session.phase, stale: !alive, recoveryNeeded: recoveryNeeded))")
        print("Controller PID: \(session.pid)\(alive ? "" : " (not running)")")
        if let tunnelMode = session.tunnelMode {
            print("Mode: \(tunnelMode.displayName)")
        }
        if let configFilePath = session.configFilePath {
            print("Config: \(configFilePath)")
        }
        print("Profile: \(session.profilePath)")
        print("Started: \(ISO8601DateFormatter().string(from: session.startedAt))")
        if alive, let requestedTunnelMode = session.requestedTunnelMode {
            print("Pending mode switch: \(requestedTunnelMode.displayName)")
        }
        if let detail = recoveryDetail(for: session, stale: !alive), !detail.isEmpty {
            print(detail)
        }
        if alive, session.phase == .connected, let serverHost = session.serverHost {
            print("Gateway: \(serverHost)")
        }
        if session.cleanupNeeded {
            print("Cleanup required: yes")
        }
        if configuredVerbosity == .debug {
            print("Event log: \(RuntimePaths.eventLogFile.path)")
        }
    }

    @MainActor
    func handleEvent(name: String, info: String, isError: Bool, isFatal: Bool) {
        if shouldPersistStatusEvent(name: name, info: info, isError: isError, isFatal: isFatal) {
            sessionState.lastEvent = name
            let redactedInfo = redactForDisplay(info)
            sessionState.lastInfo = redactedInfo.isEmpty ? nil : redactedInfo
        }
        EventLog.append(eventName: name,
                        info: info,
                        isError: isError,
                        isFatal: isFatal,
                        phase: sessionState.phase)
        try? saveState()
        updateMenuBar()

        switch name {
        case "LOG":
            parseAndPersistPushedDNS(from: info)
            if shouldSurfaceLogLine(info) {
                emit(redactForDisplay(info), level: .debug)
            }
        case "AUTH_PENDING":
            sessionState.phase = .authPending
            EventLog.append(note: "Authentication entered AUTH_PENDING.", phase: sessionState.phase)
            try? saveState()
            updateMenuBar()
        case "INFO":
            if !info.isEmpty {
                emit("INFO: \(redactForDisplay(info))", level: .debug)
            }
            handleInfoEvent(info)
        case "APP_CONTROL_MESSAGE":
            if !info.isEmpty {
                emit("APP_CONTROL_MESSAGE: \(redactForDisplay(info))", level: .debug)
            }
            if let bridgedInfo = extractInfoPayload(fromAppControlMessage: info) {
                handleInfoEvent(bridgedInfo)
            }
        case "CONNECTED":
            do {
                try handleConnected()
            } catch {
                emit("The \(tunnelMode.modeDescription) configuration could not be completed: \(error.localizedDescription)", level: .error)
                requestStop()
            }
        case "ASSIGN_IP":
            emit("Sign-in complete. Finalizing connection.")
            EventLog.append(note: "Authentication completed; finalizing tunnel setup.", phase: sessionState.phase)
            closeAuthenticationUI()
        case "DISCONNECTED":
            sessionState.phase = .disconnected
            try? saveState()
            updateMenuBar()
            completeCleanupAndExit()
        case "CORE_STATUS":
            if !info.isEmpty {
                emit(redactForDisplay(info), level: isFatal ? .error : .debug)
            }
            if isFatal {
                sessionState.phase = .failed
                try? saveState()
            }
        default:
            if isError || isFatal {
                emit("\(name): \(redactForDisplay(info))", level: .error)
            }
        }
    }

    @MainActor
    @objc fileprivate func handleEventPayload(_ payload: VPNEventPayload) {
        handleEvent(name: payload.name, info: payload.info, isError: payload.isError, isFatal: payload.isFatal)
    }

    @MainActor
    private func handleConnected() throws {
        guard let client else {
            return
        }
        guard !handlingConnectedEvent else {
            return
        }

        handlingConnectedEvent = true
        defer { handlingConnectedEvent = false }

        var connectedState = sessionState
        connectedState.tunName = copyString { cwru_ovpn_client_copy_tun_name(client) }
        connectedState.vpnIPv4 = copyString { cwru_ovpn_client_copy_vpn_ipv4(client) }
        connectedState.serverHost = copyString { cwru_ovpn_client_copy_server_host(client) }
        connectedState.serverIP = copyString { cwru_ovpn_client_copy_server_ip(client) }
        connectedState.phase = .connected

        if let tunnelName = connectedState.tunName,
           let capturedRoutes = try? routeManager.captureCurrentFullTunnelDefaultRoutes(tunnelName: tunnelName),
           !capturedRoutes.isEmpty {
            connectedState.fullTunnelDefaultRoutes = capturedRoutes
        }

        if let capturedDNS = try? routeManager.captureCurrentDNSConfiguration(using: connectedState) {
            connectedState.fullTunnelDNSServers = capturedDNS.dnsServers
            connectedState.fullTunnelSearchDomains = capturedDNS.searchDomains
        }

        if connectedState.fullTunnelDNSServers == nil {
            connectedState.fullTunnelDNSServers = connectedState.pushedDNSServers
        }
        if connectedState.fullTunnelSearchDomains == nil {
            connectedState.fullTunnelSearchDomains = connectedState.pushedSearchDomains
        }

        connectedState.cleanupNeeded = true
        sessionState = connectedState
        try saveState()
        updateMenuBar()

        if tunnelMode == .split {
            do {
                try routeManager.applySplitTunnel(using: &connectedState)
            } catch {
                do {
                    let cleanupHealthy = try routeManager.cleanup(using: connectedState)
                    sessionState.cleanupNeeded = !cleanupHealthy
                    sessionState.routesApplied = false
                    try? saveState()
                    if !cleanupHealthy {
                        EventLog.append(note: "Cleanup completed but the network still looked unhealthy.", phase: sessionState.phase)
                        UserAlert.showCritical(message: "Cleanup completed, but the network still looks unhealthy. If traffic does not recover, toggle Wi-Fi.")
                    }
                } catch {
                    try? saveState()
                }
                throw error
            }
        } else {
            do {
                try routeManager.applyFullTunnelSafety(using: connectedState)
            } catch {
                EventLog.append(note: "Full-tunnel IPv6 safety adjustment failed: \(error.localizedDescription)",
                                phase: sessionState.phase)
                emit("Full-tunnel IPv6 safety adjustment failed: \(error.localizedDescription)", level: .debug)
            }
        }

        guard !cleanupComplete, !requestedStop else {
            return
        }
        guard sessionState.phase == .connected || sessionState.phase == .authPending else {
            return
        }

        connectedState.lastEvent = sessionState.lastEvent
        connectedState.lastInfo = sessionState.lastInfo
        connectedState.pushedDNSServers = sessionState.pushedDNSServers
        connectedState.pushedSearchDomains = sessionState.pushedSearchDomains
        connectedState.requestedTunnelMode = sessionState.requestedTunnelMode
        sessionState = connectedState

        try saveState()

        do {
            try applyPendingModeSwitchIfNeeded(trigger: "post-connect")
        } catch {
            emit("Requested mode switch failed: \(error.localizedDescription)", level: .error)
        }

        startRouteMonitorIfNeeded()
        startCaffeinateIfNeeded()
        scheduleReachabilityProbeIfNeeded(reason: "initial split-tunnel connection")

        closeAuthenticationUI()
        EventLog.append(note: tunnelMode == .split
                        ? "VPN tunnel connected and split-tunnel routes applied."
                        : "VPN tunnel connected in full-tunnel mode.",
                        phase: sessionState.phase)
        emit("Connected.")
        updateMenuBar()
    }

    @MainActor
    private func handleInfoEvent(_ info: String) {
        if let request = WebAuthRequest.parse(info: info) {
            presentWebAuth(request)
            return
        }

        if info.hasPrefix("CR_TEXT:") {
            emit("An interactive challenge was requested, but this client does not support that prompt type.", level: .error)
            EventLog.append(note: "Received unsupported CR_TEXT challenge.", phase: sessionState.phase)
        }
    }

    @MainActor
    private func presentWebAuth(_ request: WebAuthRequest) {
        switch request.presentation {
        case .externalBrowser:
            EventLog.append(note: "Opening dedicated browser authentication session: \(request.url.absoluteString)", phase: sessionState.phase)
            webAuthWindowController?.close()
            webAuthWindowController = nil
            externalWebAuthSession?.close()
            let controller = ExternalWebAuthSession(url: request.url)
            if controller.start() {
                externalWebAuthSession = controller
                emit("Opening browser for sign-in.")
            } else {
                EventLog.append(note: "Browser authentication session failed to start.", phase: sessionState.phase)
                emit("The browser sign-in session could not be started.", level: .error)
            }
        case .embedded:
            EventLog.append(note: "Preparing embedded web authentication window for \(request.url.absoluteString)", phase: sessionState.phase)
            NSApplication.shared.setActivationPolicy(.regular)

            let controller: WebAuthWindowController
            if let existing = webAuthWindowController {
                controller = existing
                controller.load(url: request.url, hiddenInitially: request.hiddenInitially)
            } else {
                controller = WebAuthWindowController(url: request.url,
                                                    hiddenInitially: request.hiddenInitially,
                                                    userAgent: AppIdentity.reportedClientVersion)
                controller.onStateEvent = { [weak self] event in
                    switch event {
                    case .actionRequired:
                        controller.showWindow(nil)
                    case .connectSuccess, .connectFailed:
                        controller.close()
                        self?.webAuthWindowController = nil
                    case .locationChange(let title):
                        controller.window?.title = title
                    }
                }
                webAuthWindowController = controller
                if !request.hiddenInitially {
                    controller.showWindow(nil)
                }
            }
        }
    }

    @MainActor
    private func requestStop() {
        guard !requestedStop else {
            return
        }
        requestedStop = true
        stopRouteMonitor()
        sessionState.phase = .disconnecting
        try? saveState()
        updateMenuBar()
        if let client {
            cwru_ovpn_client_stop(client)
        } else {
            completeCleanupAndExit()
        }
    }

    @MainActor
    private func scheduleManagedReconnect(reason: String) {
        guard backgroundChild,
              sessionState.phase == .connected,
              managedReconnectRequest == nil,
              !requestedStop,
              !cleanupComplete else {
            return
        }

        managedReconnectRequest = ManagedReconnectRequest(configFilePath: configFilePath,
                                                         tunnelMode: tunnelMode,
                                                         allowSleep: allowSleep,
                                                         reason: reason)
        EventLog.append(note: "Scheduling managed reconnect after \(reason).", phase: sessionState.phase)
        emit("Reconnecting after \(reason).", level: .error)
        requestStop()
    }

    @MainActor
    private func completeCleanupAndExit() {
        guard !cleanupComplete else {
            return
        }
        cleanupComplete = true
        stopRouteMonitor()
        stopCaffeinate()
        EventLog.append(note: "Completing cleanup.", phase: sessionState.phase)
        var shouldRemoveSessionState = true

        if sessionState.cleanupNeeded {
            do {
                let cleanupHealthy = try routeManager.cleanup(using: sessionState)
                if !cleanupHealthy {
                    if disconnectingAfterWake {
                        EventLog.append(note: "Cleanup completed after wake; physical network is still re-associating.",
                                        phase: sessionState.phase)
                    } else {
                        shouldRemoveSessionState = false
                        EventLog.append(note: "Cleanup completed but the network still looked unhealthy.", phase: sessionState.phase)
                        sessionState.markRecoveryRequired(message: "Cleanup completed, but the network still looks unhealthy.")
                        try? saveState()
                        UserAlert.showCritical(message: "Cleanup completed, but the network still looks unhealthy. If traffic does not recover, toggle Wi-Fi.")
                    }
                }
            } catch {
                shouldRemoveSessionState = false
                EventLog.append(note: "Cleanup failed: \(error.localizedDescription)", phase: sessionState.phase)
                sessionState.markRecoveryRequired(message: "Cleanup failed: \(error.localizedDescription)")
                try? saveState()
                UserAlert.showCritical(message: "Cleanup failed. Your network may require manual recovery.")
            }
        }

        closeAuthenticationUI()
        menuBarController?.close()
        menuBarController = nil
        if shouldRemoveSessionState {
            SessionState.remove()
        }
        removeWorkspaceObservers()
        releaseControllerLock()
        if shouldRemoveSessionState, let reconnectRequest = managedReconnectRequest {
            spawnManagedReconnect(reconnectRequest)
        } else if managedReconnectRequest != nil {
            EventLog.append(note: "Managed reconnect was cancelled because cleanup did not complete cleanly.",
                            phase: sessionState.phase)
        }
        NSApplication.shared.stop(nil)
        if let event = NSEvent.otherEvent(with: .applicationDefined,
                                          location: .zero,
                                          modifierFlags: [],
                                          timestamp: 0,
                                          windowNumber: 0,
                                          context: nil,
                                          subtype: 0,
                                          data1: 0,
                                          data2: 0) {
            NSApplication.shared.postEvent(event, atStart: false)
        }
    }

    @MainActor
    private func startRouteMonitorIfNeeded() {
        guard tunnelMode == .split else {
            return
        }
        guard routeMonitorTimer == nil else {
            return
        }

        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + .seconds(15), repeating: .seconds(30))
        timer.setEventHandler { [weak self] in
            self?.performRouteHealthCheck()
        }
        timer.resume()
        routeMonitorTimer = timer
        startRouteChangeWatcherIfNeeded()
    }

    @MainActor
    private func stopRouteMonitor() {
        routeMonitorTimer?.cancel()
        routeMonitorTimer = nil
        routeMonitorOutputPipe?.fileHandleForReading.readabilityHandler = nil
        routeMonitorOutputPipe = nil
        if let routeMonitorProcess, routeMonitorProcess.isRunning {
            routeMonitorProcess.terminate()
        }
        routeMonitorProcess = nil
        routeMonitorBuffer.removeAll(keepingCapacity: false)
        routeHealthCheckScheduled = false
    }

    @MainActor
    private func performRouteHealthCheck() {
        guard sessionState.phase == .connected else {
            return
        }

        if tunnelMode == .split, routeManager.physicalNetworkHasChanged(comparedTo: sessionState) {
            scheduleManagedReconnect(reason: "the local network changed")
            return
        }
        guard tunnelMode == .split else {
            return
        }

        do {
            let snapshot = sessionState
            let stillConnected = try routeManager.monitorAndRepair(using: snapshot)
            if stillConnected {
                scheduleReachabilityProbeIfNeeded(reason: "route health check")
            } else {
                emit("The VPN tunnel is no longer available. Disconnecting.", level: .error)
                EventLog.append(note: "Route health check detected a missing tunnel interface.", phase: sessionState.phase)
                requestStop()
            }
        } catch {
            emit("The route monitor failed: \(error.localizedDescription)", level: .error)
            EventLog.append(note: "Route monitor failed: \(error.localizedDescription)", phase: sessionState.phase)
        }
    }

    @MainActor
    private func startRouteChangeWatcherIfNeeded() {
        guard routeMonitorProcess == nil else {
            return
        }

        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/sbin/route")
        process.arguments = ["-n", "monitor"]
        process.standardOutput = pipe
        process.standardError = pipe

        let relay = routeMonitorRelay
        pipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                return
            }
            relay.deliver(data)
        }

        do {
            try process.run()
            routeMonitorProcess = process
            routeMonitorOutputPipe = pipe
            EventLog.append(note: "Started route-change watcher.", phase: sessionState.phase)
        } catch {
            EventLog.append(note: "Failed to start route-change watcher: \(error.localizedDescription)",
                            phase: sessionState.phase)
        }
    }

    @MainActor
    private func consumeRouteMonitorData(_ data: Data) {
        routeMonitorBuffer.append(data)

        while let newlineIndex = routeMonitorBuffer.firstIndex(of: 0x0A) {
            let lineData = routeMonitorBuffer.subdata(in: 0..<newlineIndex)
            routeMonitorBuffer.removeSubrange(0...newlineIndex)

            let line = String(decoding: lineData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty else {
                continue
            }

            // Already on the main actor; call directly without re-dispatching.
            scheduleRouteHealthCheck(reason: line)
        }
    }

    @MainActor
    @objc fileprivate func handleRouteMonitorPayload(_ payload: RouteMonitorPayload) {
        consumeRouteMonitorData(payload.data)
    }

    @MainActor
    private func scheduleRouteHealthCheck(reason: String) {
        guard sessionState.phase == .connected, tunnelMode == .split else {
            return
        }
        guard !routeHealthCheckScheduled else {
            return
        }

        routeHealthCheckScheduled = true
        EventLog.append(note: "Route-change watcher noticed: \(reason)", phase: sessionState.phase)
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(500)) { [weak self] in
            guard let self else {
                return
            }
            self.routeHealthCheckScheduled = false
            self.performRouteHealthCheck()
        }
    }

    @MainActor
    private func installSignalHandlers() {
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        signal(SIGUSR1, SIG_IGN)
        signal(SIGHUP, SIG_IGN)

        var handledSignals = [SIGINT, SIGTERM, SIGUSR1]
        if !backgroundChild {
            handledSignals.append(SIGHUP)
        }

        for signalNumber in handledSignals {
            let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .main)
            source.setEventHandler { [weak self] in
                guard let self else {
                    return
                }

                if signalNumber == SIGUSR1 {
                    self.handleModeSwitchSignal()
                } else {
                    self.requestStop()
                }
            }
            source.resume()
            signalSources.append(source)
        }
    }

    @MainActor
    private func handleModeSwitchSignal() {
        guard !cleanupComplete, !requestedStop else {
            return
        }

        do {
            try applyPendingModeSwitchIfNeeded(trigger: "signal")
        } catch {
            emit("Mode switch failed: \(error.localizedDescription)", level: .error)
            EventLog.append(note: "Mode switch failed: \(error.localizedDescription)", phase: sessionState.phase)
        }
    }

    @MainActor
    private func applyPendingModeSwitchIfNeeded(trigger: String) throws {
        guard sessionState.phase == .connected,
              let persistedState = SessionState.load(),
              persistedState.pid == sessionState.pid,
              let requestedMode = persistedState.requestedTunnelMode else {
            return
        }

        try applyModeSwitch(to: requestedMode, trigger: trigger)
    }

    @MainActor
    private func applyModeSwitch(to requestedMode: AppTunnelMode, trigger: String) throws {
        guard sessionState.phase == .connected else {
            return
        }

        if requestedMode == tunnelMode {
            sessionState.requestedTunnelMode = nil
            try saveState()
            updateMenuBar()
            return
        }

        emit("Switching to \(requestedMode.modeDescription) mode without reconnecting.")
        EventLog.append(note: "Applying in-place mode switch to \(requestedMode.modeDescription) (trigger: \(trigger)).",
                        phase: sessionState.phase)

        let previousMode = tunnelMode
        var updatedState = sessionState
        updatedState.requestedTunnelMode = requestedMode

        do {
            switch requestedMode {
            case .split:
                try routeManager.applySplitTunnel(using: &updatedState)
            case .full:
                try routeManager.switchToFullTunnel(using: &updatedState,
                                                    fullTunnelRoutes: updatedState.fullTunnelDefaultRoutes ?? [])
            }
        } catch {
            // Try to preserve the previous mode behavior if transition fails.
            var rollbackState = sessionState
            rollbackState.requestedTunnelMode = nil
            if previousMode == .split {
                _ = try? routeManager.applySplitTunnel(using: &rollbackState)
            } else {
                _ = try? routeManager.switchToFullTunnel(using: &rollbackState,
                                                         fullTunnelRoutes: rollbackState.fullTunnelDefaultRoutes ?? [])
            }

            sessionState = rollbackState
            tunnelMode = previousMode
            try? saveState()
            updateMenuBar()
            throw error
        }

        tunnelMode = requestedMode
        updatedState.tunnelMode = requestedMode
        updatedState.requestedTunnelMode = nil
        updatedState.lastInfo = nil
        sessionState = updatedState

        if requestedMode == .split {
            startRouteMonitorIfNeeded()
            scheduleReachabilityProbeIfNeeded(reason: "mode switch")
        } else {
            stopRouteMonitor()
            reachabilityProbeInFlight = false
        }

        try saveState()
        updateMenuBar()

        EventLog.append(note: "Mode switched to \(requestedMode.modeDescription) without reconnecting.",
                        phase: sessionState.phase)
        emit("Mode switched to \(requestedMode.modeDescription) mode without reconnecting.")
    }

    @MainActor
    private func scheduleReachabilityProbeIfNeeded(reason: String) {
        guard tunnelMode == .split,
              sessionState.phase == .connected,
              !reachabilityProbeHosts.isEmpty,
              !reachabilityProbeInFlight else {
            return
        }

        reachabilityProbeInFlight = true
        let hosts = reachabilityProbeHosts
        let queue = reachabilityProbeQueue
        let relay = reachabilityProbeRelay
        queue.async {
            let result = ReachabilityProbe.run(hosts: hosts)
            relay.deliver(result, reason: reason)
        }
    }

    @MainActor
    private func handleReachabilityProbeResult(_ result: ReachabilityProbeResult, reason: String) {
        reachabilityProbeInFlight = false

        guard sessionState.phase == .connected else {
            return
        }

        if let reachableHost = result.reachableHost {
            if !lastReachabilityProbeHealthy {
                EventLog.append(note: "Reachability probe recovered via \(reachableHost).",
                                phase: sessionState.phase)
            }
            lastReachabilityProbeHealthy = true
            lastReachabilityFailureAt = nil
            return
        }

        let now = Date()
        let shouldSurface = lastReachabilityFailureAt.map { now.timeIntervalSince($0) >= 300 } ?? true
        lastReachabilityFailureAt = now

        let hostList = result.checkedHosts.joined(separator: ", ")
        if lastReachabilityProbeHealthy {
            EventLog.append(note: "Reachability probe failed after \(reason). Checked: \(hostList)",
                            phase: sessionState.phase)
        }
        lastReachabilityProbeHealthy = false

        guard shouldSurface else {
            return
        }

        emit("Reachability probe failed for all configured hosts. If traffic does not recover, reconnect or toggle Wi-Fi.",
             level: .error)
    }

    @MainActor
    @objc fileprivate func handleReachabilityProbePayload(_ payload: ReachabilityProbePayload) {
        handleReachabilityProbeResult(ReachabilityProbeResult(checkedHosts: payload.checkedHosts,
                                                              reachableHost: payload.reachableHost),
                                      reason: payload.reason)
    }

    private func saveState() throws {
        try sessionState.save()
    }

    private func acquireControllerLock() throws {
        guard controllerLockFD < 0 else {
            return
        }

        try RuntimePaths.ensureSessionStateDirectory()
        let lockFile = RuntimePaths.sessionStateDirectory.appendingPathComponent("controller.lock")
        let fd = open(lockFile.path, O_CREAT | O_RDWR, mode_t(S_IRUSR | S_IWUSR))
        guard fd >= 0 else {
            throw VPNControllerError.failedToStart("Failed to open the controller lock file.")
        }

        if flock(fd, LOCK_EX | LOCK_NB) != 0 {
            close(fd)
            throw VPNControllerError.failedToStart("Another VPN controller instance is already running.")
        }

        try? RuntimePaths.secureSessionStateFile(at: lockFile)

        let pidLine = "\(getpid())\n"
        _ = ftruncate(fd, 0)
        _ = lseek(fd, 0, SEEK_SET)
        pidLine.utf8CString.withUnsafeBytes { bytes in
            _ = write(fd, bytes.baseAddress, bytes.count - 1)
        }

        controllerLockFD = fd
    }

    private func releaseControllerLock() {
        guard controllerLockFD >= 0 else {
            return
        }

        _ = flock(controllerLockFD, LOCK_UN)
        _ = close(controllerLockFD)
        controllerLockFD = -1
    }

    private func startCleanupWatchdog() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])

        process.arguments = ["cleanup-watchdog", "--parent-pid", String(getpid())]

        do {
            try process.run()
        } catch {
            EventLog.append(note: "Failed to start cleanup watchdog: \(error.localizedDescription)",
                            phase: sessionState.phase)
        }
    }

    private func installWorkspaceObservers() {
        guard !workspaceObserversInstalled else {
            return
        }

        let center = NSWorkspace.shared.notificationCenter
        center.addObserver(self,
                           selector: #selector(handleDidWakeNotification),
                           name: NSWorkspace.didWakeNotification,
                           object: nil)
        center.addObserver(self,
                           selector: #selector(handleWillSleepNotification),
                           name: NSWorkspace.willSleepNotification,
                           object: nil)
        workspaceObserversInstalled = true
    }

    private func removeWorkspaceObservers() {
        guard workspaceObserversInstalled else {
            return
        }

        let center = NSWorkspace.shared.notificationCenter
        center.removeObserver(self, name: NSWorkspace.didWakeNotification, object: nil)
        center.removeObserver(self, name: NSWorkspace.willSleepNotification, object: nil)
        workspaceObserversInstalled = false
    }

    @MainActor
    @objc private func handleDidWakeNotification(_ notification: Notification) {
        guard sessionState.phase == .connected, !requestedStop, !cleanupComplete else {
            return
        }
        EventLog.append(note: "System woke from sleep; disconnecting VPN.", phase: sessionState.phase)
        // Sleep tears down the tunnel socket, so we always disconnect. The physical
        // network often hasn't re-associated yet, which makes cleanup health checks
        // look unhealthy — suppress that alert and show a single drop notice instead.
        disconnectingAfterWake = true
        UserAlert.showCritical(message: "VPN disconnected because your Mac slept. Reconnect when you are back online.")
        requestStop()
    }

    @MainActor
    @objc private func handleWillSleepNotification(_ notification: Notification) {
        EventLog.append(note: "System will sleep while VPN is active.", phase: sessionState.phase)
    }

    private func spawnManagedReconnect(_ request: ManagedReconnectRequest) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: Self.currentExecutablePath)

        var arguments = ["connect"]
        if let configFilePath = request.configFilePath {
            arguments += ["--config", configFilePath]
        }
        arguments += ["--mode", request.tunnelMode.rawValue]
        if request.allowSleep {
            arguments.append("--allow-sleep")
        }
        arguments.append("--background-child")
        process.arguments = arguments
        process.environment = ProcessInfo.processInfo.environment
        process.standardInput = FileHandle(forReadingAtPath: "/dev/null")
        process.standardOutput = FileHandle(forWritingAtPath: "/dev/null")
        process.standardError = FileHandle(forWritingAtPath: "/dev/null")

        do {
            try process.run()
            EventLog.append(note: "Started managed reconnect after \(request.reason).",
                            phase: .connecting)
        } catch {
            EventLog.append(note: "Failed to start managed reconnect after \(request.reason): \(error.localizedDescription)",
                            phase: .failed)
            UserAlert.showCritical(message: "Reconnect after \(request.reason) failed to start.")
        }
    }

    private func copyString(_ getter: () -> UnsafeMutablePointer<CChar>?) -> String? {
        guard let pointer = getter() else {
            return nil
        }
        defer { cwru_ovpn_string_free(pointer) }
        let value = String(cString: pointer)
        return value.isEmpty ? nil : value
    }

    private func shouldSurfaceLogLine(_ info: String) -> Bool {
        guard !info.isEmpty else {
            return false
        }

        let highSignalMarkers = [
            "AUTH_PENDING",
            "WEB_AUTH",
            "OPEN_URL",
            "CR_TEXT",
            "CONNECTED",
            "DISCONNECTED",
            "ERROR",
            "FATAL",
        ]
        return highSignalMarkers.contains { info.localizedCaseInsensitiveContains($0) }
    }

    private func shouldPersistStatusEvent(name: String, info: String, isError: Bool, isFatal: Bool) -> Bool {
        if isError || isFatal {
            return true
        }

        switch name {
        case "LOG":
            return shouldSurfaceLogLine(info)
        case "CORE_STATUS":
            return false
        default:
            return true
        }
    }

    @MainActor
    private func parseAndPersistPushedDNS(from info: String) {
        guard info.contains("OPTIONS:") || info.contains("CAPTURED OPTIONS:") else {
            return
        }

        var dnsServers: [String] = []
        var searchDomains: [String] = []

        for rawLine in info.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)

            if line.contains("[dhcp-option] [DNS] ["),
               let value = bracketFields(in: line).last {
                let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                if AppConfig.SplitTunnelConfiguration.isValidIPAddress(trimmed) {
                    dnsServers.append(trimmed)
                }
                continue
            }

            if line.contains("[dhcp-option] [DOMAIN-SEARCH] ["),
               let value = bracketFields(in: line).last {
                let parsedDomains = value
                    .split(separator: ",")
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter(AppConfig.SplitTunnelConfiguration.isValidDomainName)
                searchDomains.append(contentsOf: parsedDomains)
                continue
            }

            if line.hasPrefix("DNS Search Domains:") {
                continue
            }

            if line.hasPrefix("Domains:") || line.hasPrefix("SearchDomains:") {
                continue
            }
        }

        let normalizedDNSServers = Array(NSOrderedSet(array: dnsServers.compactMap { value -> String? in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        })) as? [String] ?? []

        let normalizedSearchDomains = Array(NSOrderedSet(array: searchDomains.compactMap { value -> String? in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        })) as? [String] ?? []

        guard !normalizedDNSServers.isEmpty || !normalizedSearchDomains.isEmpty else {
            return
        }

        if !normalizedDNSServers.isEmpty {
            if sessionState.pushedDNSServers != normalizedDNSServers {
                EventLog.append(note: "Learned live VPN DNS servers: \(normalizedDNSServers.joined(separator: ", "))",
                                phase: sessionState.phase)
            }
            sessionState.pushedDNSServers = normalizedDNSServers
        }
        if !normalizedSearchDomains.isEmpty {
            if sessionState.pushedSearchDomains != normalizedSearchDomains {
                EventLog.append(note: "Learned live VPN search domains: \(normalizedSearchDomains.joined(separator: ", "))",
                                phase: sessionState.phase)
            }
            sessionState.pushedSearchDomains = normalizedSearchDomains
        }
        try? saveState()
    }

    private func bracketFields(in line: String) -> [String] {
        let pattern = #"\[([^\]\r\n]+)\]"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return []
        }
        let range = NSRange(line.startIndex..., in: line)
        return regex.matches(in: line, range: range).compactMap { match in
            guard match.numberOfRanges > 1,
                  let valueRange = Range(match.range(at: 1), in: line) else {
                return nil
            }
            return String(line[valueRange])
        }
    }

    private func extractInfoPayload(fromAppControlMessage info: String) -> String? {
        for prefix in ["WEB_AUTH:", "OPEN_URL:", "CR_TEXT:"] {
            if let range = info.range(of: prefix) {
                return String(info[range.lowerBound...])
            }
        }
        return nil
    }

    private func emit(_ message: String, level: ConsoleMessageLevel = .info) {
        guard verbosity.includes(level) else {
            return
        }

        if level == .error {
            fputs("\(message)\n", stderr)
        } else {
            print(message)
        }
    }

    @MainActor
    private func closeAuthenticationUI() {
        webAuthWindowController?.close()
        webAuthWindowController = nil
        externalWebAuthSession?.close()
        externalWebAuthSession = nil
    }

    private func startCaffeinateIfNeeded() {
        guard !allowSleep else {
            EventLog.append(note: "Idle sleep is allowed; skipping caffeinate.", phase: sessionState.phase)
            return
        }
        guard caffeinateProcess == nil else {
            return
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/caffeinate")
        process.arguments = ["-i"]
        process.standardInput = FileHandle(forReadingAtPath: "/dev/null")
        process.standardOutput = FileHandle(forWritingAtPath: "/dev/null")
        process.standardError = FileHandle(forWritingAtPath: "/dev/null")

        do {
            try process.run()
            caffeinateProcess = process
            EventLog.append(note: "Started caffeinate while VPN is connected.", phase: sessionState.phase)
        } catch {
            EventLog.append(note: "Failed to start caffeinate: \(error.localizedDescription)", phase: sessionState.phase)
        }
    }

    private func stopCaffeinate() {
        if let caffeinateProcess, caffeinateProcess.isRunning {
            caffeinateProcess.terminate()
        }
        caffeinateProcess = nil
    }

    @MainActor
    private func installMenuBarIfNeeded() {
        guard menuBarController == nil else {
            return
        }

        let controller = MenuBarController()
        controller.onDisconnect = { [weak self] in
            Task { @MainActor in
                self?.requestStop()
            }
        }
        menuBarController = controller
    }

    @MainActor
    private func updateMenuBar() {
        menuBarController?.update(with: MenuBarSnapshot(phase: sessionState.phase,
                                                        tunnelMode: tunnelMode,
                                                        statusText: Self.statusTitle(for: sessionState.phase,
                                                                                     stale: false,
                                                                                     recoveryNeeded: false),
                                                        detailText: menuBarDetailText()))
    }

    private func menuBarDetailText() -> String {
        if sessionState.phase == .connected,
           let requestedTunnelMode = sessionState.requestedTunnelMode {
            return "Switching to \(requestedTunnelMode.displayName)"
        }

        switch sessionState.phase {
        case .connecting:
            return sessionState.lastInfo ?? ""
        case .authPending:
            return "Browser sign-in required"
        case .connected:
            if let serverHost = sessionState.serverHost, !serverHost.isEmpty {
                return "Gateway: \(serverHost)"
            }
            return tunnelMode == .split ? "Split tunnel active" : "Full tunnel active"
        case .disconnecting:
            return "Restoring network configuration"
        case .failed:
            return sessionState.lastInfo ?? ""
        case .disconnected:
            return ""
        }
    }

    private func redactForDisplay(_ value: String) -> String {
        if value.hasPrefix("WEB_AUTH:") || value.hasPrefix("OPEN_URL:") {
            return "Browser sign-in required."
        }

        return value
            .replacingOccurrences(of: #"\[auth-token\]\s+[^\s\n]+"#,
                                  with: "[auth-token] [redacted]",
                                  options: .regularExpression)
            .replacingOccurrences(of: #"https?://cwru\.openvpn\.com/connect[^\s\n]*"#,
                                  with: "https://cwru.openvpn.com/connect?[redacted]",
                                  options: .regularExpression)
    }

    static func recoveryDetail(for session: SessionState, stale: Bool) -> String? {
        guard stale, session.cleanupNeeded else {
            return nil
        }

        if let message = session.lastInfo, !message.isEmpty {
            return "\(message) Run ovpnd again to retry restoring routes and DNS."
        }

        return "Previous cleanup did not finish. Run ovpnd again to retry restoring routes and DNS."
    }

    static func statusIndicator(for phase: SessionState.Phase, tunnelMode: AppTunnelMode?) -> String {
        guard phase == .connected else {
            return "○"
        }

        switch tunnelMode {
        case .split:
            return "◐"
        case .full:
            return "●"
        case nil:
            return "○"
        }
    }

    static func statusTitle(for phase: SessionState.Phase, stale: Bool, recoveryNeeded: Bool) -> String {
        if recoveryNeeded {
            return "Recovery Needed"
        }
        if stale {
            return "Stale"
        }

        switch phase {
        case .connecting:
            return "Connecting"
        case .authPending:
            return "Sign-In Required"
        case .connected:
            return "Connected"
        case .disconnecting:
            return "Disconnecting"
        case .disconnected:
            return "Disconnected"
        case .failed:
            return "Failed"
        }
    }

}
