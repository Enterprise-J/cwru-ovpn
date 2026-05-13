import AppKit
import COpenVPN3Wrapper
import Darwin
import Foundation
import Network

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

fileprivate final class PathMonitorPayload: NSObject {
    let reason: String

    init(reason: String) {
        self.reason = reason
    }
}

private struct ManagedReconnectRequest {
    let configFilePath: String?
    let tunnelMode: AppTunnelMode
    let preventSleep: Bool
    let reason: String
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

private final class PathMonitorRelay: @unchecked Sendable {
    weak var owner: VPNController?

    func deliver(reason: String) {
        guard let owner else {
            return
        }

        let payload = PathMonitorPayload(reason: reason)
        owner.perform(#selector(VPNController.handlePathMonitorPayload(_:)),
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
    private var reachabilityProbeHosts: [String]
    private var routeManager: RouteManager
    private var menuBarController: MenuBarController?
    private var sessionState: SessionState
    private var client: OpaquePointer?
    private var signalSources: [DispatchSourceSignal] = []
    private var pathMonitor: NWPathMonitor?
    private let pathMonitorQueue = DispatchQueue(label: "cwru-ovpn.network-path-monitor", qos: .utility)
    private let pathMonitorRelay = PathMonitorRelay()
    private var hasSeenInitialPathUpdate = false
    private let reachabilityProbeRelay = ReachabilityProbeRelay()
    private var routeHealthCheckScheduled = false
    private let reachabilityProbeQueue = DispatchQueue(label: "cwru-ovpn.reachability-probe", qos: .utility)
    private var reachabilityProbeInFlight = false
    private var lastReachabilityProbeHealthy = true
    private var lastReachabilityFailureAt: Date?
    private var sleepAssertionID: PowerManagement.AssertionID?
    private var externalWebAuthSession: ExternalWebAuthSession?
    private var controllerLockFD: Int32 = -1
    private var cleanupComplete = false
    private var requestedStop = false
    private var handlingConnectedEvent = false
    private var managedReconnectRequest: ManagedReconnectRequest?
    private var workspaceObserversInstalled = false
    private var disconnectingAfterWake = false
    private let preventSleep: Bool
    private let privacyMode: Bool
    private let backgroundChild: Bool
    private let startupStatusFilePath: String?
    private var exitFailureMessage: String?

    init(profilePath: String,
         configFilePath: String?,
         configuration: AppConfig,
         verbosity: AppVerbosity,
         tunnelMode: AppTunnelMode,
         preventSleep: Bool,
         backgroundChild: Bool = false,
         startupStatusFilePath: String? = nil) throws {
        let routeManager = RouteManager(configuration: configuration.splitTunnel)
        let physicalNetwork = try routeManager.detectPhysicalNetwork()
        let physicalDNSConfiguration = try routeManager.capturePhysicalDNSConfiguration(for: physicalNetwork.interfaceName)
        if tunnelMode == .split, physicalDNSConfiguration == nil {
            throw VPNControllerError.failedToStart(
                "Could not capture the active macOS DNS service for split-tunnel DNS isolation."
            )
        }
        self.profilePath = URL(fileURLWithPath: profilePath).standardized.path
        self.configFilePath = configFilePath.map { URL(fileURLWithPath: $0).standardized.path }
        self.ssoMethods = AppConfig.hardcodedSSOMethods.joined(separator: ",")
        self.verbosity = verbosity
        self.tunnelMode = tunnelMode
        self.reachabilityProbeHosts = configuration.splitTunnel.effectiveReachabilityProbeHosts
        self.routeManager = routeManager
        self.preventSleep = preventSleep
        self.privacyMode = configuration.privacyMode
        self.backgroundChild = backgroundChild
        self.startupStatusFilePath = startupStatusFilePath.map { URL(fileURLWithPath: $0).standardized.path }
        self.sessionState = SessionState(
            pid: getpid(),
            executablePath: try ExecutionIdentity.currentExecutablePath(),
            processStartTime: processStartTime(getpid()),
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
            appliedIncludedRoutes: configuration.splitTunnel.effectiveIncludedRoutes,
            appliedResolverDomains: configuration.splitTunnel.effectiveResolverDomains,
            routesApplied: false,
            cleanupNeeded: false
        )
        super.init()
        self.pathMonitorRelay.owner = self
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
        EventLog.configure(privacyMode: privacyMode)
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

        let expectedExecutablePath = try session.executablePath ?? ExecutionIdentity.currentExecutablePath()

        if processExists(session.pid) {
            guard try signalValidatedProcess(pid: session.pid,
                                             expectedExecutablePath: expectedExecutablePath,
                                             expectedStartTime: session.processStartTime,
                                             signal: SIGTERM) else {
                if session.cleanupNeeded {
                    return try disconnectExistingSession(force: force)
                }
                SessionState.remove()
                print("Removed stale state.")
                return
            }
            print("Disconnect requested.")
            return
        }

        if session.cleanupNeeded {
            try validateSessionForPrivilegedCleanup(session)
            do {
                let cleanupHealthy = try cleanupRouteManager(for: session).cleanup(using: session)
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

        let expectedExecutablePath = try session.executablePath ?? ExecutionIdentity.currentExecutablePath()
        if !processExists(session.pid) {
            if session.cleanupNeeded {
                print("Recovering stale network state from the previous session before reconnecting.")
                try disconnectExistingSession(force: true)
            } else {
                SessionState.remove()
            }
            return false
        }

        _ = try signalValidatedProcess(pid: session.pid,
                                       expectedExecutablePath: expectedExecutablePath,
                                       expectedStartTime: session.processStartTime,
                                       signal: 0)

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
                if activeMode == .split {
                    session.requestedTunnelMode = targetMode
                    session.requestedConfigurationRefresh = true
                    try session.save()
                    _ = try signalValidatedProcess(pid: session.pid,
                                                   expectedExecutablePath: expectedExecutablePath,
                                                   expectedStartTime: session.processStartTime,
                                                   signal: SIGUSR1)
                    try waitForModeSwitch(pid: session.pid, targetMode: targetMode)
                    print("Refreshed split-tunnel configuration.")
                    return true
                }
                print("Already connected in \(activeMode.modeDescription) mode.")
                return true
            }

            session.requestedTunnelMode = targetMode
            try session.save()
            _ = try signalValidatedProcess(pid: session.pid,
                                           expectedExecutablePath: expectedExecutablePath,
                                           expectedStartTime: session.processStartTime,
                                           signal: SIGUSR1)
            try waitForModeSwitch(pid: session.pid, targetMode: targetMode)
            print("Switched to \(targetMode.modeDescription) mode.")
            return true

        case .connecting, .authPending:
            if session.requestedTunnelMode != targetMode {
                session.requestedTunnelMode = targetMode
                try session.save()
                _ = try signalValidatedProcess(pid: session.pid,
                                               expectedExecutablePath: expectedExecutablePath,
                                               expectedStartTime: session.processStartTime,
                                               signal: SIGUSR1)
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
        let monitor = BlockingEventMonitor(directoryURLs: [RuntimePaths.sessionStateDirectory], processIDs: [pid])
        let deadline = DispatchTime.now() + timeout
        var sawRequestedMode = false

        while true {
            guard processExists(pid) else {
                throw VPNControllerError.failedToStart(
                    "The active VPN session exited while applying the mode switch."
                )
            }

            switch evaluateModeSwitchWaitState(session: SessionState.load(),
                                               pid: pid,
                                               targetMode: targetMode,
                                               sawRequestedMode: sawRequestedMode) {
            case .pending(let updatedSawRequestedMode):
                sawRequestedMode = updatedSawRequestedMode
            case .succeeded:
                return
            case .failed(let message):
                throw VPNControllerError.failedToStart(message)
            }

            if monitor.wait(until: deadline) == .timedOut {
                break
            }
        }

        switch evaluateModeSwitchWaitState(session: SessionState.load(),
                                           pid: pid,
                                           targetMode: targetMode,
                                           sawRequestedMode: sawRequestedMode) {
        case .pending:
            break
        case .succeeded:
            return
        case .failed(let message):
            throw VPNControllerError.failedToStart(message)
        }

        throw VPNControllerError.failedToStart(
            "Timed out while waiting for mode switch to \(targetMode.modeDescription)."
        )
    }

    static func evaluateModeSwitchWaitState(session: SessionState?,
                                            pid: Int32,
                                            targetMode: AppTunnelMode,
                                            sawRequestedMode: Bool) -> ModeSwitchWaitState {
        var sawRequestedMode = sawRequestedMode

        guard let session, session.pid == pid else {
            return .pending(updatedSawRequestedMode: sawRequestedMode)
        }

        if session.requestedTunnelMode == targetMode {
            sawRequestedMode = true
        }

        if session.phase == .failed {
            return .failed(session.lastInfo ?? "Mode switch failed.")
        }

        if sawRequestedMode,
           session.phase == .connected,
           session.requestedTunnelMode == nil,
           session.lastEvent == "MODE_SWITCH_FAILED" {
            return .failed(session.lastInfo ?? "Mode switch failed.")
        }

        if session.phase == .connected,
           session.tunnelMode == targetMode,
           session.requestedTunnelMode == nil {
            return .succeeded
        }

        if sawRequestedMode,
           session.phase == .connected,
           session.requestedTunnelMode == nil,
           session.tunnelMode != targetMode {
            return .failed(
                session.lastInfo ?? "Mode switch to \(targetMode.modeDescription) failed."
            )
        }

        return .pending(updatedSawRequestedMode: sawRequestedMode)
    }

    static func validateSessionForPrivilegedCleanup(_ session: SessionState) throws {
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

        if let physicalServiceName = session.physicalServiceName,
           !physicalServiceName.isEmpty,
           !isSafeNetworkServiceName(physicalServiceName) {
            throw VPNControllerError.unsafeSessionState(
                "Refusing cleanup due to an unexpected network service name in session state."
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
               && ResolverPaths.isSafeDomainFileName($0)
           }) {
            throw VPNControllerError.unsafeSessionState(
                "Refusing cleanup due to invalid resolver domains in session state."
            )
        }

        if !isSafeUserControlledPath(session.profilePath) {
            throw VPNControllerError.unsafeSessionState(
                "Refusing cleanup due to an unexpected profile path in session state."
            )
        }
    }

    static func cleanupRouteManager(for session: SessionState) -> RouteManager {
        var includedRoutes = session.appliedIncludedRoutes ?? []
        var resolverDomains = session.appliedResolverDomains ?? []

        if includedRoutes.isEmpty,
           resolverDomains.isEmpty,
           let configFilePath = session.configFilePath {
            let expandedConfigPath = URL(fileURLWithPath: AppConfig.expandUserPath(configFilePath))
                .standardized.path
            if isSafeUserControlledPath(expandedConfigPath),
               let configuration = try? AppConfig.load(explicitConfigPath: expandedConfigPath) {
                includedRoutes = configuration.splitTunnel.effectiveIncludedRoutes
                resolverDomains = configuration.splitTunnel.effectiveResolverDomains
            }
        }

        return RouteManager(configuration: AppConfig.SplitTunnelConfiguration(
            includedRoutes: includedRoutes,
            resolverDomains: resolverDomains,
            resolverNameServers: [],
            reachabilityProbeHosts: nil
        ))
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
        guard !value.isEmpty,
              value.count <= AppConfig.SplitTunnelConfiguration.maxIPAddressLength else {
            return false
        }

        var ipv4 = in_addr()
        var ipv6 = in6_addr()

        return value.withCString { pointer in
            inet_pton(AF_INET, pointer, &ipv4) == 1 || inet_pton(AF_INET6, pointer, &ipv6) == 1
        }
    }

    private static let maxUserControlledPathLength = 1024
    private static let safeNetworkServiceNameAllowedCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -./()_+'&")

    private static func isSafeNetworkServiceName(_ value: String) -> Bool {
        guard !value.isEmpty,
              !value.hasPrefix("-"),
              value.count <= 128 else {
            return false
        }

        return value.unicodeScalars.allSatisfy { safeNetworkServiceNameAllowedCharacters.contains($0) }
    }

    private static func isSafeUserControlledPath(_ value: String) -> Bool {
        guard !value.isEmpty,
              value.utf8.count <= maxUserControlledPathLength,
              value.hasPrefix("/"),
              !value.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F || (0x80...0x9F).contains($0.value) }) else {
            return false
        }

        let standardizedPath = URL(fileURLWithPath: value).standardized.path
        let allowedRoots = [
            "/Users/",
            "/var/root/",
            "/private/",
            "/tmp/",
        ]
        return allowedRoots.contains(where: { standardizedPath.hasPrefix($0) })
    }

    @discardableResult
    private static func signalValidatedProcess(pid: Int32,
                                               expectedExecutablePath: String,
                                               expectedStartTime: ProcessStartTime?,
                                               signal: Int32) throws -> Bool {
        guard processExists(pid) else {
            return false
        }

        guard processMatchesExecutable(pid,
                                       expectedExecutablePath: expectedExecutablePath,
                                       expectedStartTime: expectedStartTime) else {
            throw VPNControllerError.unsafeSessionState(
                "Refusing to signal PID \(pid) because it does not match the expected \(AppIdentity.executableName) executable path."
            )
        }

        if signal == 0 {
            return true
        }

        if kill(pid, signal) == 0 {
            return true
        }

        if errno == ESRCH {
            return false
        }

        throw VPNControllerError.failedToStart("Failed to signal the active VPN controller process.")
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
        if alive, session.requestedConfigurationRefresh == true {
            print("Pending split-tunnel refresh")
        } else if alive, let requestedTunnelMode = session.requestedTunnelMode {
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
                EventLog.append(note: "Post-connect configuration failed: \(error.localizedDescription)",
                                phase: sessionState.phase)
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
            if !capturedDNS.dnsServers.isEmpty {
                connectedState.fullTunnelDNSServers = capturedDNS.dnsServers
            }
            if !capturedDNS.searchDomains.isEmpty {
                connectedState.fullTunnelSearchDomains = capturedDNS.searchDomains
            }
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
                try reloadSplitTunnelConfiguration()
                try routeManager.applySplitTunnel(using: &connectedState) { [self] preparedState in
                    sessionState = preparedState
                    try saveState()
                }
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
            try routeManager.applyFullTunnelSafety(using: connectedState)
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
        startSleepAssertionIfNeeded()
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
        EventLog.append(note: "Opening dedicated browser authentication session: \(request.url.absoluteString)",
                        phase: sessionState.phase)
        externalWebAuthSession?.close()
        let controller = ExternalWebAuthSession(url: request.url)
        controller.onUserCancelled = { [weak self] in
            self?.handleAuthenticationCancellation()
        }
        if controller.start() {
            externalWebAuthSession = controller
            emit("Opening browser for sign-in.")
        } else {
            EventLog.append(note: "Browser authentication session failed to start.", phase: sessionState.phase)
            emit("The browser sign-in session could not be started.", level: .error)
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
    private func handleAuthenticationCancellation() {
        guard !requestedStop, !cleanupComplete else {
            return
        }

        let message = "Browser sign-in was cancelled."
        exitFailureMessage = message
        sessionState.lastEvent = "AUTH_CANCELLED"
        sessionState.lastInfo = message
        try? saveState()
        updateMenuBar()

        if backgroundChild {
            DetachedStartupStatus.writeFailure(message: message, to: startupStatusFilePath)
        }

        EventLog.append(note: message, phase: sessionState.phase)
        emit(message, level: .error)
        requestStop()
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
                                                         preventSleep: preventSleep,
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
        stopSleepAssertion()
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
        guard pathMonitor == nil else {
            return
        }

        let monitor = NWPathMonitor()
        let relay = pathMonitorRelay
        monitor.pathUpdateHandler = { path in
            let status: String
            switch path.status {
            case .satisfied:
                status = "satisfied"
            case .requiresConnection:
                status = "requires-connection"
            case .unsatisfied:
                status = "unsatisfied"
            @unknown default:
                status = "unknown"
            }

            let interfaces = path.availableInterfaces.map(\.name).sorted().joined(separator: ", ")
            let reason = interfaces.isEmpty
                ? "network path changed (\(status))"
                : "network path changed (\(status); interfaces: \(interfaces))"

            relay.deliver(reason: reason)
        }
        monitor.start(queue: pathMonitorQueue)
        pathMonitor = monitor
        hasSeenInitialPathUpdate = false
        EventLog.append(note: "Started network path monitor.", phase: sessionState.phase)
    }

    @MainActor
    private func stopRouteMonitor() {
        pathMonitor?.cancel()
        pathMonitor = nil
        hasSeenInitialPathUpdate = false
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
            emit("The route health check failed: \(error.localizedDescription)", level: .error)
            EventLog.append(note: "Route health check failed: \(error.localizedDescription)", phase: sessionState.phase)
        }
    }

    @MainActor
    @objc fileprivate func handlePathMonitorPayload(_ payload: PathMonitorPayload) {
        if !hasSeenInitialPathUpdate {
            hasSeenInitialPathUpdate = true
            return
        }

        scheduleRouteHealthCheck(reason: payload.reason)
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
        EventLog.append(note: "Network path monitor noticed: \(reason)", phase: sessionState.phase)
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
              persistedState.pid == sessionState.pid else {
            return
        }

        let refreshCurrentMode = persistedState.requestedConfigurationRefresh == true
        if let requestedMode = persistedState.requestedTunnelMode {
            try applyModeSwitch(to: requestedMode,
                                trigger: trigger,
                                refreshCurrentMode: refreshCurrentMode)
        } else if refreshCurrentMode, tunnelMode == .split {
            try applyModeSwitch(to: .split,
                                trigger: trigger,
                                refreshCurrentMode: true)
        }
    }

    @MainActor
    private func applyModeSwitch(to requestedMode: AppTunnelMode,
                                 trigger: String,
                                 refreshCurrentMode: Bool = false) throws {
        guard sessionState.phase == .connected else {
            return
        }

        if requestedMode == tunnelMode {
            guard requestedMode == .split, refreshCurrentMode else {
                sessionState.requestedTunnelMode = nil
                sessionState.requestedConfigurationRefresh = nil
                try saveState(preservingPendingModeSwitch: false)
                updateMenuBar()
                return
            }
        }

        let refreshingSplitTunnel = requestedMode == tunnelMode && refreshCurrentMode
        if refreshingSplitTunnel {
            emit("Refreshing split-tunnel configuration.")
            EventLog.append(note: "Refreshing split-tunnel configuration (trigger: \(trigger)).",
                            phase: sessionState.phase)
        } else {
            emit("Switching to \(requestedMode.modeDescription) mode.")
            EventLog.append(note: "Applying in-place mode switch to \(requestedMode.modeDescription) (trigger: \(trigger)).",
                            phase: sessionState.phase)
        }

        let previousMode = tunnelMode
        let previousRouteManager = routeManager
        let previousReachabilityProbeHosts = reachabilityProbeHosts
        var updatedState = sessionState
        updatedState.requestedTunnelMode = requestedMode
        updatedState.requestedConfigurationRefresh = refreshingSplitTunnel ? true : nil

        do {
            switch requestedMode {
            case .split:
                try reloadSplitTunnelConfiguration()
                try routeManager.applySplitTunnel(using: &updatedState) { [self] preparedState in
                    sessionState = preparedState
                    try saveState()
                }
            case .full:
                try routeManager.switchToFullTunnel(using: &updatedState,
                                                    fullTunnelRoutes: updatedState.fullTunnelDefaultRoutes ?? [])
            }
        } catch {
            routeManager = previousRouteManager
            reachabilityProbeHosts = previousReachabilityProbeHosts
            var rollbackState = sessionState
            rollbackState.requestedTunnelMode = nil
            rollbackState.requestedConfigurationRefresh = nil
            rollbackState.lastEvent = "MODE_SWITCH_FAILED"
            rollbackState.lastInfo = refreshingSplitTunnel
                ? "Split-tunnel refresh failed: \(error.localizedDescription)"
                : "Mode switch to \(requestedMode.modeDescription) failed: \(error.localizedDescription)"
            if previousMode == .split {
                _ = try? routeManager.applySplitTunnel(using: &rollbackState) { [self] preparedState in
                    sessionState = preparedState
                    try saveState(preservingPendingModeSwitch: false)
                }
            } else {
                _ = try? routeManager.switchToFullTunnel(using: &rollbackState,
                                                         fullTunnelRoutes: rollbackState.fullTunnelDefaultRoutes ?? [])
            }

            sessionState = rollbackState
            tunnelMode = previousMode
            try? saveState(preservingPendingModeSwitch: false)
            updateMenuBar()
            throw error
        }

        tunnelMode = requestedMode
        updatedState.tunnelMode = requestedMode
        updatedState.requestedTunnelMode = nil
        updatedState.requestedConfigurationRefresh = nil
        updatedState.lastEvent = "MODE_SWITCHED"
        updatedState.lastInfo = nil
        sessionState = updatedState

        if requestedMode == .split {
            startRouteMonitorIfNeeded()
            scheduleReachabilityProbeIfNeeded(reason: "mode switch")
        } else {
            stopRouteMonitor()
            reachabilityProbeInFlight = false
        }

        try saveState(preservingPendingModeSwitch: false)
        updateMenuBar()

        if refreshingSplitTunnel {
            EventLog.append(note: "Split-tunnel configuration refreshed.",
                            phase: sessionState.phase)
            emit("Split-tunnel configuration refreshed.")
        } else {
            EventLog.append(note: "Mode switched to \(requestedMode.modeDescription).",
                            phase: sessionState.phase)
            emit("Mode switched to \(requestedMode.modeDescription) mode.")
        }
    }

    @MainActor
    private func reloadSplitTunnelConfiguration() throws {
        let configuration = try AppConfig.load(explicitConfigPath: configFilePath)
        routeManager = RouteManager(configuration: configuration.splitTunnel)
        reachabilityProbeHosts = configuration.splitTunnel.effectiveReachabilityProbeHosts
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

    static func sessionStateForSave(currentState: SessionState,
                                    persistedState: SessionState?,
                                    preservingPendingModeSwitch: Bool = true) -> SessionState {
        guard preservingPendingModeSwitch,
              currentState.requestedTunnelMode == nil,
              currentState.phase == .connected || currentState.phase == .connecting || currentState.phase == .authPending,
              let persistedState,
              persistedState.pid == currentState.pid,
              persistedState.executablePath == currentState.executablePath,
              persistedState.processStartTime == currentState.processStartTime,
              let pendingMode = persistedState.requestedTunnelMode,
              currentState.phase != .connected
                || persistedState.requestedConfigurationRefresh == true
                || pendingMode != currentState.tunnelMode else {
            return currentState
        }

        var mergedState = currentState
        mergedState.requestedTunnelMode = pendingMode
        mergedState.requestedConfigurationRefresh = persistedState.requestedConfigurationRefresh
        return mergedState
    }

    private func saveState(preservingPendingModeSwitch: Bool = true) throws {
        let preparedState = Self.sessionStateForSave(currentState: sessionState,
                                                     persistedState: SessionState.load(),
                                                     preservingPendingModeSwitch: preservingPendingModeSwitch)
        sessionState = preparedState
        try preparedState.save()
    }

    private func acquireControllerLock() throws {
        guard controllerLockFD < 0 else {
            return
        }

        try RuntimePaths.ensureSessionStateDirectory()
        let lockFile = RuntimePaths.sessionStateDirectory.appendingPathComponent("controller.lock")
        let fd = open(lockFile.path, O_CREAT | O_RDWR | O_CLOEXEC, mode_t(S_IRUSR | S_IWUSR))
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
        do {
            process.executableURL = URL(fileURLWithPath: try ExecutionIdentity.currentExecutablePath())
            var arguments = ["cleanup-watchdog", "--parent-pid", String(getpid())]
            if let startTime = sessionState.processStartTime {
                arguments += ["--parent-start-seconds", String(startTime.seconds),
                              "--parent-start-microseconds", String(startTime.microseconds)]
            }
            process.arguments = arguments
            process.standardInput = FileHandle(forReadingAtPath: "/dev/null")
            process.standardOutput = FileHandle(forWritingAtPath: "/dev/null")
            process.standardError = FileHandle(forWritingAtPath: "/dev/null")
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
        do {
            process.executableURL = URL(fileURLWithPath: try ExecutionIdentity.currentExecutablePath())

            var arguments = ["connect"]
            if let configFilePath = request.configFilePath {
                arguments += ["--config", configFilePath]
            }
            arguments += ["--mode", request.tunnelMode.rawValue]
            if !request.preventSleep {
                arguments.append("--allow-sleep")
            }
            arguments.append("--background-child")
            process.arguments = arguments
            process.environment = ProcessInfo.processInfo.environment
            process.standardInput = FileHandle(forReadingAtPath: "/dev/null")
            process.standardOutput = FileHandle(forWritingAtPath: "/dev/null")
            process.standardError = FileHandle(forWritingAtPath: "/dev/null")
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

        let normalizedDNSServers = uniqueTrimmedNonEmptyStrings(dnsServers)
        let normalizedSearchDomains = uniqueTrimmedNonEmptyStrings(searchDomains)

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
        guard let regex = Self.bracketFieldRegex else {
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

    private static let bracketFieldRegex = try? NSRegularExpression(pattern: #"\[([^\]\r\n]+)\]"#)

    private func uniqueTrimmedNonEmptyStrings(_ values: [String]) -> [String] {
        var seen = Set<String>()
        var result: [String] = []

        for value in values {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty, seen.insert(trimmed).inserted {
                result.append(trimmed)
            }
        }

        return result
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
        externalWebAuthSession?.close()
        externalWebAuthSession = nil
    }

    private func startSleepAssertionIfNeeded() {
        guard preventSleep else {
            EventLog.append(note: "System sleep is allowed; skipping the system-sleep assertion.", phase: sessionState.phase)
            return
        }
        guard sleepAssertionID == nil else {
            return
        }

        do {
            sleepAssertionID = try PowerManagement.beginPreventUserIdleSystemSleepAssertion(
                reason: "Keep CWRU OpenVPN active while connected"
            )
            EventLog.append(note: "Preventing user idle system sleep while VPN is connected.",
                            phase: sessionState.phase)
        } catch {
            EventLog.append(note: "Failed to prevent system sleep: \(error.localizedDescription)",
                            phase: sessionState.phase)
            emit("Failed to prevent system sleep: \(error.localizedDescription)", level: .error)
        }
    }

    private func stopSleepAssertion() {
        if let sleepAssertionID {
            PowerManagement.endAssertion(sleepAssertionID)
        }
        sleepAssertionID = nil
    }

    @MainActor
    private func installMenuBarIfNeeded() {
        guard menuBarController == nil else {
            return
        }

        let controller = MenuBarController()
        controller.onSwitchMode = { [weak self] in
            Task { @MainActor in
                self?.requestMenuBarModeSwitch()
            }
        }
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
                                                        requestedTunnelMode: sessionState.requestedTunnelMode,
                                                        statusText: Self.statusTitle(for: sessionState.phase,
                                                                                     stale: false,
                                                                                     recoveryNeeded: false),
                                                        detailText: menuBarDetailText()))
    }

    private func menuBarDetailText() -> String {
        if let requestedTunnelMode = sessionState.requestedTunnelMode {
            switch sessionState.phase {
            case .connected:
                return "Switching to \(requestedTunnelMode.displayName)"
            case .connecting, .authPending:
                return "Pending mode: \(requestedTunnelMode.displayName)"
            case .disconnecting, .failed, .disconnected:
                break
            }
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

    @MainActor
    private func requestMenuBarModeSwitch() {
        guard !cleanupComplete, !requestedStop else {
            return
        }

        let targetMode = tunnelMode == .split ? AppTunnelMode.full : .split

        switch sessionState.phase {
        case .connected:
            do {
                try applyModeSwitch(to: targetMode, trigger: "menu bar")
            } catch {
                emit("Mode switch failed: \(error.localizedDescription)", level: .error)
                EventLog.append(note: "Mode switch failed: \(error.localizedDescription)", phase: sessionState.phase)
            }

        case .connecting, .authPending:
            sessionState.requestedTunnelMode = targetMode
            do {
                try saveState()
                updateMenuBar()
                emit("Queued \(targetMode.modeDescription) mode switch for after connection.")
                EventLog.append(note: "Queued mode switch to \(targetMode.modeDescription) from the menu bar.",
                                phase: sessionState.phase)
            } catch {
                sessionState.requestedTunnelMode = nil
                emit("Could not queue mode switch: \(error.localizedDescription)", level: .error)
                EventLog.append(note: "Could not queue mode switch: \(error.localizedDescription)",
                                phase: sessionState.phase)
            }

        case .disconnecting, .disconnected, .failed:
            break
        }
    }

    private func redactForDisplay(_ value: String) -> String {
        if value.hasPrefix("WEB_AUTH:") || value.hasPrefix("OPEN_URL:") {
            return "Browser sign-in required."
        }

        return redactSensitiveText(value)
    }

    @MainActor
    func terminalFailureMessage() -> String? {
        exitFailureMessage
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

enum ModeSwitchWaitState {
    case pending(updatedSawRequestedMode: Bool)
    case succeeded
    case failed(String)
}
