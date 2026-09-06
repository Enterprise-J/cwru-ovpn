import AppKit
import COpenVPN3Wrapper
import Darwin
import Foundation
import Network

enum VPNControllerError: LocalizedError {
    case failedToStart(String)
    case missingSession
    case modeSwitchRollbackFailed(String)
    case unsafeSessionState(String)

    var errorDescription: String? {
        switch self {
        case .failedToStart(let message):
            return message
        case .missingSession:
            return "No active \(AppIdentity.executableName) session was found."
        case .modeSwitchRollbackFailed(let message):
            return message
        case .unsafeSessionState(let message):
            return message
        }
    }
}

private struct ManagedReconnectRequest {
    let configFilePath: String?
    let tunnelMode: AppTunnelMode
    let reason: String
}

private enum PhysicalNetworkMigrationOutcome {
    case unchanged
    case migrated(transportAffecting: Bool)
    case deferred
}

private enum TransportRecoveryState: Equatable {
    case reconnecting
    case hostPathDegraded
    case stabilizing
}

private final class VPNEventRelay: @unchecked Sendable {
    private let lock = NSLock()
    private weak var owner: VPNController?
    private var generation = 0
    private var buffer = VPNEventBuffer()

    func configure(owner: VPNController?, generation: Int) {
        lock.lock()
        self.owner = owner
        self.generation = generation
        buffer = VPNEventBuffer()
        lock.unlock()
    }

    func clear(generation: Int) {
        configure(owner: nil, generation: generation)
    }

    func deliver(name: UnsafePointer<CChar>, info: UnsafePointer<CChar>?, isError: Bool, isFatal: Bool) {
        lock.lock()
        guard let owner else {
            lock.unlock()
            return
        }
        let shouldSchedule = buffer.append(
            name: VPNEventBuffer.readCString(name, maximumBytes: VPNEventBuffer.maximumNameBytes),
            info: VPNEventBuffer.readCString(info, maximumBytes: VPNEventBuffer.maximumInfoBytes),
            isError: isError, isFatal: isFatal, generation: generation)
        lock.unlock()
        if shouldSchedule {
            Task { @MainActor [weak owner] in
                owner?.handlePendingVPNEvents()
            }
        }
    }

    func drain() -> [VPNEventBuffer.Event] {
        lock.lock()
        defer { lock.unlock() }
        return buffer.drain()
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

    let relay = Unmanaged<VPNEventRelay>.fromOpaque(context).takeUnretainedValue()
    relay.deliver(name: name,
                  info: info,
                  isError: isError,
                  isFatal: isFatal)
}

@MainActor
final class VPNController: NSObject {
    private let profilePath: String
    private let configFilePath: String?
    private let verbosity: AppVerbosity
    private var tunnelMode: AppTunnelMode
    private var routeManager: RouteManager
    private var menuBarController: MenuBarController?
    private var sessionState: SessionState
    private var client: OpaquePointer?
    private let vpnEventRelay = VPNEventRelay()
    private var vpnEventGeneration = 0
    private var signalSources: [DispatchSourceSignal] = []
    private var pathMonitor: NWPathMonitor?
    private let pathMonitorQueue = DispatchQueue(label: "cwru-ovpn.network-path-monitor", qos: .utility)
    private var hasSeenInitialPathUpdate = false
    private var menuBarRefreshTimer: Timer?
    private let reachabilityProbeQueue = DispatchQueue(label: "cwru-ovpn.reachability-probe", qos: .utility)
    private let gatewayResolveQueue = DispatchQueue(label: "cwru-ovpn.gateway-resolve", qos: .userInitiated)
    private var webAuthPresentationGeneration = 0
    private var pendingWebAuthRequest: WebAuthRequest?
    private var webAuthDNSOverrideInstalled = false
    private var reachabilityProbeInFlight = false
    private var reachabilityProbeGeneration = 0
    private var lastReachabilityProbeHealthy = true
    private var lastReachabilityAlertAt: Date?
    private var routeHealthCheckGeneration = 0
    private var routeHealthCheckDeadline: Date?
    private var routeHealthCheckLogReason: String?
    private var routeHealthCheckLoggedAt: Date?
    private var routeHealthCheckSuppressedLogCount = 0
    private var webAuthRecovery = WebAuthRecovery()
    private var dnsBootstrapRetryGeneration = 0
    private var dnsBootstrapRetryAttempted = false
    private var handshakeProgressObserved = false
    private var connectProfileContent: String?
    private var connectServerOverride: String?
    private var localTransportFailureWindowStartedAt: Date?
    private var localTransportFailureCount = 0
    private var lastOpenVPNTransportReconnectAt: Date?
    private var transportDegradedAt: Date?
    private var transportRecoveryState: TransportRecoveryState?
    private var transportRecoveryDeadlineGeneration = 0
    private var stableTransportGeneration = 0
    private var reconnectLifecycleEventLogWindow = ReconnectLifecycleEventLogWindow(startedAt: nil,
                                                                                     eventNames: [])
    private var lastEventLogLine: (info: String, at: Date)?
    private var fullTunnelControlChannelSettleCount = 0
    private var postConnectConfigurationSettleCount = 0
    private var postConnectConfigurationGeneration = 0
    private var preexistingBlockedIPv6Routes: Set<String>?
    private var sleepAssertionID: PowerManagement.AssertionID?
    private var externalWebAuthSession: ExternalWebAuthSession?
    private var controllerLock: ControllerLock?
    private var cleanupComplete = false
    private var requestedStop = false
    private var disconnectCleanupFallbackScheduled = false
    private var handlingConnectedEvent = false
    private var managedReconnectRequest: ManagedReconnectRequest?
    private var workspaceObserversInstalled = false
    private var systemAsleep = false
    private var disconnectingAfterWake = false
    private var pendingDisconnectAlertMessage: String?
    private var applicationTerminationPending = false
    private var estimatedSessionCountdownAlertShown = false
    private let preventSleep: Bool
    private let privacyMode: Bool
    private let webAuthSession: WebAuthSessionMode
    private let backgroundChild: Bool
    private var startupStatusFilePath: String?
    private var exitStatus: Int32 = EXIT_SUCCESS

    init(profilePath: String,
         configFilePath: String?,
         configuration: AppConfig,
         verbosity: AppVerbosity,
         tunnelMode: AppTunnelMode,
         preventSleep: Bool,
         backgroundChild: Bool,
         startupStatusFilePath: String?) throws {
        let startupLock = try ControllerLock()
        let controllerPID = getpid()
        guard let controllerStartTime = processStartTime(controllerPID) else {
            throw VPNControllerError.failedToStart("Could not establish the VPN controller process identity.")
        }
        let routeManager = RouteManager(dnsBootstrapServers: configuration.effectiveDNSBootstrapServers)
        let physicalNetwork = try routeManager.detectPhysicalNetwork()
        guard let physicalDNSConfiguration = try routeManager.capturePhysicalDNSConfiguration(for: physicalNetwork.interfaceName) else {
            throw VPNControllerError.failedToStart(
                "Could not capture the active macOS DNS service for VPN DNS isolation."
            )
        }
        let originalDefaultSearchDomains = routeManager.captureActiveDefaultSearchDomains()
        if tunnelMode == .full {
            try routeManager.assertFullTunnelSupported(physicalInterface: physicalNetwork.interfaceName,
                                                       ipv6Mode: physicalDNSConfiguration.ipv6Mode)
        }
        self.profilePath = URL(fileURLWithPath: profilePath).standardized.path
        self.configFilePath = configFilePath.map { URL(fileURLWithPath: $0).standardized.path }
        self.verbosity = verbosity
        self.tunnelMode = tunnelMode
        self.routeManager = routeManager
        self.preventSleep = preventSleep
        self.privacyMode = configuration.privacyMode
        self.webAuthSession = configuration.webAuthSession
        self.backgroundChild = backgroundChild
        self.startupStatusFilePath = startupStatusFilePath.map { URL(fileURLWithPath: $0).standardized.path }
        self.controllerLock = startupLock
        self.sessionState = SessionState(
            pid: controllerPID,
            executablePath: try ExecutionIdentity.currentExecutablePath(),
            processStartTime: controllerStartTime,
            phase: .connecting,
            profilePath: self.profilePath,
            configFilePath: self.configFilePath,
            startedAt: Date(),
            lastEvent: nil,
            lastInfo: nil,
            physicalGateway: physicalNetwork.gateway,
            physicalInterface: physicalNetwork.interfaceName,
            physicalServiceName: physicalDNSConfiguration.serviceName,
            originalDNSServers: physicalDNSConfiguration.dnsServers,
            originalSearchDomains: physicalDNSConfiguration.searchDomains,
            originalDefaultSearchDomains: originalDefaultSearchDomains,
            originalIPv6Mode: physicalDNSConfiguration.ipv6Mode,
            pushedDNSServers: nil,
            pushedSearchDomains: nil,
            tunName: nil,
            vpnIPv4: nil,
            vpnIPv6: nil,
            serverHost: nil,
            serverIP: nil,
            tunnelMode: tunnelMode,
            requestedTunnelMode: nil,
            fullTunnelDefaultRoutes: nil,
            fullTunnelDNSServers: nil,
            fullTunnelSearchDomains: nil,
            appliedSplitIPv4Routes: nil,
            appliedSplitIPv6Routes: nil,
            appliedDNSDomains: nil,
            cleanupNeeded: false
        )
        super.init()
        self.vpnEventRelay.configure(owner: self, generation: vpnEventGeneration)
    }

    isolated deinit {
        menuBarRefreshTimer?.invalidate()
        removeWorkspaceObservers()
        shutdownOpenVPNClient()
        releaseControllerLock()
    }

    func start() throws {
        emit("Starting VPN in \(tunnelMode.modeDescription) mode.")
        installMenuBarIfNeeded()
        updateMenuBar()

        try RuntimePaths.ensureStateDirectory()
        let profileData = try ProfileManifest.readProfileData(at: URL(fileURLWithPath: profilePath))
        try ProfileManifest.verifyApprovedIfEnforced(profileData: profileData)
        let configContent = String(decoding: profileData, as: UTF8.self)
        try OpenVPNProfilePolicy.validate(configContent: configContent)
        let effectiveConfigContent = Self.openVPNConfigContent(configContent, for: tunnelMode)
        EventLog.configure(privacyMode: privacyMode)
        EventLog.startSession(profilePath: profilePath)

        var startupCleanupArmed = false

        do {
            sessionState.cleanupNeeded = true
            try sessionState.create()
            startupCleanupArmed = true
            try startCleanupWatchdog()

            EventLog.append(note: "Starting VPN client.", phase: sessionState.phase)
            emit("Event log: \(RuntimePaths.eventLogFile.path)", level: .debug)
            removeStaleWebAuthDNSOverride()
            installSignalHandlers()
            installWorkspaceObservers()
            connectProfileContent = effectiveConfigContent
            preexistingBlockedIPv6Routes = Set(try routeManager.presentOpenVPNBlockedIPv6Routes())
            let gatewayOverride = sinkholedGatewayOverride(profileContent: effectiveConfigContent)
            try launchOpenVPNClient(profileContent: effectiveConfigContent, serverOverride: gatewayOverride)

            armDNSBootstrapRetryIfNeeded()
        } catch {
            if startupCleanupArmed {
                cleanupAfterStartupFailure(error)
            }
            throw error
        }
    }

    private func launchOpenVPNClient(profileContent: String, serverOverride: String?) throws {
        guard let client = cwru_ovpn_client_create() else {
            throw VPNControllerError.failedToStart("OpenVPN 3 client allocation failed")
        }
        self.client = client

        vpnEventGeneration += 1
        vpnEventRelay.configure(owner: self, generation: vpnEventGeneration)
        cwru_ovpn_client_set_event_callback(client, vpnEventTrampoline, Unmanaged.passUnretained(vpnEventRelay).toOpaque())

        var errorPointer: UnsafeMutablePointer<CChar>?
        let started = profileContent.withCString { configCString in
            AppIdentity.reportedClientVersion.withCString { guiCString in
                AppConfig.supportedSSOMethods.joined(separator: ",").withCString { ssoCString in
                    Self.openVPNAllowUnusedAddrFamilies(for: tunnelMode).withCString { allowUnusedCString in
                        (serverOverride ?? "").withCString { serverOverrideCString in
                            cwru_ovpn_client_start(client, configCString, guiCString, ssoCString, allowUnusedCString, serverOverrideCString, &errorPointer)
                        }
                    }
                }
            }
        }

        if !started {
            let message = errorPointer.map { String(cString: $0) } ?? "OpenVPN 3 failed to start"
            if let errorPointer {
                cwru_ovpn_string_free(errorPointer)
            }
            shutdownOpenVPNClient()
            throw VPNControllerError.failedToStart(message)
        }
        connectServerOverride = serverOverride
        armConnectingDeadline()
    }

    private func shutdownOpenVPNClient() {
        guard let activeClient = client else {
            return
        }

        client = nil
        pendingWebAuthRequest = nil
        vpnEventGeneration += 1
        vpnEventRelay.clear(generation: vpnEventGeneration)
        cwru_ovpn_client_shutdown(activeClient)
        cwru_ovpn_client_destroy(activeClient)
    }

    func handleEvent(name: String, info: String, isError: Bool, isFatal: Bool) {
        if requestedStop && name != "DISCONNECTED" {
            EventLog.append(eventName: name,
                            info: info,
                            isError: isError,
                            isFatal: isFatal,
                            phase: sessionState.phase)
            return
        }

        let persistStatusEvent = shouldPersistStatusEvent(name: name, info: info, isError: isError, isFatal: isFatal)
        if persistStatusEvent {
            sessionState.lastEvent = name
            let redactedInfo = redactForDisplay(info)
            sessionState.lastInfo = redactedInfo.isEmpty ? nil : redactedInfo
        }
        recordFatalDisconnectIfNeeded(name: name, info: info, isFatal: isFatal)
        if shouldAppendEventToEventLog(name: name, info: info, isError: isError, isFatal: isFatal) {
            EventLog.append(eventName: name,
                            info: info,
                            isError: isError,
                            isFatal: isFatal,
                            phase: sessionState.phase)
        }
        if persistStatusEvent {
            saveStatusState()
        }
        updateMenuBar()

        if Self.isOpenVPNGatewayProgressEvent(name) {
            handshakeProgressObserved = true
        }

        switch name {
        case "LOG":
            handleLocalTransportFailureLogIfNeeded(info)
            if Self.isOpenVPNNetworkLifecycleLog(info) {
                scheduleRouteHealthCheck(reason: "OpenVPN network lifecycle update")
            }
            parseAndPersistPushedDNS(from: info)
            if shouldSurfaceLogLine(info) {
                emit(redactForDisplay(info), level: .debug)
            }
        case "RECONNECTING":
            postConnectConfigurationGeneration += 1
            markTransportDegraded(.reconnecting,
                                  detail: "OpenVPN is reconnecting after its transport path failed.")
            scheduleRouteHealthCheck(reason: "OpenVPN reconnecting")
        case "AUTH_PENDING":
            postConnectConfigurationGeneration += 1
            sessionState.phase = .authPending
            EventLog.append(note: "Authentication entered AUTH_PENDING.", phase: sessionState.phase)
            saveStatusState()
            armAuthPendingDeadline(info: info)
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
            postConnectConfigurationGeneration += 1
            handleConnected()
        case "ASSIGN_IP":
            postConnectConfigurationGeneration += 1
            emit("Sign-in complete. Finalizing connection.")
            EventLog.append(note: "Authentication completed; finalizing tunnel setup.", phase: sessionState.phase)
            closeAuthenticationUI()
        case "DISCONNECTED":
            sessionState.phase = .disconnected
            saveStatusState()
            updateMenuBar()
            completeCleanupAndExit()
        case "CORE_STATUS":
            if !info.isEmpty {
                emit(redactForDisplay(info), level: isFatal ? .error : .debug)
            }
        default:
            if isError || isFatal {
                emit("\(name): \(redactForDisplay(info))", level: .error)
            }
        }

        if shouldStopAfterFatalEvent(name: name, isFatal: isFatal) {
            requestStop(reason: "fatal OpenVPN event \(name)")
        }
    }

    fileprivate func handlePendingVPNEvents() {
        for payload in vpnEventRelay.drain() {
            guard payload.generation == vpnEventGeneration, !cleanupComplete else {
                continue
            }
            handleEvent(name: payload.name, info: payload.info, isError: payload.isError, isFatal: payload.isFatal)
        }
    }

    private func handleConnected() {
        do {
            guard try configureConnectedTunnel() else {
                return
            }
            postConnectConfigurationSettleCount = 0
            markTransportRecoveredAfterConnectedEvent()
        } catch {
            handlePostConnectConfigurationFailure(error)
        }
    }

    private func configureConnectedTunnel() throws -> Bool {
        guard let client else {
            return false
        }
        guard !handlingConnectedEvent else {
            return false
        }

        handlingConnectedEvent = true
        defer { handlingConnectedEvent = false }

        var connectedState = sessionState
        connectedState.tunName = copyString { cwru_ovpn_client_copy_tun_name(client) }
        connectedState.vpnIPv4 = copyString { cwru_ovpn_client_copy_vpn_ipv4(client) }
        connectedState.vpnGatewayIPv4 = copyString { cwru_ovpn_client_copy_vpn_gateway_ipv4(client) }
        connectedState.vpnIPv6 = copyString { cwru_ovpn_client_copy_vpn_ipv6(client) }
        connectedState.serverHost = copyString { cwru_ovpn_client_copy_server_host(client) }
        connectedState.serverIP = copyString { cwru_ovpn_client_copy_server_ip(client) }
        let connectedAt = connectedState.connectedAt ?? Date()

        if let tunnelName = connectedState.tunName,
           let capturedRoutes = try? routeManager.captureCurrentFullTunnelDefaultRoutes(tunnelName: tunnelName),
           !capturedRoutes.isEmpty {
            connectedState.fullTunnelDefaultRoutes = capturedRoutes
        }

        let presentBlockedIPv6Routes = try routeManager.presentOpenVPNBlockedIPv6Routes()
        connectedState.sessionOwnedBlockedIPv6Routes = Self.sessionOwnedBlockedIPv6Routes(
            present: presentBlockedIPv6Routes,
            preexisting: preexistingBlockedIPv6Routes
        )

        connectedState.fullTunnelDNSServers = connectedState.pushedDNSServers
        connectedState.fullTunnelSearchDomains = connectedState.pushedSearchDomains

        connectedState.cleanupNeeded = true
        sessionState = connectedState
        try saveState()
        updateMenuBar()

        if tunnelMode == .split {
            do {
                try routeManager.applySplitTunnel(
                    using: &connectedState,
                    persistPreparedState: persistPreparedNetworkState
                )
            } catch {
                do {
                    let cleanupHealthy = try routeManager.cleanup(using: connectedState)
                    sessionState.cleanupNeeded = !cleanupHealthy
                    saveStatusState()
                    if !cleanupHealthy {
                        EventLog.append(note: "Cleanup completed but the network still looked unhealthy.", phase: sessionState.phase)
                        UserAlert.showCritical(message: "Cleanup completed, but the network still looks unhealthy. Run cwru-ovpn doctor for recovery guidance.")
                    }
                } catch {
                    saveStatusState()
                }
                throw error
            }
        } else {
            try routeManager.applyFullTunnelSafety(
                using: &connectedState,
                persistPreparedState: persistPreparedNetworkState
            )
        }

        guard !cleanupComplete, !requestedStop else {
            return false
        }
        guard sessionState.phase == .connecting || sessionState.phase == .authPending else {
            do {
                try applyPendingModeSwitchIfNeeded(trigger: "reconnect")
            } catch {
                emit("Requested mode switch failed: \(error.localizedDescription)", level: .error)
            }
            return !cleanupComplete && !requestedStop
        }

        connectedState.lastEvent = sessionState.lastEvent
        connectedState.lastInfo = sessionState.lastInfo
        connectedState.pushedDNSServers = sessionState.pushedDNSServers
        connectedState.pushedSearchDomains = sessionState.pushedSearchDomains
        connectedState.requestedTunnelMode = sessionState.requestedTunnelMode
        connectedState.phase = .connected
        connectedState.connectedAt = connectedAt
        sessionState = connectedState
        webAuthRecovery.finish()

        do {
            try applyPendingModeSwitchIfNeeded(trigger: "post-connect")
        } catch {
            emit("Requested mode switch failed: \(error.localizedDescription)", level: .error)
        }

        guard !cleanupComplete, !requestedStop else {
            return false
        }

        try saveState()

        startRouteMonitorIfNeeded()
        startSleepAssertionIfNeeded()
        if tunnelMode == .split {
            scheduleReachabilityProbeIfNeeded(reason: "initial split-tunnel connection")
        }

        closeAuthenticationUI()
        EventLog.append(note: tunnelMode == .split
                        ? "VPN tunnel connected and split-tunnel routes applied."
                        : "VPN tunnel connected in full-tunnel mode.",
                        phase: sessionState.phase)
        emit("Connected.")
        updateMenuBar()
        return true
    }

    private func handlePostConnectConfigurationFailure(_ error: Error) {
        if tunnelMode == .full,
           shouldRetryPostConnectConfigurationFailure(error),
           postConnectConfigurationSettleCount < Self.postConnectConfigurationSettleMaxRetries,
           !requestedStop,
           !cleanupComplete {
            postConnectConfigurationSettleCount += 1
            EventLog.append(note: "Post-connect configuration failed while the network settles (attempt \(postConnectConfigurationSettleCount) of \(Self.postConnectConfigurationSettleMaxRetries)): \(error.localizedDescription). Retrying with fail-closed routes in place.",
                            phase: sessionState.phase)
            let generation = vpnEventGeneration
            let configurationGeneration = postConnectConfigurationGeneration
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(Self.postConnectConfigurationSettleDelaySeconds)) { [weak self] in
                guard let self else {
                    return
                }
                guard !self.requestedStop,
                      !self.cleanupComplete,
                      self.vpnEventGeneration == generation,
                      self.postConnectConfigurationGeneration == configurationGeneration,
                      self.sessionState.phase == .connecting || self.sessionState.phase == .authPending || self.sessionState.phase == .connected else {
                    return
                }
                self.handleConnected()
            }
            return
        }

        EventLog.append(note: "Post-connect configuration failed: \(error.localizedDescription)",
                        phase: sessionState.phase)
        failSession(event: "CONFIGURATION_FAILED",
                    message: "The \(tunnelMode.modeDescription) configuration could not be completed: \(error.localizedDescription)")
    }

    private func shouldRetryPostConnectConfigurationFailure(_ error: Error) -> Bool {
        guard let routeManagerError = error as? RouteManagerError else {
            return false
        }

        switch routeManagerError {
        case .failedToSecureFullTunnelIPv4Routes,
             .failedToSecureFullTunnelIPv6Routes:
            return false
        default:
            return true
        }
    }

    private func handleInfoEvent(_ info: String) {
        if info.hasPrefix("OPEN_URL:") {
            failSession(event: "UNSUPPORTED_AUTH_METHOD",
                        message: "The VPN server requested the deprecated OPEN_URL authentication method.")
            return
        }

        switch WebAuthRequest.parseResult(info: info) {
        case .request(let request):
            presentWebAuth(request)
            return
        case .invalid:
            failSession(event: "INVALID_AUTH_REQUEST",
                        message: "The VPN server sent an invalid WebAuth request.")
            return
        case .unrelated:
            break
        }

        if info.hasPrefix("CR_TEXT:") {
            failSession(event: "UNSUPPORTED_AUTH_CHALLENGE",
                        message: "An interactive challenge was requested, but this client does not support that prompt type.")
        }
    }

    private func presentWebAuth(_ request: WebAuthRequest) {
        postConnectConfigurationGeneration += 1
        closeAuthenticationUI()

        let generation = webAuthPresentationGeneration

        guard let host = request.url.host,
              !routeManager.dnsBootstrapServers.isEmpty else {
            startWebAuthSession(request)
            return
        }

        pendingWebAuthRequest = request
        let timeoutSeconds = Self.dnsBootstrapResolveTimeoutSeconds
        let shell = routeManager.shell
        gatewayResolveQueue.async { [weak self] in
            let sinkholed = RouteManager.systemResolverSinkholes(host: host,
                                                                 timeoutSeconds: timeoutSeconds,
                                                                 shell: shell)
            Task { @MainActor [weak self] in
                self?.finishWebAuthDNSProbe(sinkholed: sinkholed, generation: generation)
            }
        }
    }

    private func finishWebAuthDNSProbe(sinkholed: Bool, generation: Int) {
        guard webAuthPresentationGeneration == generation else {
            return
        }

        guard let request = pendingWebAuthRequest,
              !requestedStop,
              !cleanupComplete else {
            pendingWebAuthRequest = nil
            return
        }
        pendingWebAuthRequest = nil

        if sinkholed {
            installWebAuthDNSOverride()
        }
        startWebAuthSession(request)
    }

    private var webAuthInFlight: Bool {
        externalWebAuthSession != nil || pendingWebAuthRequest != nil
    }

    private func installWebAuthDNSOverride() {
        guard !webAuthDNSOverrideInstalled else {
            return
        }

        do {
            try routeManager.installWebAuthBootstrapResolvers()
            try routeManager.flushDNS()
            webAuthDNSOverrideInstalled = true
            EventLog.append(note: "This network's resolver returns a blocked address for the sign-in host; installed scoped resolver files for the OpenVPN namespace pointing at the configured DNS bootstrap servers, for the sign-in window only.",
                            phase: sessionState.phase)
            emit("This network blocks DNS for the sign-in page; resolving it through the configured DNS bootstrap servers until sign-in finishes.", level: .debug)
        } catch {
            EventLog.append(note: "Could not install scoped resolver files for the sign-in host: \(error.localizedDescription)",
                            phase: sessionState.phase)
            emit("Could not work around this network's DNS block for the sign-in page: \(error.localizedDescription)", level: .debug)
            try? routeManager.removeWebAuthBootstrapResolvers()
            try? routeManager.flushDNS()
        }
    }

    private func removeStaleWebAuthDNSOverride() {
        let leftovers = RouteManager.webAuthBootstrapResolverDomains.filter {
            routeManager.resolverFileIsManaged(at: routeManager.resolverFileURL(for: $0))
        }
        guard !leftovers.isEmpty else {
            return
        }

        do {
            try routeManager.removeResolverFiles(for: leftovers)
            try routeManager.flushDNS()
            EventLog.append(note: "Removed scoped resolver files left behind by an interrupted sign-in.",
                            phase: sessionState.phase)
        } catch {
            EventLog.append(note: "Could not remove scoped resolver files left behind by an interrupted sign-in: \(error.localizedDescription)",
                            phase: sessionState.phase)
        }
    }

    private func removeWebAuthDNSOverrideIfNeeded() {
        guard webAuthDNSOverrideInstalled else {
            return
        }
        webAuthDNSOverrideInstalled = false

        do {
            try routeManager.removeWebAuthBootstrapResolvers()
            try routeManager.flushDNS()
            EventLog.append(note: "Removed the scoped resolver files installed for the sign-in window.",
                            phase: sessionState.phase)
        } catch {
            EventLog.append(note: "Could not remove the scoped resolver files installed for the sign-in window: \(error.localizedDescription)",
                            phase: sessionState.phase)
            emit("Could not remove the sign-in DNS workaround: \(error.localizedDescription)", level: .error)
        }
    }

    private func startWebAuthSession(_ request: WebAuthRequest) {
        let isPrivilegedWebAuth = geteuid() == 0
        let usesSystemSession = webAuthSession.usesSystemSession(isPrivileged: isPrivilegedWebAuth)
        let prefersEphemeralSession = webAuthSession != .systemShared
        let url = request.presentationURL(usesSystemSession: usesSystemSession)
        let presentation: String
        let reason: String
        if usesSystemSession {
            presentation = prefersEphemeralSession
                ? "ephemeral system authentication session"
                : "shared system authentication session"
            if webAuthSession == .browser && isPrivilegedWebAuth {
                reason = "privileged session overriding browser mode"
            } else {
                reason = request.requiresExternalBrowser
                    ? "configured system mode overriding server external request"
                    : "configured system mode"
            }
        } else if request.requiresExternalBrowser {
            presentation = "default browser"
            reason = "server-required external browser"
        } else {
            presentation = "default browser"
            reason = "configured browser mode"
        }
        EventLog.append(note: "Opening \(presentation) (\(reason)) for a validated CWRU WebAuth endpoint.",
                        phase: sessionState.phase)
        let controller = ExternalWebAuthSession(
            url: url,
            usesSystemSession: usesSystemSession,
            prefersEphemeralSession: prefersEphemeralSession
        )
        let generation = webAuthPresentationGeneration
        controller.onUserCancelled = { [weak self] in
            guard let self, self.webAuthPresentationGeneration == generation else {
                return
            }
            self.handleAuthenticationCancellation()
        }
        controller.onFailure = { [weak self] error in
            guard let self, self.webAuthPresentationGeneration == generation else {
                return
            }
            self.handleAuthenticationSessionFailure(error)
        }
        if controller.start() {
            externalWebAuthSession = controller
            emit("Opening sign-in window.")
            updateMenuBar()
        } else {
            EventLog.append(note: "Authentication session failed to start.", phase: sessionState.phase)
            failSession(event: "AUTH_SESSION_FAILED",
                        message: "The sign-in session could not be started.")
        }
    }

    func beginApplicationTermination() -> Bool {
        guard !cleanupComplete else {
            return false
        }

        applicationTerminationPending = true
        requestStop(reason: "application quit")
        return true
    }

    private func requestStop(reason: String, failed: Bool = false) {
        if failed {
            exitStatus = EXIT_FAILURE
        }
        guard !requestedStop else {
            return
        }
        requestedStop = true
        EventLog.append(note: "Stopping VPN: \(reason).", phase: sessionState.phase)
        stopRouteMonitor()
        sessionState.phase = .disconnecting
        saveStatusState()
        updateMenuBar()
        if let client {
            scheduleDisconnectCleanupFallback(reason: "controller stop")
            cwru_ovpn_client_stop(client)
        } else {
            completeCleanupAndExit()
        }
    }

    private func handleAuthenticationCancellation() {
        guard !requestedStop, !cleanupComplete else {
            return
        }
        failSession(event: "AUTH_CANCELLED", message: "Sign-in was cancelled.")
    }

    private func handleAuthenticationSessionFailure(_ error: Error) {
        guard !requestedStop, !cleanupComplete else {
            return
        }

        let failure = error as NSError
        EventLog.append(eventName: "AUTH_SESSION_ERROR",
                        info: "\(failure.domain) (\(failure.code))",
                        isError: true,
                        isFatal: false,
                        phase: sessionState.phase)
        closeAuthenticationUI()
        failSession(event: "AUTH_SESSION_FAILED",
                    message: "The sign-in session ended unexpectedly. Disconnecting; reconnect to try again.")
    }

    private func armConnectingDeadline() {
        guard sessionState.phase == .connecting, !requestedStop, !cleanupComplete else {
            return
        }
        let generation = vpnEventGeneration
        scheduleDeadline(.connecting, after: TimeInterval(Self.connectingDeadlineSeconds)) { [weak self] in
            guard let self,
                  self.vpnEventGeneration == generation,
                  self.sessionState.phase == .connecting,
                  !self.requestedStop,
                  !self.cleanupComplete else {
                return
            }
            self.failSession(event: "CONNECT_TIMED_OUT",
                             message: Self.startupConnectTimeoutMessage)
        }
    }

    private func sinkholedGatewayOverride(profileContent: String) -> String? {
        let servers = routeManager.dnsBootstrapServers
        guard let host = Self.firstOpenVPNRemoteHost(in: profileContent),
              Self.shouldPreResolveGateway(host: host, bootstrapServers: servers) else {
            return nil
        }

        let timeoutSeconds = Self.dnsBootstrapResolveTimeoutSeconds
        guard RouteManager.systemResolverSinkholes(host: host,
                                                   timeoutSeconds: timeoutSeconds,
                                                   shell: routeManager.shell) else {
            return nil
        }

        guard let resolvedIP = RouteManager.resolveHostUsingBootstrap(host: host,
                                                                     servers: servers,
                                                                     timeoutSeconds: timeoutSeconds,
                                                                     shell: routeManager.shell) else {
            EventLog.append(note: "This network's resolver returns a blocked address for the VPN gateway, but the configured DNS bootstrap servers could not resolve it either; connecting through the system resolver anyway.",
                            phase: sessionState.phase)
            emit("This network blocks DNS for the VPN gateway and the configured DNS bootstrap servers did not answer.", level: .debug)
            return nil
        }

        EventLog.append(note: "This network's resolver returns a blocked address for the VPN gateway; connecting to the address from the configured DNS bootstrap servers instead of waiting for the connection to stall.",
                        phase: sessionState.phase)
        emit("This network blocks DNS for the VPN gateway; connecting through the configured DNS bootstrap servers.", level: .debug)
        return resolvedIP
    }

    private func armDNSBootstrapRetryIfNeeded() {
        guard !dnsBootstrapRetryAttempted,
              !routeManager.dnsBootstrapServers.isEmpty,
              connectProfileContent != nil,
              sessionState.phase == .connecting,
              !requestedStop,
              !cleanupComplete else {
            return
        }
        dnsBootstrapRetryGeneration += 1
        let generation = dnsBootstrapRetryGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(Self.dnsBootstrapRetryDeadlineSeconds)) { [weak self] in
            guard let self,
                  self.dnsBootstrapRetryGeneration == generation,
                  !self.dnsBootstrapRetryAttempted,
                  !self.handshakeProgressObserved,
                  self.sessionState.phase == .connecting,
                  !self.webAuthInFlight,
                  !self.requestedStop,
                  !self.cleanupComplete else {
                return
            }
            self.performDNSBootstrapRetry()
        }
    }

    private func performDNSBootstrapRetry() {
        dnsBootstrapRetryAttempted = true
        guard client != nil,
              let profileContent = connectProfileContent,
              let host = Self.firstOpenVPNRemoteHost(in: profileContent),
              !SplitTunnelPolicy.isValidIPAddress(host) else {
            return
        }

        let servers = routeManager.dnsBootstrapServers
        let timeoutSeconds = Self.dnsBootstrapResolveTimeoutSeconds
        let generation = dnsBootstrapRetryGeneration
        let shell = routeManager.shell
        emit("Still connecting; re-resolving the VPN gateway through the configured DNS bootstrap servers.", level: .debug)
        gatewayResolveQueue.async { [weak self] in
            let resolvedIP = RouteManager.resolveHostUsingBootstrap(host: host,
                                                                    servers: servers,
                                                                    timeoutSeconds: timeoutSeconds,
                                                                    shell: shell)
            Task { @MainActor [weak self] in
                self?.finishDNSBootstrapRetry(profileContent: profileContent, resolvedIP: resolvedIP, generation: generation)
            }
        }
    }

    private func finishDNSBootstrapRetry(profileContent: String, resolvedIP: String?, generation: Int) {
        guard dnsBootstrapRetryGeneration == generation,
              !handshakeProgressObserved,
              sessionState.phase == .connecting,
              !webAuthInFlight,
              !requestedStop,
              !cleanupComplete,
              client != nil else {
            return
        }

        guard let resolvedIP else {
            EventLog.append(note: "Could not re-resolve the VPN gateway through the configured DNS bootstrap servers; continuing with the system resolver.",
                            phase: sessionState.phase)
            emit("Could not re-resolve the VPN gateway through the configured DNS bootstrap servers.", level: .debug)
            return
        }

        EventLog.append(note: "Connection stalled before reaching the gateway; re-resolved it through the configured DNS bootstrap servers and reconnecting to the verified address.",
                        phase: sessionState.phase)
        emit("Reconnecting to the VPN gateway using the address from the configured DNS bootstrap servers.", level: .debug)

        shutdownOpenVPNClient()

        do {
            try launchOpenVPNClient(profileContent: profileContent, serverOverride: resolvedIP)
        } catch {
            EventLog.append(note: "DNS bootstrap reconnect failed to start: \(error.localizedDescription)",
                            phase: sessionState.phase)
            failSession(event: "DNS_BOOTSTRAP_FAILED",
                        message: "Reconnecting with the bootstrap-resolved gateway address failed: \(error.localizedDescription)")
        }
    }

    private func armAuthPendingDeadline(info: String) {
        guard sessionState.phase == .authPending,
              !requestedStop,
              !cleanupComplete,
              let deadline = webAuthRecovery.begin(info: info, now: Date()) else {
            return
        }
        scheduleDeadline(.authPending, after: max(0, deadline.timeIntervalSinceNow)) { [weak self] in
            guard let self,
                  self.webAuthRecovery.deadline == deadline,
                  self.sessionState.phase == .authPending,
                  !self.requestedStop,
                  !self.cleanupComplete else {
                return
            }
            self.closeAuthenticationUI()
            self.failSession(event: "AUTH_TIMED_OUT",
                             message: "The sign-in request expired before the VPN connection completed. Reconnect to start a new request.")
        }
    }

    private var canRetryWebAuthentication: Bool {
        sessionState.phase == .authPending
            && sessionState.connectedAt == nil
            && webAuthRecovery.canRetry
            && webAuthInFlight
            && webAuthSession.usesSystemSession(isPrivileged: geteuid() == 0)
            && !requestedStop
            && !cleanupComplete
            && !systemAsleep
            && client != nil
            && connectProfileContent != nil
    }

    private func retryWebAuthentication() {
        guard canRetryWebAuthentication,
              let profileContent = connectProfileContent,
              webAuthRecovery.retry() else {
            return
        }

        let serverOverride = connectServerOverride
        closeAuthenticationUI()
        shutdownOpenVPNClient()
        dnsBootstrapRetryGeneration += 1
        dnsBootstrapRetryAttempted = false
        handshakeProgressObserved = false
        sessionState.phase = .connecting
        sessionState.lastEvent = "AUTH_RETRY"
        sessionState.lastInfo = "Retrying sign-in with a new VPN authentication request."
        sessionState.pushedDNSServers = nil
        sessionState.pushedSearchDomains = nil
        EventLog.append(eventName: "AUTH_RETRY",
                        info: "user requested sign-in retry",
                        isError: false,
                        isFatal: false,
                        phase: sessionState.phase)
        emit("Retrying sign-in. Your existing browser sign-in may be reused.")

        do {
            try saveState()
            try launchOpenVPNClient(profileContent: profileContent, serverOverride: serverOverride)
            armDNSBootstrapRetryIfNeeded()
        } catch {
            failSession(event: "AUTH_RETRY_FAILED",
                        message: "The sign-in retry could not be started: \(error.localizedDescription)")
        }
        updateMenuBar()
    }

    private func failSession(event: String, message: String) {
        sessionState.lastEvent = event
        sessionState.lastInfo = message
        if backgroundChild {
            DetachedStartupStatus.writeFailure(message: message, to: startupStatusFilePath)
        }
        saveStatusState()
        updateMenuBar()
        EventLog.append(note: message, phase: sessionState.phase)
        emit(message, level: .error)
        requestStop(reason: message, failed: true)
    }

    private func handleLocalTransportFailureLogIfNeeded(_ info: String) {
        guard Self.isLocalTransportFailureLog(info),
              sessionState.phase == .connected,
              !requestedStop,
              !cleanupComplete else {
            return
        }

        let decision = Self.evaluateLocalTransportFailure(
            window: LocalTransportFailureWindow(startedAt: localTransportFailureWindowStartedAt,
                                                count: localTransportFailureCount),
            now: Date(),
            systemAsleep: systemAsleep
        )
        localTransportFailureWindowStartedAt = decision.window.startedAt
        localTransportFailureCount = decision.window.count

        switch decision.action {
        case .none:
            break
        case .reconnect:
            markTransportDegraded(.reconnecting,
                                  detail: "The VPN transport path is unavailable and OpenVPN is reconnecting.")
            requestOpenVPNTransportReconnect(reason: "local transport send failures")
        case .restart:
            scheduleManagedReconnect(reason: "persistent local transport send failures")
        }
    }

    private func requestOpenVPNTransportReconnect(reason: String) {
        guard let client,
              sessionState.phase == .connected,
              managedReconnectRequest == nil,
              !requestedStop,
              !cleanupComplete else {
            return
        }

        let now = Date()
        if let lastOpenVPNTransportReconnectAt,
           now.timeIntervalSince(lastOpenVPNTransportReconnectAt) < Self.openVPNTransportReconnectThrottleSeconds {
            return
        }

        lastOpenVPNTransportReconnectAt = now
        EventLog.append(note: "Requesting OpenVPN reconnect after \(reason).", phase: sessionState.phase)
        cwru_ovpn_client_reconnect(client, 1)
        scheduleRouteHealthCheck(reason: "OpenVPN reconnect requested after \(reason)")
    }

    private func resetLocalTransportFailureTracking() {
        localTransportFailureWindowStartedAt = nil
        localTransportFailureCount = 0
        lastOpenVPNTransportReconnectAt = nil
        fullTunnelControlChannelSettleCount = 0
    }

    private func markTransportDegraded(_ state: TransportRecoveryState, detail: String) {
        guard sessionState.phase == .connected,
              !requestedStop,
              !cleanupComplete else {
            return
        }

        stableTransportGeneration += 1
        let firstFailure = transportDegradedAt == nil
        if firstFailure {
            transportDegradedAt = Date()
        }
        if transportRecoveryState != .reconnecting || state == .reconnecting {
            transportRecoveryState = state
        }

        if state == .hostPathDegraded,
           Self.reachabilityDegradationStateNeedsUpdate(lastEvent: sessionState.lastEvent,
                                                        lastInfo: sessionState.lastInfo,
                                                        detail: detail) {
            sessionState.lastEvent = "DATA_PATH_DEGRADED"
            sessionState.lastInfo = detail
            saveStatusState()
        }

        if firstFailure {
            EventLog.append(note: detail, phase: sessionState.phase)
            armTransportRecoveryDeadline()
        }
        updateMenuBar()
    }

    private func markTransportRecoveredAfterConnectedEvent() {
        let wasDegraded = transportDegradedAt != nil
        if wasDegraded {
            let alreadyStabilizing = transportRecoveryState == .stabilizing
            transportRecoveryState = .stabilizing
            sessionState.lastEvent = "TRANSPORT_RECOVERY_STABILIZING"
            sessionState.lastInfo = "OpenVPN reconnected; verifying that the transport path remains stable."
            saveStatusState()
            if !alreadyStabilizing {
                EventLog.append(note: "OpenVPN reconnected; waiting for a stable recovery interval before clearing the outage deadline.",
                                phase: sessionState.phase)
                armStableTransportReset()
            }
            updateMenuBar()
            return
        }
        armStableTransportReset()
        updateMenuBar()
    }

    private func markReachabilityRecoveredIfNeeded() {
        guard transportRecoveryState == .hostPathDegraded else {
            return
        }
        transportRecoveryState = .stabilizing
        sessionState.lastEvent = "TRANSPORT_RECOVERY_STABILIZING"
        sessionState.lastInfo = "The split-tunnel host path recovered; verifying that it remains stable."
        saveStatusState()
        EventLog.append(note: "The split-tunnel host path recovered; waiting for a stable interval before clearing the outage deadline.",
                        phase: sessionState.phase)
        armStableTransportReset()
        updateMenuBar()
    }

    private func armTransportRecoveryDeadline() {
        guard let degradedAt = transportDegradedAt else {
            return
        }
        transportRecoveryDeadlineGeneration += 1
        let generation = transportRecoveryDeadlineGeneration
        let delay = Self.transportRecoveryDeadlineDelay(degradedAt: degradedAt, now: Date())
        scheduleDeadline(.transportRecovery, after: delay) { [weak self] in
            guard let self,
                  self.transportRecoveryDeadlineGeneration == generation,
                  self.transportDegradedAt == degradedAt,
                  self.sessionState.phase == .connected,
                  !self.requestedStop,
                  !self.cleanupComplete else {
                return
            }
            let message = "VPN recovery did not complete within 10 minutes. Disconnecting to restore normal system networking; reconnect when the network is stable."
            self.sessionState.lastEvent = "TRANSPORT_RECOVERY_TIMED_OUT"
            self.sessionState.lastInfo = message
            self.pendingDisconnectAlertMessage = self.pendingDisconnectAlertMessage ?? message
            self.saveStatusState()
            self.updateMenuBar()
            EventLog.append(note: message, phase: self.sessionState.phase)
            self.requestStop(reason: "transport recovery deadline expired", failed: true)
        }
    }

    private func scheduleDeadline(_ kind: DeadlineKind,
                                  after delay: TimeInterval,
                                  execute: @escaping @MainActor @Sendable () -> Void) {
        switch Self.deadlineClock(for: kind) {
        case .wall:
            DispatchQueue.main.asyncAfter(wallDeadline: .now() + delay, execute: execute)
        case .monotonic:
            DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: execute)
        }
    }

    private func armStableTransportReset() {
        stableTransportGeneration += 1
        let generation = stableTransportGeneration
        let degradedAt = transportDegradedAt
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.stableTransportResetSeconds) { [weak self] in
            guard let self,
                  self.stableTransportGeneration == generation,
                  self.transportDegradedAt == degradedAt,
                  self.sessionState.phase == .connected,
                  !self.requestedStop,
                  !self.cleanupComplete else {
                return
            }
            if degradedAt != nil {
                guard self.transportRecoveryState == .stabilizing else {
                    return
                }
                self.transportDegradedAt = nil
                self.transportRecoveryState = nil
                self.transportRecoveryDeadlineGeneration += 1
                self.sessionState.lastEvent = "CONNECTED"
                self.sessionState.lastInfo = nil
                self.saveStatusState()
                EventLog.append(note: "VPN transport remained stable and the outage deadline was cleared.",
                                phase: self.sessionState.phase)
                self.updateMenuBar()
            }
            self.resetLocalTransportFailureTracking()
            do {
                try ManagedReconnectBudget.reset()
            } catch {
                EventLog.append(note: "Could not reset the managed reconnect budget after a stable connection: \(error.localizedDescription)",
                                phase: self.sessionState.phase)
            }
        }
    }

    private func scheduleManagedReconnect(reason: String) {
        guard sessionState.phase == .connected,
              managedReconnectRequest == nil,
              !requestedStop,
              !cleanupComplete else {
            return
        }

        guard backgroundChild else {
            let message = "VPN transport recovery failed. Disconnecting to restore normal system networking; reconnect when the network is stable."
            pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? message
            requestStop(reason: "persistent transport failure", failed: true)
            return
        }

        let budgetAvailable: Bool
        do {
            budgetAvailable = try ManagedReconnectBudget.reserveAttempt()
        } catch {
            let message = "Automatic VPN recovery could not safely reserve its retry budget. Disconnecting to avoid a reconnect loop."
            pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? message
            EventLog.append(note: "Managed reconnect budget failed closed: \(error.localizedDescription)",
                            phase: sessionState.phase)
            requestStop(reason: "managed reconnect budget unavailable", failed: true)
            return
        }
        guard budgetAvailable else {
            let message = "VPN recovery failed repeatedly. Automatic reconnect stopped to restore normal system networking; reconnect manually when the network is stable."
            pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? message
            EventLog.append(note: "Managed reconnect budget exhausted.", phase: sessionState.phase)
            requestStop(reason: "managed reconnect budget exhausted", failed: true)
            return
        }

        let reconnectTunnelMode = Self.managedReconnectTunnelMode(persistedState: SessionState.load(),
                                                                  controllerPID: sessionState.pid,
                                                                  controllerExecutablePath: sessionState.executablePath,
                                                                  controllerStartTime: sessionState.processStartTime,
                                                                  currentMode: tunnelMode)
        managedReconnectRequest = ManagedReconnectRequest(configFilePath: configFilePath,
                                                         tunnelMode: reconnectTunnelMode,
                                                         reason: reason)
        EventLog.append(note: "Scheduling managed reconnect after \(reason).", phase: sessionState.phase)
        emit("Reconnecting after \(reason).", level: .error)
        requestStop(reason: "managed reconnect after \(reason)")
    }

    private func recordSessionOwnedBlockedIPv6RoutesBeforeCleanupIfNeeded() {
        guard sessionState.connectedAt == nil,
              sessionState.sessionOwnedBlockedIPv6Routes == nil,
              preexistingBlockedIPv6Routes != nil,
              let presentBlockedIPv6Routes = try? routeManager.presentOpenVPNBlockedIPv6Routes() else {
            return
        }
        sessionState.sessionOwnedBlockedIPv6Routes = Self.sessionOwnedBlockedIPv6Routes(
            present: presentBlockedIPv6Routes,
            preexisting: preexistingBlockedIPv6Routes
        )
    }

    private func cleanupAfterStartupFailure(_ startupError: Error) {
        guard !cleanupComplete else {
            return
        }

        cleanupComplete = true
        stopRouteMonitor()
        stopSleepAssertion()
        EventLog.append(note: "Startup failed before the VPN client fully started; restoring network configuration: \(startupError.localizedDescription)",
                        phase: sessionState.phase)
        shutdownOpenVPNClient()
        recordSessionOwnedBlockedIPv6RoutesBeforeCleanupIfNeeded()

        var shouldRemoveSessionState = true
        do {
            let cleanupHealthy = try RouteManager(appliedState: sessionState).cleanup(using: sessionState)
            if cleanupHealthy {
                sessionState.cleanupNeeded = false
            } else {
                shouldRemoveSessionState = false
                sessionState.markRecoveryRequired(message: "Startup failed and cleanup completed, but the network still looks unhealthy.")
                EventLog.append(note: "Startup-failure cleanup completed but the network still looked unhealthy.",
                                phase: sessionState.phase)
                saveStatusState()
                UserAlert.showCritical(message: "Startup failed and cleanup completed, but the network still looks unhealthy. Run cwru-ovpn doctor for recovery guidance.")
            }
        } catch {
            shouldRemoveSessionState = false
            sessionState.markRecoveryRequired(message: "Startup failed and cleanup failed: \(error.localizedDescription)")
            EventLog.append(note: "Startup-failure cleanup failed: \(error.localizedDescription)",
                            phase: sessionState.phase)
            saveStatusState()
            UserAlert.showCritical(message: "Startup failed and cleanup failed. Your network may require manual recovery.")
        }

        closeAuthenticationUI()
        removeWorkspaceObservers()
        if shouldRemoveSessionState {
            SessionState.remove()
        }
        releaseControllerLock()
    }

    private func completeCleanupAndExit() {
        guard !cleanupComplete else {
            return
        }
        cleanupComplete = true
        stopRouteMonitor()
        stopSleepAssertion()
        EventLog.append(note: "Completing cleanup.", phase: sessionState.phase)
        shutdownOpenVPNClient()
        recordSessionOwnedBlockedIPv6RoutesBeforeCleanupIfNeeded()
        var shouldRemoveSessionState = true

        if sessionState.cleanupNeeded {
            do {
                let cleanupHealthy = try routeManager.cleanup(using: sessionState)
                let outcome = Self.cleanupCompletionOutcome(cleanupHealthy: cleanupHealthy,
                                                            disconnectingAfterWake: disconnectingAfterWake)
                shouldRemoveSessionState = outcome.shouldRemoveSessionState
                if let message = outcome.recoveryMessage {
                    exitStatus = EXIT_FAILURE
                    EventLog.append(note: message, phase: sessionState.phase)
                    sessionState.markRecoveryRequired(message: message)
                    saveStatusState()
                    UserAlert.showCritical(message: "\(message) If traffic does not recover, run ovpnd again.")
                } else {
                    EventLog.append(note: "Restored pre-connection network configuration.", phase: sessionState.phase)
                }
            } catch {
                shouldRemoveSessionState = false
                exitStatus = EXIT_FAILURE
                EventLog.append(note: "Cleanup failed: \(error.localizedDescription)", phase: sessionState.phase)
                sessionState.markRecoveryRequired(message: "Cleanup failed: \(error.localizedDescription)")
                saveStatusState()
                UserAlert.showCritical(message: "Cleanup failed. Your network may require manual recovery.")
            }
        }

        closeAuthenticationUI()
        menuBarRefreshTimer?.invalidate()
        menuBarRefreshTimer = nil
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
        if shouldRemoveSessionState, let pendingDisconnectAlertMessage {
            UserAlert.showCritical(message: pendingDisconnectAlertMessage)
        }
        UserAlert.whenNoAlertIsPending { [self] in
            if applicationTerminationPending {
                applicationTerminationPending = false
                NSApplication.shared.reply(toApplicationShouldTerminate: true)
            } else {
                DispatchQueue.main.async {
                    exit(self.exitStatus)
                }
            }
        }
    }

    private func scheduleDisconnectCleanupFallback(reason: String) {
        guard !disconnectCleanupFallbackScheduled else {
            return
        }
        disconnectCleanupFallbackScheduled = true

        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(2)) { [weak self] in
            guard let self, !self.cleanupComplete else {
                return
            }
            EventLog.append(note: "Completing cleanup after \(reason) without a DISCONNECTED event.",
                            phase: self.sessionState.phase)
            self.completeCleanupAndExit()
        }
    }

    private func startRouteMonitorIfNeeded() {
        guard pathMonitor == nil else {
            return
        }

        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
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

            let interfaces = Set(path.availableInterfaces.map(\.name)).sorted().joined(separator: ", ")
            let reason = interfaces.isEmpty
                ? "network path changed (\(status))"
                : "network path changed (\(status); interfaces: \(interfaces))"

            Task { @MainActor [weak self] in
                self?.handlePathMonitorChange(reason: reason)
            }
        }
        monitor.start(queue: pathMonitorQueue)
        pathMonitor = monitor
        hasSeenInitialPathUpdate = false
        EventLog.append(note: "Started network path monitor.", phase: sessionState.phase)
    }

    private func stopRouteMonitor() {
        pathMonitor?.cancel()
        pathMonitor = nil
        hasSeenInitialPathUpdate = false
        routeHealthCheckGeneration += 1
        routeHealthCheckDeadline = nil
        flushSuppressedRouteHealthCheckLog()
        routeHealthCheckLogReason = nil
        routeHealthCheckLoggedAt = nil
        invalidateReachabilityProbe()
    }

    private func performRouteHealthCheck() {
        guard sessionState.phase == .connected else {
            return
        }

        guard let client, cwru_ovpn_client_is_running(client) else {
            let message = "The OpenVPN worker exited while the tunnel still appeared connected. Disconnecting to restore network configuration."
            pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? message
            EventLog.append(note: message, phase: sessionState.phase)
            requestStop(reason: "OpenVPN worker is no longer running", failed: true)
            return
        }

        do {
            if tunnelMode == .split,
               try repairSplitTunnelPhysicalNetworkChangeIfNeeded(reason: "route health check") {
                return
            }

            if tunnelMode == .full,
               try repairFullTunnelPhysicalNetworkChangeIfNeeded(reason: "route health check") {
                return
            }

            switch tunnelMode {
            case .split:
                let snapshot = sessionState
                let stillConnected = try routeManager.monitorAndRepair(using: snapshot)
                if stillConnected {
                    scheduleReachabilityProbeIfNeeded(reason: "route health check")
                } else {
                    emit("The VPN tunnel is no longer available. Disconnecting.", level: .error)
                    EventLog.append(note: "Route health check detected a missing tunnel interface.", phase: sessionState.phase)
                    requestStop(reason: "missing split-tunnel interface", failed: true)
                }
            case .full:
                var fullState = sessionState
                let stillConnected = try routeManager.monitorFullTunnel(
                    using: &fullState,
                    persistPreparedState: persistPreparedNetworkState
                )
                if stillConnected {
                    sessionState = fullState
                    fullTunnelControlChannelSettleCount = 0
                    saveStatusState()
                } else {
                    emit("The VPN tunnel is no longer available. Disconnecting.", level: .error)
                    EventLog.append(note: "Full-tunnel route health check detected a missing tunnel interface.",
                                    phase: sessionState.phase)
                    requestStop(reason: "missing full-tunnel interface", failed: true)
                }
            }
        } catch RouteManagerError.failedToSecureFullTunnelControlChannel
                    where tunnelMode == .full
                        && fullTunnelControlChannelSettleCount < Self.fullTunnelControlChannelSettleMaxRetries {
            fullTunnelControlChannelSettleCount += 1
            EventLog.append(note: "Full-tunnel control channel is still settling after a network change (attempt \(fullTunnelControlChannelSettleCount) of \(Self.fullTunnelControlChannelSettleMaxRetries)); allowing a bounded recovery interval.",
                            phase: sessionState.phase)
            requestOpenVPNTransportReconnect(reason: "full-tunnel control channel settling")
            scheduleRouteHealthCheck(reason: "full-tunnel control channel is still settling")
        } catch {
            emit("The route health check failed: \(error.localizedDescription). Disconnecting.", level: .error)
            EventLog.append(note: "Route health check failed closed: \(error.localizedDescription)", phase: sessionState.phase)
            requestStop(reason: "route health check failed closed", failed: true)
        }
    }

    private func handlePathMonitorChange(reason: String) {
        if !hasSeenInitialPathUpdate {
            hasSeenInitialPathUpdate = true
            return
        }

        scheduleRouteHealthCheck(reason: reason)
    }

    private func scheduleRouteHealthCheck(reason: String) {
        guard sessionState.phase == .connected else {
            return
        }

        guard let deadline = Self.routeHealthCheckSchedule(existingDeadline: routeHealthCheckDeadline,
                                                           now: Date()) else {
            return
        }

        routeHealthCheckGeneration += 1
        let generation = routeHealthCheckGeneration
        routeHealthCheckDeadline = deadline
        appendRouteHealthCheckLog(reason: reason)
        DispatchQueue.main.asyncAfter(deadline: .now() + max(0, deadline.timeIntervalSinceNow)) { [weak self] in
            guard let self else {
                return
            }
            guard generation == self.routeHealthCheckGeneration else {
                return
            }
            self.routeHealthCheckDeadline = nil
            self.performRouteHealthCheck()
        }
    }

    private func appendRouteHealthCheckLog(reason: String) {
        let now = Date()
        let plan = Self.routeHealthCheckLogPlan(reason: reason,
                                                lastReason: routeHealthCheckLogReason,
                                                lastLoggedAt: routeHealthCheckLoggedAt,
                                                suppressedCount: routeHealthCheckSuppressedLogCount,
                                                now: now)
        routeHealthCheckLogReason = reason
        guard plan.shouldLog else {
            routeHealthCheckSuppressedLogCount = plan.suppressedCount
            return
        }
        routeHealthCheckLoggedAt = now
        routeHealthCheckSuppressedLogCount = 0
        EventLog.append(note: Self.routeHealthCheckLogNote(reason: reason,
                                                           suppressedCount: plan.suppressedCount),
                        phase: sessionState.phase)
    }

    private func flushSuppressedRouteHealthCheckLog() {
        guard routeHealthCheckSuppressedLogCount > 0,
              let reason = routeHealthCheckLogReason else {
            routeHealthCheckSuppressedLogCount = 0
            return
        }
        let suppressedCount = routeHealthCheckSuppressedLogCount
        routeHealthCheckSuppressedLogCount = 0
        EventLog.append(note: Self.routeHealthCheckLogNote(reason: reason, suppressedCount: suppressedCount),
                        phase: sessionState.phase)
    }

    private func migratePhysicalNetworkStateIfNeeded(reason: String,
                                                     rescheduleIfSettling: Bool) throws -> PhysicalNetworkMigrationOutcome {
        let physicalNetwork: PhysicalNetwork
        do {
            physicalNetwork = try routeManager.detectPhysicalNetwork()
        } catch {
            if rescheduleIfSettling {
                try routeManager.validateNetworkSafetyWhileSettling(using: sessionState)
                EventLog.append(note: "Physical network is still settling after \(reason): \(error.localizedDescription)",
                                phase: sessionState.phase)
                scheduleRouteHealthCheck(reason: "the physical network is still settling")
                return .deferred
            }
            throw VPNControllerError.failedToStart(
                "The physical network is still settling after \(reason): \(error.localizedDescription)"
            )
        }

        guard let physicalDNSConfiguration = try routeManager.capturePhysicalDNSConfiguration(for: physicalNetwork.interfaceName) else {
            if rescheduleIfSettling {
                try routeManager.validateNetworkSafetyWhileSettling(using: sessionState)
                EventLog.append(note: "Could not capture the active DNS service after \(reason); waiting for the network to settle.",
                                phase: sessionState.phase)
                scheduleRouteHealthCheck(reason: "the active DNS service is still settling")
                return .deferred
            }
            throw VPNControllerError.failedToStart(
                "Could not capture the active DNS service after \(reason)."
            )
        }

        if sessionState.tunnelMode == .full {
            try routeManager.assertFullTunnelSupported(physicalInterface: physicalNetwork.interfaceName,
                                                       ipv6Mode: physicalDNSConfiguration.ipv6Mode)
        }

        let migration = Self.sessionStateForPhysicalNetworkChange(currentState: sessionState,
                                                                  physicalNetwork: physicalNetwork,
                                                                  physicalDNSConfiguration: physicalDNSConfiguration,
                                                                  activeDefaultSearchDomains: routeManager.captureActiveDefaultSearchDomains())
        guard migration.changed else {
            return .unchanged
        }

        EventLog.append(note: "Captured physical network or DNS change after \(reason): \(sessionState.physicalGateway)/\(sessionState.physicalInterface) to \(physicalNetwork.gateway)/\(physicalNetwork.interfaceName).",
                        phase: sessionState.phase)
        if migration.shouldRestorePreviousService {
            try routeManager.restoreDNSConfiguration(using: sessionState)
            try routeManager.restorePhysicalIPv6Configuration(using: sessionState)
        }

        sessionState = migration.state
        try saveState()
        return .migrated(transportAffecting: migration.transportAffecting)
    }

    private func repairSplitTunnelPhysicalNetworkChangeIfNeeded(reason: String) throws -> Bool {
        let migrationOutcome = try migratePhysicalNetworkStateIfNeeded(reason: reason,
                                                                       rescheduleIfSettling: true)
        let transportAffecting: Bool
        switch migrationOutcome {
        case .unchanged:
            return false
        case .deferred:
            return true
        case .migrated(let affecting):
            transportAffecting = affecting
        }

        var updatedState = sessionState

        try routeManager.applySplitTunnel(
            using: &updatedState,
            persistPreparedState: persistPreparedNetworkState
        )
        try routeManager.ensureRemoteHostRoutes(using: &updatedState,
                                                mode: .split,
                                                context: "split-tunnel repair",
                                                persistPreparedState: persistPreparedNetworkState)

        sessionState = updatedState
        try saveState()
        updateMenuBar()
        scheduleReachabilityProbeIfNeeded(reason: "physical network change")
        if transportAffecting {
            requestOpenVPNTransportReconnect(reason: "split-tunnel physical network repair")
        }
        EventLog.append(note: "Split tunnel repaired after physical network change.",
                        phase: sessionState.phase)
        return true
    }

    private func repairFullTunnelPhysicalNetworkChangeIfNeeded(reason: String) throws -> Bool {
        let migrationOutcome = try migratePhysicalNetworkStateIfNeeded(reason: reason,
                                                                       rescheduleIfSettling: true)
        let transportAffecting: Bool
        switch migrationOutcome {
        case .unchanged:
            return false
        case .deferred:
            return true
        case .migrated(let affecting):
            transportAffecting = affecting
        }

        var updatedState = sessionState
        try routeManager.applyFullTunnelSafety(
            using: &updatedState,
            persistPreparedState: persistPreparedNetworkState
        )
        updatedState.tunnelMode = .full
        sessionState = updatedState
        fullTunnelControlChannelSettleCount = 0
        try saveState()
        updateMenuBar()
        if transportAffecting {
            requestOpenVPNTransportReconnect(reason: "full-tunnel physical network repair")
        }
        EventLog.append(note: "Full tunnel repaired after physical network change.",
                        phase: sessionState.phase)
        return true
    }

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
                    self.requestStop(reason: "signal \(Self.signalName(signalNumber))")
                }
            }
            source.resume()
            signalSources.append(source)
        }
    }

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

    private func applyPendingModeSwitchIfNeeded(trigger: String) throws {
        guard sessionState.phase == .connected,
              let persistedState = SessionState.load(),
              persistedState.pid == sessionState.pid,
              persistedState.executablePath == sessionState.executablePath,
              persistedState.processStartTime == sessionState.processStartTime else {
            return
        }

        sessionState = Self.sessionStateForSave(
            currentState: sessionState,
            persistedState: persistedState
        )
        if let requestedMode = sessionState.requestedTunnelMode {
            try applyModeSwitch(to: requestedMode, trigger: trigger)
        }
    }

    private func applyModeSwitch(to requestedMode: AppTunnelMode,
                                 trigger: String) throws {
        guard sessionState.phase == .connected else {
            return
        }

        if requestedMode == tunnelMode {
            sessionState.requestedTunnelMode = nil
            if sessionState.lastEvent == "MODE_SWITCH_DEFERRED" {
                sessionState.lastEvent = nil
                sessionState.lastInfo = nil
            }
            try saveState(consumingModeRequest: requestedMode)
            continuePendingModeSwitchIfNeeded()
            updateMenuBar()
            return
        }

        if let tunnelName = sessionState.tunName,
           !routeManager.tunnelInterfaceIsPresent(named: tunnelName) {
            let message = "Mode switch to \(requestedMode.modeDescription) deferred while the VPN reconnects; it will apply automatically once the connection recovers."
            sessionState.requestedTunnelMode = requestedMode
            sessionState.lastEvent = "MODE_SWITCH_DEFERRED"
            sessionState.lastInfo = message
            try saveState()
            updateMenuBar()
            EventLog.append(note: "Deferred mode switch to \(requestedMode.modeDescription) because tunnel interface \(tunnelName) is unavailable (trigger: \(trigger)).",
                            phase: sessionState.phase)
            emit(message)
            return
        }
        emit("Switching to \(requestedMode.modeDescription) mode.")
        EventLog.append(note: "Applying in-place mode switch to \(requestedMode.modeDescription) (trigger: \(trigger)).",
                        phase: sessionState.phase)

        let previousMode = tunnelMode
        routeHealthCheckGeneration += 1
        routeHealthCheckDeadline = nil
        invalidateReachabilityProbe()

        var updatedState = sessionState
        updatedState.requestedTunnelMode = requestedMode

        do {
            _ = try migratePhysicalNetworkStateIfNeeded(
                reason: "mode switch to \(requestedMode.modeDescription)",
                rescheduleIfSettling: false
            )
            updatedState = sessionState
            updatedState.requestedTunnelMode = requestedMode

            switch requestedMode {
            case .split:
                try routeManager.applySplitTunnel(
                    using: &updatedState,
                    persistPreparedState: persistPreparedNetworkState
                )
                try routeManager.ensureRemoteHostRoutes(using: &updatedState,
                                                        mode: .split,
                                                        context: "mode switch to split-tunnel",
                                                        persistPreparedState: persistPreparedNetworkState)
            case .full:
                try routeManager.switchToFullTunnel(
                    using: &updatedState,
                    persistPreparedState: persistPreparedNetworkState
                )
            }
        } catch {
            let modeSwitchError = error
            var rollbackState = sessionState
            rollbackState.requestedTunnelMode = nil
            rollbackState.lastEvent = "MODE_SWITCH_FAILED"
            rollbackState.lastInfo = "Mode switch to \(requestedMode.modeDescription) failed: \(modeSwitchError.localizedDescription)"

            var rollbackError: Error?
            do {
                sessionState = rollbackState
                try saveState(consumingModeRequest: requestedMode)
                rollbackState = sessionState
                if previousMode == .split {
                    try routeManager.applySplitTunnel(
                        using: &rollbackState,
                        persistPreparedState: persistPreparedNetworkState
                    )
                    try routeManager.restorePhysicalIPv6Configuration(using: rollbackState)
                } else {
                    try routeManager.switchToFullTunnel(
                        using: &rollbackState,
                        persistPreparedState: persistPreparedNetworkState
                    )
                }
                rollbackState.tunnelMode = previousMode
                sessionState = rollbackState
                tunnelMode = previousMode
                try saveState(consumingModeRequest: previousMode)
            } catch {
                rollbackError = error
            }

            if let rollbackError {
                let detail = "Mode switch failed and restoring \(previousMode.modeDescription) mode also failed. Disconnecting to avoid an unknown network state. Switch error: \(modeSwitchError.localizedDescription). Rollback error: \(rollbackError.localizedDescription)"
                rollbackState.lastEvent = "MODE_SWITCH_ROLLBACK_FAILED"
                rollbackState.lastInfo = detail
                sessionState = rollbackState
                tunnelMode = previousMode
                saveStatusState()
                updateMenuBar()
                EventLog.append(note: detail, phase: sessionState.phase)
                requestStop(reason: "mode switch rollback failed", failed: true)
                throw VPNControllerError.modeSwitchRollbackFailed(detail)
            }

            updateMenuBar()
            scheduleRouteHealthCheck(reason: "mode switch rollback")
            continuePendingModeSwitchIfNeeded()
            throw modeSwitchError
        }

        tunnelMode = requestedMode
        updatedState.tunnelMode = requestedMode
        updatedState.requestedTunnelMode = nil
        updatedState.lastEvent = "MODE_SWITCHED"
        updatedState.lastInfo = nil
        sessionState = updatedState

        startRouteMonitorIfNeeded()
        if requestedMode == .split {
            scheduleReachabilityProbeIfNeeded(reason: "mode switch")
        } else {
            invalidateReachabilityProbe()
        }

        try saveState(consumingModeRequest: requestedMode)
        continuePendingModeSwitchIfNeeded()
        updateMenuBar()

        EventLog.append(note: "Mode switched to \(requestedMode.modeDescription).",
                        phase: sessionState.phase)
        emit("Mode switched to \(requestedMode.modeDescription) mode.")
    }

    private func continuePendingModeSwitchIfNeeded() {
        guard sessionState.requestedTunnelMode != nil else {
            return
        }
        DispatchQueue.main.async { [weak self] in
            self?.handleModeSwitchSignal()
        }
    }

    private func scheduleReachabilityProbeIfNeeded(reason: String) {
        guard tunnelMode == .split,
              sessionState.phase == .connected,
              !reachabilityProbeInFlight else {
            return
        }

        reachabilityProbeInFlight = true
        reachabilityProbeGeneration += 1
        let generation = reachabilityProbeGeneration
        let hosts = SplitTunnelPolicy.fixedHealthCheckHosts
        let queue = reachabilityProbeQueue
        queue.async { [weak self] in
            let result = ReachabilityProbe.run(hosts: hosts)
            Task { @MainActor [weak self] in
                self?.handleReachabilityProbeResult(result, reason: reason, generation: generation)
            }
        }
    }

    private func handleReachabilityProbeResult(_ result: ReachabilityProbeResult,
                                               reason: String,
                                               generation: Int) {
        guard Self.shouldAcceptReachabilityProbe(payloadGeneration: generation,
                                                 currentGeneration: reachabilityProbeGeneration,
                                                 tunnelMode: tunnelMode,
                                                 phase: sessionState.phase) else {
            return
        }
        reachabilityProbeInFlight = false

        if let reachableHost = result.reachableHost {
            if !lastReachabilityProbeHealthy {
                EventLog.append(note: "CWRU data-path check recovered via \(reachableHost).",
                                phase: sessionState.phase)
            }
            lastReachabilityProbeHealthy = true
            lastReachabilityAlertAt = nil
            markReachabilityRecoveredIfNeeded()
            return
        }

        let hostList = result.checkedHosts.joined(separator: ", ")
        if lastReachabilityProbeHealthy {
            EventLog.append(note: "CWRU data-path check failed after \(reason). Checked: \(hostList)",
                            phase: sessionState.phase)
        }
        lastReachabilityProbeHealthy = false

        if reason != "health check repair" {
            repairSplitDefaultDNSIfNeeded()
            scheduleReachabilityProbeIfNeeded(reason: "health check repair")
            return
        }

        markTransportDegraded(.hostPathDegraded,
                              detail: "The CWRU split-tunnel data path remains unavailable after route and DNS checks.")
        scheduleReachabilityRetry()
        let now = Date()
        if let lastReachabilityAlertAt,
           now.timeIntervalSince(lastReachabilityAlertAt) < Self.reachabilityFailureSurfaceThrottleSeconds {
            return
        }
        lastReachabilityAlertAt = now
        emit("CWRU data-path check failed for both fixed CWRU DNS endpoints. Reconnect after the network stabilizes.",
             level: .error)
    }

    private func invalidateReachabilityProbe() {
        reachabilityProbeGeneration += 1
        reachabilityProbeInFlight = false
    }

    private func scheduleReachabilityRetry() {
        let generation = reachabilityProbeGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.reachabilityRetrySeconds) { [weak self] in
            guard let self,
                  self.reachabilityProbeGeneration == generation,
                  self.transportRecoveryState == .hostPathDegraded,
                  self.tunnelMode == .split,
                  self.sessionState.phase == .connected,
                  !self.requestedStop,
                  !self.cleanupComplete else {
                return
            }
            self.scheduleReachabilityProbeIfNeeded(reason: "degraded host path retry")
        }
    }

    private func repairSplitDefaultDNSIfNeeded() {
        guard tunnelMode == .split,
              !requestedStop,
              (sessionState.phase == .authPending || sessionState.phase == .connected) else {
            return
        }

        do {
            let changed = try routeManager.restorePhysicalDNSConfigurationIfNeeded(using: sessionState)
            guard changed else {
                return
            }
            try routeManager.flushDNS()
            EventLog.append(note: "Repaired split-tunnel DNS state after a health check failure.",
                            phase: sessionState.phase)
        } catch {
            if Self.splitDNSRepairFailureRequiresFlush(error) {
                do {
                    try routeManager.flushDNS()
                } catch {
                    EventLog.append(note: "Could not flush DNS after a partial split-tunnel DNS repair: \(error.localizedDescription)",
                                    phase: sessionState.phase)
                }
            }
            EventLog.append(note: "Could not repair split-tunnel DNS state after a health check failure: \(error.localizedDescription)",
                            phase: sessionState.phase)
        }
    }

    private func saveState() throws {
        let preparedState = try SessionState.saveAtomically { persistedState in
            Self.sessionStateForSave(currentState: sessionState,
                                     persistedState: persistedState)
        }
        sessionState = preparedState
        if sessionState.phase == .connected {
            startupStatusFilePath = nil
        }
    }

    private func saveStatusState() {
        do {
            try saveState()
        } catch {
            EventLog.append(note: "Could not persist VPN status: \(error.localizedDescription)", phase: sessionState.phase)
        }
    }

    private func persistPreparedNetworkState(_ preparedState: SessionState) throws {
        sessionState = preparedState
        try saveState()
    }

    private func saveState(consumingModeRequest consumedMode: AppTunnelMode) throws {
        let preparedState = try SessionState.saveAtomically { persistedState in
            Self.sessionStateAfterConsumingModeRequest(currentState: sessionState,
                                                       persistedState: persistedState,
                                                       consumedMode: consumedMode)
        }
        sessionState = preparedState
        if sessionState.phase == .connected {
            startupStatusFilePath = nil
        }
    }

    private func releaseControllerLock() {
        controllerLock = nil
    }

    private func startCleanupWatchdog() throws {
        let startTime = sessionState.processStartTime
        do {
            _ = try ChildProcess.launch(arguments: ["cleanup-watchdog",
                                                    "--parent-pid", String(getpid()),
                                                    "--parent-start-seconds", String(startTime.seconds),
                                                    "--parent-start-microseconds", String(startTime.microseconds)])
        } catch {
            EventLog.append(note: "Failed to start cleanup watchdog: \(error.localizedDescription)",
                            phase: sessionState.phase)
            throw VPNControllerError.failedToStart("Failed to start cleanup watchdog: \(error.localizedDescription)")
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

    @objc private func handleDidWakeNotification(_: Notification) {
        let transition = Self.workspaceSleepTransition(event: .didWake,
                                                       phase: sessionState.phase,
                                                       requestedStop: requestedStop,
                                                       cleanupComplete: cleanupComplete)
        systemAsleep = transition.systemAsleep
        guard transition.shouldDisconnect else {
            return
        }
        EventLog.append(note: "System woke from sleep; disconnecting VPN.", phase: sessionState.phase)
        disconnectingAfterWake = true
        pendingDisconnectAlertMessage = pendingDisconnectAlertMessage
            ?? "VPN disconnected because your Mac slept. Reconnect when you are back online."
        requestStop(reason: "system wake")
    }

    @objc private func handleWillSleepNotification(_: Notification) {
        let transition = Self.workspaceSleepTransition(event: .willSleep,
                                                       phase: sessionState.phase,
                                                       requestedStop: requestedStop,
                                                       cleanupComplete: cleanupComplete)
        systemAsleep = transition.systemAsleep
        EventLog.append(note: "System will sleep while VPN is active.", phase: sessionState.phase)
    }

    private func spawnManagedReconnect(_ request: ManagedReconnectRequest) {
        var arguments = ["connect"]
        if let configFilePath = request.configFilePath {
            arguments += ["--config", configFilePath]
        }
        arguments += ["--mode", request.tunnelMode.rawValue, "--background-child"]
        do {
            _ = try ChildProcess.launch(arguments: arguments)
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

        if name == "WAIT" {
            return false
        }
        if name == "RECONNECTING" {
            return sessionState.lastEvent != "RECONNECTING"
        }
        if transportDegradedAt != nil && name != "CONNECTED" && name != "DISCONNECTED" {
            return false
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

    private func shouldAppendEventToEventLog(name: String,
                                             info: String,
                                             isError: Bool,
                                             isFatal: Bool) -> Bool {
        guard !isError, !isFatal else {
            return true
        }
        switch name {
        case "WAIT", "RECONNECTING":
            let result = Self.evaluateReconnectLifecycleEventLog(window: reconnectLifecycleEventLogWindow,
                                                                 eventName: name,
                                                                 now: Date())
            reconnectLifecycleEventLogWindow = result.window
            return result.shouldLog
        case "LOG":
            let now = Date()
            if Self.isDuplicateLogLine(info, previous: lastEventLogLine, now: now) {
                return false
            }
            lastEventLogLine = (info: info, at: now)
            return true
        default:
            return true
        }
    }

    private func recordFatalDisconnectIfNeeded(name: String, info: String, isFatal: Bool) {
        guard let record = Self.fatalDisconnectRecord(name: name, info: info, isFatal: isFatal) else {
            return
        }

        exitStatus = EXIT_FAILURE
        if backgroundChild {
            DetachedStartupStatus.writeFailure(message: record.alertMessage, to: startupStatusFilePath)
        }
        pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? record.alertMessage
        sessionState.lastEvent = record.event
        sessionState.lastInfo = record.alertMessage
    }

    private func shouldStopAfterFatalEvent(name: String, isFatal: Bool) -> Bool {
        guard isFatal,
              name != "DISCONNECTED",
              !requestedStop,
              !cleanupComplete else {
            return false
        }

        switch sessionState.phase {
        case .connecting, .authPending, .connected:
            return true
        case .disconnecting, .disconnected, .failed:
            return false
        }
    }

    private func parseAndPersistPushedDNS(from info: String) {
        guard let parsedOptions = Self.parsePushedDNSOptions(info) else {
            return
        }
        let uniqueDNSServers = Self.uniqueTrimmedNonEmptyStrings(parsedOptions.dnsServers)
        let uniqueSearchDomains = Self.uniqueTrimmedNonEmptyStrings(parsedOptions.searchDomains)
        let normalizedDNSServers = Array(uniqueDNSServers.prefix(Self.maximumPushedDNSServerCount))
        let normalizedSearchDomains = Array(uniqueSearchDomains.prefix(Self.maximumPushedSearchDomainCount))

        if uniqueDNSServers.count > normalizedDNSServers.count
            || uniqueSearchDomains.count > normalizedSearchDomains.count {
            EventLog.append(note: "Ignored server-pushed DNS entries beyond the recovery-state safety limit.",
                            phase: sessionState.phase)
        }

        let updatedDNSServers = Self.updatedPushedOptionValues(
            existing: sessionState.pushedDNSServers,
            parsed: normalizedDNSServers,
            isAuthoritativeSnapshot: parsedOptions.isAuthoritativeSnapshot
        )
        let updatedSearchDomains = Self.updatedPushedOptionValues(
            existing: sessionState.pushedSearchDomains,
            parsed: normalizedSearchDomains,
            isAuthoritativeSnapshot: parsedOptions.isAuthoritativeSnapshot
        )
        let dnsServersChanged = sessionState.pushedDNSServers != updatedDNSServers
        let searchDomainsChanged = sessionState.pushedSearchDomains != updatedSearchDomains
        guard dnsServersChanged || searchDomainsChanged else {
            return
        }
        if dnsServersChanged {
            sessionState.pushedDNSServers = updatedDNSServers
        }
        if searchDomainsChanged {
            sessionState.pushedSearchDomains = updatedSearchDomains
        }

        if dnsServersChanged, !normalizedDNSServers.isEmpty {
            EventLog.append(note: "Learned server-pushed DNS servers: \(normalizedDNSServers.joined(separator: ", "))",
                            phase: sessionState.phase)
        }
        if searchDomainsChanged, !normalizedSearchDomains.isEmpty {
            EventLog.append(note: "Learned server-pushed search domains: \(normalizedSearchDomains.joined(separator: ", "))",
                            phase: sessionState.phase)
        }
        saveStatusState()
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

    private func closeAuthenticationUI() {
        webAuthPresentationGeneration += 1
        externalWebAuthSession?.close()
        externalWebAuthSession = nil
        pendingWebAuthRequest = nil
        removeWebAuthDNSOverrideIfNeeded()
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

    private func installMenuBarIfNeeded() {
        guard menuBarController == nil else {
            return
        }

        let controller = MenuBarController()
        controller.onRetrySignIn = { [weak self] in
            Task { @MainActor in
                self?.retryWebAuthentication()
            }
        }
        controller.onSwitchMode = { [weak self] in
            Task { @MainActor in
                self?.requestMenuBarModeSwitch()
            }
        }
        controller.onDisconnect = { [weak self] in
            Task { @MainActor in
                self?.requestStop(reason: "menu bar disconnect")
            }
        }
        menuBarController = controller
    }

    private func updateMenuBar() {
        let gatewayText = menuBarGatewayText()
        let estimatedSessionText = menuBarEstimatedSessionText()
        let transportStatus = SessionPresentation.transportStatusTitle(for: sessionState)
        menuBarController?.update(with: MenuBarSnapshot(phase: sessionState.phase,
                                                        canRetrySignIn: canRetryWebAuthentication,
                                                        tunnelMode: tunnelMode,
                                                        requestedTunnelMode: sessionState.requestedTunnelMode,
                                                        transportDegraded: transportStatus != nil,
                                                        statusText: transportStatus
                                                            ?? SessionPresentation.statusTitle(for: sessionState.phase,
                                                                                               stale: false,
                                                                                               recoveryNeeded: false),
                                                        gatewayText: gatewayText,
                                                        estimatedSessionText: estimatedSessionText))
        updateMenuBarRefreshTimer()
        showEstimatedSessionCountdownAlertIfNeeded()
    }

    private func menuBarGatewayText() -> String {
        guard sessionState.phase == .connected,
              let serverHost = sessionState.serverHost,
              !serverHost.isEmpty else {
            return ""
        }

        return SessionPresentation.gatewayLine(for: serverHost) ?? ""
    }

    private func menuBarEstimatedSessionText() -> String {
        SessionPresentation.estimatedSessionCountdownText(for: sessionState) ?? ""
    }

    private func updateMenuBarRefreshTimer() {
        guard sessionState.phase == .connected,
              !cleanupComplete else {
            menuBarRefreshTimer?.invalidate()
            menuBarRefreshTimer = nil
            return
        }

        guard menuBarRefreshTimer == nil else {
            return
        }

        let timer = Timer(timeInterval: 1,
                          target: self,
                          selector: #selector(handleMenuBarRefreshTimer(_:)),
                          userInfo: nil,
                          repeats: true)
        RunLoop.main.add(timer, forMode: .common)
        menuBarRefreshTimer = timer
        menuBarRefreshTimer?.tolerance = 0.2
    }

    @objc private func handleMenuBarRefreshTimer(_: Timer) {
        updateMenuBar()
    }

    private func showEstimatedSessionCountdownAlertIfNeeded() {
        let remaining = SessionPresentation.estimatedSessionCountdownRemaining(for: sessionState)
        guard Self.shouldShowEstimatedSessionCountdownAlert(
            phase: sessionState.phase,
            requestedStop: requestedStop,
            cleanupComplete: cleanupComplete,
            systemAsleep: systemAsleep,
            disconnectingAfterWake: disconnectingAfterWake,
            alertShown: estimatedSessionCountdownAlertShown,
            remaining: remaining
        ) else {
            return
        }

        estimatedSessionCountdownAlertShown = true
        EventLog.append(note: "Estimated session countdown reached zero.", phase: sessionState.phase)
        UserAlert.scheduleCritical(message: "Estimated VPN session countdown reached zero. The server may expire this session soon; reconnect if you need to avoid an unexpected disconnect.")
    }

    private func requestMenuBarModeSwitch() {
        guard !cleanupComplete, !requestedStop else {
            return
        }

        let targetMode = tunnelMode == .split ? AppTunnelMode.full : .split

        switch sessionState.phase {
        case .connected:
            do {
                sessionState = try SessionControl.updateActiveSessionRequest(expectedSession: sessionState) {
                    $0.requestingModeSwitch(to: targetMode)
                }
                try applyPendingModeSwitchIfNeeded(trigger: "menu bar")
            } catch {
                emit("Mode switch failed: \(error.localizedDescription)", level: .error)
                EventLog.append(note: "Mode switch failed: \(error.localizedDescription)", phase: sessionState.phase)
            }

        case .connecting, .authPending:
            do {
                sessionState = try SessionControl.updateActiveSessionRequest(expectedSession: sessionState) {
                    $0.requestingModeSwitch(to: targetMode)
                }
                updateMenuBar()
                emit("Queued \(targetMode.modeDescription) mode switch for after connection.")
                EventLog.append(note: "Queued mode switch to \(targetMode.modeDescription) from the menu bar.",
                                phase: sessionState.phase)
            } catch {
                emit("Could not queue mode switch: \(error.localizedDescription)", level: .error)
                EventLog.append(note: "Could not queue mode switch: \(error.localizedDescription)",
                                phase: sessionState.phase)
            }

        case .disconnecting, .disconnected, .failed:
            break
        }
    }

    private func redactForDisplay(_ value: String) -> String {
        if ["WEB_AUTH:", "OPEN_URL:", "CR_TEXT:"].contains(where: value.contains) {
            return "Browser sign-in required."
        }

        return redactSensitiveText(value)
    }

}

nonisolated extension VPNController {
    private static let maximumPushedDNSServerCount = 16
    private static let maximumPushedSearchDomainCount = 128
    private static let connectingDeadlineSeconds = 60
    private static let dnsBootstrapRetryDeadlineSeconds = 3
    private static let dnsBootstrapResolveTimeoutSeconds = 1
    static let localTransportFailureWindowSeconds: TimeInterval = 60
    static let localTransportOpenVPNReconnectSeconds: TimeInterval = 3
    static let localTransportManagedReconnectSeconds: TimeInterval = 20
    static let localTransportOpenVPNReconnectMinimumCount = 2
    static let localTransportManagedReconnectMinimumCount = 5
    static let openVPNTransportReconnectThrottleSeconds: TimeInterval = 10
    static let reachabilityFailureSurfaceThrottleSeconds: TimeInterval = 300
    static let reachabilityRetrySeconds: TimeInterval = 30
    static let transportRecoveryDeadlineSeconds: TimeInterval = 10 * 60
    static let stableTransportResetSeconds: TimeInterval = 60
    static let routeHealthCheckLogCoalesceSeconds: TimeInterval = 300
    static let reconnectLifecycleEventLogWindowSeconds: TimeInterval = 60
    static let duplicateLogLineSuppressionSeconds: TimeInterval = 1
    static let fullTunnelControlChannelSettleMaxRetries = 3
    static let postConnectConfigurationSettleMaxRetries = 3
    static let postConnectConfigurationSettleDelaySeconds = 3

    enum DeadlineKind {
        case connecting
        case authPending
        case transportRecovery
    }

    enum DeadlineClock {
        case wall
        case monotonic
    }

    enum WorkspaceSleepEvent {
        case willSleep
        case didWake
    }

    struct WorkspaceSleepTransition: Equatable {
        let systemAsleep: Bool
        let shouldDisconnect: Bool
    }

    static func deadlineClock(for kind: DeadlineKind) -> DeadlineClock {
        switch kind {
        case .connecting, .authPending:
            return .wall
        case .transportRecovery:
            return .monotonic
        }
    }

    static func workspaceSleepTransition(event: WorkspaceSleepEvent,
                                         phase: SessionState.Phase,
                                         requestedStop: Bool,
                                         cleanupComplete: Bool) -> WorkspaceSleepTransition {
        switch event {
        case .willSleep:
            return WorkspaceSleepTransition(systemAsleep: true, shouldDisconnect: false)
        case .didWake:
            return WorkspaceSleepTransition(systemAsleep: false,
                                            shouldDisconnect: phase == .connected
                                                && !requestedStop
                                                && !cleanupComplete)
        }
    }

    static func shouldShowEstimatedSessionCountdownAlert(phase: SessionState.Phase,
                                                         requestedStop: Bool,
                                                         cleanupComplete: Bool,
                                                         systemAsleep: Bool,
                                                         disconnectingAfterWake: Bool,
                                                         alertShown: Bool,
                                                         remaining: TimeInterval?) -> Bool {
        phase == .connected
            && !requestedStop
            && !cleanupComplete
            && !systemAsleep
            && !disconnectingAfterWake
            && !alertShown
            && remaining.map { $0 <= 0 } == true
    }

    static let startupConnectTimeoutMessage = "The VPN did not finish connecting in time. On public Wi-Fi, finish any captive-portal sign-in and wait for the network to stabilize, then try again."

    static func shouldPreResolveGateway(host: String, bootstrapServers: [String]) -> Bool {
        !bootstrapServers.isEmpty && !SplitTunnelPolicy.isValidIPAddress(host)
    }

    struct LocalTransportFailureWindow: Equatable {
        var startedAt: Date?
        var count: Int
    }

    enum TransportRecoveryAction {
        case none
        case reconnect
        case restart
    }

    struct ReconnectLifecycleEventLogWindow: Equatable {
        var startedAt: Date?
        var eventNames: Set<String>
    }

    static func evaluateLocalTransportFailure(window: LocalTransportFailureWindow,
                                              now: Date,
                                              systemAsleep: Bool)
        -> (window: LocalTransportFailureWindow, action: TransportRecoveryAction) {
        var updated = window
        if let startedAt = window.startedAt,
           now.timeIntervalSince(startedAt) <= localTransportFailureWindowSeconds {
            updated.count += 1
        } else {
            updated.startedAt = now
            updated.count = 1
        }

        let elapsed = updated.startedAt.map { now.timeIntervalSince($0) } ?? 0
        if !systemAsleep,
           updated.count >= localTransportManagedReconnectMinimumCount,
           elapsed >= localTransportManagedReconnectSeconds {
            return (updated, .restart)
        }
        if updated.count >= localTransportOpenVPNReconnectMinimumCount,
           elapsed >= localTransportOpenVPNReconnectSeconds {
            return (updated, .reconnect)
        }
        return (updated, .none)
    }

    static func evaluateReconnectLifecycleEventLog(window: ReconnectLifecycleEventLogWindow,
                                                    eventName: String,
                                                    now: Date)
        -> (window: ReconnectLifecycleEventLogWindow, shouldLog: Bool) {
        var updated = window
        if let startedAt = window.startedAt,
           now >= startedAt,
           now.timeIntervalSince(startedAt) < reconnectLifecycleEventLogWindowSeconds {
            let inserted = updated.eventNames.insert(eventName).inserted
            return (updated, inserted)
        }

        updated.startedAt = now
        updated.eventNames = [eventName]
        return (updated, true)
    }

    static func isDuplicateLogLine(_ info: String, previous: (info: String, at: Date)?, now: Date) -> Bool {
        guard let previous, previous.info == info else {
            return false
        }
        return now.timeIntervalSince(previous.at) < duplicateLogLineSuppressionSeconds
    }

    static func transportRecoveryDeadlineDelay(degradedAt: Date, now: Date) -> TimeInterval {
        max(0, degradedAt.addingTimeInterval(transportRecoveryDeadlineSeconds).timeIntervalSince(now))
    }

    static func reachabilityDegradationStateNeedsUpdate(lastEvent: String?,
                                                        lastInfo: String?,
                                                        detail: String) -> Bool {
        lastEvent != "RECONNECTING"
            && (lastEvent != "DATA_PATH_DEGRADED" || lastInfo != detail)
    }

    static func managedReconnectTunnelMode(persistedState: SessionState?,
                                           controllerPID: Int32,
                                           controllerExecutablePath: String,
                                           controllerStartTime: ProcessStartTime,
                                           currentMode: AppTunnelMode) -> AppTunnelMode {
        guard let persistedState,
              persistedState.pid == controllerPID,
              persistedState.executablePath == controllerExecutablePath,
              persistedState.processStartTime == controllerStartTime,
              let requestedTunnelMode = persistedState.requestedTunnelMode else {
            return currentMode
        }
        return requestedTunnelMode
    }

    static func sessionOwnedBlockedIPv6Routes(present: [String], preexisting: Set<String>?) -> [String]? {
        guard let preexisting else {
            return nil
        }
        let ownedBlockedIPv6Routes = present.filter { !preexisting.contains($0) }
        return ownedBlockedIPv6Routes.isEmpty ? nil : ownedBlockedIPv6Routes
    }

    static func routeHealthCheckSchedule(existingDeadline: Date?, now: Date) -> Date? {
        guard existingDeadline == nil else {
            return nil
        }
        return now.addingTimeInterval(3)
    }

    struct RouteHealthCheckLogPlan: Equatable {
        var shouldLog: Bool
        var suppressedCount: Int
    }

    static func routeHealthCheckLogPlan(reason: String,
                                        lastReason: String?,
                                        lastLoggedAt: Date?,
                                        suppressedCount: Int,
                                        now: Date) -> RouteHealthCheckLogPlan {
        if reason == lastReason,
           let lastLoggedAt,
           now.timeIntervalSince(lastLoggedAt) < routeHealthCheckLogCoalesceSeconds {
            return RouteHealthCheckLogPlan(shouldLog: false, suppressedCount: suppressedCount + 1)
        }
        return RouteHealthCheckLogPlan(shouldLog: true, suppressedCount: suppressedCount)
    }

    static func routeHealthCheckLogNote(reason: String, suppressedCount: Int) -> String {
        guard suppressedCount > 0 else {
            return "Network path monitor noticed: \(reason)"
        }
        let plural = suppressedCount == 1 ? "" : "s"
        return "Network path monitor noticed: \(reason) (\(suppressedCount) preceding duplicate update\(plural) not logged)"
    }

    private static func signalName(_ signalNumber: Int32) -> String {
        switch signalNumber {
        case SIGINT:
            return "SIGINT"
        case SIGTERM:
            return "SIGTERM"
        case SIGHUP:
            return "SIGHUP"
        default:
            return String(signalNumber)
        }
    }

    static func shouldAcceptReachabilityProbe(payloadGeneration: Int,
                                              currentGeneration: Int,
                                              tunnelMode: AppTunnelMode,
                                              phase: SessionState.Phase) -> Bool {
        payloadGeneration == currentGeneration
            && tunnelMode == .split
            && phase == .connected
    }

    static func splitDNSRepairFailureRequiresFlush(_ error: Error) -> Bool {
        guard let routeManagerError = error as? RouteManagerError else {
            return false
        }
        if case .dnsMutationMayHaveOccurred = routeManagerError {
            return true
        }
        return false
    }

    static func sessionStateForSave(currentState: SessionState,
                                    persistedState: SessionState?) -> SessionState {
        guard currentState.phase == .connected || currentState.phase == .connecting || currentState.phase == .authPending,
              let persistedState,
              persistedState.pid == currentState.pid,
              persistedState.executablePath == currentState.executablePath,
              persistedState.processStartTime == currentState.processStartTime else {
            return currentState
        }

        var mergedState = currentState
        let requestChanged = mergedState.requestedTunnelMode != persistedState.requestedTunnelMode
        mergedState.requestedTunnelMode = persistedState.requestedTunnelMode
        if mergedState.lastEvent == "MODE_SWITCH_DEFERRED",
           requestChanged
            || persistedState.requestedTunnelMode == nil {
            mergedState.lastEvent = nil
            mergedState.lastInfo = nil
        }
        return mergedState
    }

    static func sessionStateAfterConsumingModeRequest(currentState: SessionState,
                                                      persistedState: SessionState?,
                                                      consumedMode: AppTunnelMode) -> SessionState {
        var updatedState = currentState
        updatedState.requestedTunnelMode = nil
        if updatedState.lastEvent == "MODE_SWITCH_DEFERRED" {
            updatedState.lastEvent = nil
            updatedState.lastInfo = nil
        }

        guard currentState.phase == .connected || currentState.phase == .connecting || currentState.phase == .authPending,
              let persistedState,
              persistedState.pid == currentState.pid,
              persistedState.executablePath == currentState.executablePath,
              persistedState.processStartTime == currentState.processStartTime else {
            return updatedState
        }

        let pendingMode = persistedState.requestedTunnelMode
        guard let pendingMode,
              pendingMode != consumedMode else {
            return updatedState
        }

        updatedState.requestedTunnelMode = pendingMode
        return updatedState
    }

    static func sessionStateForPhysicalNetworkChange(currentState: SessionState,
                                                     physicalNetwork: PhysicalNetwork,
                                                     physicalDNSConfiguration: PhysicalDNSConfiguration,
                                                     activeDefaultSearchDomains: [String]) -> (state: SessionState, changed: Bool, shouldRestorePreviousService: Bool, transportAffecting: Bool) {
        let serviceChanged = currentState.physicalServiceName != nil
            && currentState.physicalServiceName != physicalDNSConfiguration.serviceName
        let transportAffecting = currentState.physicalGateway != physicalNetwork.gateway
            || currentState.physicalInterface != physicalNetwork.interfaceName

        let fullTunnelSameService = currentState.tunnelMode == .full && !serviceChanged
        let capturedDNSServers: [String]? = fullTunnelSameService
            ? currentState.originalDNSServers
            : physicalDNSConfiguration.dnsServers
        let capturedSearchDomains: [String]? = fullTunnelSameService
            ? currentState.originalSearchDomains
            : physicalDNSConfiguration.searchDomains
        let capturedDefaultSearchDomains: [String]? = fullTunnelSameService
            ? (transportAffecting ? nil : currentState.originalDefaultSearchDomains)
            : activeDefaultSearchDomains

        let dnsSnapshotChanged = currentState.originalDNSServers != capturedDNSServers
            || currentState.originalSearchDomains != capturedSearchDomains
            || currentState.originalDefaultSearchDomains != capturedDefaultSearchDomains
        let changed = transportAffecting
            || currentState.physicalServiceName != physicalDNSConfiguration.serviceName
            || dnsSnapshotChanged

        guard changed else {
            return (currentState, false, false, false)
        }

        var updated = currentState
        updated.physicalGateway = physicalNetwork.gateway
        updated.physicalInterface = physicalNetwork.interfaceName
        updated.physicalServiceName = physicalDNSConfiguration.serviceName
        updated.originalDNSServers = capturedDNSServers
        updated.originalSearchDomains = capturedSearchDomains
        updated.originalDefaultSearchDomains = capturedDefaultSearchDomains
        updated.originalIPv6Mode = serviceChanged
            ? physicalDNSConfiguration.ipv6Mode
            : currentState.originalIPv6Mode ?? physicalDNSConfiguration.ipv6Mode
        return (updated, true, serviceChanged, transportAffecting)
    }

    static func isOpenVPNNetworkLifecycleLog(_ info: String) -> Bool {
        info.contains("MacLifeCycle NET_IFACE")
            || info.contains("MacLifeCycle NET_STATE")
            || info.contains("MacLifeCycle ACTION")
    }

    static func isLocalTransportFailureLog(_ info: String) -> Bool {
        let normalized = info.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else {
            return false
        }

        return (normalized.contains("udp send exception")
            && (
                normalized.contains("can't assign requested address")
                    || normalized.contains("no buffer space available")
                    || normalized.contains("network is down")
                    || normalized.contains("network is unreachable")
                    || normalized.contains("no route to host")
            ))
            || normalized.contains("route_gateway_error")
    }

    static func openVPNConfigContent(_ configContent: String, for tunnelMode: AppTunnelMode) -> String {
        let filters: [String]
        switch tunnelMode {
        case .split:
            filters = [
                "route-nopull",
                "pull-filter ignore \"route ''\"",
                "pull-filter ignore \"route-ipv6 ''\"",
                "pull-filter ignore redirect-gateway",
                "pull-filter ignore redirect-private",
                "pull-filter ignore dns",
                "pull-filter ignore dhcp-option",
                "pull-filter ignore block-ipv4",
                "pull-filter ignore block-ipv6",
            ]
        case .full:
            filters = [
                "pull-filter ignore \"route ''\"",
                "pull-filter ignore \"route-ipv6 ''\"",
                "pull-filter ignore redirect-gateway",
                "pull-filter ignore redirect-private",
                "pull-filter ignore block-ipv4",
                "pull-filter ignore block-ipv6",
            ]
        }
        return "\(filters.joined(separator: "\n"))\n\(configContent)"
    }

    static func firstOpenVPNRemoteHost(in configContent: String) -> String? {
        for rawLine in configContent.components(separatedBy: .newlines) {
            let fields = openVPNDirectiveFields(rawLine)
            if fields.first == "remote", fields.count >= 2 {
                return fields[1]
            }
        }
        return nil
    }

    static func isOpenVPNGatewayProgressEvent(_ name: String) -> Bool {
        switch name {
        case "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES", "CONNECTED":
            return true
        default:
            return false
        }
    }

    static func openVPNDirectiveFields(_ line: String) -> [String] {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("#"), !trimmed.hasPrefix(";") else {
            return []
        }
        return trimmed.split { $0 == " " || $0 == "\t" }.map(String.init)
    }

    static func openVPNAllowUnusedAddrFamilies(for tunnelMode: AppTunnelMode) -> String {
        tunnelMode == .split ? "yes" : "no"
    }

    static func cleanupCompletionOutcome(cleanupHealthy: Bool,
                                         disconnectingAfterWake: Bool) -> (shouldRemoveSessionState: Bool, recoveryMessage: String?) {
        guard !cleanupHealthy else {
            return (true, nil)
        }
        let message = disconnectingAfterWake
            ? "Cleanup completed after wake, but the network still looks unhealthy."
            : "Cleanup completed, but the network still looks unhealthy."
        return (false, message)
    }

    static func fatalDisconnectRecord(name: String,
                                      info: String,
                                      isFatal: Bool) -> (event: String, alertMessage: String)? {
        guard isFatal, name != "DISCONNECTED" else {
            return nil
        }

        return (name, userFacingFatalDisconnectMessage(name: name, info: info))
    }

    static func userFacingFatalDisconnectMessage(name: String, info: String) -> String {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        switch name {
        case "SESSION_EXPIRED":
            return "VPN disconnected because the server-side session expired. Reconnect to sign in again."
        case "AUTH_FAILED":
            return "VPN disconnected because authentication failed. Reconnect to sign in again."
        case "CORE_EXIT":
            return "VPN disconnected because the OpenVPN worker stopped unexpectedly. Reconnect to try again."
        default:
            let detail = redactSensitiveText(info).trimmingCharacters(in: .whitespacesAndNewlines)
            let eventDescription = name.isEmpty ? "a fatal OpenVPN event" : "fatal OpenVPN event \(name)"
            if detail.isEmpty {
                return "VPN disconnected after \(eventDescription)."
            }
            return "VPN disconnected after \(eventDescription): \(detail)"
        }
    }

    struct ParsedPushedDNSOptions: Equatable {
        let isAuthoritativeSnapshot: Bool
        let dnsServers: [String]
        let searchDomains: [String]
    }

    private enum CapturedDNSSection {
        case none
        case serverAddresses
        case searchDomains
    }

    static func parsePushedDNSOptions(_ info: String) -> ParsedPushedDNSOptions? {
        if info.contains("CAPTURED OPTIONS:") {
            var sawSession = false
            var sawExcludeRoutes = false
            var insideDNSServers = false
            var section = CapturedDNSSection.none
            var dnsServers: [String] = []
            var searchDomains: [String] = []

            for rawLine in info.components(separatedBy: .newlines) {
                let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                if line.hasPrefix("Session Name:") {
                    sawSession = true
                }
                if line == "Exclude Routes:" {
                    sawExcludeRoutes = true
                }

                switch line {
                case "DNS Servers:":
                    insideDNSServers = true
                    section = .none
                case "DNS Search Domains:":
                    insideDNSServers = false
                    section = .searchDomains
                case "Addresses:" where insideDNSServers:
                    section = .serverAddresses
                case "Domains:" where insideDNSServers:
                    section = .none
                default:
                    if line.hasPrefix("Priority:")
                        || line.hasPrefix("DNSSEC:")
                        || line.hasPrefix("Transport:")
                        || line.hasPrefix("SNI:") {
                        section = .none
                        continue
                    }
                    if rawLine.first?.isWhitespace != true {
                        insideDNSServers = false
                        section = .none
                        continue
                    }
                    switch section {
                    case .serverAddresses:
                        if let address = capturedDNSAddress(line) {
                            dnsServers.append(address)
                        }
                    case .searchDomains:
                        if SplitTunnelPolicy.isValidDomainName(line) {
                            searchDomains.append(line)
                        }
                    case .none:
                        break
                    }
                }
            }

            guard sawSession, sawExcludeRoutes else {
                return nil
            }
            return ParsedPushedDNSOptions(isAuthoritativeSnapshot: true,
                                         dnsServers: dnsServers,
                                         searchDomains: searchDomains)
        }

        guard info.contains("OPTIONS:") else {
            return nil
        }
        var dnsServers: [String] = []
        var searchDomains: [String] = []
        for rawLine in info.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.contains("[dhcp-option] [DNS] ["),
               let value = bracketFields(in: line).last {
                let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                if SplitTunnelPolicy.isValidIPAddress(trimmed) {
                    dnsServers.append(trimmed)
                }
            } else if line.contains("[dhcp-option] [DOMAIN-SEARCH] ["),
                      let value = bracketFields(in: line).last {
                searchDomains.append(contentsOf: value
                    .split(separator: ",")
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter(SplitTunnelPolicy.isValidDomainName))
            }
        }
        guard !dnsServers.isEmpty || !searchDomains.isEmpty else {
            return nil
        }
        return ParsedPushedDNSOptions(isAuthoritativeSnapshot: false,
                                     dnsServers: dnsServers,
                                     searchDomains: searchDomains)
    }

    static func updatedPushedOptionValues(existing: [String]?,
                                          parsed: [String],
                                          isAuthoritativeSnapshot: Bool) -> [String]? {
        if isAuthoritativeSnapshot {
            return parsed.isEmpty ? nil : parsed
        }
        return parsed.isEmpty ? existing : parsed
    }

    private static func capturedDNSAddress(_ value: String) -> String? {
        if SplitTunnelPolicy.isValidIPAddress(value) {
            return value
        }
        if value.hasPrefix("["),
           let closingBracket = value.firstIndex(of: "]") {
            let start = value.index(after: value.startIndex)
            let address = String(value[start..<closingBracket])
            return SplitTunnelPolicy.isValidIPv6Address(address) ? address : nil
        }
        if let separator = value.lastIndex(of: ":") {
            let address = String(value[..<separator])
            let port = value[value.index(after: separator)...]
            if !port.isEmpty,
               port.allSatisfy(\.isNumber),
               SplitTunnelPolicy.isValidIPv4Address(address) {
                return address
            }
        }
        return nil
    }

    private static func bracketFields(in line: String) -> [String] {
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

    private static func uniqueTrimmedNonEmptyStrings(_ values: [String]) -> [String] {
        values.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }.uniqued()
    }
}
