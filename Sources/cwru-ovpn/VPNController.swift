import AppKit
import COpenVPN3Wrapper
import Darwin
import Foundation
import Network

enum VPNControllerError: LocalizedError {
    case operationFailed(String)
    case missingSession
    case modeSwitchRollbackFailed(String)
    case unsafeSessionState(String)
    case cleanupFailed(String)

    var errorDescription: String? {
        switch self {
        case .operationFailed(let message), .modeSwitchRollbackFailed(let message),
             .unsafeSessionState(let message), .cleanupFailed(let message):
            return message
        case .missingSession:
            return "No active \(AppIdentity.executableName) session was found."
        }
    }
}

struct ManagedReconnectRequest {
    let configFilePath: String?
    let tunnelMode: AppTunnelMode
    let reason: String
}

enum PhysicalNetworkMigrationOutcome {
    case unchanged
    case migrated(transportAffecting: Bool)
    case deferred
}

enum TransportRecoveryState: Equatable {
    case reconnecting
    case hostPathDegraded
    case stabilizing

    mutating func beginStabilizing() -> Bool {
        guard self != .stabilizing else { return false }
        self = .stabilizing
        return true
    }

    mutating func interruptStabilization() -> Bool {
        guard self == .stabilizing else { return false }
        self = .reconnecting
        return true
    }
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
    let configFilePath: String?
    private let verbosity: AppVerbosity
    var tunnelMode: AppTunnelMode
    let routeManager: RouteManager
    var menuBarController: MenuBarController?
    var sessionState: SessionState
    var client: OpaquePointer?
    private let vpnEventRelay = VPNEventRelay()
    private var vpnEventGeneration = 0
    private var signalSources: [DispatchSourceSignal] = []
    var pathMonitor: NWPathMonitor?
    var physicalNetworkObserver: PhysicalNetworkObserver?
    var physicalNetworkNeedsRouteRefresh = false
    let pathMonitorQueue = DispatchQueue(label: "cwru-ovpn.network-path-monitor", qos: .utility)
    var hasSeenInitialPathUpdate = false
    var menuBarRefreshTimer: Timer?
    let reachabilityProbeQueue = DispatchQueue(label: "cwru-ovpn.reachability-probe", qos: .utility)
    let gatewayResolveQueue = DispatchQueue(label: "cwru-ovpn.gateway-resolve", qos: .userInitiated)
    var webAuthPresentationGeneration = 0
    var pendingWebAuthRequest: WebAuthRequest?
    var webAuthDNSOverrideInstalled = false
    var reachabilityProbeInFlight = false
    var reachabilityProbeGeneration = 0
    var lastReachabilityProbeHealthy = true
    var lastReachabilityAlertAt: Date?
    var routeHealthCheckGeneration = 0
    var routeHealthCheckDeadline: Date?
    var routeHealthCheckLogReason: String?
    var routeHealthCheckLoggedAt: Date?
    var routeHealthCheckSuppressedLogCount = 0
    var webAuthRecovery = WebAuthRecovery()
    var dnsBootstrapRetryGeneration = 0
    var dnsBootstrapRetryAttempted = false
    var handshakeProgressObserved = false
    var connectProfileContent: String?
    var connectRemoteHost: String?
    var connectServerOverride: String?
    var localTransportFailureWindowStartedAt: Date?
    var localTransportFailureCount = 0
    var lastOpenVPNTransportReconnectAt: Date?
    var transportDegradedAt: Date?
    var transportRecoveryState: TransportRecoveryState?
    var transportRecoveryDeadlineGeneration = 0
    var stableTransportGeneration = 0
    private var reconnectLifecycleEventLogWindow = ReconnectLifecycleEventLogWindow(startedAt: nil,
                                                                                    eventNames: [])
    private var lastEventLogLine: (info: String, at: Date)?
    var fullTunnelControlChannelSettleCount = 0
    private var postConnectConfigurationSettleCount = 0
    var postConnectConfigurationGeneration = 0
    private var sleepAssertionID: PowerManagement.AssertionID?
    var externalWebAuthSession: ExternalWebAuthSession?
    private var controllerLock: ControllerLock?
    var cleanupComplete = false
    var requestedStop = false
    private var dnsWithdrawalFailure: Error?
    private var disconnectCleanupFallbackScheduled = false
    private var handlingConnectedEvent = false
    var managedReconnectRequest: ManagedReconnectRequest?
    private var workspaceObserversInstalled = false
    var systemAsleep = false
    var disconnectingAfterWake = false
    var pendingDisconnectAlertMessage: String?
    private var applicationTerminationPending = false
    var estimatedSessionCountdownAlertShown = false
    private let preventSleep: Bool
    private let privacyMode: Bool
    let webAuthSession: WebAuthSessionMode
    let backgroundChild: Bool
    private var reportsStartupStatus: Bool
    private var exitStatus: Int32 = EXIT_SUCCESS

    init(intent: PrivilegedConnectIntent, backgroundChild: Bool) throws {
        let configuration = intent.configuration
        let tunnelMode = intent.tunnelMode
        let startupLock = try ControllerLock()
        let controllerPID = getpid()
        guard let controllerStartTime = processStartTime(controllerPID) else {
            throw VPNControllerError.operationFailed("Could not establish the VPN controller process identity.")
        }
        let routeManager = RouteManager(dnsBootstrapServers: configuration.effectiveDNSBootstrapServers)
        let physicalNetwork = try routeManager.detectPhysicalNetwork()
        guard let physicalDNSConfiguration = try routeManager.capturePhysicalDNSConfiguration(for: physicalNetwork.interfaceName) else {
            throw VPNControllerError.operationFailed(
                "Could not capture the active macOS DNS service for VPN DNS isolation."
            )
        }
        let originalDefaultSearchDomains = routeManager.captureActiveDefaultSearchDomains()
        if tunnelMode == .full {
            try routeManager.assertFullTunnelSupported(physicalInterface: physicalNetwork.interfaceName,
                                                       ipv6Mode: physicalDNSConfiguration.ipv6Mode)
        }
        self.profilePath = URL(fileURLWithPath: intent.profilePath).standardized.path
        self.configFilePath = intent.configFilePath.map { URL(fileURLWithPath: $0).standardized.path }
        self.verbosity = intent.verbosity
        self.tunnelMode = tunnelMode
        self.routeManager = routeManager
        self.preventSleep = configuration.preventSleep
        self.privacyMode = configuration.privacyMode
        self.webAuthSession = configuration.webAuthSession
        self.backgroundChild = backgroundChild
        self.reportsStartupStatus = backgroundChild
        self.controllerLock = startupLock
        self.sessionState = SessionState(
            pid: controllerPID,
            executablePath: try ExecutionIdentity.currentExecutablePath(),
            processStartTime: controllerStartTime,
            phase: .connecting,
            profilePath: self.profilePath,
            configFilePath: self.configFilePath,
            startedAt: Date(),
            physicalGateway: physicalNetwork.gateway,
            physicalInterface: physicalNetwork.interfaceName,
            physicalServiceName: physicalDNSConfiguration.serviceName,
            originalDNSServers: physicalDNSConfiguration.dnsServers,
            originalSearchDomains: physicalDNSConfiguration.searchDomains,
            originalDefaultSearchDomains: originalDefaultSearchDomains,
            originalIPv6Mode: physicalDNSConfiguration.ipv6Mode,
            tunnelMode: tunnelMode,
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
        try RuntimePaths.ensureHomeStateDirectory()
        let profileData = try ProfileManifest.readProfileData(at: URL(fileURLWithPath: profilePath))
        try ProfileManifest.verifyApproved(profileData: profileData)
        let configContent = String(decoding: profileData, as: UTF8.self)
        let effectiveConfigContent = OpenVPNProfile.connectContent(configContent, for: tunnelMode)
        let profile = try OpenVPNProfile(content: effectiveConfigContent)
        try OpenVPNProfilePolicy.validate(profile)
        EventLog.configure(privacyMode: privacyMode)
        EventLog.startSession(profilePath: profilePath)
        installMenuBarIfNeeded()
        updateMenuBar()

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
            connectRemoteHost = profile.firstRemoteHost
            armConnectingDeadline()
            try prepareOpenVPNClient(profileContent: effectiveConfigContent)
        } catch {
            if startupCleanupArmed {
                cleanupAfterStartupFailure(error)
            }
            throw error
        }
    }

    func launchOpenVPNClient(profileContent: String, serverOverride: String?) throws {
        guard let client = cwru_ovpn_client_create() else {
            throw VPNControllerError.operationFailed("OpenVPN 3 client allocation failed")
        }
        self.client = client

        vpnEventGeneration += 1
        vpnEventRelay.configure(owner: self, generation: vpnEventGeneration)
        cwru_ovpn_client_set_event_callback(client, vpnEventTrampoline, Unmanaged.passUnretained(vpnEventRelay).toOpaque())

        var errorPointer: UnsafeMutablePointer<CChar>?
        let started = profileContent.withCString { configCString in
            AppIdentity.reportedClientVersion.withCString { guiCString in
                Self.supportedSSOMethods.withCString { ssoCString in
                    (serverOverride ?? "").withCString { serverOverrideCString in
                        cwru_ovpn_client_start(client, configCString, guiCString, ssoCString, serverOverrideCString, &errorPointer)
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
            throw VPNControllerError.operationFailed(message)
        }
        connectServerOverride = serverOverride
        armConnectingDeadline()
    }

    func shutdownOpenVPNClient() {
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
            if Self.isLocalTransportFailureLog(info) {
                handleLocalTransportFailure()
            }
            if Self.isOpenVPNNetworkLifecycleLog(info) {
                scheduleRouteHealthCheck(reason: "OpenVPN network lifecycle update")
            }
            parseAndPersistPushedDNS(from: info)
            if shouldSurfaceLogLine(info) {
                emit(redactForDisplay(info), level: .debug)
            }
        case "TRANSPORT_ENDPOINT":
            prepareTransportEndpoint(info)
        case "RECONNECTING":
            postConnectConfigurationGeneration += 1
            markTransportDegraded(.reconnecting,
                                  detail: "OpenVPN is reconnecting after its transport path failed.")
            scheduleRouteHealthCheck(reason: "OpenVPN reconnecting")
        case "AUTH_PENDING":
            postConnectConfigurationGeneration += 1
            if transportRecoveryState?.interruptStabilization() == true {
                stableTransportGeneration += 1
            }
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
        connectedState.tunnelName = copyString { cwru_ovpn_client_copy_tun_name(client) }
        connectedState.vpnIPv4 = copyString { cwru_ovpn_client_copy_vpn_ipv4(client) }
        connectedState.vpnIPv6 = copyString { cwru_ovpn_client_copy_vpn_ipv6(client) }
        connectedState.serverHost = copyString { cwru_ovpn_client_copy_server_host(client) }
        connectedState.serverIP = copyString { cwru_ovpn_client_copy_server_ip(client) }
        connectedState.transportServerIP = nil
        let connectedAt = connectedState.connectedAt ?? Date()

        connectedState.cleanupNeeded = true
        sessionState = connectedState
        try saveState()
        updateMenuBar()

        switch tunnelMode {
        case .split:
            try routeManager.applySplitTunnel(using: &connectedState,
                                              persistPreparedState: persistPreparedNetworkState)
        case .full:
            try routeManager.applyFullTunnelSafety(using: &connectedState,
                                                   persistPreparedState: persistPreparedNetworkState)
        }

        guard !cleanupComplete, !requestedStop else {
            return false
        }
        try startRouteMonitorIfNeeded()
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
           postConnectConfigurationSettleCount < Self.postConnectConfigurationSettleMaxRetries,
           !requestedStop,
           !cleanupComplete,
           routeManager.canDeferFullTunnelFailure(error, using: sessionState) {
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

    func beginApplicationTermination() -> Bool {
        guard !cleanupComplete else {
            return false
        }

        applicationTerminationPending = true
        requestStop(reason: "application quit")
        return true
    }

    func requestStop(reason: String, failed: Bool = false, reconnect: ManagedReconnectRequest? = nil) {
        managedReconnectRequest = reconnect
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
        guard let client else {
            completeCleanupAndExit()
            return
        }
        withdrawVPNDNSBeforeTunnelTeardown()
        scheduleDisconnectCleanupFallback(reason: "controller stop")
        cwru_ovpn_client_stop(client)
    }

    private func withdrawVPNDNSBeforeTunnelTeardown() {
        do {
            guard try routeManager.withdrawVPNDNS(using: sessionState) else {
                throw VPNControllerError.cleanupFailed("VPN DNS withdrawal was not published before tunnel shutdown.")
            }
        } catch {
            dnsWithdrawalFailure = dnsWithdrawalFailure ?? error
            exitStatus = EXIT_FAILURE
            managedReconnectRequest = nil
            EventLog.append(eventName: "DNS_WITHDRAWAL_FAILED",
                            info: "Could not withdraw VPN DNS before stopping the tunnel: \(error.localizedDescription)",
                            isError: true, isFatal: false, phase: sessionState.phase)
        }
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

    func failSession(event: String, message: String) {
        sessionState.lastEvent = event
        sessionState.lastInfo = message
        if reportsStartupStatus {
            DetachedStartupStatus.report(message)
        }
        saveStatusState()
        updateMenuBar()
        EventLog.append(note: message, phase: sessionState.phase)
        emit(message, level: .error)
        requestStop(reason: message, failed: true)
    }

    func scheduleDeadline(_ kind: DeadlineKind,
                          after delay: TimeInterval,
                          execute: @escaping @MainActor @Sendable () -> Void) {
        switch Self.deadlineClock(for: kind) {
        case .wall:
            DispatchQueue.main.asyncAfter(wallDeadline: .now() + delay, execute: execute)
        case .monotonic:
            DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: execute)
        }
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
        withdrawVPNDNSBeforeTunnelTeardown()
        shutdownOpenVPNClient()

        let cleanupFailureAlert = restoreNetworkConfiguration()

        closeAuthenticationUI()
        removeWorkspaceObservers()
        releaseControllerLock()
        if let cleanupFailureAlert {
            UserAlert.present(cleanupFailureAlert)
        }
    }

    private func completeCleanupAndExit() {
        guard !cleanupComplete else {
            return
        }
        cleanupComplete = true
        stopRouteMonitor()
        stopSleepAssertion()
        EventLog.append(note: "Completing cleanup.", phase: sessionState.phase)
        if !requestedStop {
            withdrawVPNDNSBeforeTunnelTeardown()
        }
        shutdownOpenVPNClient()
        let cleanupFailureAlert = restoreNetworkConfiguration()

        closeAuthenticationUI()
        menuBarRefreshTimer?.invalidate()
        menuBarRefreshTimer = nil
        menuBarController?.close()
        menuBarController = nil
        removeWorkspaceObservers()
        releaseControllerLock()
        if let cleanupFailureAlert {
            if managedReconnectRequest != nil {
                EventLog.append(note: "Managed reconnect was cancelled because cleanup did not complete cleanly.",
                                phase: sessionState.phase)
            }
            UserAlert.present(cleanupFailureAlert)
        } else {
            if let managedReconnectRequest {
                spawnManagedReconnect(managedReconnectRequest)
            }
            if let pendingDisconnectAlertMessage {
                UserAlert.present(pendingDisconnectAlertMessage)
            }
        }
        if applicationTerminationPending {
            applicationTerminationPending = false
            NSApplication.shared.reply(toApplicationShouldTerminate: true)
        } else {
            DispatchQueue.main.async {
                exit(self.exitStatus)
            }
        }
    }

    private func restoreNetworkConfiguration() -> String? {
        do {
            try Self.restoreNetworkConfiguration(using: sessionState,
                                                 routeManager: routeManager,
                                                 dnsWithdrawalFailure: dnsWithdrawalFailure,
                                                 disconnectingAfterWake: disconnectingAfterWake)
            sessionState.cleanupNeeded = false
            EventLog.append(note: "Restored pre-connection network configuration.", phase: sessionState.phase)
            return nil
        } catch {
            exitStatus = EXIT_FAILURE
            let message = "Cleanup failed: \(error.localizedDescription)"
            sessionState.markRecoveryRequired(message: message)
            saveStatusState()
            updateMenuBar()
            EventLog.append(eventName: "CLEANUP_FAILED", info: message,
                            isError: true, isFatal: false, phase: sessionState.phase)
            return "\(message) Run cwru-ovpn doctor for recovery guidance."
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
                    self.handlePendingModeSwitch(trigger: "signal")
                } else {
                    self.requestStop(reason: "signal \(Self.signalName(signalNumber))")
                }
            }
            source.resume()
            signalSources.append(source)
        }
    }

    func saveState(consumingModeRequest consumedMode: AppTunnelMode? = nil) throws {
        let preparedState = try SessionState.saveAtomically { persistedState in
            guard let consumedMode else {
                return Self.sessionStateForSave(currentState: sessionState,
                                                persistedState: persistedState)
            }
            return Self.sessionStateAfterConsumingModeRequest(currentState: sessionState,
                                                              persistedState: persistedState,
                                                              consumedMode: consumedMode)
        }
        sessionState = preparedState
        if sessionState.phase == .connected {
            reportsStartupStatus = false
        }
    }

    func saveStatusState() {
        do {
            try saveState()
        } catch {
            EventLog.append(note: "Could not persist VPN status: \(error.localizedDescription)", phase: sessionState.phase)
        }
    }

    func persistPreparedNetworkState(_ preparedState: SessionState) throws {
        sessionState = preparedState
        try saveState()
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
            throw VPNControllerError.operationFailed("Failed to start cleanup watchdog: \(error.localizedDescription)")
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
        EventLog.append(note: "System will sleep.", phase: sessionState.phase)
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

        if name == "WAIT" || name == "TRANSPORT_ENDPOINT" {
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
        if reportsStartupStatus {
            DetachedStartupStatus.report(record.alertMessage)
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

    func emit(_ message: @autoclosure () -> String, level: ConsoleMessageLevel = .info) {
        guard verbosity.includes(level), !backgroundChild else {
            return
        }

        if level == .error {
            fputs("\(message())\n", stderr)
        } else {
            print(message())
        }
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

    private func redactForDisplay(_ value: String) -> String {
        if ["WEB_AUTH:", "OPEN_URL:", "CR_TEXT:"].contains(where: value.contains) {
            return "Browser sign-in required."
        }

        return redactSensitiveText(value)
    }
}
