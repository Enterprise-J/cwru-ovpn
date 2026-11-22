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

enum TransportRecoveryState: String, Codable {
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

struct RouteMonitorCoordinator {
    var pathMonitor: NWPathMonitor?
    var physicalObserver: PhysicalNetworkObserver?
    var needsPhysicalRouteRefresh = false
    let queue = DispatchQueue(label: "cwru-ovpn.network-path-monitor", qos: .utility)
    var hasSeenInitialPathUpdate = false
    var generation = 0
    var deadline: DispatchTime?
    var lastLogReason: String?
    var lastLoggedAt: Date?
    var suppressedLogCount = 0
    var controlChannelSettleCount = 0
    var postConnectSettleCount = 0
    var postConnectGeneration = 0
}

struct TransportRecoveryTracker {
    let probeQueue = DispatchQueue(label: "cwru-ovpn.reachability-probe", qos: .utility)
    var isProbeInFlight = false
    var probeGeneration = 0
    var wasLastProbeHealthy = true
    var lastAlertAt: ContinuousClock.Instant?
    var lastReconnectAt: ContinuousClock.Instant?
    var degradedAt: ContinuousClock.Instant?
    var deadlineGeneration = 0
    var stableGeneration = 0
    var managedReconnect: ManagedReconnectRequest?
    var localFailures = VPNController.LocalTransportFailureWindow(startedAt: nil, count: 0)
}

struct WebAuthCoordinator {
    let resolveQueue = DispatchQueue(label: "cwru-ovpn.gateway-resolve", qos: .userInitiated)
    var presentationGeneration = 0
    var pendingRequest: WebAuthRequest?
    var isDNSOverrideInstalled = false
    var recovery = WebAuthRecovery()
    var bootstrapGeneration = 0
    var hasAttemptedBootstrapRetry = false
    var hasObservedHandshake = false
    var profileContent: String?
    var remoteHost: String?
    var serverOverride: String?
    var isPresenting = false
}

enum DaemonExecutionMode: Equatable {
    case foreground
    case detached(reportsStartupStatus: Bool)
}

@MainActor
final class VPNController: NSObject {
    private let profilePath: String
    let configFilePath: String?
    private let verbosity: AppVerbosity
    var tunnelMode: AppTunnelMode
    let routeManager: RouteManager
    var userInterface: InterfaceChannel<InterfaceAction, InterfaceUpdate>?
    var lastMenuSnapshot: MenuBarSnapshot?
    var routeMonitor = RouteMonitorCoordinator()
    var transport = TransportRecoveryTracker()
    var webAuth = WebAuthCoordinator()
    var sessionState: SessionState
    var client: OpaquePointer?
    private let vpnEventRelay = VPNEventRelay()
    private(set) var vpnEventGeneration = 0
    private var signalSources: [DispatchSourceSignal] = []
    var menuBarRefreshTimer: Timer?
    private var reconnectLifecycleEventLogWindow = ReconnectLifecycleEventLogWindow(startedAt: nil,
                                                                                    eventNames: [])
    private var lastEventLogLine: (info: String, at: Date)?
    private var sleepAssertionID: PowerManagement.AssertionID?
    private var controllerLock: ControllerLock?
    var isCleanupComplete = false
    var isStopRequested = false
    private var dnsWithdrawalFailure: Error?
    private var disconnectCleanupFallbackScheduled = false
    private var isHandlingConnectedEvent = false
    private var powerObserver: OpaquePointer?
    var isSystemAsleep = false
    var isDisconnectingAfterWake = false
    var pendingDisconnectAlertMessage: String?
    var hasShownSessionCountdownAlert = false
    private let preventSleep: Bool
    private let privacyMode: Bool
    let webAuthSessionMode: WebAuthSessionMode
    private(set) var executionMode: DaemonExecutionMode
    private var exitStatus: Int32 = EXIT_SUCCESS

    init(intent: PrivilegedConnectIntent, executionMode: DaemonExecutionMode, inheritedLock: ControllerLock? = nil) throws {
        let configuration = intent.configuration
        let tunnelMode = intent.tunnelMode
        let startupLock = try inheritedLock ?? ControllerLock()
        let controllerPID = getpid()
        guard let controllerStartTime = processStartTime(controllerPID) else {
            throw VPNControllerError.operationFailed("Could not establish the VPN controller process identity.")
        }
        let routeManager = RouteManager(dnsBootstrapServers: configuration.effectiveDNSBootstrapServers)
        let physicalNetwork = try routeManager.detectPhysicalNetwork()
        guard let physicalDNSConfiguration = try routeManager.serviceStore.activeService(for: physicalNetwork.interfaceName) else {
            throw VPNControllerError.operationFailed(
                "Could not read the active macOS DNS service for VPN DNS isolation."
            )
        }
        let originalDefaultSearchDomains = try routeManager.captureActiveDefaultSearchDomains()
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
        self.webAuthSessionMode = configuration.webAuthSessionMode
        self.executionMode = executionMode
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
            physicalServiceID: physicalDNSConfiguration.serviceID,
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
        removePowerObserver()
        shutdownOpenVPNClient()
        releaseControllerLock()
    }

    func start(replacing previous: SessionState? = nil) throws {
        emit("Starting VPN in \(tunnelMode.modeDescription) mode.")
        try RuntimePaths.ensureHomeStateDirectory()
        let profileData = try ProfileManifest.readProfileData(at: URL(fileURLWithPath: profilePath))
        try ProfileManifest.verifyApproved(profileData: profileData)
        let configContent = String(decoding: profileData, as: UTF8.self)
        let effectiveConfigContent = try OpenVPNProfile.connectContent(configContent)
        let profile = try OpenVPNProfile(content: configContent)
        EventLog.configure(privacyMode: privacyMode)
        EventLog.startSession(profilePath: profilePath)
        try startUserInterface()
        updateMenuBar()

        var startupCleanupArmed = false

        do {
            installSignalHandlers()
            sessionState.cleanupNeeded = true
            if let previous {
                sessionState = try SessionState.saveAtomically { current in
                    guard let current, current.pid == previous.pid, current.processStartTime == previous.processStartTime,
                          !current.stopRequestedByUser else { throw POSIXError(.ECANCELED) }
                    var next = sessionState
                    next.modeReceipts = current.modeReceipts
                    next.modeRequest = current.modeRequest
                    return next
                }
                startupCleanupArmed = true
            } else {
                try sessionState.create()
                startupCleanupArmed = true
                try startCleanupWatchdog()
            }

            EventLog.append(note: "Starting VPN client.", phase: sessionState.phase)
            emit("Event log: \(RuntimePaths.eventLogFile.path)", level: .debug)
            removeStaleWebAuthDNSOverride()
            try installPowerObserver()
            webAuth.profileContent = effectiveConfigContent
            webAuth.remoteHost = profile.firstRemoteHost
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
        webAuth.serverOverride = serverOverride
        armConnectingDeadline()
    }

    func shutdownOpenVPNClient() {
        guard let activeClient = client else {
            return
        }

        client = nil
        webAuth.pendingRequest = nil
        vpnEventGeneration += 1
        vpnEventRelay.clear(generation: vpnEventGeneration)
        cwru_ovpn_client_shutdown(activeClient)
        cwru_ovpn_client_destroy(activeClient)
    }

    func handleEvent(name: String, info: String, isError: Bool, isFatal: Bool) {
        if isStopRequested && name != "DISCONNECTED" {
            EventLog.append(eventName: name,
                            info: info,
                            isError: isError,
                            isFatal: isFatal,
                            phase: sessionState.phase)
            return
        }

        if name == "CONNECTED" {
            webAuth.hasObservedHandshake = true
            routeMonitor.postConnectGeneration += 1
            do {
                let snapshot = try JSONDecoder().decode(TunnelConnectionSnapshot.self, from: Data(info.utf8))
                handleConnected(snapshot)
            } catch {
                failSession(event: "CONFIGURATION_FAILED", message: error.localizedDescription)
            }
            return
        }
        let persistStatusEvent = shouldPersistStatusEvent(name: name, info: info, isError: isError, isFatal: isFatal)
        if persistStatusEvent {
            sessionState.lastEventName = name
            let redactedInfo = redactForDisplay(info)
            sessionState.diagnosticDetail = redactedInfo.isEmpty ? nil : redactedInfo
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
            webAuth.hasObservedHandshake = true
        }

        switch name {
        case "LOG":
            if Self.isLocalTransportFailureLog(info) {
                handleLocalTransportFailure()
            }
            if Self.isOpenVPNNetworkLifecycleLog(info) {
                scheduleRouteHealthCheck(reason: "OpenVPN network status update")
            }
            if shouldSurfaceLogLine(info) {
                emit(redactForDisplay(info), level: .debug)
            }
        case "TRANSPORT_ENDPOINT":
            prepareTransportEndpoint(info)
        case "RECONNECTING":
            routeMonitor.postConnectGeneration += 1
            markTransportDegraded(.reconnecting,
                                  detail: "OpenVPN is reconnecting after its transport path failed.")
            scheduleRouteHealthCheck(reason: "OpenVPN reconnecting")
        case "AUTH_PENDING":
            routeMonitor.postConnectGeneration += 1
            if sessionState.transportHealth?.interruptStabilization() == true {
                transport.stableGeneration += 1
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
        case "ASSIGN_IP":
            routeMonitor.postConnectGeneration += 1
            emit("Sign-in complete. Finalizing connection.")
            EventLog.append(note: "Authentication completed. Finalizing tunnel setup.", phase: sessionState.phase)
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
            guard payload.generation == vpnEventGeneration, !isCleanupComplete else {
                continue
            }
            handleEvent(name: payload.name, info: payload.info, isError: payload.isError, isFatal: payload.isFatal)
        }
    }

    private func handleConnected(_ snapshot: TunnelConnectionSnapshot) {
        do {
            guard try configureConnectedTunnel(snapshot) else {
                return
            }
            routeMonitor.postConnectSettleCount = 0
            markTransportRecoveredAfterConnectedEvent()
            handlePendingModeSwitch(trigger: "transport ready")
        } catch {
            handlePostConnectConfigurationFailure(error, snapshot: snapshot)
        }
    }

    private func configureConnectedTunnel(_ snapshot: TunnelConnectionSnapshot) throws -> Bool {
        guard client != nil else {
            return false
        }
        guard !isHandlingConnectedEvent else {
            return false
        }

        isHandlingConnectedEvent = true
        defer { isHandlingConnectedEvent = false }

        var connectedState = sessionState
        connectedState.tunnelName = snapshot.tunnelName
        connectedState.vpnIPv4 = snapshot.vpnIPv4.isEmpty ? nil : snapshot.vpnIPv4
        connectedState.vpnIPv6 = snapshot.vpnIPv6.isEmpty ? nil : snapshot.vpnIPv6
        connectedState.serverHost = snapshot.serverHost
        connectedState.connectedServerAddress = snapshot.serverIP
        connectedState.pushedDNS = snapshot.dns
        connectedState.pendingTransportEndpoint = nil
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

        guard !isCleanupComplete, !isStopRequested else {
            return false
        }
        try startRouteMonitorIfNeeded()
        connectedState.lastEventName = "CONNECTED"
        connectedState.diagnosticDetail = nil
        connectedState.modeRequest = sessionState.modeRequest
        connectedState.phase = .connected
        connectedState.connectedAt = connectedAt
        sessionState = connectedState
        webAuth.recovery.finish()

        do {
            try applyPendingModeSwitchIfNeeded(trigger: "post-connect")
        } catch {
            emit("Requested mode switch failed: \(error.localizedDescription)", level: .error)
        }

        guard !isCleanupComplete, !isStopRequested else {
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

    private func handlePostConnectConfigurationFailure(_ error: Error, snapshot: TunnelConnectionSnapshot) {
        if tunnelMode == .full,
           routeMonitor.postConnectSettleCount < Self.postConnectConfigurationSettleMaxRetries,
           !isStopRequested,
           !isCleanupComplete,
           routeManager.canDeferFullTunnelFailure(error, using: sessionState) {
            routeMonitor.postConnectSettleCount += 1
            EventLog.append(note: "Post-connect configuration failed while the network settles (attempt \(routeMonitor.postConnectSettleCount) of \(Self.postConnectConfigurationSettleMaxRetries)): \(error.localizedDescription). Retrying with fail-closed routes in place.",
                            phase: sessionState.phase)
            let generation = vpnEventGeneration
            let configurationGeneration = routeMonitor.postConnectGeneration
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(Self.postConnectConfigurationSettleDelaySeconds)) { [weak self] in
                guard let self else {
                    return
                }
                guard !self.isStopRequested,
                      !self.isCleanupComplete,
                      self.vpnEventGeneration == generation,
                      self.routeMonitor.postConnectGeneration == configurationGeneration,
                      self.sessionState.phase == .connecting || self.sessionState.phase == .authPending || self.sessionState.phase == .connected else {
                    return
                }
                self.handleConnected(snapshot)
            }
            return
        }

        EventLog.append(note: "Post-connect configuration failed: \(error.localizedDescription)",
                        phase: sessionState.phase)
        failSession(event: "CONFIGURATION_FAILED",
                    message: "Could not complete the \(tunnelMode.modeDescription) configuration: \(error.localizedDescription)")
    }

    func requestStop(reason: String, failed: Bool = false, reconnect: ManagedReconnectRequest? = nil) {
        transport.managedReconnect = reconnect
        if failed {
            exitStatus = EXIT_FAILURE
        }
        guard !isStopRequested else {
            return
        }
        isStopRequested = true
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
            let withdrawn = try routeManager.withdrawVPNDNS(using: sessionState) { change in
                var next = sessionState
                next.retire(change)
                try persistPreparedNetworkState(next)
            }
            guard withdrawn else {
                throw VPNControllerError.cleanupFailed("VPN DNS withdrawal was not published before tunnel shutdown.")
            }
        } catch {
            dnsWithdrawalFailure = dnsWithdrawalFailure ?? error
            exitStatus = EXIT_FAILURE
            transport.managedReconnect = nil
            EventLog.append(eventName: "DNS_WITHDRAWAL_FAILED",
                            info: "Could not confirm that VPN DNS was withdrawn before stopping the tunnel: \(error.localizedDescription)",
                            isError: true, isFatal: false, phase: sessionState.phase)
        }
    }

    private func armConnectingDeadline() {
        guard sessionState.phase == .connecting, !isStopRequested, !isCleanupComplete else {
            return
        }
        let generation = vpnEventGeneration
        scheduleDeadline(at: .now + .seconds(Self.connectingDeadlineSeconds)) { [weak self] in
            guard let self,
                  self.vpnEventGeneration == generation,
                  self.sessionState.phase == .connecting,
                  !self.isStopRequested,
                  !self.isCleanupComplete else {
                return
            }
            self.failSession(event: "CONNECT_TIMED_OUT",
                             message: Self.startupConnectTimeoutMessage)
        }
    }

    func failSession(event: String, message: String) {
        sessionState.lastEventName = event
        sessionState.diagnosticDetail = message
        if executionMode == .detached(reportsStartupStatus: true) {
            DetachedStartupStatus.report(message)
        }
        saveStatusState()
        updateMenuBar()
        EventLog.append(note: message, phase: sessionState.phase)
        emit(message, level: .error)
        requestStop(reason: message, failed: true)
    }

    func scheduleDeadline(at deadline: ContinuousClock.Instant,
                          execute: @escaping @MainActor @Sendable () -> Void) {
        Task { @MainActor in
            do { try await Task.sleep(until: deadline, clock: .continuous) }
            catch { return }
            execute()
        }
    }

    private func cleanupAfterStartupFailure(_ startupError: Error) {
        guard !isCleanupComplete else {
            return
        }

        isCleanupComplete = true
        stopRouteMonitor()
        stopSleepAssertion()
        EventLog.append(note: "Restoring network configuration because startup failed before the VPN client started: \(startupError.localizedDescription)",
                        phase: sessionState.phase)
        withdrawVPNDNSBeforeTunnelTeardown()
        shutdownOpenVPNClient()

        let cleanupFailureAlert = restoreNetworkConfiguration()

        closeAuthenticationUI()
        removePowerObserver()
        releaseControllerLock()
        if let cleanupFailureAlert {
            UserAlert.present(cleanupFailureAlert)
        }
    }

    private func completeCleanupAndExit() {
        guard !isCleanupComplete else {
            return
        }
        isCleanupComplete = true
        stopRouteMonitor()
        stopSleepAssertion()
        EventLog.append(note: "Completing cleanup.", phase: sessionState.phase)
        if !isStopRequested {
            withdrawVPNDNSBeforeTunnelTeardown()
        }
        shutdownOpenVPNClient()
        let restart = transport.managedReconnect
        let cleanupFailureAlert = restoreNetworkConfiguration(keepLedger: restart != nil)
        closeAuthenticationUI()
        menuBarRefreshTimer?.invalidate()
        menuBarRefreshTimer = nil
        userInterface?.close()
        userInterface = nil
        removePowerObserver()
        if let cleanupFailureAlert {
            UserAlert.present(cleanupFailureAlert)
        } else if let restart, let controllerLock {
            do {
                let intent = try PrivilegedConnectIntent.resolve(configFilePath: restart.configFilePath, verbosityOverride: verbosity,
                                                                 tunnelModeOverride: restart.tunnelMode)
                try CWRUOVPNMain.replaceController(intent: intent, mode: executionMode, lock: controllerLock, previous: sessionState)
                releaseControllerLock()
                return
            } catch {
                if let remaining = SessionState.load(), !remaining.cleanupNeeded {
                    do { try SessionState.remove() } catch { exitStatus = EXIT_FAILURE }
                } else {
                    exitStatus = EXIT_FAILURE
                    UserAlert.present("Could not restart the VPN: \(error.localizedDescription)")
                }
            }
        } else if let pendingDisconnectAlertMessage {
            UserAlert.present(pendingDisconnectAlertMessage)
        }
        releaseControllerLock()
        DispatchQueue.main.async { exit(self.exitStatus) }
    }

    private func restoreNetworkConfiguration(keepLedger: Bool = false) -> String? {
        do {
            try Self.restoreNetworkConfiguration(using: sessionState,
                                                 routeManager: routeManager,
                                                 dnsWithdrawalFailure: dnsWithdrawalFailure,
                                                 isDisconnectingAfterWake: isDisconnectingAfterWake, keepLedger: keepLedger,
                                                 persist: persistPreparedNetworkState)
            sessionState.cleanupNeeded = false
            if keepLedger { try saveState() }
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
            return "\(message) Run \"$CWRU_OVPN_BIN\" doctor for recovery guidance."
        }
    }

    private func scheduleDisconnectCleanupFallback(reason: String) {
        guard !disconnectCleanupFallbackScheduled else {
            return
        }
        disconnectCleanupFallbackScheduled = true

        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(2)) { [weak self] in
            guard let self, !self.isCleanupComplete else {
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
        if executionMode == .foreground {
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

    func saveState(finishing request: ModeRequest? = nil, outcome: ModeReceipt.Outcome = .applied, detail: String? = nil) throws {
        let preparedState = try SessionState.saveAtomically { persistedState in
            var result = Self.sessionStateForSave(currentState: sessionState, persistedState: persistedState)
            if let request { result.finish(request, outcome: outcome, detail: detail) }
            return result
        }
        sessionState = preparedState
        if sessionState.phase == .connected, executionMode == .detached(reportsStartupStatus: true) {
            executionMode = .detached(reportsStartupStatus: false)
            let null = open("/dev/null", O_WRONLY | O_CLOEXEC)
            if null >= 0 { _ = dup2(null, STDOUT_FILENO); close(null) }
        }
    }

    func saveStatusState() {
        do {
            try saveState()
        } catch {
            EventLog.append(note: "Could not save VPN status: \(error.localizedDescription)", phase: sessionState.phase)
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

    private func installPowerObserver() throws {
        powerObserver = cwru_power_observe({ pointer, awake in
            guard let pointer else { return }
            let owner = Unmanaged<VPNController>.fromOpaque(pointer).takeUnretainedValue()
            MainActor.assumeIsolated {
                if awake { owner.handleDidWake() } else { owner.handleWillSleep() }
            }
        }, Unmanaged.passUnretained(self).toOpaque())
        guard powerObserver != nil else { throw VPNControllerError.operationFailed("Could not observe system sleep and wake.") }
    }

    private func removePowerObserver() {
        cwru_power_stop(powerObserver)
        powerObserver = nil
    }

    private func handleDidWake() {
        let transition = Self.workspaceSleepTransition(event: .didWake,
                                                       phase: sessionState.phase,
                                                       isStopRequested: isStopRequested,
                                                       isCleanupComplete: isCleanupComplete)
        isSystemAsleep = transition.isSystemAsleep
        guard transition.shouldDisconnect else {
            return
        }
        EventLog.append(note: "System woke from sleep. Disconnecting VPN.", phase: sessionState.phase)
        isDisconnectingAfterWake = true
        pendingDisconnectAlertMessage = pendingDisconnectAlertMessage
            ?? "VPN disconnected because your Mac slept. Reconnect when you are back online."
        requestStop(reason: "system wake")
    }

    private func handleWillSleep() {
        let transition = Self.workspaceSleepTransition(event: .willSleep,
                                                       phase: sessionState.phase,
                                                       isStopRequested: isStopRequested,
                                                       isCleanupComplete: isCleanupComplete)
        isSystemAsleep = transition.isSystemAsleep
        EventLog.append(note: "System will sleep.", phase: sessionState.phase)
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
            return sessionState.lastEventName != "RECONNECTING"
        }
        if transport.degradedAt != nil && name != "CONNECTED" && name != "DISCONNECTED" {
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
        if executionMode == .detached(reportsStartupStatus: true) {
            DetachedStartupStatus.report(record.alertMessage)
        }
        pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? record.alertMessage
        sessionState.lastEventName = record.event
        sessionState.diagnosticDetail = record.alertMessage
    }

    private func shouldStopAfterFatalEvent(name: String, isFatal: Bool) -> Bool {
        guard isFatal,
              name != "DISCONNECTED",
              !isStopRequested,
              !isCleanupComplete else {
            return false
        }

        switch sessionState.phase {
        case .connecting, .authPending, .connected:
            return true
        case .disconnecting, .disconnected, .failed:
            return false
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

    func emit(_ message: @autoclosure () -> String, level: ConsoleMessageLevel = .info) {
        guard verbosity.includes(level), executionMode == .foreground else {
            return
        }

        if level == .error {
            fputs("\(redactSensitiveText(message()))\n", stderr)
        } else {
            print(redactSensitiveText(message()))
        }
    }

    private func startSleepAssertionIfNeeded() {
        guard preventSleep else {
            EventLog.append(note: "System sleep is allowed. Skipping the system-sleep assertion.", phase: sessionState.phase)
            return
        }
        guard sleepAssertionID == nil else {
            return
        }

        do {
            sleepAssertionID = try PowerManagement.beginPreventUserIdleSystemSleepAssertion(
                reason: "Keep CWRU OpenVPN active while connected"
            )
            EventLog.append(note: "Preventing idle system sleep while the VPN is connected.",
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
