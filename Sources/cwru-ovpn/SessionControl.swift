import Darwin
import Foundation

enum SessionControl {
    enum ExistingSessionDisposition: Equatable {
        case live
        case refuse
        case stale
    }

    enum ModeSwitchWaitState {
        case pending
        case deferred(String)
        case succeeded
                case failed(String)
    }

    static func disconnectExistingSession(force: Bool,
                                          sessionStore: StateDirectory = StateDirectory(),
                                          routeManager: RouteManager = RouteManager()) throws {
        let session: SessionState
        switch SessionState.loadResult(from: sessionStore) {
        case .missing:
            throw VPNControllerError.missingSession
        case .loaded(let loadedSession):
            session = loadedSession
        case .invalid(let message):
            throw VPNControllerError.unsafeSessionState(
                "Could not read the saved session: \(message). The network settings have been retained."
            )
        }

        let expectedExecutablePath = session.executablePath

        let identityAssessment = processIdentityAssessment(
            session.pid,
            expectedExecutablePath: expectedExecutablePath,
            expectedStartTime: session.processStartTime
        )
        switch existingSessionDisposition(identityAssessment: identityAssessment) {
        case .live:
            _ = try updateActiveSessionRequest(expectedSession: session, sessionStore: sessionStore) { current in
                var updated = current
                updated.stopRequestedByUser = true
                return updated
            }
            guard try signalValidatedProcess(pid: session.pid,
                                             expectedExecutablePath: expectedExecutablePath,
                                             expectedStartTime: session.processStartTime,
                                             signal: SIGTERM) else {
                return try recoverStaleSession(session, force: force,
                                               sessionStore: sessionStore, routeManager: routeManager)
            }
            print("Disconnecting.")
            try reportControllerShutdown(pid: session.pid,
                                         expectedExecutablePath: expectedExecutablePath,
                                         expectedStartTime: session.processStartTime,
                                         sessionStore: sessionStore)
            return
        case .refuse:
            let message = processIdentityRefusalMessage(pid: session.pid,
                                                        assessment: identityAssessment,
                                                        operation: "disconnect")
                ?? "Refusing to disconnect PID \(session.pid) because its process identity could not be verified."
            throw VPNControllerError.unsafeSessionState(message)
        case .stale:
            break
        }

        try recoverStaleSession(session, force: force, sessionStore: sessionStore, routeManager: routeManager)
    }

    static func recoverStaleSession(_ expectedSession: SessionState,
                                    force: Bool,
                                    sessionStore: StateDirectory,
                                    routeManager: RouteManager) throws {
        let recoveryLock = try ControllerLock(in: sessionStore)
        defer { withExtendedLifetime(recoveryLock) {} }
        try recoverUnderLifecycleLock(expectedSession, force: force, sessionStore: sessionStore, routeManager: routeManager)
    }

    static func recoverUnderLifecycleLock(_ expectedSession: SessionState, force: Bool,
                                          sessionStore: StateDirectory, routeManager: RouteManager) throws {
        var session = expectedSession
        switch SessionState.loadResult(from: sessionStore) {
        case .missing:
            return
        case .invalid(let message):
            throw VPNControllerError.unsafeSessionState(message)
        case .loaded(let current):
            guard current.pid == session.pid,
                  current.executablePath == session.executablePath,
                  current.processStartTime == session.processStartTime else {
                throw VPNControllerError.unsafeSessionState("The VPN session changed before recovery. Retry the command.")
            }
            session = current
        }

        if session.cleanupNeeded {
            try session.validateForPrivilegedCleanup()
            do {
                if force { routeManager.refreshDHCPLeaseIfAvailable(using: session) }
                let restored = try routeManager.cleanup(using: session) { next in
                    try next.save(in: sessionStore)
                    session = next
                }
                guard restored else {
                    throw VPNControllerError.cleanupFailed(unhealthyCleanupMessage(networkOffline: try routeManager.routeLookup(for: "default") == nil))
                }
            } catch {
                session.markRecoveryRequired(message: "Cleanup failed: \(error.localizedDescription)")
                try session.save(in: sessionStore)
                throw error
            }
        }
        try SessionState.remove(from: sessionStore)
        print("Removed stale recovery state.")
    }

    private static let controllerShutdownWaitSeconds = 20.0
    private static let modeSwitchReportWaitSeconds = 8.0

    private static func reportControllerShutdown(pid: Int32,
                                                 expectedExecutablePath: String,
                                                 expectedStartTime: ProcessStartTime,
                                                 sessionStore: StateDirectory) throws {
        let monitor = BlockingEventMonitor(directoryURLs: [sessionStore.url], processIDs: [pid])
        let deadline = DispatchTime.now() + controllerShutdownWaitSeconds
        while true {
            switch SessionState.loadResult(from: sessionStore) {
            case .missing:
                print("Disconnected.")
                return
            case .invalid(let message):
                throw VPNControllerError.cleanupFailed("Disconnect requested, but the saved session is unreadable: \(message)")
            case .loaded(let remaining):
                if remaining.pid != pid
                    || remaining.executablePath != expectedExecutablePath
                    || remaining.processStartTime != expectedStartTime {
                    print("The previous VPN session ended. A different session is active.")
                    return
                }
                if remaining.phase == .failed {
                    throw VPNControllerError.cleanupFailed(
                        SessionPresentation.recoveryDetail(for: remaining, stale: true)
                            ?? "Disconnect did not complete. Run \"$CWRU_OVPN_BIN\" doctor for recovery guidance.")
                }
            }
            guard DispatchTime.now() < deadline else {
                switch processIdentityAssessment(pid, expectedExecutablePath: expectedExecutablePath,
                                                 expectedStartTime: expectedStartTime) {
                case .matched:
                    throw VPNControllerError.cleanupFailed("The VPN controller is still shutting down. Check ovpnstatus in a moment.")
                case .notRunning, .mismatched:
                    throw VPNControllerError.cleanupFailed("The VPN controller stopped, but recovery state remains. Run ovpnd again.")
                case .unavailable:
                    throw VPNControllerError.cleanupFailed("The VPN controller identity is unavailable and recovery state remains. Run \"$CWRU_OVPN_BIN\" doctor.")
                }
            }
            _ = monitor.wait(until: deadline)
        }
    }

    static func existingSessionDisposition(identityAssessment: ProcessIdentityAssessment) -> ExistingSessionDisposition {
        switch identityAssessment {
        case .matched:
            return .live
        case .unavailable:
            return .refuse
        case .mismatched, .notRunning:
            return .stale
        }
    }

    static func handleConnectRequestForActiveSession(targetMode: AppTunnelMode,
                                                     configFilePath: String?,
                                                     sessionStore: StateDirectory = StateDirectory(),
                                                     routeManager: RouteManager = RouteManager()) throws -> Bool {
        var session: SessionState
        switch SessionState.loadResult(from: sessionStore) {
        case .missing:
            return false
        case .loaded(let loadedSession):
            session = loadedSession
        case .invalid(let message):
            throw VPNControllerError.operationFailed(
                "Could not read the saved session: \(message). Run \"$CWRU_OVPN_BIN\" doctor before reconnecting."
            )
        }

        let expectedExecutablePath = session.executablePath
        let identityAssessment = processIdentityAssessment(session.pid,
                                                           expectedExecutablePath: expectedExecutablePath,
                                                           expectedStartTime: session.processStartTime)
        switch existingSessionDisposition(identityAssessment: identityAssessment) {
        case .stale:
            if session.cleanupNeeded {
                print("Restoring routes and DNS from the previous session before reconnecting.")
            }
            try recoverStaleSession(session, force: false, sessionStore: sessionStore, routeManager: routeManager)
            return false
        case .refuse:
            throw VPNControllerError.unsafeSessionState(
                processIdentityRefusalMessage(pid: session.pid, assessment: identityAssessment, operation: "reconnect to")
                    ?? "Refusing to reconnect to PID \(session.pid) because its process identity could not be verified."
            )
        case .live:
            break
        }

        if let configFilePath {
            let requestedConfigFilePath = URL(fileURLWithPath: AppConfig.expandUserPath(configFilePath)).standardized.path
            if requestedConfigFilePath != session.configFilePath {
                throw VPNControllerError.operationFailed(
                    "A VPN session is already running with a different config file. Disconnect first to switch config files."
                )
            }
        }

        switch session.phase {
        case .connected:
            let activeMode = session.tunnelMode
            if activeMode == targetMode, session.requestedTunnelMode == nil {
                print("Already connected in \(activeMode.modeDescription) mode.")
                return true
            }

            session = try updateActiveSessionRequest(expectedSession: session, sessionStore: sessionStore) {
                $0.requestingModeSwitch(to: targetMode)
            }
            _ = try signalValidatedProcess(pid: session.pid,
                                           expectedExecutablePath: expectedExecutablePath,
                                           expectedStartTime: session.processStartTime,
                                           signal: SIGUSR1)
            guard let request = session.modeRequest else { throw VPNControllerError.operationFailed("The mode request was superseded.") }
            if try waitForModeSwitch(pid: session.pid,
                                     expectedExecutablePath: session.executablePath,
                                     expectedStartTime: session.processStartTime,
                                     request: request,
                                     sessionStore: sessionStore) {
                print("Switched to \(targetMode.modeDescription) mode.")
            }
            return true

        case .connecting, .authPending:
            if session.requestedTunnelMode ?? session.tunnelMode == targetMode {
                print("A VPN session is already connecting in \(targetMode.modeDescription) mode.")
                return true
            }
            session = try updateActiveSessionRequest(expectedSession: session, sessionStore: sessionStore) {
                $0.requestingModeSwitch(to: targetMode)
            }
            _ = try signalValidatedProcess(pid: session.pid,
                                           expectedExecutablePath: expectedExecutablePath,
                                           expectedStartTime: session.processStartTime,
                                           signal: SIGUSR1)
            print("A VPN session is already connecting. Requested \(targetMode.modeDescription) mode, which will apply once connected.")
            return true

        case .disconnecting:
            throw VPNControllerError.operationFailed("A VPN session is disconnecting. Wait a moment and retry.")

        case .disconnected, .failed:
            throw VPNControllerError.operationFailed(
                "An active VPN controller is in \(session.phase.rawValue) state. Run ovpnd, then retry."
            )
        }
    }

    static func updateActiveSessionRequest(expectedSession: SessionState,
                                           sessionStore: StateDirectory = StateDirectory(),
                                           _ transform: (SessionState) -> SessionState) throws -> SessionState {
        try SessionState.saveAtomically(in: sessionStore) { persistedState in
            guard let current = persistedState,
                  current.pid == expectedSession.pid,
                  current.executablePath == expectedSession.executablePath,
                  current.processStartTime == expectedSession.processStartTime else {
                throw VPNControllerError.operationFailed(
                    "The active VPN session changed while recording the request. Retry the command."
                )
            }
            return transform(current)
        }
    }

    static func waitForModeSwitch(pid: Int32,
                                  expectedExecutablePath: String,
                                  expectedStartTime: ProcessStartTime,
                                  request: ModeRequest,
                                  sessionStore: StateDirectory = StateDirectory()) throws -> Bool {
        let monitor = BlockingEventMonitor(directoryURLs: [sessionStore.url],
                                           processIDs: [pid])
        let deadline = DispatchTime.now() + modeSwitchReportWaitSeconds

        while true {
            guard processMatchesExecutable(pid,
                                           expectedExecutablePath: expectedExecutablePath,
                                           expectedStartTime: expectedStartTime) else {
                throw VPNControllerError.operationFailed(
                    "The active VPN session identity changed or became unavailable while applying the mode switch."
                )
            }

            switch evaluateModeSwitchWaitState(session: SessionState.load(from: sessionStore),
                                               pid: pid,
                                               expectedExecutablePath: expectedExecutablePath,
                                               expectedStartTime: expectedStartTime,
                                               request: request) {
            case .deferred(let detail):
                print(detail)
                return false
            case .pending: break
            case .succeeded: return true
            case .failed(let message):
                throw VPNControllerError.operationFailed(message)
            }

            guard DispatchTime.now() < deadline else {
                throw VPNControllerError.operationFailed("Timed out waiting for mode request \(request.id). Check ovpnstatus for the pending mode.")
            }
            _ = monitor.wait(until: deadline)
        }
    }

    static func evaluateModeSwitchWaitState(session: SessionState?,
                                            pid: Int32,
                                            expectedExecutablePath: String,
                                            expectedStartTime: ProcessStartTime,
                                            request: ModeRequest) -> ModeSwitchWaitState {
        guard let session, session.pid == pid, session.executablePath == expectedExecutablePath,
              session.processStartTime == expectedStartTime else { return .failed("The session ended before the request was confirmed.") }
        if let receipt = session.modeReceipts.last(where: { $0.id == request.id }) {
            return receipt.outcome == .applied ? .succeeded : .failed(receipt.detail ?? "Mode request \(receipt.outcome.rawValue).")
        }
        if session.applyingModeRequest?.id == request.id { return .pending }
        guard session.modeRequest?.id == request.id else { return .failed("The mode request has been superseded.") }
        if session.phase == .failed || session.phase == .disconnecting { return .failed("The session is stopping.") }
        if let detail = session.modeRequest?.deferral { return .deferred(detail) }
        return .pending
    }

    static func signalValidatedProcess(pid: Int32,
                                       expectedExecutablePath: String,
                                       expectedStartTime: ProcessStartTime,
                                       signal: Int32) throws -> Bool {
        let identityAssessment = processIdentityAssessment(
            pid,
            expectedExecutablePath: expectedExecutablePath,
            expectedStartTime: expectedStartTime
        )
        guard identityAssessment != .notRunning else {
            return false
        }

        guard identityAssessment.isVerifiedMatch else {
            let message = processIdentityRefusalMessage(pid: pid,
                                                        assessment: identityAssessment,
                                                        operation: "signal")
                ?? "Refusing to signal PID \(pid) because its process identity could not be verified."
            throw VPNControllerError.unsafeSessionState(message)
        }

        if kill(pid, signal) == 0 {
            return true
        }

        if errno == ESRCH {
            return false
        }

        throw VPNControllerError.operationFailed("Failed to signal the active VPN controller process.")
    }

    static func processIdentityRefusalMessage(pid: Int32,
                                              assessment: ProcessIdentityAssessment,
                                              operation: String) -> String? {
        switch assessment {
        case .mismatched:
            return "Refusing to \(operation) PID \(pid) because it does not match the expected \(AppIdentity.executableName) controller identity."
        case .unavailable:
            return "Refusing to \(operation) PID \(pid) because its process identity is unavailable to the current user. Retry the command with sudo."
        case .matched, .notRunning:
            return nil
        }
    }

    static func printStatus() {
        let loadResult = SessionState.statusResult()
        if case .invalid(let message) = loadResult {
            print("Status: Recovery Needed")
            print("Version: \(AppIdentity.version)")
            print("Saved session error: \(message)")
            return
        }
        guard let session = loadResult.loadedSession else {
            print(SessionPresentation.statusLine(for: .disconnected, stale: false, recoveryNeeded: false))
            print("Version: \(AppIdentity.version)")
            return
        }

        let identityAssessment = processIdentityAssessment(
            session.pid,
            expectedExecutablePath: session.executablePath,
            expectedStartTime: session.processStartTime
        )
        let sessionMayBeActive = identityAssessment.permitsReadOnlyStatus
        print(SessionPresentation.statusLine(title: SessionPresentation.readOnlyStatusTitle(
            for: session,
            identityAssessment: identityAssessment
        )))
        print("Version: \(AppIdentity.version)")
        print(SessionPresentation.readOnlyControllerPIDLine(pid: session.pid,
                                                            identityAssessment: identityAssessment))
        print("Mode: \(session.tunnelMode.displayName)")
        if let configFilePath = session.configFilePath {
            print("Config: \(configFilePath)")
        }
        print("Profile: \(session.profilePath)")
        print("Started: \(session.startedAt.formatted(.iso8601))")
        if sessionMayBeActive, let requestedTunnelMode = session.requestedTunnelMode {
            print("Pending mode switch: \(requestedTunnelMode.displayName)")
        }
        if let detail = SessionPresentation.recoveryDetail(for: session, stale: !sessionMayBeActive),
           !detail.isEmpty {
            print(detail)
        }
        if sessionMayBeActive,
           let countdownText = SessionPresentation.estimatedSessionCountdownText(for: session) {
            print(countdownText)
        }
        if sessionMayBeActive,
           session.phase == .connected,
           let gatewayLine = SessionPresentation.gatewayLine(for: session.serverHost) {
            print(gatewayLine)
        }
        if sessionMayBeActive {
            printTunnelHealthIfNeeded(for: session)
        }
    }

    static func printTunnelHealthIfNeeded(for session: SessionState) {
        guard session.connectedAt != nil || session.phase == .connected else { return }
        let manager = RouteManager()
        let checks: [TunnelHealthCheck]
        switch session.tunnelMode {
        case .split: checks = manager.splitTunnelHealthChecks(using: session)
        case .full:
            do {
                try manager.validateNetworkSafetyWhileSettling(using: session)
                checks = [TunnelHealthCheck(status: .pass, name: "policy", detail: "IPv4, IPv6 and published DNS match the full-tunnel policy")]
            } catch { checks = [TunnelHealthCheck(status: .fail, name: "policy", detail: error.localizedDescription)] }
        }
        print("\(session.tunnelMode.displayName) health at \(Date.now.formatted(.iso8601)):")
        for check in checks {
            print("  \(check.status.rawValue) \(check.name): \(check.detail)")
        }
    }

    static func unhealthyCleanupMessage(networkOffline: Bool) -> String {
        networkOffline
            ? "Cleanup ran, but this Mac appears offline or behind a captive portal, so network restoration could not be confirmed. Join a network, complete any sign-in, and retry."
            : "Cleanup ran, but network restoration could not be confirmed. Run ovpnd to retry. To renew DHCP during recovery, use sudo \"$CWRU_OVPN_BIN\" disconnect --force."
    }
}
