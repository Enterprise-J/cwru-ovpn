import Darwin
import Foundation

enum SessionControl {
    enum ExistingSessionDisposition: Equatable {
        case live
        case refuse
        case stale
    }

    enum ModeSwitchWaitState {
        case pending(updatedSawRequestedMode: Bool)
        case succeeded
        case deferred(String)
        case failed(String)
    }

    static func disconnectExistingSession(force: Bool,
                                          announceUnhealthyOutcome: Bool = true,
                                          sessionStore: StateDirectory = StateDirectory(),
                                          shell: Shell = Shell(),
                                          resolverDirectory: URL = ResolverPaths.directory,
                                          remoteHostRouteLedger: RemoteHostRouteLedger = RemoteHostRouteLedger(),
                                          eventLogDirectory: URL? = nil) throws {
        var session: SessionState
        switch SessionState.loadResult(from: sessionStore) {
        case .missing:
            throw VPNControllerError.missingSession
        case .loaded(let loadedSession):
            session = loadedSession
        case .invalid(let message):
            throw VPNControllerError.unsafeSessionState(
                "The persisted recovery ledger is unreadable. Refusing to discard network recovery data: \(message)"
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
            guard try signalValidatedProcess(pid: session.pid,
                                             expectedExecutablePath: expectedExecutablePath,
                                             expectedStartTime: session.processStartTime,
                                             signal: SIGTERM) else {
                return try disconnectExistingSession(force: force,
                                                     announceUnhealthyOutcome: announceUnhealthyOutcome,
                                                     sessionStore: sessionStore,
                                                     shell: shell,
                                                     resolverDirectory: resolverDirectory,
                                                     remoteHostRouteLedger: remoteHostRouteLedger,
                                                     eventLogDirectory: eventLogDirectory)
            }
            print("Disconnect requested.")
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

        let recoveryLock = try ControllerLock(in: sessionStore)
        defer { withExtendedLifetime(recoveryLock) {} }
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
            let cleanupManager = RouteManager(appliedState: session,
                                              shell: shell,
                                              resolverDirectory: resolverDirectory,
                                              remoteHostRouteLedger: remoteHostRouteLedger,
                                              eventLogDirectory: eventLogDirectory)
            do {
                let cleanupHealthy = try cleanupManager.cleanup(using: session)
                if !cleanupHealthy {
                    if force {
                        print("Cleanup ran but network looks unhealthy; forcing state removal anyway.")
                    } else {
                        let messages = unhealthyCleanupMessages(
                            networkOffline: !cleanupManager.physicalDefaultRouteIsPresent()
                        )
                        var recoveryState = session
                        recoveryState.markRecoveryRequired(message: messages.recovery)
                        try? recoveryState.save(to: sessionStore)
                        if announceUnhealthyOutcome {
                            print(messages.console)
                        }
                        return
                    }
                }
            } catch {
                if force {
                    print("Cleanup raised \(error.localizedDescription); forcing state removal anyway.")
                } else {
                    var recoveryState = session
                    recoveryState.markRecoveryRequired(message: "Cleanup failed: \(error.localizedDescription)")
                    try? recoveryState.save(to: sessionStore)
                    throw error
                }
            }
            if force {
                cleanupManager.refreshDHCPLeaseIfAvailable(using: session)
            }
        }
        try SessionState.remove(from: sessionStore)
        print(session.cleanupNeeded
              ? "Removed stale state and restored network configuration."
              : "Removed stale state.")
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
                                                     shell: Shell = Shell(),
                                                     resolverDirectory: URL = ResolverPaths.directory,
                                                     remoteHostRouteLedger: RemoteHostRouteLedger = RemoteHostRouteLedger(),
                                                     eventLogDirectory: URL? = nil) throws -> Bool {
        var session: SessionState
        switch SessionState.loadResult(from: sessionStore) {
        case .missing:
            return false
        case .loaded(let loadedSession):
            session = loadedSession
        case .invalid(let message):
            throw VPNControllerError.failedToStart(
                "The persisted recovery ledger is unreadable. Run cwru-ovpn doctor before reconnecting: \(message)"
            )
        }

        let expectedExecutablePath = session.executablePath
        let identityAssessment = processIdentityAssessment(session.pid,
                                                           expectedExecutablePath: expectedExecutablePath,
                                                           expectedStartTime: session.processStartTime)
        switch existingSessionDisposition(identityAssessment: identityAssessment) {
        case .stale:
            if session.cleanupNeeded {
                print("Recovering stale network state from the previous session before reconnecting.")
            }
            try disconnectExistingSession(force: false,
                                          announceUnhealthyOutcome: false,
                                          sessionStore: sessionStore,
                                          shell: shell,
                                          resolverDirectory: resolverDirectory,
                                          remoteHostRouteLedger: remoteHostRouteLedger,
                                          eventLogDirectory: eventLogDirectory)
            if let remainingSession = SessionState.load(from: sessionStore), remainingSession.cleanupNeeded {
                let detail = remainingSession.lastInfo
                    ?? "Previous network state could not be fully recovered."
                throw VPNControllerError.failedToStart(
                    "\(detail) Run cwru-ovpn disconnect --force to drop the stale state, or cwru-ovpn doctor for recovery guidance."
                )
            }
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
            if let activeConfigFilePath = session.configFilePath,
               requestedConfigFilePath != activeConfigFilePath {
                throw VPNControllerError.failedToStart(
                    "A VPN session is already running with a different config file. Disconnect first to switch config files."
                )
            }
        }

        switch session.phase {
        case .connected:
            let activeMode = session.tunnelMode
            if activeMode == targetMode {
                if session.requestedTunnelMode != nil {
                    session = try updateActiveSessionRequest(expectedSession: session, sessionStore: sessionStore) {
                        $0.requestingModeSwitch(to: $0.tunnelMode)
                    }
                    _ = try signalValidatedProcess(pid: session.pid,
                                                   expectedExecutablePath: expectedExecutablePath,
                                                   expectedStartTime: session.processStartTime,
                                                   signal: SIGUSR1)
                }
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
            if try waitForModeSwitch(pid: session.pid,
                                     expectedExecutablePath: session.executablePath,
                                     expectedStartTime: session.processStartTime,
                                     targetMode: targetMode,
                                     sessionStore: sessionStore) {
                print("Switched to \(targetMode.modeDescription) mode.")
            }
            return true

        case .connecting, .authPending:
            session = try updateActiveSessionRequest(expectedSession: session, sessionStore: sessionStore) {
                $0.requestingModeSwitch(to: targetMode)
            }
            _ = try signalValidatedProcess(pid: session.pid,
                                           expectedExecutablePath: expectedExecutablePath,
                                           expectedStartTime: session.processStartTime,
                                           signal: SIGUSR1)
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

    static func updateActiveSessionRequest(expectedSession: SessionState,
                                           sessionStore: StateDirectory = StateDirectory(),
                                           _ transform: (SessionState) -> SessionState) throws -> SessionState {
        try SessionState.saveAtomically(in: sessionStore) { persistedState in
            guard let current = persistedState,
                  current.pid == expectedSession.pid,
                  current.executablePath == expectedSession.executablePath,
                  current.processStartTime == expectedSession.processStartTime else {
                throw VPNControllerError.failedToStart(
                    "The active VPN session changed while recording the request. Retry the command."
                )
            }
            return transform(current)
        }
    }

    static func waitForModeSwitch(pid: Int32,
                                  expectedExecutablePath: String,
                                  expectedStartTime: ProcessStartTime,
                                  targetMode: AppTunnelMode,
                                  sessionStore: StateDirectory = StateDirectory()) throws -> Bool {
        let monitor = BlockingEventMonitor(directoryURLs: [sessionStore.url],
                                            processIDs: [pid])
        let deadline = DispatchTime.now() + 8.0
        var sawRequestedMode = false

        while true {
            guard processMatchesExecutable(pid,
                                           expectedExecutablePath: expectedExecutablePath,
                                           expectedStartTime: expectedStartTime) else {
                throw VPNControllerError.failedToStart(
                    "The active VPN session identity changed or became unavailable while applying the mode switch."
                )
            }

            switch evaluateModeSwitchWaitState(session: SessionState.load(from: sessionStore),
                                               pid: pid,
                                               expectedExecutablePath: expectedExecutablePath,
                                               expectedStartTime: expectedStartTime,
                                               targetMode: targetMode,
                                               sawRequestedMode: sawRequestedMode) {
            case .pending(let updatedSawRequestedMode):
                sawRequestedMode = updatedSawRequestedMode
            case .succeeded:
                return true
            case .deferred(let message):
                print(message)
                return false
            case .failed(let message):
                throw VPNControllerError.failedToStart(message)
            }

            guard DispatchTime.now() < deadline else {
                break
            }
            _ = monitor.wait(until: deadline)
        }

        throw VPNControllerError.failedToStart(
            "Timed out while waiting for mode switch to \(targetMode.modeDescription)."
        )
    }

    static func evaluateModeSwitchWaitState(session: SessionState?,
                                            pid: Int32,
                                            expectedExecutablePath: String,
                                            expectedStartTime: ProcessStartTime,
                                            targetMode: AppTunnelMode,
                                            sawRequestedMode: Bool) -> ModeSwitchWaitState {
        var sawRequestedMode = sawRequestedMode

        guard let session,
              session.pid == pid,
              session.executablePath == expectedExecutablePath,
              session.processStartTime == expectedStartTime else {
            return .pending(updatedSawRequestedMode: sawRequestedMode)
        }

        if session.requestedTunnelMode == targetMode {
            sawRequestedMode = true
        }

        if session.phase == .failed {
            return .failed(session.lastInfo ?? "Mode switch failed.")
        }

        if session.requestedTunnelMode == targetMode,
           session.lastEvent == "MODE_SWITCH_DEFERRED" {
            return .deferred(session.lastInfo
                ?? "Mode switch deferred until the VPN finishes reconnecting; it will apply automatically.")
        }

        if sawRequestedMode,
           session.requestedTunnelMode == nil,
           ["MODE_SWITCH_FAILED", "MODE_SWITCH_ROLLBACK_FAILED"].contains(session.lastEvent) {
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

        throw VPNControllerError.failedToStart("Failed to signal the active VPN controller process.")
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
        let loadResult = SessionState.loadResult()
        if case .invalid(let message) = loadResult {
            print("Status: Recovery Needed")
            print("Version: \(AppIdentity.version)")
            print("Recovery ledger error: \(message)")
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
        print("Started: \(ISO8601DateFormatter().string(from: session.startedAt))")
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
        printSplitTunnelHealthIfNeeded(for: session)
    }

    static func splitTunnelHealthChecks(for session: SessionState) -> [SplitTunnelHealthCheck] {
        guard session.phase == .connected,
              session.tunnelMode == .split else {
            return []
        }

        return RouteManager().splitTunnelHealthChecks(using: session)
    }

    static func printSplitTunnelHealthIfNeeded(for session: SessionState) {
        let checks = splitTunnelHealthChecks(for: session)
        guard !checks.isEmpty else {
            return
        }

        print("Split health:")
        for check in checks {
            print("  \(check.status.rawValue) \(check.name): \(check.detail)")
        }
    }

    static func unhealthyCleanupMessages(networkOffline: Bool) -> (recovery: String, console: String) {
        guard networkOffline else {
            return (
                "Cleanup ran, but the network still appears unhealthy.",
                "Cleanup ran, but the network still appears unhealthy. State was kept so you can retry disconnect. Pass --force to drop state anyway."
            )
        }
        return (
            "Cleanup ran while the network was offline or behind a captive portal, so its health could not be verified.",
            "Cleanup ran, but this Mac appears offline or behind a captive portal, so the network's health could not be verified. Join the network and finish any sign-in, then retry."
        )
    }
}
