import Foundation

enum CleanupWatchdog {
    enum CleanupOutcome: Equatable {
        case lockBusy
        case finished(criticalAlert: String?)
    }

    private static let fallbackPollSeconds = 60

    @MainActor
    static func run(parentPID: Int32, parentStartTime: ProcessStartTime) -> Never {
        let store = StateDirectory()
        let monitor = BlockingEventMonitor(directoryURLs: [store.url], processIDs: [parentPID])
        guard let executable = try? ExecutionIdentity.currentExecutablePath() else { exit(1) }
        while true {
            guard ledgerAwaitsCleanup(in: store, parentPID: parentPID, parentStartTime: parentStartTime) else {
                exit(0)
            }
            let stale = processIdentityAssessment(parentPID, expectedExecutablePath: executable,
                                                   expectedStartTime: parentStartTime).indicatesStaleOwner
            if stale,
               case .finished(let criticalAlert) = performCleanup(parentPID: parentPID,
                                                                  parentStartTime: parentStartTime,
                                                                  sessionStore: store) {
                if let criticalAlert {
                    UserAlert.present(criticalAlert)
                }
                exit(0)
            }
            _ = monitor.wait(until: .now() + .seconds(stale ? 1 : fallbackPollSeconds))
        }
    }

    static func ledgerAwaitsCleanup(in sessionStore: StateDirectory,
                                    parentPID: Int32,
                                    parentStartTime: ProcessStartTime) -> Bool {
        switch SessionState.loadResult(from: sessionStore) {
        case .missing:
            return false
        case .loaded(let session):
            return session.pid == parentPID
                && session.processStartTime == parentStartTime
                && !session.isRecoveryRequired
        case .invalid:
            return true
        }
    }

    @MainActor
    static func performCleanup(parentPID: Int32,
                               parentStartTime: ProcessStartTime,
                               sessionStore: StateDirectory = StateDirectory(),
                               routeManager: RouteManager = RouteManager()) -> CleanupOutcome {
        let eventLogDirectory = routeManager.eventLogDirectory
        let recoveryLock: ControllerLock
        do {
            recoveryLock = try ControllerLock(in: sessionStore, createDirectoryIfMissing: false)
        } catch ControllerLockError.busy {
            return .lockBusy
        } catch let error as POSIXError where error.code == .ENOENT {
            return .finished(criticalAlert: nil)
        } catch {
            let detail = "Cleanup could not lock the saved session file: \(error.localizedDescription)"
            EventLog.append(note: detail, phase: .failed, in: eventLogDirectory)
            return .finished(criticalAlert: detail)
        }
        defer { withExtendedLifetime(recoveryLock) {} }

        var session: SessionState
        switch SessionState.loadResult(from: sessionStore) {
        case .missing:
            return .finished(criticalAlert: nil)
        case .loaded(let loadedSession):
            session = loadedSession
        case .invalid(let message):
            let detail = "Cleanup could not read the saved session file: \(message)"
            EventLog.append(note: detail, phase: .failed, in: eventLogDirectory)
            fputs("\(AppIdentity.executableName): \(detail)\n", stderr)
            return .finished(criticalAlert: "\(AppIdentity.bundleName) could not read the saved network settings. Run \"$CWRU_OVPN_BIN\" doctor before reconnecting.")
        }

        let watchdogExecutablePath: String
        do {
            watchdogExecutablePath = try ExecutionIdentity.currentExecutablePath()
        } catch {
            EventLog.append(note: "Cleanup watchdog could not verify its executable identity: \(error.localizedDescription)",
                            phase: .failed,
                            in: eventLogDirectory)
            return .finished(criticalAlert: nil)
        }

        guard sessionMatchesParent(session,
                                   parentPID: parentPID,
                                   parentStartTime: parentStartTime,
                                   watchdogExecutablePath: watchdogExecutablePath) else {
            EventLog.append(note: "Cleanup watchdog ignored session state for an unexpected process identity.",
                            phase: .failed,
                            in: eventLogDirectory)
            return .finished(criticalAlert: nil)
        }

        let cleanupConfig = try? AppConfig.load(explicitConfigPath: session.configFilePath)
        EventLog.configure(privacyMode: cleanupConfig?.privacyMode ?? true)
        guard !session.isRecoveryRequired else {
            return .finished(criticalAlert: nil)
        }

        func markRecoveryRequired(_ message: String) {
            var recoveryState = session
            recoveryState.markRecoveryRequired(message: message)
            try? recoveryState.save(in: sessionStore)
            EventLog.append(note: message, phase: .failed, in: eventLogDirectory)
        }

        do {
            if session.cleanupNeeded {
                try session.validateForPrivilegedCleanup()
                let restored = try routeManager.cleanup(using: session) { next in
                    try next.save(in: sessionStore)
                    session = next
                }
                guard restored else {
                    markRecoveryRequired("Cleanup ran, but network health could not be confirmed.")
                    return .finished(criticalAlert: "\(AppIdentity.bundleName) restored the original network settings. Network health could not be confirmed. Run \"$CWRU_OVPN_BIN\" doctor for details.")
                }
            }
            try SessionState.remove(from: sessionStore)
            EventLog.append(note: "Cleanup watchdog restored pre-connection configuration after unexpected process exit.",
                            phase: .disconnected,
                            in: eventLogDirectory)
            return .finished(criticalAlert: nil)
        } catch {
            markRecoveryRequired("Cleanup watchdog failed: \(error.localizedDescription)")
            return .finished(criticalAlert: "\(AppIdentity.bundleName) could not restore the network settings. Run \"$CWRU_OVPN_BIN\" doctor for details.")
        }
    }

    static func sessionMatchesParent(_ session: SessionState,
                                     parentPID: Int32,
                                     parentStartTime: ProcessStartTime,
                                     watchdogExecutablePath: String) -> Bool {
        guard session.pid == parentPID,
              session.processStartTime == parentStartTime else {
            return false
        }

        let normalizedSessionPath = URL(fileURLWithPath: session.executablePath)
            .resolvingSymlinksInPath()
            .standardized.path
        let normalizedWatchdogPath = URL(fileURLWithPath: watchdogExecutablePath)
            .resolvingSymlinksInPath()
            .standardized.path
        return normalizedSessionPath == normalizedWatchdogPath
    }
}
