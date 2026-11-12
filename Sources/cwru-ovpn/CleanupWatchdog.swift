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
        while true {
            guard ledgerAwaitsCleanup(in: store, parentPID: parentPID, parentStartTime: parentStartTime) else {
                exit(0)
            }
            if !processExists(parentPID, expectedStartTime: parentStartTime),
               case .finished(let criticalAlert) = performCleanup(parentPID: parentPID,
                                                                  parentStartTime: parentStartTime,
                                                                  sessionStore: store) {
                if let criticalAlert {
                    UserAlert.present(criticalAlert)
                }
                exit(0)
            }
            _ = monitor.wait(until: .now() + .seconds(fallbackPollSeconds))
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
                && session.lastEvent != SessionState.recoveryRequiredEvent
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
            let detail = "Cleanup watchdog could not lock the recovery ledger: \(error.localizedDescription)"
            EventLog.append(note: detail, phase: .failed, in: eventLogDirectory)
            return .finished(criticalAlert: detail)
        }
        defer { withExtendedLifetime(recoveryLock) {} }

        let session: SessionState
        switch SessionState.loadResult(from: sessionStore) {
        case .missing:
            return .finished(criticalAlert: nil)
        case .loaded(let loadedSession):
            session = loadedSession
        case .invalid(let message):
            let detail = "Cleanup watchdog could not read the persistent recovery ledger: \(message)"
            EventLog.append(note: detail, phase: .failed, in: eventLogDirectory)
            fputs("\(AppIdentity.executableName): \(detail)\n", stderr)
            return .finished(criticalAlert: "\(AppIdentity.bundleName) could not read its network recovery ledger. Do not reconnect until cwru-ovpn doctor reports a healthy state.")
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
        guard session.lastEvent != SessionState.recoveryRequiredEvent else {
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
                guard try routeManager.cleanup(using: session) else {
                    markRecoveryRequired("Cleanup watchdog ran, but the network still looks unhealthy.")
                    return .finished(criticalAlert: "\(AppIdentity.bundleName) restored your pre-connection configuration, but the network still looks unhealthy. Run cwru-ovpn doctor for recovery guidance.")
                }
            }
            try SessionState.remove(from: sessionStore)
            EventLog.append(note: "Cleanup watchdog restored pre-connection configuration after unexpected process exit.",
                            phase: .disconnected,
                            in: eventLogDirectory)
            return .finished(criticalAlert: nil)
        } catch {
            markRecoveryRequired("Cleanup watchdog failed: \(error.localizedDescription)")
            return .finished(criticalAlert: "\(AppIdentity.bundleName) cleanup watchdog failed. Your network may require manual recovery.")
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
