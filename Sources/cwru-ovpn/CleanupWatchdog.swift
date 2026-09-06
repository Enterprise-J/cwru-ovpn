import Foundation

enum CleanupWatchdog {
    static func run(parentPID: Int32, parentStartTime: ProcessStartTime) {
        let source = DispatchSource.makeProcessSource(
            identifier: pid_t(parentPID),
            eventMask: .exit,
            queue: .main
        )
        let timer = DispatchSource.makeTimerSource(queue: .main)
        var finished = false
        let finish = {
            guard !finished else {
                return
            }
            finished = true
            guard performCleanup(parentPID: parentPID, parentStartTime: parentStartTime) else {
                finished = false
                return
            }
            source.cancel()
            timer.cancel()
            exit(0)
        }

        source.setEventHandler {
            finish()
        }
        timer.schedule(deadline: .now(), repeating: .seconds(1))
        timer.setEventHandler {
            let sessionMissing: Bool
            if case .missing = SessionState.loadResult() {
                sessionMissing = true
            } else {
                sessionMissing = false
            }
            if shouldFinishMonitoring(
                parentExists: processExists(parentPID, expectedStartTime: parentStartTime),
                sessionExists: !sessionMissing
            ) {
                finish()
            }
        }

        source.resume()
        timer.resume()

        dispatchMain()
    }

    static func shouldFinishMonitoring(parentExists: Bool, sessionExists: Bool) -> Bool {
        !parentExists || !sessionExists
    }

    @discardableResult
    static func performCleanup(parentPID: Int32,
                               parentStartTime: ProcessStartTime,
                               sessionStore: StateDirectory = StateDirectory(),
                               shell: Shell = Shell(),
                               resolverDirectory: URL = ResolverPaths.directory,
                               remoteHostRouteLedger: RemoteHostRouteLedger = RemoteHostRouteLedger(),
                               eventLogDirectory: URL? = nil,
                               showCriticalAlert: (String) -> Void = UserAlert.showCritical) -> Bool {
        let recoveryLock: ControllerLock
        do {
            recoveryLock = try ControllerLock(in: sessionStore)
        } catch ControllerLockError.busy {
            return false
        } catch {
            let detail = "Cleanup watchdog could not lock the recovery ledger: \(error.localizedDescription)"
            EventLog.append(note: detail, phase: .failed, in: eventLogDirectory)
            showCriticalAlert(detail)
            return true
        }
        defer { withExtendedLifetime(recoveryLock) {} }

        let session: SessionState
        switch SessionState.loadResult(from: sessionStore) {
        case .missing:
            return true
        case .loaded(let loadedSession):
            session = loadedSession
        case .invalid(let message):
            let detail = "Cleanup watchdog could not read the persistent recovery ledger: \(message)"
            EventLog.append(note: detail, phase: .failed, in: eventLogDirectory)
            fputs("\(AppIdentity.executableName): \(detail)\n", stderr)
            showCriticalAlert("\(AppIdentity.bundleName) could not read its network recovery ledger. Do not reconnect until cwru-ovpn doctor reports a healthy state.")
            return true
        }

        let watchdogExecutablePath: String
        do {
            watchdogExecutablePath = try ExecutionIdentity.currentExecutablePath()
        } catch {
            EventLog.append(note: "Cleanup watchdog could not verify its executable identity: \(error.localizedDescription)",
                            phase: .failed,
                            in: eventLogDirectory)
            return true
        }

        guard sessionMatchesParent(session,
                                   parentPID: parentPID,
                                   parentStartTime: parentStartTime,
                                   watchdogExecutablePath: watchdogExecutablePath) else {
            EventLog.append(note: "Cleanup watchdog ignored session state for an unexpected process identity.",
                            phase: .failed,
                            in: eventLogDirectory)
            return true
        }

        let cleanupConfig = try? AppConfig.load(explicitConfigPath: session.configFilePath)
        EventLog.configure(privacyMode: cleanupConfig?.privacyMode ?? true)

        do {
            if session.cleanupNeeded {
                try session.validateForPrivilegedCleanup()
                let cleanupHealthy = try RouteManager(appliedState: session,
                                                      shell: shell,
                                                      resolverDirectory: resolverDirectory,
                                                      remoteHostRouteLedger: remoteHostRouteLedger,
                                                      eventLogDirectory: eventLogDirectory).cleanup(using: session)
                if !cleanupHealthy {
                    var recoveryState = session
                    recoveryState.markRecoveryRequired(message: "Cleanup watchdog ran, but the network still looks unhealthy.")
                    try? recoveryState.save(to: sessionStore)
                    EventLog.append(note: "Cleanup watchdog restored state, but the network still looked unhealthy.",
                                    phase: .failed,
                                    in: eventLogDirectory)
                    showCriticalAlert("\(AppIdentity.bundleName) restored your pre-connection configuration, but the network still looks unhealthy. Run cwru-ovpn doctor for recovery guidance.")
                    return true
                }
            }
            try SessionState.remove(from: sessionStore)
            EventLog.append(note: "Cleanup watchdog restored pre-connection configuration after unexpected process exit.",
                            phase: .disconnected,
                            in: eventLogDirectory)
        } catch {
            var recoveryState = session
            recoveryState.markRecoveryRequired(message: "Cleanup watchdog failed: \(error.localizedDescription)")
            try? recoveryState.save(to: sessionStore)
            EventLog.append(note: "Cleanup watchdog failed: \(error.localizedDescription)",
                            phase: .failed,
                            in: eventLogDirectory)
            showCriticalAlert("\(AppIdentity.bundleName) cleanup watchdog failed. Your network may require manual recovery.")
        }
        return true
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
