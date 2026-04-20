import Foundation

enum CleanupWatchdog {
    static func run(parentPID: Int32) {
        // Use a kernel-level process-exit event instead of a polling loop so the
        // watchdog consumes no CPU while the parent is running.
        let source = DispatchSource.makeProcessSource(
            identifier: pid_t(parentPID),
            eventMask: .exit,
            queue: .main
        )

        source.setEventHandler {
            source.cancel()
            performCleanup(parentPID: parentPID)
            exit(0)
        }

        source.resume()

        // Handle the race where the parent exited (or the session was already
        // cleaned up) before the DispatchSource was armed.
        DispatchQueue.main.async {
            if !processExists(parentPID) || SessionState.load() == nil {
                source.cancel()
                performCleanup(parentPID: parentPID)
                exit(0)
            }
        }

        dispatchMain()
    }

    private static func performCleanup(parentPID: Int32) {
        guard let session = SessionState.load() else {
            return
        }

        guard session.pid == parentPID else {
            EventLog.append(note: "Cleanup watchdog ignored session state for unexpected PID \(session.pid).",
                            phase: .failed)
            return
        }

        do {
            let configuration = try AppConfig.load(explicitConfigPath: session.configFilePath)
            if session.cleanupNeeded {
                let cleanupHealthy = try RouteManager(configuration: configuration.splitTunnel).cleanup(using: session)
                if !cleanupHealthy {
                    var recoveryState = session
                    recoveryState.markRecoveryRequired(message: "Cleanup watchdog ran, but the network still looks unhealthy.")
                    try? recoveryState.save()
                    EventLog.append(note: "Cleanup watchdog restored state, but the network still looked unhealthy.",
                                    phase: .failed)
                    UserAlert.showCritical(message: "\(AppIdentity.bundleName) restored your pre-connection configuration, but the network still looks unhealthy. If traffic does not recover, toggle Wi-Fi.")
                    return
                }
            }
            SessionState.remove()
            EventLog.append(note: "Cleanup watchdog restored pre-connection configuration after unexpected process exit.",
                            phase: .disconnected)
        } catch {
            var recoveryState = session
            recoveryState.markRecoveryRequired(message: "Cleanup watchdog failed: \(error.localizedDescription)")
            try? recoveryState.save()
            EventLog.append(note: "Cleanup watchdog failed: \(error.localizedDescription)",
                            phase: .failed)
            UserAlert.showCritical(message: "\(AppIdentity.bundleName) cleanup watchdog failed. Your network may require manual recovery.")
        }
    }
}
