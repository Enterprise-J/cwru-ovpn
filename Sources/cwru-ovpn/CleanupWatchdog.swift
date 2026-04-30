import Foundation

enum CleanupWatchdog {
    static func run(parentPID: Int32, parentStartTime: ProcessStartTime?) {
        let source = DispatchSource.makeProcessSource(
            identifier: pid_t(parentPID),
            eventMask: .exit,
            queue: .main
        )

        source.setEventHandler {
            source.cancel()
            performCleanup(parentPID: parentPID, parentStartTime: parentStartTime)
            exit(0)
        }

        source.resume()

        DispatchQueue.main.async {
            if !processExists(parentPID, expectedStartTime: parentStartTime) || SessionState.load() == nil {
                source.cancel()
                performCleanup(parentPID: parentPID, parentStartTime: parentStartTime)
                exit(0)
            }
        }

        dispatchMain()
    }

    static func performCleanup(parentPID: Int32, parentStartTime: ProcessStartTime?) {
        guard let session = SessionState.load() else {
            return
        }
        let cleanupConfig = try? AppConfig.load(explicitConfigPath: session.configFilePath)
        EventLog.configure(privacyMode: cleanupConfig?.privacyMode ?? false)

        guard session.pid == parentPID,
              parentStartTime == nil || session.processStartTime == parentStartTime else {
            EventLog.append(note: "Cleanup watchdog ignored session state for unexpected PID \(session.pid).",
                            phase: .failed)
            return
        }

        do {
            if session.cleanupNeeded {
                try VPNController.validateSessionForPrivilegedCleanup(session)
                let cleanupHealthy = try VPNController.cleanupRouteManager(for: session).cleanup(using: session)
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
