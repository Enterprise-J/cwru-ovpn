import Darwin
import Foundation

extension VPNController {
    func startUserInterface() throws {
        guard try ExecutionIdentity.validatedSudoUserIfAvailable()?.userID != nil else { return }
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
            throw FileIO.failure("Could not create the private interface channel", errno)
        }
        defer { close(pair[1]) }
        userInterface = try InterfaceChannel(owning: pair[0], onMessage: { [weak self] action in
            guard let self, !self.isStopRequested, !self.isCleanupComplete else { return }
            switch action {
            case .retry: self.retryWebAuthentication()
            case .disconnect: self.requestStop(reason: "menu bar disconnect")
            case .switchMode: self.requestMenuBarModeSwitch()
            case .cancelled(let generation) where generation == self.webAuth.presentationGeneration:
                self.failSession(event: "AUTH_CANCELLED", message: "Sign-in was cancelled.")
            case .authenticationFailed(let generation) where generation == self.webAuth.presentationGeneration:
                self.failSession(event: "AUTH_SESSION_FAILED", message: "The sign-in session failed.")
            default: break
            }
        }, onClose: { [weak self] in
            guard let self, !self.isCleanupComplete, !self.isStopRequested else { return }
            self.failSession(event: "UI_EXITED", message: "The VPN menu and sign-in process exited.")
        })
        _ = try ChildProcess.launch(arguments: ["ui-agent"], input: pair[1])
    }

    func updateMenuBar() {
        let snapshot = MenuBarSnapshot(phase: sessionState.phase,
                                       canRetrySignIn: canRetryWebAuthentication,
                                       tunnelMode: tunnelMode,
                                       requestedTunnelMode: sessionState.requestedTunnelMode,
                                       transportDegraded: SessionPresentation.transportStatusTitle(for: sessionState) != nil,
                                       statusText: SessionPresentation.statusTitle(for: sessionState, stale: false, recoveryNeeded: false),
                                       gatewayText: menuBarGatewayText(),
                                       estimatedSessionText: menuBarEstimatedSessionText())
        if snapshot != lastMenuSnapshot {
            lastMenuSnapshot = snapshot
            userInterface?.send(.status(snapshot), replacingQueuedStatus: true)
        }
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
              !isCleanupComplete,
              let remaining = SessionPresentation.estimatedSessionCountdownRemaining(for: sessionState),
              remaining > 0 else {
            menuBarRefreshTimer?.invalidate()
            menuBarRefreshTimer = nil
            return
        }

        guard menuBarRefreshTimer == nil else {
            return
        }

        let secondsUntilTextChanges = (remaining + 1).truncatingRemainder(dividingBy: 60)
        let timer = Timer(fireAt: Date(timeIntervalSinceNow: secondsUntilTextChanges > 0 ? secondsUntilTextChanges : 60),
                          interval: 60,
                          target: self,
                          selector: #selector(handleMenuBarRefreshTimer(_:)),
                          userInfo: nil,
                          repeats: true)
        timer.tolerance = 1
        RunLoop.main.add(timer, forMode: .common)
        menuBarRefreshTimer = timer
    }

    @objc private func handleMenuBarRefreshTimer(_: Timer) {
        updateMenuBar()
    }

    private func showEstimatedSessionCountdownAlertIfNeeded() {
        let remaining = SessionPresentation.estimatedSessionCountdownRemaining(for: sessionState)
        guard Self.shouldShowEstimatedSessionCountdownAlert(
            phase: sessionState.phase,
            isStopRequested: isStopRequested,
            isCleanupComplete: isCleanupComplete,
            isSystemAsleep: isSystemAsleep,
            isDisconnectingAfterWake: isDisconnectingAfterWake,
            alertShown: hasShownSessionCountdownAlert,
            remaining: remaining
        ) else {
            return
        }

        hasShownSessionCountdownAlert = true
        EventLog.append(note: "Estimated session countdown reached zero.", phase: sessionState.phase)
        UserAlert.present("The estimated session time has elapsed. The server may end the connection soon.")
    }
}
