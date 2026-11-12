import AppKit
import Foundation

extension VPNController {
    func installMenuBarIfNeeded() {
        guard menuBarController == nil else {
            return
        }

        let controller = MenuBarController()
        controller.onRetrySignIn = { [weak self] in
            Task { @MainActor in
                self?.retryWebAuthentication()
            }
        }
        controller.onSwitchMode = { [weak self] in
            Task { @MainActor in
                self?.requestMenuBarModeSwitch()
            }
        }
        controller.onDisconnect = { [weak self] in
            Task { @MainActor in
                self?.requestStop(reason: "menu bar disconnect")
            }
        }
        menuBarController = controller
    }

    func updateMenuBar() {
        menuBarController?.update(with: MenuBarSnapshot(phase: sessionState.phase,
                                                        canRetrySignIn: canRetryWebAuthentication,
                                                        tunnelMode: tunnelMode,
                                                        requestedTunnelMode: sessionState.requestedTunnelMode,
                                                        transportDegraded: SessionPresentation.transportStatusTitle(for: sessionState) != nil,
                                                        statusText: SessionPresentation.statusTitle(for: sessionState,
                                                                                                    stale: false,
                                                                                                    recoveryNeeded: false),
                                                        gatewayText: menuBarGatewayText(),
                                                        estimatedSessionText: menuBarEstimatedSessionText()))
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
              !cleanupComplete,
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
            requestedStop: requestedStop,
            cleanupComplete: cleanupComplete,
            systemAsleep: systemAsleep,
            disconnectingAfterWake: disconnectingAfterWake,
            alertShown: estimatedSessionCountdownAlertShown,
            remaining: remaining
        ) else {
            return
        }

        estimatedSessionCountdownAlertShown = true
        EventLog.append(note: "Estimated session countdown reached zero.", phase: sessionState.phase)
        UserAlert.present("Estimated VPN session countdown reached zero. The server may expire this session soon; reconnect if you need to avoid an unexpected disconnect.")
    }
}
