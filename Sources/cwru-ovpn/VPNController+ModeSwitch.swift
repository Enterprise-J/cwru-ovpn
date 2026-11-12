import Foundation

extension VPNController {
    func handlePendingModeSwitch(trigger: String) {
        guard !cleanupComplete, !requestedStop else {
            return
        }

        do {
            try applyPendingModeSwitchIfNeeded(trigger: trigger)
        } catch {
            emit("Mode switch failed: \(error.localizedDescription)", level: .error)
            EventLog.append(note: "Mode switch failed: \(error.localizedDescription)", phase: sessionState.phase)
        }
    }

    func applyPendingModeSwitchIfNeeded(trigger: String) throws {
        guard sessionState.phase == .connected,
              let persistedState = SessionState.load(),
              persistedState.pid == sessionState.pid,
              persistedState.executablePath == sessionState.executablePath,
              persistedState.processStartTime == sessionState.processStartTime else {
            return
        }

        sessionState = Self.sessionStateForSave(
            currentState: sessionState,
            persistedState: persistedState
        )
        if let requestedMode = sessionState.requestedTunnelMode {
            try applyModeSwitch(to: requestedMode, trigger: trigger)
        }
    }

    private func applyModeSwitch(to requestedMode: AppTunnelMode,
                                 trigger: String) throws {
        guard sessionState.phase == .connected else {
            return
        }

        if requestedMode == tunnelMode {
            sessionState.requestedTunnelMode = nil
            if sessionState.lastEvent == "MODE_SWITCH_DEFERRED" {
                sessionState.lastEvent = nil
                sessionState.lastInfo = nil
            }
            try saveState(consumingModeRequest: requestedMode)
            continuePendingModeSwitchIfNeeded()
            updateMenuBar()
            return
        }

        if let tunnelName = sessionState.tunnelName,
           !routeManager.tunnelInterfaceIsPresent(named: tunnelName) {
            try deferModeSwitch(to: requestedMode,
                                reason: "tunnel interface \(tunnelName) is unavailable",
                                trigger: trigger)
            return
        }
        emit("Switching to \(requestedMode.modeDescription) mode.")
        EventLog.append(note: "Applying in-place mode switch to \(requestedMode.modeDescription) (trigger: \(trigger)).",
                        phase: sessionState.phase)

        let previousMode = tunnelMode
        routeHealthCheckGeneration += 1
        routeHealthCheckDeadline = nil
        invalidateReachabilityProbe()

        var updatedState: SessionState
        do {
            let migration = try migratePhysicalNetworkStateIfNeeded(
                reason: "mode switch to \(requestedMode.modeDescription)",
                rescheduleIfSettling: true
            )
            if case .deferred = migration {
                try deferModeSwitch(to: requestedMode,
                                    reason: "the physical network is still settling",
                                    trigger: trigger)
                return
            }
            updatedState = sessionState
            updatedState.requestedTunnelMode = requestedMode

            switch requestedMode {
            case .split:
                try routeManager.applySplitTunnel(
                    using: &updatedState,
                    persistPreparedState: persistPreparedNetworkState
                )
            case .full:
                try routeManager.switchToFullTunnel(
                    using: &updatedState,
                    persistPreparedState: persistPreparedNetworkState
                )
            }
        } catch {
            let modeSwitchError = error
            var rollbackState = sessionState
            rollbackState.requestedTunnelMode = nil
            rollbackState.lastEvent = "MODE_SWITCH_FAILED"
            rollbackState.lastInfo = "Mode switch to \(requestedMode.modeDescription) failed: \(modeSwitchError.localizedDescription)"

            var rollbackError: Error?
            do {
                sessionState = rollbackState
                try saveState(consumingModeRequest: requestedMode)
                rollbackState = sessionState
                if previousMode == .split {
                    try routeManager.applySplitTunnel(
                        using: &rollbackState,
                        persistPreparedState: persistPreparedNetworkState
                    )
                    try routeManager.restorePhysicalIPv6Configuration(using: rollbackState)
                } else {
                    try routeManager.switchToFullTunnel(
                        using: &rollbackState,
                        persistPreparedState: persistPreparedNetworkState
                    )
                }
                rollbackState.tunnelMode = previousMode
                sessionState = rollbackState
                tunnelMode = previousMode
                try saveState(consumingModeRequest: previousMode)
            } catch {
                rollbackError = error
            }

            if let rollbackError {
                let detail = "Mode switch failed and restoring \(previousMode.modeDescription) mode also failed. Disconnecting to avoid an unknown network state. Switch error: \(modeSwitchError.localizedDescription). Rollback error: \(rollbackError.localizedDescription)"
                rollbackState.lastEvent = "MODE_SWITCH_ROLLBACK_FAILED"
                rollbackState.lastInfo = detail
                sessionState = rollbackState
                tunnelMode = previousMode
                saveStatusState()
                updateMenuBar()
                EventLog.append(note: detail, phase: sessionState.phase)
                requestStop(reason: "mode switch rollback failed", failed: true)
                throw VPNControllerError.modeSwitchRollbackFailed(detail)
            }

            updateMenuBar()
            scheduleRouteHealthCheck(reason: "mode switch rollback")
            continuePendingModeSwitchIfNeeded()
            throw modeSwitchError
        }

        tunnelMode = requestedMode
        updatedState.tunnelMode = requestedMode
        updatedState.requestedTunnelMode = nil
        updatedState.lastEvent = "MODE_SWITCHED"
        updatedState.lastInfo = nil
        sessionState = updatedState

        try startRouteMonitorIfNeeded()
        if requestedMode == .split {
            scheduleReachabilityProbeIfNeeded(reason: "mode switch")
        } else {
            invalidateReachabilityProbe()
        }

        try saveState(consumingModeRequest: requestedMode)
        continuePendingModeSwitchIfNeeded()
        updateMenuBar()

        EventLog.append(note: "Mode switched to \(requestedMode.modeDescription).",
                        phase: sessionState.phase)
        emit("Mode switched to \(requestedMode.modeDescription) mode.")
    }

    private func deferModeSwitch(to requestedMode: AppTunnelMode, reason: String, trigger: String) throws {
        let message = "Mode switch to \(requestedMode.modeDescription) deferred while the VPN reconnects; it will apply automatically once the connection recovers."
        sessionState.requestedTunnelMode = requestedMode
        sessionState.lastEvent = "MODE_SWITCH_DEFERRED"
        sessionState.lastInfo = message
        try saveState()
        updateMenuBar()
        EventLog.append(note: "Deferred mode switch to \(requestedMode.modeDescription) because \(reason) (trigger: \(trigger)).",
                        phase: sessionState.phase)
        emit(message)
    }

    private func continuePendingModeSwitchIfNeeded() {
        guard sessionState.requestedTunnelMode != nil else {
            return
        }
        DispatchQueue.main.async { [weak self] in
            self?.handlePendingModeSwitch(trigger: "pending request")
        }
    }

    func requestMenuBarModeSwitch() {
        guard !cleanupComplete, !requestedStop else {
            return
        }

        let targetMode = tunnelMode == .split ? AppTunnelMode.full : .split

        switch sessionState.phase {
        case .connected:
            do {
                sessionState = try SessionControl.updateActiveSessionRequest(expectedSession: sessionState) {
                    $0.requestingModeSwitch(to: targetMode)
                }
                try applyPendingModeSwitchIfNeeded(trigger: "menu bar")
            } catch {
                emit("Mode switch failed: \(error.localizedDescription)", level: .error)
                EventLog.append(note: "Mode switch failed: \(error.localizedDescription)", phase: sessionState.phase)
            }

        case .connecting, .authPending:
            do {
                sessionState = try SessionControl.updateActiveSessionRequest(expectedSession: sessionState) {
                    $0.requestingModeSwitch(to: targetMode)
                }
                updateMenuBar()
                emit("Queued \(targetMode.modeDescription) mode switch for after connection.")
                EventLog.append(note: "Queued mode switch to \(targetMode.modeDescription) from the menu bar.",
                                phase: sessionState.phase)
            } catch {
                emit("Could not queue mode switch: \(error.localizedDescription)", level: .error)
                EventLog.append(note: "Could not queue mode switch: \(error.localizedDescription)",
                                phase: sessionState.phase)
            }

        case .disconnecting, .disconnected, .failed:
            break
        }
    }
}
