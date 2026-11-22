import Foundation

extension VPNController {
    func handlePendingModeSwitch(trigger: String) {
        guard !isCleanupComplete, !isStopRequested else {
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
        guard sessionState.transportHealth != .reconnecting, sessionState.transportHealth != .hostPathDegraded,
              sessionState.phase == .connected,
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
        guard let request = sessionState.modeRequest else { return }
        sessionState = try SessionControl.updateActiveSessionRequest(expectedSession: sessionState) { current in
            var updated = current
            _ = updated.claim(request)
            return updated
        }
        if sessionState.applyingModeRequest?.id == request.id { try applyModeSwitch(request, trigger: trigger) }
    }

    private func applyModeSwitch(_ request: ModeRequest,
                                 trigger: String) throws {
        guard sessionState.transportHealth != .reconnecting, sessionState.transportHealth != .hostPathDegraded,
              sessionState.phase == .connected else {
            return
        }

        let requestedMode = request.mode
        if requestedMode == tunnelMode {
            if sessionState.lastEventName == "MODE_SWITCH_DEFERRED" {
                sessionState.lastEventName = nil
                sessionState.diagnosticDetail = nil
            }
            try saveState(finishing: request)
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
        routeMonitor.generation += 1
        routeMonitor.deadline = nil
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
            rollbackState.lastEventName = "MODE_SWITCH_FAILED"
            rollbackState.diagnosticDetail = "Mode switch to \(requestedMode.modeDescription) failed: \(modeSwitchError.localizedDescription)"

            var rollbackError: Error?
            do {
                sessionState = rollbackState
                try saveState()
                rollbackState = sessionState
                if previousMode == .split {
                    try routeManager.applySplitTunnel(
                        using: &rollbackState,
                        persistPreparedState: persistPreparedNetworkState
                    )
                } else {
                    try routeManager.switchToFullTunnel(
                        using: &rollbackState,
                        persistPreparedState: persistPreparedNetworkState
                    )
                }
                rollbackState.tunnelMode = previousMode
                sessionState = rollbackState
                tunnelMode = previousMode
                try saveState(finishing: request, outcome: .rolledBack, detail: rollbackState.diagnosticDetail)
            } catch {
                rollbackError = error
            }

            if let rollbackError {
                rollbackState = sessionState
                let detail = "Mode switch failed, and restoring \(previousMode.modeDescription) mode also failed. Disconnecting to avoid inconsistent routing or DNS. Switch error: \(modeSwitchError.localizedDescription). Restore error: \(rollbackError.localizedDescription)"
                rollbackState.lastEventName = "MODE_SWITCH_ROLLBACK_FAILED"
                rollbackState.diagnosticDetail = detail
                sessionState = rollbackState
                tunnelMode = previousMode
                try saveState(finishing: request, outcome: .recoveryRequired, detail: detail)
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
        updatedState.lastEventName = "MODE_SWITCHED"
        updatedState.diagnosticDetail = nil
        sessionState = updatedState

        try startRouteMonitorIfNeeded()
        if requestedMode == .split {
            scheduleReachabilityProbeIfNeeded(reason: "mode switch")
        } else {
            invalidateReachabilityProbe()
        }

        try saveState(finishing: request)
        continuePendingModeSwitchIfNeeded()
        updateMenuBar()

        EventLog.append(note: "Mode switched to \(requestedMode.modeDescription).",
                        phase: sessionState.phase)
        emit("Switched to \(requestedMode.modeDescription) mode.")
    }

    private func deferModeSwitch(to requestedMode: AppTunnelMode, reason: String, trigger: String) throws {
        let message = "Mode switch to \(requestedMode.modeDescription) is queued while the VPN reconnects and will apply automatically once the connection recovers."
        sessionState = try SessionControl.updateActiveSessionRequest(expectedSession: sessionState) { current in
            var updated = current
            guard var request = current.applyingModeRequest else { return current }
            if current.modeRequest == nil {
                request.deferral = message
                updated.modeRequest = request
                updated.applyingModeRequest = nil
            } else { updated.finish(request, outcome: .superseded) }
            return updated
        }
        sessionState.lastEventName = "MODE_SWITCH_DEFERRED"
        sessionState.diagnosticDetail = message
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
        guard !isCleanupComplete, !isStopRequested else {
            return
        }

        let targetMode = (sessionState.requestedTunnelMode ?? tunnelMode) == .split ? AppTunnelMode.full : .split

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
                emit("Queued \(targetMode.modeDescription) mode switch until the VPN connects.")
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
