import COpenVPN3Wrapper
import Foundation

extension VPNController {
    func prepareTransportEndpoint(_ info: String) {
        let fields = info.split(separator: " ", omittingEmptySubsequences: false)
        guard let client,
              !requestedStop, !cleanupComplete,
              fields.count == 2, let requestID = UInt64(fields[0]),
              NetworkValidation.isValidIPv4Address(String(fields[1])),
              cwru_ovpn_client_transport_endpoint_pending(client, requestID) else {
            return
        }
        var allowed = false
        defer { _ = cwru_ovpn_client_complete_transport_endpoint(client, requestID, allowed) }
        do {
            let migration: PhysicalNetworkMigrationOutcome
            if sessionState.phase == .connected {
                migration = try repairPhysicalNetworkChangeIfNeeded(reason: "transport endpoint preparation",
                                                                    reconnectTransport: false)
            } else {
                migration = try migratePhysicalNetworkStateIfNeeded(reason: "transport endpoint preparation",
                                                                    rescheduleIfSettling: false)
            }
            if case .deferred = migration { return }
            guard cwru_ovpn_client_transport_endpoint_pending(client, requestID) else { return }
            var prepared = sessionState
            try routeManager.prepareTransportEndpoint(String(fields[1]), using: &prepared,
                                                      persistPreparedState: persistPreparedNetworkState)
            sessionState = prepared
            try saveState()
            allowed = true
            EventLog.append(note: "Prepared VPN transport endpoint \(fields[1]) via \(prepared.physicalInterface).",
                            phase: sessionState.phase)
        } catch {
            EventLog.append(note: "Could not prepare VPN transport endpoint \(fields[1]): \(error.localizedDescription)",
                            phase: sessionState.phase)
            scheduleRouteHealthCheck(reason: "transport endpoint preparation failed")
        }
    }

    func handleLocalTransportFailure() {
        guard sessionState.phase == .connected,
              !requestedStop,
              !cleanupComplete else {
            return
        }

        let decision = Self.evaluateLocalTransportFailure(
            window: LocalTransportFailureWindow(startedAt: localTransportFailureWindowStartedAt,
                                                count: localTransportFailureCount),
            now: Date(),
            systemAsleep: systemAsleep
        )
        localTransportFailureWindowStartedAt = decision.window.startedAt
        localTransportFailureCount = decision.window.count

        switch decision.action {
        case .none:
            break
        case .reconnect:
            markTransportDegraded(.reconnecting,
                                  detail: "The VPN transport path is unavailable and OpenVPN is reconnecting.")
            requestOpenVPNTransportReconnect(reason: "local transport failures")
        case .restart:
            scheduleManagedReconnect(reason: "persistent local transport failures")
        }
    }

    func requestOpenVPNTransportReconnect(reason: String) {
        guard let client,
              sessionState.phase == .connected,
              managedReconnectRequest == nil,
              !requestedStop,
              !cleanupComplete else {
            return
        }

        let now = Date()
        if let lastOpenVPNTransportReconnectAt,
           now.timeIntervalSince(lastOpenVPNTransportReconnectAt) < Self.openVPNTransportReconnectThrottleSeconds {
            return
        }

        lastOpenVPNTransportReconnectAt = now
        EventLog.append(note: "Requesting OpenVPN reconnect after \(reason).", phase: sessionState.phase)
        cwru_ovpn_client_reconnect(client, 1)
        scheduleRouteHealthCheck(reason: "OpenVPN reconnect requested after \(reason)")
    }

    private func resetLocalTransportFailureTracking() {
        localTransportFailureWindowStartedAt = nil
        localTransportFailureCount = 0
        lastOpenVPNTransportReconnectAt = nil
        fullTunnelControlChannelSettleCount = 0
    }

    func markTransportDegraded(_ state: TransportRecoveryState, detail: String) {
        guard sessionState.phase == .connected,
              !requestedStop,
              !cleanupComplete else {
            return
        }

        stableTransportGeneration += 1
        let firstFailure = transportDegradedAt == nil
        if firstFailure {
            transportDegradedAt = Date()
        }
        if transportRecoveryState != .reconnecting || state == .reconnecting {
            transportRecoveryState = state
        }

        if state == .hostPathDegraded,
           Self.reachabilityDegradationStateNeedsUpdate(lastEvent: sessionState.lastEvent,
                                                        lastInfo: sessionState.lastInfo,
                                                        detail: detail) {
            sessionState.lastEvent = "DATA_PATH_DEGRADED"
            sessionState.lastInfo = detail
            saveStatusState()
        }

        if firstFailure {
            EventLog.append(note: detail, phase: sessionState.phase)
            armTransportRecoveryDeadline()
        }
        updateMenuBar()
    }

    func markTransportRecoveredAfterConnectedEvent() {
        let wasDegraded = transportDegradedAt != nil
        if wasDegraded {
            var recoveryState = transportRecoveryState ?? .reconnecting
            let startedStabilizing = recoveryState.beginStabilizing()
            transportRecoveryState = recoveryState
            sessionState.lastEvent = "TRANSPORT_RECOVERY_STABILIZING"
            sessionState.lastInfo = "OpenVPN reconnected; verifying that the transport path remains stable."
            saveStatusState()
            if startedStabilizing {
                EventLog.append(note: "OpenVPN reconnected; waiting for a stable recovery interval before clearing the outage deadline.",
                                phase: sessionState.phase)
                armStableTransportReset()
            }
            updateMenuBar()
            return
        }
        armStableTransportReset()
        updateMenuBar()
    }

    private func markReachabilityRecoveredIfNeeded() {
        guard transportRecoveryState == .hostPathDegraded else {
            return
        }
        transportRecoveryState = .stabilizing
        sessionState.lastEvent = "TRANSPORT_RECOVERY_STABILIZING"
        sessionState.lastInfo = "The split-tunnel host path recovered; verifying that it remains stable."
        saveStatusState()
        EventLog.append(note: "The split-tunnel host path recovered; waiting for a stable interval before clearing the outage deadline.",
                        phase: sessionState.phase)
        armStableTransportReset()
        updateMenuBar()
    }

    private func armTransportRecoveryDeadline() {
        guard let degradedAt = transportDegradedAt else {
            return
        }
        transportRecoveryDeadlineGeneration += 1
        let generation = transportRecoveryDeadlineGeneration
        let delay = Self.transportRecoveryDeadlineDelay(degradedAt: degradedAt, now: Date())
        scheduleDeadline(.transportRecovery, after: delay) { [weak self] in
            guard let self,
                  self.transportRecoveryDeadlineGeneration == generation,
                  self.transportDegradedAt == degradedAt,
                  Self.shouldEnforceTransportRecoveryDeadline(degradedAt: self.transportDegradedAt,
                                                              phase: self.sessionState.phase,
                                                              requestedStop: self.requestedStop,
                                                              cleanupComplete: self.cleanupComplete) else {
                return
            }
            let message = "VPN recovery did not complete within 10 minutes. Disconnecting to restore normal system networking; reconnect when the network is stable."
            self.sessionState.lastEvent = "TRANSPORT_RECOVERY_TIMED_OUT"
            self.sessionState.lastInfo = message
            self.pendingDisconnectAlertMessage = self.pendingDisconnectAlertMessage ?? message
            self.saveStatusState()
            self.updateMenuBar()
            EventLog.append(note: message, phase: self.sessionState.phase)
            self.requestStop(reason: "transport recovery deadline expired", failed: true)
        }
    }

    private func armStableTransportReset() {
        stableTransportGeneration += 1
        let generation = stableTransportGeneration
        let degradedAt = transportDegradedAt
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.stableTransportResetSeconds) { [weak self] in
            guard let self,
                  self.stableTransportGeneration == generation,
                  self.transportDegradedAt == degradedAt,
                  self.sessionState.phase == .connected,
                  !self.requestedStop,
                  !self.cleanupComplete else {
                return
            }
            if degradedAt != nil {
                guard self.transportRecoveryState == .stabilizing else {
                    return
                }
                self.transportDegradedAt = nil
                self.transportRecoveryState = nil
                self.transportRecoveryDeadlineGeneration += 1
                self.sessionState.lastEvent = "CONNECTED"
                self.sessionState.lastInfo = nil
                self.saveStatusState()
                EventLog.append(note: "VPN transport remained stable and the outage deadline was cleared.",
                                phase: self.sessionState.phase)
                self.updateMenuBar()
            }
            self.resetLocalTransportFailureTracking()
            do {
                try ManagedReconnectBudget.reset()
            } catch {
                EventLog.append(note: "Could not reset the managed reconnect budget after a stable connection: \(error.localizedDescription)",
                                phase: self.sessionState.phase)
            }
        }
    }

    private func scheduleManagedReconnect(reason: String) {
        guard sessionState.phase == .connected,
              managedReconnectRequest == nil,
              !requestedStop,
              !cleanupComplete else {
            return
        }

        guard backgroundChild else {
            let message = "VPN transport recovery failed. Disconnecting to restore normal system networking; reconnect when the network is stable."
            pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? message
            requestStop(reason: "persistent transport failure", failed: true)
            return
        }

        let budgetAvailable: Bool
        do {
            budgetAvailable = try ManagedReconnectBudget.reserveAttempt()
        } catch {
            let message = "Automatic VPN recovery could not safely reserve its retry budget. Disconnecting to avoid a reconnect loop."
            pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? message
            EventLog.append(note: "Managed reconnect budget failed closed: \(error.localizedDescription)",
                            phase: sessionState.phase)
            requestStop(reason: "managed reconnect budget unavailable", failed: true)
            return
        }
        guard budgetAvailable else {
            let message = "VPN recovery failed repeatedly. Automatic reconnect stopped to restore normal system networking; reconnect manually when the network is stable."
            pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? message
            EventLog.append(note: "Managed reconnect budget exhausted.", phase: sessionState.phase)
            requestStop(reason: "managed reconnect budget exhausted", failed: true)
            return
        }

        let reconnectTunnelMode = Self.managedReconnectTunnelMode(persistedState: SessionState.load(),
                                                                  controllerPID: sessionState.pid,
                                                                  controllerExecutablePath: sessionState.executablePath,
                                                                  controllerStartTime: sessionState.processStartTime,
                                                                  currentMode: tunnelMode)
        let request = ManagedReconnectRequest(configFilePath: configFilePath,
                                              tunnelMode: reconnectTunnelMode,
                                              reason: reason)
        EventLog.append(note: "Scheduling managed reconnect after \(reason).", phase: sessionState.phase)
        requestStop(reason: "managed reconnect after \(reason)", reconnect: request)
    }

    func scheduleReachabilityProbeIfNeeded(reason: String, afterRepair: Bool = false) {
        guard tunnelMode == .split,
              sessionState.phase == .connected,
              !reachabilityProbeInFlight else {
            return
        }

        reachabilityProbeInFlight = true
        reachabilityProbeGeneration += 1
        let generation = reachabilityProbeGeneration
        let hosts = SplitTunnelPolicy.fixedHealthCheckHosts
        let queue = reachabilityProbeQueue
        queue.async { [weak self] in
            let result = ReachabilityProbe.run(hosts: hosts)
            Task { @MainActor [weak self] in
                self?.handleReachabilityProbeResult(result,
                                                    reason: reason,
                                                    afterRepair: afterRepair,
                                                    generation: generation)
            }
        }
    }

    private func handleReachabilityProbeResult(_ result: ReachabilityProbeResult,
                                               reason: String,
                                               afterRepair: Bool,
                                               generation: Int) {
        guard Self.completeReachabilityProbe(payloadGeneration: generation,
                                             currentGeneration: reachabilityProbeGeneration,
                                             tunnelMode: tunnelMode,
                                             phase: sessionState.phase,
                                             inFlight: &reachabilityProbeInFlight) else {
            return
        }

        if let reachableHost = result.reachableHost {
            if !lastReachabilityProbeHealthy {
                EventLog.append(note: "CWRU data-path check recovered via \(reachableHost).",
                                phase: sessionState.phase)
            }
            lastReachabilityProbeHealthy = true
            lastReachabilityAlertAt = nil
            markReachabilityRecoveredIfNeeded()
            return
        }

        let hostList = result.checkedHosts.joined(separator: ", ")
        if lastReachabilityProbeHealthy {
            EventLog.append(note: "CWRU data-path check failed after \(reason). Checked: \(hostList)",
                            phase: sessionState.phase)
        }
        lastReachabilityProbeHealthy = false

        guard afterRepair else {
            restorePhysicalDNSAfterFailedProbe()
            scheduleReachabilityProbeIfNeeded(reason: "health check repair", afterRepair: true)
            return
        }

        markTransportDegraded(.hostPathDegraded,
                              detail: "The CWRU split-tunnel data path remains unavailable after route and DNS checks.")
        scheduleReachabilityRetry()
        let now = Date()
        if let lastReachabilityAlertAt,
           now.timeIntervalSince(lastReachabilityAlertAt) < Self.reachabilityFailureSurfaceThrottleSeconds {
            return
        }
        lastReachabilityAlertAt = now
        emit("CWRU data-path check failed for both fixed CWRU DNS endpoints. Reconnect after the network stabilizes.",
             level: .error)
    }

    func invalidateReachabilityProbe() {
        reachabilityProbeGeneration += 1
        reachabilityProbeInFlight = false
    }

    private func scheduleReachabilityRetry() {
        let generation = reachabilityProbeGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.reachabilityRetrySeconds) { [weak self] in
            guard let self,
                  self.reachabilityProbeGeneration == generation,
                  self.transportRecoveryState == .hostPathDegraded,
                  self.tunnelMode == .split,
                  self.sessionState.phase == .connected,
                  !self.requestedStop,
                  !self.cleanupComplete else {
                return
            }
            self.scheduleReachabilityProbeIfNeeded(reason: "degraded host path retry")
        }
    }

    private func restorePhysicalDNSAfterFailedProbe() {
        guard tunnelMode == .split,
              !requestedStop,
              (sessionState.phase == .authPending || sessionState.phase == .connected) else {
            return
        }

        do {
            let changed = try routeManager.restorePhysicalDNSConfigurationIfNeeded(using: sessionState)
            guard changed else {
                return
            }
            try routeManager.flushDNS()
            EventLog.append(note: "Repaired split-tunnel DNS state after a health check failure.",
                            phase: sessionState.phase)
        } catch {
            if Self.splitDNSRepairFailureRequiresFlush(error) {
                do {
                    try routeManager.flushDNS()
                } catch {
                    EventLog.append(note: "Could not flush DNS after a partial split-tunnel DNS repair: \(error.localizedDescription)",
                                    phase: sessionState.phase)
                }
            }
            EventLog.append(note: "Could not repair split-tunnel DNS state after a health check failure: \(error.localizedDescription)",
                            phase: sessionState.phase)
        }
    }

    func spawnManagedReconnect(_ request: ManagedReconnectRequest) {
        var arguments = ["connect"]
        if let configFilePath = request.configFilePath {
            arguments += ["--config", configFilePath]
        }
        arguments += ["--mode", request.tunnelMode.rawValue, "--background-child"]
        do {
            _ = try ChildProcess.launch(arguments: arguments)
            EventLog.append(note: "Started managed reconnect after \(request.reason).",
                            phase: .connecting)
        } catch {
            EventLog.append(note: "Failed to start managed reconnect after \(request.reason): \(error.localizedDescription)",
                            phase: .failed)
            UserAlert.present("Reconnect after \(request.reason) failed to start.")
        }
    }
}
