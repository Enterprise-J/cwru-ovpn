import COpenVPN3Wrapper
import Foundation

extension VPNController {
    func prepareTransportEndpoint(_ info: String) {
        let fields = info.split(separator: " ", omittingEmptySubsequences: false)
        guard let client,
              !isStopRequested, !isCleanupComplete,
              fields.count == 2, let requestID = UInt64(fields[0]),
              NetworkValidation.isValidIPv4Address(String(fields[1])),
              cwru_ovpn_client_transport_endpoint_pending(client, requestID) else {
            return
        }
        let endpoint = PendingTransportEndpoint(address: String(fields[1]), clientGeneration: vpnEventGeneration, requestID: requestID)
        var accepted = false
        defer {
            if !accepted {
                _ = cwru_ovpn_client_complete_transport_endpoint(client, requestID, false)
                if sessionState.pendingTransportEndpoint == endpoint {
                    do {
                        var state = sessionState
                        state.pendingTransportEndpoint = nil
                        let mode = state.tunnelMode
                        try routeManager.ensureRemoteHostRoutes(using: &state, mode: mode,
                                                                context: "cancelled endpoint", persistPreparedState: persistPreparedNetworkState)
                        try persistPreparedNetworkState(state)
                        if mode == .full, endpoint.address != state.connectedServerAddress,
                           (state.replacedRemoteIPv4Routes ?? []).contains(where: {
                               IPRoute.canonicalIPv4($0.destination)?.addressString == endpoint.address
                           }) {
                            failSession(event: "TRANSPORT_PROTECTION_FAILED", message: "The cancelled endpoint displaced an existing host route. Restoring its original next hop.")
                        }
                    } catch {
                        failSession(event: "TRANSPORT_PROTECTION_FAILED", message: error.localizedDescription)
                    }
                }
            }
        }
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
            try routeManager.prepareTransportEndpoint(endpoint, using: &prepared,
                                                      persistPreparedState: persistPreparedNetworkState)
            sessionState = prepared
            try saveState()
            accepted = cwru_ovpn_client_complete_transport_endpoint(client, requestID, true)
            guard accepted else { return }
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
              !isStopRequested,
              !isCleanupComplete else {
            return
        }

        let decision = Self.evaluateLocalTransportFailure(
            window: transport.localFailures,
            now: .now,
            isSystemAsleep: isSystemAsleep
        )
        transport.localFailures = decision.window

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
              transport.managedReconnect == nil,
              !isStopRequested,
              !isCleanupComplete else {
            return
        }

        let now = ContinuousClock.now
        if let lastReconnect = transport.lastReconnectAt,
           lastReconnect.duration(to: now) < .seconds(Self.openVPNTransportReconnectThrottleSeconds) {
            return
        }

        transport.lastReconnectAt = now
        EventLog.append(note: "Requesting OpenVPN reconnect after \(reason).", phase: sessionState.phase)
        cwru_ovpn_client_reconnect(client, 1)
        scheduleRouteHealthCheck(reason: "OpenVPN reconnect requested after \(reason)")
    }

    private func resetLocalTransportFailureTracking() {
        transport.localFailures = LocalTransportFailureWindow(startedAt: nil, count: 0)
        transport.lastReconnectAt = nil
        routeMonitor.controlChannelSettleCount = 0
    }

    func markTransportDegraded(_ state: TransportRecoveryState, detail: String) {
        guard sessionState.phase == .connected,
              !isStopRequested,
              !isCleanupComplete else {
            return
        }

        transport.stableGeneration += 1
        let firstFailure = transport.degradedAt == nil
        if firstFailure {
            transport.degradedAt = .now
        }
        let previousHealth = sessionState.transportHealth
        if sessionState.transportHealth != .reconnecting || state == .reconnecting {
            sessionState.transportHealth = state
        }

        if state == .hostPathDegraded,
           Self.reachabilityDegradationStateNeedsUpdate(health: previousHealth,
                                                        diagnosticDetail: sessionState.diagnosticDetail,
                                                        detail: detail) {
            sessionState.lastEventName = "DATA_PATH_DEGRADED"
            sessionState.diagnosticDetail = detail
            saveStatusState()
        } else if sessionState.transportHealth != previousHealth {
            saveStatusState()
        }

        if firstFailure {
            EventLog.append(note: detail, phase: sessionState.phase)
            armTransportRecoveryDeadline()
        }
        updateMenuBar()
    }

    func markTransportRecoveredAfterConnectedEvent() {
        let wasDegraded = transport.degradedAt != nil
        if wasDegraded {
            var recoveryState = sessionState.transportHealth ?? .reconnecting
            let startedStabilizing = recoveryState.beginStabilizing()
            sessionState.transportHealth = recoveryState
            sessionState.lastEventName = "TRANSPORT_RECOVERY_STABILIZING"
            sessionState.diagnosticDetail = "OpenVPN reconnected. Verifying that the transport path remains stable."
            saveStatusState()
            if startedStabilizing {
                EventLog.append(note: "OpenVPN reconnected. Waiting for the connection to remain stable before clearing the outage deadline.",
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
        guard sessionState.transportHealth == .hostPathDegraded else {
            return
        }
        sessionState.transportHealth = .stabilizing
        sessionState.lastEventName = "TRANSPORT_RECOVERY_STABILIZING"
        sessionState.diagnosticDetail = "The split-tunnel host path recovered. Verifying that it remains stable."
        saveStatusState()
        EventLog.append(note: "The split-tunnel host path recovered. Waiting for it to remain stable before clearing the outage deadline.",
                        phase: sessionState.phase)
        armStableTransportReset()
        updateMenuBar()
    }

    private func armTransportRecoveryDeadline() {
        guard let degradedAt = transport.degradedAt else {
            return
        }
        transport.deadlineGeneration += 1
        let generation = transport.deadlineGeneration
        scheduleDeadline(at: degradedAt + .seconds(Self.transportRecoveryDeadlineSeconds)) { [weak self] in
            guard let self,
                  self.transport.deadlineGeneration == generation,
                  self.transport.degradedAt == degradedAt,
                  Self.shouldEnforceTransportRecoveryDeadline(degradedAt: self.transport.degradedAt,
                                                              phase: self.sessionState.phase,
                                                              isStopRequested: self.isStopRequested,
                                                              isCleanupComplete: self.isCleanupComplete) else {
                return
            }
            let message = "VPN recovery did not complete within 10 minutes. Disconnecting to restore normal network settings. Reconnect when the network is stable."
            self.sessionState.lastEventName = "TRANSPORT_RECOVERY_TIMED_OUT"
            self.sessionState.diagnosticDetail = message
            self.pendingDisconnectAlertMessage = self.pendingDisconnectAlertMessage ?? message
            self.saveStatusState()
            self.updateMenuBar()
            EventLog.append(note: message, phase: self.sessionState.phase)
            self.requestStop(reason: "transport recovery deadline expired", failed: true)
        }
    }

    private func armStableTransportReset() {
        transport.stableGeneration += 1
        let generation = transport.stableGeneration
        let degradedAt = transport.degradedAt
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.stableTransportResetSeconds) { [weak self] in
            guard let self,
                  self.transport.stableGeneration == generation,
                  self.transport.degradedAt == degradedAt,
                  self.sessionState.phase == .connected,
                  !self.isStopRequested,
                  !self.isCleanupComplete else {
                return
            }
            if degradedAt != nil {
                guard self.sessionState.transportHealth == .stabilizing else {
                    return
                }
                self.transport.degradedAt = nil
                self.sessionState.transportHealth = nil
                self.transport.deadlineGeneration += 1
                self.sessionState.lastEventName = "CONNECTED"
                self.sessionState.diagnosticDetail = nil
                self.saveStatusState()
                EventLog.append(note: "VPN transport remained stable and the outage deadline was cleared.",
                                phase: self.sessionState.phase)
                self.updateMenuBar()
            }
            self.resetLocalTransportFailureTracking()
            do {
                try ManagedReconnectBudget.reset()
            } catch {
                EventLog.append(note: "Could not reset automatic reconnect history after a stable connection: \(error.localizedDescription)",
                                phase: self.sessionState.phase)
            }
        }
    }

    private func scheduleManagedReconnect(reason: String) {
        guard sessionState.phase == .connected,
              transport.managedReconnect == nil,
              !isStopRequested,
              !isCleanupComplete else {
            return
        }

        guard case .detached = executionMode else {
            let message = "VPN transport recovery failed. Disconnecting to restore normal network settings. Reconnect when the network is stable."
            pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? message
            requestStop(reason: "persistent transport failure", failed: true)
            return
        }

        let budgetAvailable: Bool
        do {
            budgetAvailable = try ManagedReconnectBudget.reserveAttempt()
        } catch {
            let message = "Automatic reconnect could not record a retry attempt. Disconnecting to avoid a reconnect loop."
            pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? message
            EventLog.append(note: "Could not record an automatic reconnect attempt: \(error.localizedDescription)",
                            phase: sessionState.phase)
            requestStop(reason: "managed reconnect budget unavailable", failed: true)
            return
        }
        guard budgetAvailable else {
            let message = "VPN recovery failed repeatedly. Automatic reconnect stopped to restore normal network settings. Reconnect when the network is stable."
            pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? message
            EventLog.append(note: "Automatic reconnect limit reached.", phase: sessionState.phase)
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
        EventLog.append(note: "Scheduling automatic reconnect after \(reason).", phase: sessionState.phase)
        requestStop(reason: "managed reconnect after \(reason)", reconnect: request)
    }

    func scheduleReachabilityProbeIfNeeded(reason: String, afterRepair: Bool = false) {
        guard tunnelMode == .split,
              sessionState.phase == .connected,
              !transport.isProbeInFlight else {
            return
        }

        transport.isProbeInFlight = true
        transport.probeGeneration += 1
        let generation = transport.probeGeneration
        let hosts = CampusNetworkPolicy.fixedHealthCheckHosts
        guard let interface = sessionState.tunnelName else { transport.isProbeInFlight = false; return }
        let queue = transport.probeQueue
        queue.async { [weak self] in
            let result = ReachabilityProbe.run(hosts: hosts, interface: interface)
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
                                             currentGeneration: transport.probeGeneration,
                                             tunnelMode: tunnelMode,
                                             phase: sessionState.phase,
                                             inFlight: &transport.isProbeInFlight) else {
            return
        }

        if let reachableHost = result.reachableHost {
            if !transport.wasLastProbeHealthy {
                EventLog.append(note: "CWRU data-path check recovered via \(reachableHost).",
                                phase: sessionState.phase)
            }
            transport.wasLastProbeHealthy = true
            transport.lastAlertAt = nil
            markReachabilityRecoveredIfNeeded()
            return
        }

        let hostList = result.checkedHosts.joined(separator: ", ")
        if transport.wasLastProbeHealthy {
            EventLog.append(note: "CWRU data-path check failed after \(reason). Checked: \(hostList)",
                            phase: sessionState.phase)
        }
        transport.wasLastProbeHealthy = false

        guard afterRepair else {
            restorePhysicalDNSAfterFailedProbe()
            scheduleReachabilityProbeIfNeeded(reason: "health check repair", afterRepair: true)
            return
        }

        markTransportDegraded(.hostPathDegraded,
                              detail: "The CWRU split-tunnel data path remains unavailable after route and DNS checks.")
        scheduleReachabilityRetry()
        let now = ContinuousClock.now
        if let lastAlert = transport.lastAlertAt,
           lastAlert.duration(to: now) < .seconds(Self.reachabilityFailureSurfaceThrottleSeconds) {
            return
        }
        transport.lastAlertAt = now
        emit("CWRU data-path check failed for both fixed CWRU DNS endpoints. Reconnect after the network stabilizes.",
             level: .error)
    }

    func invalidateReachabilityProbe() {
        transport.probeGeneration += 1
        transport.isProbeInFlight = false
    }

    private func scheduleReachabilityRetry() {
        let generation = transport.probeGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.reachabilityRetrySeconds) { [weak self] in
            guard let self,
                  self.transport.probeGeneration == generation,
                  self.sessionState.transportHealth == .hostPathDegraded,
                  self.tunnelMode == .split,
                  self.sessionState.phase == .connected,
                  !self.isStopRequested,
                  !self.isCleanupComplete else {
                return
            }
            self.scheduleReachabilityProbeIfNeeded(reason: "degraded host path retry")
        }
    }

    private func restorePhysicalDNSAfterFailedProbe() {
        guard tunnelMode == .split,
              !isStopRequested,
              (sessionState.phase == .authPending || sessionState.phase == .connected) else {
            return
        }

        do {
            let changed = try routeManager.restoreService(.dns, using: sessionState)
            guard changed else {
                return
            }
            try routeManager.flushDNS()
            EventLog.append(note: "Repaired split-tunnel DNS settings after a health check failure.",
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
            EventLog.append(note: "Could not repair split-tunnel DNS settings after a health check failure: \(error.localizedDescription)",
                            phase: sessionState.phase)
        }
    }

}
