import COpenVPN3Wrapper
import Foundation
import Network

extension VPNController {
    func startRouteMonitorIfNeeded() throws {
        guard routeMonitor.pathMonitor == nil else {
            return
        }

        guard let observer = PhysicalNetworkObserver(handler: { [weak self] keys in
            guard let self,
                  !self.isStopRequested,
                  !self.isCleanupComplete else {
                return
            }
            if keys.contains("State:/Network/Interface/\(self.sessionState.physicalInterface)/IPv4") {
                self.routeMonitor.needsPhysicalRouteRefresh = true
            }
            self.scheduleRouteHealthCheck(reason: "system network configuration changed")
        }) else {
            throw VPNControllerError.operationFailed("Could not monitor physical IPv4 configuration.")
        }
        routeMonitor.physicalObserver = observer

        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            let status: String
            switch path.status {
            case .satisfied:
                status = "satisfied"
            case .requiresConnection:
                status = "requires-connection"
            case .unsatisfied:
                status = "unsatisfied"
            @unknown default:
                status = "unknown"
            }

            let interfaces = Set(path.availableInterfaces.map(\.name)).sorted().joined(separator: ", ")
            let reason = interfaces.isEmpty
                ? "network path changed (\(status))"
                : "network path changed (\(status); interfaces: \(interfaces))"

            Task { @MainActor [weak self] in
                self?.handlePathMonitorChange(reason: reason)
            }
        }
        monitor.start(queue: routeMonitor.queue)
        routeMonitor.pathMonitor = monitor
        routeMonitor.hasSeenInitialPathUpdate = false
        EventLog.append(note: "Started network path monitor.", phase: sessionState.phase)
    }

    func stopRouteMonitor() {
        routeMonitor.physicalObserver?.cancel()
        routeMonitor.physicalObserver = nil
        routeMonitor.needsPhysicalRouteRefresh = false
        routeMonitor.pathMonitor?.cancel()
        routeMonitor.pathMonitor = nil
        routeMonitor.hasSeenInitialPathUpdate = false
        routeMonitor.generation += 1
        routeMonitor.deadline = nil
        flushSuppressedRouteHealthCheckLog()
        routeMonitor.lastLogReason = nil
        routeMonitor.lastLoggedAt = nil
        invalidateReachabilityProbe()
    }

    private func performRouteHealthCheck() {
        guard sessionState.connectedAt != nil, !isStopRequested, !isCleanupComplete else {
            return
        }

        guard let client, cwru_ovpn_client_is_running(client) else {
            let message = "The OpenVPN worker exited while the tunnel still appeared connected. Disconnecting to restore network configuration."
            pendingDisconnectAlertMessage = pendingDisconnectAlertMessage ?? message
            EventLog.append(note: message, phase: sessionState.phase)
            requestStop(reason: "OpenVPN worker is no longer running", failed: true)
            return
        }

        do {
            switch try repairPhysicalNetworkChangeIfNeeded(reason: "route health check") {
            case .unchanged: break
            case .deferred: return
            case .migrated:
                handlePendingModeSwitch(trigger: "physical network recovery")
                return
            }

            switch tunnelMode {
            case .split:
                let snapshot = sessionState
                let stillConnected = try routeManager.monitorSplitTunnel(using: snapshot)
                if stillConnected {
                    scheduleReachabilityProbeIfNeeded(reason: "route health check")
                } else {
                    emit("The VPN tunnel is no longer available. Disconnecting.", level: .error)
                    EventLog.append(note: "Route health check detected a missing tunnel interface.", phase: sessionState.phase)
                    requestStop(reason: "missing split-tunnel interface", failed: true)
                }
            case .full:
                var fullState = sessionState
                let stillConnected = try routeManager.monitorFullTunnel(
                    using: &fullState,
                    persistPreparedState: persistPreparedNetworkState
                )
                if stillConnected {
                    sessionState = fullState
                    routeMonitor.controlChannelSettleCount = 0
                    saveStatusState()
                } else {
                    emit("The VPN tunnel is no longer available. Disconnecting.", level: .error)
                    EventLog.append(note: "Full-tunnel route health check detected a missing tunnel interface.",
                                    phase: sessionState.phase)
                    requestStop(reason: "missing full-tunnel interface", failed: true)
                }
            }
            if !isStopRequested {
                handlePendingModeSwitch(trigger: "route health check")
            }
        } catch where tunnelMode == .full
                    && routeMonitor.controlChannelSettleCount < Self.fullTunnelControlChannelSettleMaxRetries
                    && routeManager.canDeferFullTunnelFailure(error, using: sessionState) {
            routeMonitor.controlChannelSettleCount += 1
            EventLog.append(note: "Full-tunnel control channel is still settling after a network change (attempt \(routeMonitor.controlChannelSettleCount) of \(Self.fullTunnelControlChannelSettleMaxRetries)). Waiting briefly before retrying.",
                            phase: sessionState.phase)
            requestOpenVPNTransportReconnect(reason: "full-tunnel control channel settling")
            scheduleRouteHealthCheck(reason: "full-tunnel control channel is still settling", delay: 3)
        } catch {
            emit("The route health check failed: \(error.localizedDescription). Disconnecting.", level: .error)
            EventLog.append(note: "Route check failed. Disconnecting: \(error.localizedDescription)", phase: sessionState.phase)
            requestStop(reason: "route health check failed closed", failed: true)
        }
    }

    private func handlePathMonitorChange(reason: String) {
        if !routeMonitor.hasSeenInitialPathUpdate {
            routeMonitor.hasSeenInitialPathUpdate = true
            return
        }

        scheduleRouteHealthCheck(reason: reason)
    }

    func scheduleRouteHealthCheck(reason: String, delay: Double = 0) {
        guard sessionState.connectedAt != nil, !isStopRequested, !isCleanupComplete else {
            return
        }

        guard let deadline = Self.routeHealthCheckSchedule(existingDeadline: routeMonitor.deadline,
                                                           proposed: .now() + delay) else {
            return
        }

        routeMonitor.generation += 1
        let generation = routeMonitor.generation
        routeMonitor.deadline = deadline
        appendRouteHealthCheckLog(reason: reason)
        DispatchQueue.main.asyncAfter(deadline: deadline) { [weak self] in
            guard let self else {
                return
            }
            guard generation == self.routeMonitor.generation else {
                return
            }
            self.routeMonitor.deadline = nil
            self.performRouteHealthCheck()
        }
    }

    private func appendRouteHealthCheckLog(reason: String) {
        let now = Date()
        let plan = Self.routeHealthCheckLogPlan(reason: reason,
                                                lastReason: routeMonitor.lastLogReason,
                                                lastLoggedAt: routeMonitor.lastLoggedAt,
                                                suppressedCount: routeMonitor.suppressedLogCount,
                                                now: now)
        routeMonitor.lastLogReason = reason
        guard plan.shouldLog else {
            routeMonitor.suppressedLogCount = plan.suppressedCount
            return
        }
        routeMonitor.lastLoggedAt = now
        routeMonitor.suppressedLogCount = 0
        EventLog.append(note: Self.routeHealthCheckLogNote(reason: reason,
                                                           suppressedCount: plan.suppressedCount),
                        phase: sessionState.phase)
    }

    private func flushSuppressedRouteHealthCheckLog() {
        guard routeMonitor.suppressedLogCount > 0,
              let reason = routeMonitor.lastLogReason else {
            routeMonitor.suppressedLogCount = 0
            return
        }
        let suppressedCount = routeMonitor.suppressedLogCount
        routeMonitor.suppressedLogCount = 0
        EventLog.append(note: Self.routeHealthCheckLogNote(reason: reason, suppressedCount: suppressedCount),
                        phase: sessionState.phase)
    }

    func migratePhysicalNetworkStateIfNeeded(reason: String,
                                             rescheduleIfSettling: Bool) throws -> PhysicalNetworkMigrationOutcome {
        let physicalNetwork: PhysicalNetwork
        do {
            physicalNetwork = try routeManager.detectPhysicalNetwork()
            if routeMonitor.needsPhysicalRouteRefresh,
               try routeManager.physicalIPv4Addresses(interfaceName: physicalNetwork.interfaceName).isEmpty {
                throw RouteManagerError.missingPhysicalIPv4Address(physicalNetwork.interfaceName)
            }
        } catch {
            if rescheduleIfSettling {
                routeMonitor.needsPhysicalRouteRefresh = true
                try routeManager.validateNetworkSafetyWhileSettling(using: sessionState)
                EventLog.append(note: "Physical network is still settling after \(reason): \(error.localizedDescription)",
                                phase: sessionState.phase)
                scheduleRouteHealthCheck(reason: "the physical network is still settling", delay: 3)
                return .deferred
            }
            throw VPNControllerError.operationFailed(
                "The physical network is still settling after \(reason): \(error.localizedDescription)"
            )
        }

        guard let physicalDNSConfiguration = try routeManager.serviceStore.activeService(for: physicalNetwork.interfaceName) else {
            if rescheduleIfSettling {
                try routeManager.validateNetworkSafetyWhileSettling(using: sessionState)
                EventLog.append(note: "Could not read the active DNS service after \(reason). Waiting for the network to settle.",
                                phase: sessionState.phase)
                scheduleRouteHealthCheck(reason: "the active DNS service is still settling", delay: 3)
                return .deferred
            }
            throw VPNControllerError.operationFailed(
                "Could not read the active DNS service after \(reason)."
            )
        }

        if sessionState.tunnelMode == .full {
            try routeManager.assertFullTunnelSupported(physicalInterface: physicalNetwork.interfaceName,
                                                       ipv6Mode: physicalDNSConfiguration.ipv6Mode)
        }

        var migration = Self.sessionStateForPhysicalNetworkChange(currentState: sessionState,
                                                                  physicalNetwork: physicalNetwork,
                                                                  physicalDNSConfiguration: physicalDNSConfiguration,
                                                                  activeDefaultSearchDomains: try routeManager.captureActiveDefaultSearchDomains())
        let refreshPhysicalRoutes = routeMonitor.needsPhysicalRouteRefresh && !migration.transportAffecting
        guard migration.changed || refreshPhysicalRoutes else {
            return .unchanged
        }

        EventLog.append(note: "Captured physical network or DNS change after \(reason): \(sessionState.physicalGateway)/\(sessionState.physicalInterface) to \(physicalNetwork.gateway)/\(physicalNetwork.interfaceName).",
                        phase: sessionState.phase)
        if migration.shouldRestorePreviousService {
            func retireService(_ change: ServiceMutation) throws {
                var previous = sessionState
                previous.retire(change)
                try persistPreparedNetworkState(previous)
                migration.state.retire(change)
            }
            try routeManager.restoreService(.dns, using: sessionState, restored: retireService)
            try routeManager.restoreService(.ipv6, using: sessionState, restored: retireService)
        }

        sessionState = migration.state
        try saveState()
        if refreshPhysicalRoutes {
            var refreshedState = sessionState
            try routeManager.refreshPhysicalRoutes(using: &refreshedState,
                                                   persistPreparedState: persistPreparedNetworkState)
            sessionState = refreshedState
            try saveState()
        }
        routeMonitor.needsPhysicalRouteRefresh = false
        return .migrated(transportAffecting: migration.transportAffecting)
    }

    func repairPhysicalNetworkChangeIfNeeded(reason: String,
                                             reconnectTransport: Bool = true) throws -> PhysicalNetworkMigrationOutcome {
        let transportAffecting: Bool
        switch try migratePhysicalNetworkStateIfNeeded(reason: reason, rescheduleIfSettling: true) {
        case .unchanged:
            return .unchanged
        case .deferred:
            markTransportDegraded(.reconnecting,
                                  detail: "The physical network is unavailable. Waiting for the connection to recover.")
            return .deferred
        case .migrated(let affecting):
            transportAffecting = affecting
        }

        var updatedState = sessionState
        switch tunnelMode {
        case .split:
            try routeManager.applySplitTunnel(using: &updatedState,
                                              persistPreparedState: persistPreparedNetworkState)
        case .full:
            try routeManager.applyFullTunnelSafety(using: &updatedState,
                                                   persistPreparedState: persistPreparedNetworkState)
            routeMonitor.controlChannelSettleCount = 0
        }
        sessionState = updatedState
        try saveState()
        updateMenuBar()
        scheduleReachabilityProbeIfNeeded(reason: "physical network change")
        if transportAffecting && reconnectTransport {
            requestOpenVPNTransportReconnect(reason: "\(tunnelMode.modeDescription) physical network repair")
        }
        EventLog.append(note: "\(tunnelMode.displayName) repaired after physical network change.",
                        phase: sessionState.phase)
        return .migrated(transportAffecting: transportAffecting)
    }
}
