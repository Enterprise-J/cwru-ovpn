import COpenVPN3Wrapper
import Foundation
import Network

extension VPNController {
    func startRouteMonitorIfNeeded() throws {
        guard pathMonitor == nil else {
            return
        }

        guard let observer = PhysicalNetworkObserver(handler: { [weak self] keys in
            guard let self,
                  !self.requestedStop,
                  !self.cleanupComplete,
                  keys.contains("State:/Network/Interface/\(self.sessionState.physicalInterface)/IPv4") else {
                return
            }
            self.physicalNetworkNeedsRouteRefresh = true
            self.scheduleRouteHealthCheck(reason: "physical interface IPv4 configuration changed")
        }) else {
            throw VPNControllerError.operationFailed("Could not monitor physical IPv4 configuration.")
        }
        physicalNetworkObserver = observer

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
        monitor.start(queue: pathMonitorQueue)
        pathMonitor = monitor
        hasSeenInitialPathUpdate = false
        EventLog.append(note: "Started network path monitor.", phase: sessionState.phase)
    }

    func stopRouteMonitor() {
        physicalNetworkObserver?.cancel()
        physicalNetworkObserver = nil
        physicalNetworkNeedsRouteRefresh = false
        pathMonitor?.cancel()
        pathMonitor = nil
        hasSeenInitialPathUpdate = false
        routeHealthCheckGeneration += 1
        routeHealthCheckDeadline = nil
        flushSuppressedRouteHealthCheckLog()
        routeHealthCheckLogReason = nil
        routeHealthCheckLoggedAt = nil
        invalidateReachabilityProbe()
    }

    private func performRouteHealthCheck() {
        guard sessionState.phase == .connected else {
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
                    fullTunnelControlChannelSettleCount = 0
                    saveStatusState()
                } else {
                    emit("The VPN tunnel is no longer available. Disconnecting.", level: .error)
                    EventLog.append(note: "Full-tunnel route health check detected a missing tunnel interface.",
                                    phase: sessionState.phase)
                    requestStop(reason: "missing full-tunnel interface", failed: true)
                }
            }
            if !requestedStop {
                handlePendingModeSwitch(trigger: "route health check")
            }
        } catch where tunnelMode == .full
                    && fullTunnelControlChannelSettleCount < Self.fullTunnelControlChannelSettleMaxRetries
                    && routeManager.canDeferFullTunnelFailure(error, using: sessionState) {
            fullTunnelControlChannelSettleCount += 1
            EventLog.append(note: "Full-tunnel control channel is still settling after a network change (attempt \(fullTunnelControlChannelSettleCount) of \(Self.fullTunnelControlChannelSettleMaxRetries)); allowing a bounded recovery interval.",
                            phase: sessionState.phase)
            requestOpenVPNTransportReconnect(reason: "full-tunnel control channel settling")
            scheduleRouteHealthCheck(reason: "full-tunnel control channel is still settling")
        } catch {
            emit("The route health check failed: \(error.localizedDescription). Disconnecting.", level: .error)
            EventLog.append(note: "Route health check failed closed: \(error.localizedDescription)", phase: sessionState.phase)
            requestStop(reason: "route health check failed closed", failed: true)
        }
    }

    private func handlePathMonitorChange(reason: String) {
        if !hasSeenInitialPathUpdate {
            hasSeenInitialPathUpdate = true
            return
        }

        scheduleRouteHealthCheck(reason: reason)
    }

    func scheduleRouteHealthCheck(reason: String) {
        guard sessionState.phase == .connected else {
            return
        }

        guard let deadline = Self.routeHealthCheckSchedule(existingDeadline: routeHealthCheckDeadline,
                                                           now: Date()) else {
            return
        }

        routeHealthCheckGeneration += 1
        let generation = routeHealthCheckGeneration
        routeHealthCheckDeadline = deadline
        appendRouteHealthCheckLog(reason: reason)
        DispatchQueue.main.asyncAfter(deadline: .now() + max(0, deadline.timeIntervalSinceNow)) { [weak self] in
            guard let self else {
                return
            }
            guard generation == self.routeHealthCheckGeneration else {
                return
            }
            self.routeHealthCheckDeadline = nil
            self.performRouteHealthCheck()
        }
    }

    private func appendRouteHealthCheckLog(reason: String) {
        let now = Date()
        let plan = Self.routeHealthCheckLogPlan(reason: reason,
                                                lastReason: routeHealthCheckLogReason,
                                                lastLoggedAt: routeHealthCheckLoggedAt,
                                                suppressedCount: routeHealthCheckSuppressedLogCount,
                                                now: now)
        routeHealthCheckLogReason = reason
        guard plan.shouldLog else {
            routeHealthCheckSuppressedLogCount = plan.suppressedCount
            return
        }
        routeHealthCheckLoggedAt = now
        routeHealthCheckSuppressedLogCount = 0
        EventLog.append(note: Self.routeHealthCheckLogNote(reason: reason,
                                                           suppressedCount: plan.suppressedCount),
                        phase: sessionState.phase)
    }

    private func flushSuppressedRouteHealthCheckLog() {
        guard routeHealthCheckSuppressedLogCount > 0,
              let reason = routeHealthCheckLogReason else {
            routeHealthCheckSuppressedLogCount = 0
            return
        }
        let suppressedCount = routeHealthCheckSuppressedLogCount
        routeHealthCheckSuppressedLogCount = 0
        EventLog.append(note: Self.routeHealthCheckLogNote(reason: reason, suppressedCount: suppressedCount),
                        phase: sessionState.phase)
    }

    func migratePhysicalNetworkStateIfNeeded(reason: String,
                                             rescheduleIfSettling: Bool) throws -> PhysicalNetworkMigrationOutcome {
        let physicalNetwork: PhysicalNetwork
        do {
            physicalNetwork = try routeManager.detectPhysicalNetwork()
            if physicalNetworkNeedsRouteRefresh,
               try routeManager.physicalIPv4Addresses(interfaceName: physicalNetwork.interfaceName).isEmpty {
                throw RouteManagerError.missingPhysicalIPv4Address(physicalNetwork.interfaceName)
            }
        } catch {
            if rescheduleIfSettling {
                physicalNetworkNeedsRouteRefresh = true
                try routeManager.validateNetworkSafetyWhileSettling(using: sessionState)
                EventLog.append(note: "Physical network is still settling after \(reason): \(error.localizedDescription)",
                                phase: sessionState.phase)
                scheduleRouteHealthCheck(reason: "the physical network is still settling")
                return .deferred
            }
            throw VPNControllerError.operationFailed(
                "The physical network is still settling after \(reason): \(error.localizedDescription)"
            )
        }

        guard let physicalDNSConfiguration = try routeManager.capturePhysicalDNSConfiguration(for: physicalNetwork.interfaceName) else {
            if rescheduleIfSettling {
                try routeManager.validateNetworkSafetyWhileSettling(using: sessionState)
                EventLog.append(note: "Could not capture the active DNS service after \(reason); waiting for the network to settle.",
                                phase: sessionState.phase)
                scheduleRouteHealthCheck(reason: "the active DNS service is still settling")
                return .deferred
            }
            throw VPNControllerError.operationFailed(
                "Could not capture the active DNS service after \(reason)."
            )
        }

        if sessionState.tunnelMode == .full {
            try routeManager.assertFullTunnelSupported(physicalInterface: physicalNetwork.interfaceName,
                                                       ipv6Mode: physicalDNSConfiguration.ipv6Mode)
        }

        let migration = Self.sessionStateForPhysicalNetworkChange(currentState: sessionState,
                                                                  physicalNetwork: physicalNetwork,
                                                                  physicalDNSConfiguration: physicalDNSConfiguration,
                                                                  activeDefaultSearchDomains: routeManager.captureActiveDefaultSearchDomains())
        let refreshPhysicalRoutes = physicalNetworkNeedsRouteRefresh && !migration.transportAffecting
        guard migration.changed || refreshPhysicalRoutes else {
            return .unchanged
        }

        EventLog.append(note: "Captured physical network or DNS change after \(reason): \(sessionState.physicalGateway)/\(sessionState.physicalInterface) to \(physicalNetwork.gateway)/\(physicalNetwork.interfaceName).",
                        phase: sessionState.phase)
        if migration.shouldRestorePreviousService {
            try routeManager.restoreDNSConfiguration(using: sessionState)
            try routeManager.restorePhysicalIPv6Configuration(using: sessionState)
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
        physicalNetworkNeedsRouteRefresh = false
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
                                  detail: "The physical network is unavailable; waiting for VPN transport recovery.")
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
            fullTunnelControlChannelSettleCount = 0
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
