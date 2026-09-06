import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct ModeSwitchAndReconnectTests {
    @Test
    func nativeEventBufferBoundsAndPreservesPayloads() throws {
        var buffer = VPNEventBuffer()
        let auth = "WEB_AUTH::https://vpn.case.edu/auth?token=fixture"
        let dns = "OPTIONS: dhcp-option DNS 129.22.4.3"
        let scheduleAuth = buffer.append(name: "INFO", info: auth, isError: false, isFatal: false, generation: 1)
        let scheduleDNS = buffer.append(name: "LOG", info: dns, isError: false, isFatal: false, generation: 1)
        #expect(scheduleAuth && !scheduleDNS)
        let pending = buffer.drain()
        #expect(pending.map(\.info) == [auth, dns])
        #expect(pending.allSatisfy { $0.generation == 1 })

        for index in 0..<10_000 {
            _ = buffer.append(name: "INFO", info: String(index), isError: false, isFatal: false, generation: 1)
        }
        let flooded = buffer.drain()
        #expect(flooded.count == VPNEventBuffer.maximumPendingEvents + 1)
        #expect(flooded.dropLast().map(\.info) == (0..<VPNEventBuffer.maximumPendingEvents).map(String.init))
        #expect(flooded.last?.name == "EVENT_OVERFLOW")
        #expect(flooded.last?.isFatal == true)
        let scheduleAfterOverflow = buffer.append(name: "CONNECTED", info: "", isError: false, isFatal: false, generation: 1)
        let afterOverflow = buffer.drain()
        #expect(!scheduleAfterOverflow && afterOverflow.isEmpty)

        buffer = VPNEventBuffer()
        let large = String(repeating: "x", count: VPNEventBuffer.maximumInfoBytes)
        for _ in 0..<20 {
            _ = buffer.append(name: "LOG", info: large, isError: false, isFatal: false, generation: 2)
        }
        let byteLimited = buffer.drain()
        #expect(byteLimited.last?.isFatal == true)
        #expect(byteLimited.dropLast().reduce(0) { $0 + $1.name.utf8.count + $1.info.utf8.count }
                    <= VPNEventBuffer.maximumPendingBytes)

        let oversized = String(repeating: "x", count: VPNEventBuffer.maximumInfoBytes + 1)
        let rejected = oversized.withCString {
            VPNEventBuffer.readCString($0, maximumBytes: VPNEventBuffer.maximumInfoBytes)
        }
        #expect(rejected == nil)
        buffer = VPNEventBuffer()
        _ = buffer.append(name: "INFO", info: rejected, isError: false, isFatal: false, generation: 3)
        let overflow = try #require(buffer.drain().first)
        #expect(overflow.isFatal && overflow.isError && overflow.generation == 3)
        let accepted = large.withCString {
            VPNEventBuffer.readCString($0, maximumBytes: VPNEventBuffer.maximumInfoBytes)
        }
        #expect(accepted == large)
    }

    @Test
    func managedReconnectTunnelMode() throws {
        var session = makeSessionState(
            pid: 1005,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

        #expect(
            VPNController.managedReconnectTunnelMode(
                persistedState: session,
                controllerPID: 1005,
                controllerExecutablePath: session.executablePath,
                controllerStartTime: session.processStartTime,
                currentMode: .full) == .full,
            "Managed reconnect should keep the current mode when no switch is pending.")

        session.requestedTunnelMode = .split
        #expect(
            VPNController.managedReconnectTunnelMode(
                persistedState: session,
                controllerPID: 1005,
                controllerExecutablePath: session.executablePath,
                controllerStartTime: session.processStartTime,
                currentMode: .full) == .split,
            "Managed reconnect should honor a pending user mode request.")
        #expect(
            VPNController.managedReconnectTunnelMode(
                persistedState: session,
                controllerPID: 1006,
                controllerExecutablePath: session.executablePath,
                controllerStartTime: session.processStartTime,
                currentMode: .full) == .full,
            "Managed reconnect must ignore persisted state owned by another controller.")
        #expect(
            VPNController.managedReconnectTunnelMode(
                persistedState: session,
                controllerPID: session.pid,
                controllerExecutablePath: "/tmp/different-cwru-ovpn",
                controllerStartTime: session.processStartTime,
                currentMode: .full) == .full,
            "Managed reconnect must ignore persisted state with a different executable identity.")
        #expect(
            VPNController.managedReconnectTunnelMode(
                persistedState: session,
                controllerPID: session.pid,
                controllerExecutablePath: session.executablePath,
                controllerStartTime: ProcessStartTime(
                    seconds: 2,
                    microseconds: 0),
                currentMode: .full) == .full,
            "Managed reconnect must ignore persisted state with a different process start time.")
        #expect(
            VPNController.managedReconnectTunnelMode(
                persistedState: nil,
                controllerPID: 1005,
                controllerExecutablePath: session.executablePath,
                controllerStartTime: session.processStartTime,
                currentMode: .split) == .split,
            "Managed reconnect should keep the current mode when no state is persisted.")
    }

    @Test
    func modeSwitchWaitState() throws {
        var failedSession = makeSessionState(
            pid: 1004,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        failedSession.lastInfo =
            "Mode switch to full-tunnel failed: Failed to secure full-tunnel IPv6 traffic."

        switch SessionControl.evaluateModeSwitchWaitState(
            session: failedSession,
            pid: failedSession.pid,
            expectedExecutablePath: failedSession.executablePath,
            expectedStartTime: failedSession.processStartTime,
            targetMode: .full,
            sawRequestedMode: true)
        {
        case .failed(let message):
            #expect(
                message
                    == "Mode switch to full-tunnel failed: Failed to secure full-tunnel IPv6 traffic.",
                "Mode switch waits should surface the persisted switch failure as soon as the request clears."
            )
        default:
            try #require(
                Bool(false),
                "Mode switch waits should not keep waiting after a failed in-place switch.")
        }

        var deferredSession = failedSession
        deferredSession.phase = .connected
        deferredSession.tunnelMode = .split
        deferredSession.requestedTunnelMode = .full
        deferredSession.lastEvent = "MODE_SWITCH_DEFERRED"
        deferredSession.lastInfo =
            "Mode switch to full-tunnel deferred while the VPN reconnects; it will apply automatically once the connection recovers."

        switch SessionControl.evaluateModeSwitchWaitState(
            session: deferredSession,
            pid: deferredSession.pid,
            expectedExecutablePath: deferredSession.executablePath,
            expectedStartTime: deferredSession.processStartTime,
            targetMode: .full,
            sawRequestedMode: true)
        {
        case .deferred(let message):
            #expect(
                message.contains("deferred"),
                "Deferred mode switches should surface the deferral message to the CLI.")
        default:
            try #require(
                Bool(false),
                "A deferred mode switch should report deferred, not keep waiting or fail.")
        }

        switch SessionControl.evaluateModeSwitchWaitState(
            session: deferredSession,
            pid: deferredSession.pid,
            expectedExecutablePath: deferredSession.executablePath,
            expectedStartTime: deferredSession.processStartTime,
            targetMode: .split,
            sawRequestedMode: false)
        {
        case .deferred:
            try #require(
                Bool(false), "A deferral for another target mode must not satisfy this wait.")
        default:
            break
        }

        var rollbackFailedSession = failedSession
        rollbackFailedSession.phase = .disconnecting
        rollbackFailedSession.lastEvent = "MODE_SWITCH_ROLLBACK_FAILED"
        rollbackFailedSession.lastInfo = "Mode switch and rollback failed; disconnecting."

        switch SessionControl.evaluateModeSwitchWaitState(
            session: rollbackFailedSession,
            pid: rollbackFailedSession.pid,
            expectedExecutablePath: rollbackFailedSession.executablePath,
            expectedStartTime: rollbackFailedSession.processStartTime,
            targetMode: .full,
            sawRequestedMode: true)
        {
        case .failed(let message):
            #expect(
                message == "Mode switch and rollback failed; disconnecting.",
                "Mode switch waits should surface rollback failures before the controller exits.")
        default:
            try #require(Bool(false), "A disconnecting rollback failure should not remain pending.")
        }

        var completedSession = failedSession
        completedSession.tunnelMode = .full
        completedSession.lastInfo = nil

        switch SessionControl.evaluateModeSwitchWaitState(
            session: completedSession,
            pid: completedSession.pid,
            expectedExecutablePath: completedSession.executablePath,
            expectedStartTime: completedSession.processStartTime,
            targetMode: .full,
            sawRequestedMode: true)
        {
        case .succeeded:
            break
        default:
            try #require(
                Bool(false),
                "Mode switch waits should finish once the persisted session reaches the target mode."
            )
        }
    }

    @Test
    func startupConnectTimeoutMessage() throws {
        #expect(
            VPNController.startupConnectTimeoutMessage.contains("did not finish connecting"),
            "The connect-timeout message should explain that connection did not complete in time.")
        #expect(
            VPNController.startupConnectTimeoutMessage.localizedCaseInsensitiveContains(
                "public Wi-Fi"),
            "The connect-timeout message should guide users on public Wi-Fi/captive portals.")
    }

    @Test
    func duplicateLogLinesAreSuppressedForOneSecond() {
        let now = Date(timeIntervalSince1970: 10_000)
        let line = "Endpoint address family (IPv6) is incompatible with transport protocol (udp4)\n"
        let previous = (info: line, at: now)
        #expect(VPNController.isDuplicateLogLine(line, previous: previous, now: now.addingTimeInterval(0.01)))
        #expect(!VPNController.isDuplicateLogLine(line, previous: previous, now: now.addingTimeInterval(1)))
        #expect(!VPNController.isDuplicateLogLine("Contacting 67.219.145.198:1194 via UDP\n", previous: previous, now: now))
        #expect(!VPNController.isDuplicateLogLine(line, previous: nil, now: now))
    }

    @Test
    func openVPNNetworkRecoveryLogDetection() throws {
        #expect(
            VPNController.isOpenVPNNetworkLifecycleLog("MacLifeCycle NET_IFACE en0\n"),
            "OpenVPN network lifecycle logs should schedule a route health check.")
        #expect(
            VPNController.isOpenVPNNetworkLifecycleLog(
                "MacLifeCycle NET_STATE 1 status=ReachableViaWiFi\n"),
            "OpenVPN network state logs should schedule a route health check.")
        #expect(
            !VPNController.isOpenVPNNetworkLifecycleLog("MacDNS: SETDNS 27.0.0\n"),
            "OpenVPN DNS logs should not be treated as network lifecycle logs.")

        #expect(
            VPNController.isLocalTransportFailureLog(
                "UDP send exception: send: Can't assign requested address\n"),
            "Local UDP address failures should trigger transport recovery.")
        #expect(
            VPNController.isLocalTransportFailureLog(
                "UDP send exception: send: No buffer space available\n"),
            "Local UDP buffer exhaustion should trigger transport recovery.")
        #expect(
            VPNController.isLocalTransportFailureLog(
                "UDP send exception: send: Network is unreachable\n"),
            "Local network-unreachable failures should trigger transport recovery.")
        #expect(
            VPNController.isLocalTransportFailureLog(
                "Client exception in transport_connecting: route_gateway_error: GDG: ioctl SIOCGIFNETMASK failed\n"
            ),
            "OpenVPN route gateway errors should trigger transport recovery.")
        #expect(
            !VPNController.isLocalTransportFailureLog(
                "Server poll timeout, trying next remote entry...\n"),
            "Remote polling timeouts alone should not trigger local transport recovery.")
        #expect(
            !VPNController.isLocalTransportFailureLog("CONNECTED\n"),
            "Successful connection logs should not trigger transport recovery.")
    }

    @Test
    func localTransportFailureEscalation() throws {
        let start = Date(timeIntervalSince1970: 1_000)
        func evaluate(
            _ window: VPNController.LocalTransportFailureWindow,
            _ offset: TimeInterval,
            systemAsleep: Bool = false
        )
            -> (
                window: VPNController.LocalTransportFailureWindow,
                action: VPNController.TransportRecoveryAction
            )
        {
            VPNController.evaluateLocalTransportFailure(
                window: window,
                now: start.addingTimeInterval(offset),
                systemAsleep: systemAsleep)
        }

        let first = evaluate(VPNController.LocalTransportFailureWindow(startedAt: nil, count: 0), 0)
        #expect(
            first.window.count == 1 && first.window.startedAt == start,
            "The first local transport failure should open a tracking window.")
        #expect(
            first.action == .none,
            "A single transport failure should not trigger any reconnect.")

        let second = evaluate(first.window, 1)
        #expect(
            second.window.count == 2 && second.action == .none,
            "Two failures inside the reconnect delay should not yet request an OpenVPN reconnect.")

        let third = evaluate(second.window, 4)
        #expect(
            third.action == .reconnect,
            "Failures persisting past the reconnect delay should request an in-place OpenVPN reconnect, not a managed reconnect."
        )

        let fourth = evaluate(third.window, 10)
        let fifth = evaluate(fourth.window, 21)
        #expect(
            fifth.window.count == 5 && fifth.action == .restart,
            "Failures persisting past the managed-reconnect threshold should escalate to a managed reconnect."
        )

        let afterWindow = evaluate(
            fifth.window, 21 + VPNController.localTransportFailureWindowSeconds + 1)
        #expect(
            afterWindow.window.count == 1 && afterWindow.action == .none,
            "A failure after the window expires should reset the count and de-escalate.")

        let asleep = evaluate(fourth.window, 21, systemAsleep: true)
        #expect(
            asleep.action != .restart,
            "A sleeping system must never escalate to a managed reconnect: it starts a successor process that has no auth token, so the gateway answers with WEB_AUTH and the sign-in window is queued for a user session that is not being serviced."
        )
        #expect(
            asleep.action == .reconnect && asleep.window.count == fifth.window.count,
            "Sleep must not suppress the in-place OpenVPN reconnect or the failure accounting; that path reuses the auth token and is what lets a tunnel survive dark wakes."
        )
    }

    @Test
    func deadlinePoliciesSurviveSystemSleepWithoutExtendingAuthentication() {
        #expect(VPNController.deadlineClock(for: .connecting) == .wall)
        #expect(VPNController.deadlineClock(for: .authPending) == .wall)
        #expect(VPNController.deadlineClock(for: .transportRecovery) == .monotonic)

        let now = Date(timeIntervalSince1970: 10_000)
        var authentication = WebAuthRecovery()
        let firstDeadline = authentication.begin(info: "", now: now)
        #expect(
            firstDeadline
                == now.addingTimeInterval(WebAuthRecovery.defaultTimeoutSeconds))
        let repeatedDeadline = authentication.begin(info: "timeout 900", now: now.addingTimeInterval(30))
        #expect(repeatedDeadline == nil)
    }

    @Test
    func workspaceSleepTransitionsClearSleepStateBeforePhaseGating() {
        let sleeping = VPNController.workspaceSleepTransition(
            event: .willSleep,
            phase: .connected,
            requestedStop: false,
            cleanupComplete: false)
        #expect(
            sleeping
                == VPNController.WorkspaceSleepTransition(
                    systemAsleep: true,
                    shouldDisconnect: false))

        let connectingWake = VPNController.workspaceSleepTransition(
            event: .didWake,
            phase: .connecting,
            requestedStop: false,
            cleanupComplete: false)
        #expect(
            connectingWake
                == VPNController.WorkspaceSleepTransition(
                    systemAsleep: false,
                    shouldDisconnect: false))

        let connectedWake = VPNController.workspaceSleepTransition(
            event: .didWake,
            phase: .connected,
            requestedStop: false,
            cleanupComplete: false)
        #expect(
            connectedWake
                == VPNController.WorkspaceSleepTransition(
                    systemAsleep: false,
                    shouldDisconnect: true))

        let stoppingWake = VPNController.workspaceSleepTransition(
            event: .didWake,
            phase: .connected,
            requestedStop: true,
            cleanupComplete: false)
        #expect(!stoppingWake.shouldDisconnect)
    }

    @Test
    func countdownAlertYieldsToSleepAndWakeDisconnect() {
        func shouldShow(
            systemAsleep: Bool = false,
            disconnectingAfterWake: Bool = false
        ) -> Bool {
            VPNController.shouldShowEstimatedSessionCountdownAlert(
                phase: .connected,
                requestedStop: false,
                cleanupComplete: false,
                systemAsleep: systemAsleep,
                disconnectingAfterWake: disconnectingAfterWake,
                alertShown: false,
                remaining: 0
            )
        }

        #expect(shouldShow())
        #expect(!shouldShow(systemAsleep: true))
        #expect(!shouldShow(disconnectingAfterWake: true))
        #expect(
            !VPNController.shouldShowEstimatedSessionCountdownAlert(
                phase: .connected,
                requestedStop: false,
                cleanupComplete: false,
                systemAsleep: false,
                disconnectingAfterWake: false,
                alertShown: false,
                remaining: 1
            ))
    }

    @Test
    func transportRecoveryLifecycleHelpers() throws {
        let start = Date(timeIntervalSince1970: 2_000)
        #expect(
            VPNController.transportRecoveryDeadlineDelay(degradedAt: start, now: start)
                == VPNController.transportRecoveryDeadlineSeconds,
            "Transport recovery should arm for the full wall-clock deadline.")
        #expect(
            VPNController.transportRecoveryDeadlineDelay(
                degradedAt: start,
                now: start.addingTimeInterval(VPNController.transportRecoveryDeadlineSeconds - 1)
            ) == 1,
            "Transport recovery should retain the remaining wall-clock deadline.")
        #expect(
            VPNController.transportRecoveryDeadlineDelay(
                degradedAt: start,
                now: start.addingTimeInterval(VPNController.transportRecoveryDeadlineSeconds)
            ) == 0,
            "Transport recovery should schedule immediately once its wall-clock deadline has elapsed."
        )

        let firstDeadline = VPNController.routeHealthCheckSchedule(
            existingDeadline: nil, now: start)
        let repeatedDeadline = VPNController.routeHealthCheckSchedule(
            existingDeadline: firstDeadline,
            now: start.addingTimeInterval(2))
        #expect(
            firstDeadline == start.addingTimeInterval(3) && repeatedDeadline == nil,
            "Repeated path events must not schedule or postpone another route health check.")

        let pathReason = "network path changed (satisfied; interfaces: en0)"
        #expect(
            VPNController.routeHealthCheckLogPlan(
                reason: pathReason,
                lastReason: nil,
                lastLoggedAt: nil,
                suppressedCount: 0,
                now: start)
                == VPNController.RouteHealthCheckLogPlan(shouldLog: true, suppressedCount: 0),
            "The first path update must be logged.")
        #expect(
            VPNController.routeHealthCheckLogPlan(
                reason: pathReason,
                lastReason: pathReason,
                lastLoggedAt: start,
                suppressedCount: 7,
                now: start.addingTimeInterval(5))
                == VPNController.RouteHealthCheckLogPlan(shouldLog: false, suppressedCount: 8),
            "An identical path update inside the coalesce window must be counted, not logged.")
        #expect(
            VPNController.routeHealthCheckLogPlan(
                reason: pathReason,
                lastReason: pathReason,
                lastLoggedAt: start,
                suppressedCount: 8,
                now: start.addingTimeInterval(VPNController.routeHealthCheckLogCoalesceSeconds))
                == VPNController.RouteHealthCheckLogPlan(shouldLog: true, suppressedCount: 8),
            "An identical path update must still be logged once the coalesce window elapses.")
        #expect(
            VPNController.routeHealthCheckLogPlan(
                reason: "network path changed (unsatisfied)",
                lastReason: pathReason,
                lastLoggedAt: start,
                suppressedCount: 3,
                now: start.addingTimeInterval(1))
                == VPNController.RouteHealthCheckLogPlan(shouldLog: true, suppressedCount: 3),
            "A changed path reason must be logged immediately regardless of the coalesce window.")
        #expect(
            VPNController.routeHealthCheckLogNote(reason: pathReason, suppressedCount: 0)
                == "Network path monitor noticed: \(pathReason)",
            "A path note without suppressed duplicates must stay unchanged.")
        #expect(
            VPNController.routeHealthCheckLogNote(reason: pathReason, suppressedCount: 1)
                .hasSuffix("(1 preceding duplicate update not logged)"),
            "A single suppressed duplicate must be reported in the singular.")
        #expect(
            VPNController.routeHealthCheckLogNote(reason: pathReason, suppressedCount: 12)
                .hasSuffix("(12 preceding duplicate updates not logged)"),
            "Suppressed duplicates must be reported with their count.")

        let degradedDetail =
            "The split-tunnel host path remains unavailable after route and DNS checks."
        #expect(
            VPNController.reachabilityDegradationStateNeedsUpdate(
                lastEvent: "CONNECTED",
                lastInfo: nil,
                detail: degradedDetail),
            "The first degraded host-path result should be persisted.")
        #expect(
            !VPNController.reachabilityDegradationStateNeedsUpdate(
                lastEvent: "DATA_PATH_DEGRADED",
                lastInfo: degradedDetail,
                detail: degradedDetail),
            "An unchanged degraded host-path result should not rewrite session state.")
        #expect(
            VPNController.reachabilityDegradationStateNeedsUpdate(
                lastEvent: "DATA_PATH_DEGRADED",
                lastInfo: degradedDetail,
                detail: "The degraded host-path diagnosis changed."),
            "A changed degraded host-path diagnosis should still be persisted.")
        #expect(
            !VPNController.reachabilityDegradationStateNeedsUpdate(
                lastEvent: "RECONNECTING",
                lastInfo: nil,
                detail: degradedDetail),
            "A reachability result must not overwrite an active OpenVPN reconnect event.")

        var logWindow = VPNController.ReconnectLifecycleEventLogWindow(
            startedAt: nil, eventNames: [])
        let firstWait = VPNController.evaluateReconnectLifecycleEventLog(
            window: logWindow,
            eventName: "WAIT",
            now: start)
        logWindow = firstWait.window
        let firstReconnect = VPNController.evaluateReconnectLifecycleEventLog(
            window: logWindow,
            eventName: "RECONNECTING",
            now: start.addingTimeInterval(1))
        logWindow = firstReconnect.window
        let repeatedWait = VPNController.evaluateReconnectLifecycleEventLog(
            window: logWindow,
            eventName: "WAIT",
            now: start.addingTimeInterval(2))
        let nextWindow = VPNController.evaluateReconnectLifecycleEventLog(
            window: repeatedWait.window,
            eventName: "WAIT",
            now: start.addingTimeInterval(VPNController.reconnectLifecycleEventLogWindowSeconds))
        #expect(
            firstWait.shouldLog && firstReconnect.shouldLog && !repeatedWait.shouldLog
                && nextWindow.shouldLog,
            "WAIT and RECONNECTING storms should retain one sample per event per log window.")

        #expect(
            VPNController.shouldAcceptReachabilityProbe(
                payloadGeneration: 7,
                currentGeneration: 7,
                tunnelMode: .split,
                phase: .connected),
            "The current split-tunnel reachability result should be accepted.")
        #expect(
            !VPNController.shouldAcceptReachabilityProbe(
                payloadGeneration: 6,
                currentGeneration: 7,
                tunnelMode: .split,
                phase: .connected),
            "A stale reachability callback must be rejected.")
        #expect(
            !VPNController.shouldAcceptReachabilityProbe(
                payloadGeneration: 7,
                currentGeneration: 7,
                tunnelMode: .full,
                phase: .connected),
            "A split-tunnel reachability callback must be rejected after a mode switch.")

        let firstBudget = ManagedReconnectBudget.decision(state: nil, now: start)
        let secondBudget = ManagedReconnectBudget.decision(
            state: firstBudget.state,
            now: start.addingTimeInterval(10))
        let exhaustedBudget = ManagedReconnectBudget.decision(
            state: secondBudget.state,
            now: start.addingTimeInterval(20))
        let renewedBudget = ManagedReconnectBudget.decision(
            state: exhaustedBudget.state,
            now: start.addingTimeInterval(ManagedReconnectBudget.windowSeconds))
        #expect(
            firstBudget.allowed && firstBudget.state.attempts == 1,
            "The first managed reconnect attempt should open its persistent budget window.")
        #expect(
            secondBudget.allowed
                && secondBudget.state.attempts == ManagedReconnectBudget.maximumAttempts,
            "The final permitted managed reconnect should consume the remaining budget.")
        #expect(
            !exhaustedBudget.allowed,
            "Managed reconnect must fail closed after its persistent budget is exhausted.")
        #expect(
            renewedBudget.allowed && renewedBudget.state.attempts == 1,
            "Managed reconnect may open a new budget only after the prior window expires.")

        let budgetEncoder = JSONEncoder()
        let budgetData = try budgetEncoder.encode(firstBudget.state)
        var budgetObject = try #require(
            try JSONSerialization.jsonObject(with: budgetData) as? [String: Any],
            "Encoded managed reconnect budget should be a JSON object.")
        budgetObject["legacyAttempts"] = 1
        let legacyBudgetData = try JSONSerialization.data(withJSONObject: budgetObject)
        #expect(throws: (any Error).self, "Managed reconnect budget should reject unknown fields.")
        {
            _ = try JSONDecoder().decode(ManagedReconnectBudgetState.self, from: legacyBudgetData)
        }

        var reconnectingSession = makeSessionState(
            pid: 1007,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Automatic",
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true)
        reconnectingSession.lastEvent = "RECONNECTING"
        #expect(
            SessionPresentation.statusTitle(
                for: reconnectingSession,
                stale: false,
                recoveryNeeded: false) == "Reconnecting",
            "Persisted RECONNECTING state must not be displayed as Connected.")
        reconnectingSession.lastEvent = "DATA_PATH_DEGRADED"
        #expect(
            SessionPresentation.statusTitle(
                for: reconnectingSession,
                stale: false,
                recoveryNeeded: false) == "Degraded",
            "Persistent host-path failure must not be displayed as Connected.")
        reconnectingSession.lastEvent = "TRANSPORT_RECOVERY_STABILIZING"
        #expect(
            SessionPresentation.statusTitle(
                for: reconnectingSession,
                stale: false,
                recoveryNeeded: false) == "Stabilizing",
            "A transient CONNECTED event must remain visibly provisional until the stable interval completes."
        )
    }

    @Test
    func deferredModeSwitchDoesNotReportCompletion() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-deferred-switch")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory)
        var session = makeSessionState(
            pid: getpid(), profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalServiceName: "Wi-Fi", originalDNSServers: [], originalSearchDomains: [],
            originalIPv6Mode: "Automatic", tunName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        session.executablePath = try ExecutionIdentity.currentExecutablePath()
        session.processStartTime = try #require(processStartTime(getpid()))
        session.requestedTunnelMode = .full
        session.lastEvent = "MODE_SWITCH_DEFERRED"
        try session.save(to: store)
        #expect(try !SessionControl.waitForModeSwitch(pid: session.pid,
                                                     expectedExecutablePath: session.executablePath,
                                                     expectedStartTime: session.processStartTime,
                                                     targetMode: .full, sessionStore: store))
        session.tunnelMode = .full
        session.requestedTunnelMode = nil
        session.lastEvent = "MODE_SWITCHED"
        try session.save(to: store)
        #expect(try SessionControl.waitForModeSwitch(pid: session.pid,
                                                    expectedExecutablePath: session.executablePath,
                                                    expectedStartTime: session.processStartTime,
                                                    targetMode: .full, sessionStore: store))
    }
}
