import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct SessionStatePersistenceTests {
    @Test
    func recoveryState() throws {
        var session = SessionState(
            pid: 100,
            executablePath: "/tmp/cwru-ovpn",
            processStartTime: ProcessStartTime(seconds: 1, microseconds: 0),
            phase: .disconnecting,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            startedAt: Date(timeIntervalSince1970: 0),
            lastEvent: nil,
            lastInfo: nil,
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: nil,
            originalDNSServers: nil,
            originalSearchDomains: nil,
            originalIPv6Mode: nil,
            pushedDNSServers: nil,
            pushedSearchDomains: nil,
            tunName: nil,
            vpnIPv4: nil,
            serverHost: nil,
            serverIP: nil,
            tunnelMode: .split,
            requestedTunnelMode: nil,
            fullTunnelDefaultRoutes: nil,
            fullTunnelDNSServers: nil,
            fullTunnelSearchDomains: nil,
            appliedSplitIPv4Routes: nil,
            appliedDNSDomains: nil,
            cleanupNeeded: false
        )

        session.markRecoveryRequired(message: "Cleanup failed.")

        #expect(
            session.phase == .failed,
            "markRecoveryRequired should set the session phase to failed.")
        #expect(
            session.lastEvent == "RECOVERY_REQUIRED",
            "markRecoveryRequired should persist a recovery event marker.")
        #expect(
            session.lastInfo == "Cleanup failed.",
            "markRecoveryRequired should preserve the recovery message.")
        #expect(
            session.cleanupNeeded,
            "markRecoveryRequired should keep cleanupNeeded enabled.")
        #expect(
            SessionPresentation.recoveryDetail(for: session, stale: true)
                == "Cleanup failed. Run ovpnd again to retry restoring routes and DNS.",
            "Recovery detail should guide the user to retry disconnect.")
        #expect(
            SessionPresentation.statusTitle(for: .failed, stale: true, recoveryNeeded: true)
                == "Recovery Needed",
            "Recovery state should have a distinct status title.")
    }

    @Test
    func persistentPrivilegedRecoveryPath() throws {
        #expect(
            RuntimePaths.privilegedSessionStateDirectoryPath == "/var/db/cwru-ovpn",
            "Privileged recovery state must live in persistent root-owned storage instead of /var/run."
        )
    }

    @Test
    func sessionStateRejectsOversizedWrites() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-oversized-session")
        defer { try? FileManager.default.removeItem(at: homeStateDirectory) }
        let store = StateDirectory(
            directory: homeStateDirectory.appendingPathComponent("state", isDirectory: true))

        var session = makeSessionState(
            pid: 2002,
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
        session.appliedDNSDomains = (0..<400).map {
            "\(String(repeating: "a", count: 220))\($0).case.edu"
        }

        do {
            try session.save(to: store)
            try #require(
                Bool(false),
                "Session persistence should reject state larger than its own read limit.")
        } catch SessionStateError.encodedStateTooLarge {
        }
        #expect(
            !FileManager.default.fileExists(atPath: store.url.appendingPathComponent("session.json").path),
            "Oversized recovery state should fail before creating an unreadable session file.")
    }

    @Test
    func sessionStateReportsInvalidPersistence() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-invalid-session")
        defer { try? FileManager.default.removeItem(at: homeStateDirectory) }
        let stateDirectory = homeStateDirectory.appendingPathComponent("state", isDirectory: true)
        let store = StateDirectory(directory: stateDirectory)

        try writeOwnedFixture(Data("{not-json".utf8), in: stateDirectory, name: "session.json")
        guard case .invalid(let message) = SessionState.loadResult(from: store) else {
            Issue.record("Malformed persistence should be reported as invalid instead of missing.")
            return
        }
        #expect(
            message.contains("session.json"),
            "Invalid-state diagnostics should identify the rejected recovery ledger.")
    }

    @Test
    func sessionStateAtomicMergePreservesConcurrentFields() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-atomic-session")
        defer { try? FileManager.default.removeItem(at: homeStateDirectory) }
        let store = StateDirectory(
            directory: homeStateDirectory.appendingPathComponent("state", isDirectory: true))

        let base = makeSessionState(
            pid: 2003,
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
        try base.save(to: store)
        _ = try SessionState.saveAtomically(in: store) { persisted in
            var requestState = try #require(
                persisted,
                "Atomic request update should load the current session.")
            requestState.requestedTunnelMode = .full
            return requestState
        }

        var controllerState = base
        controllerState.physicalGateway = "192.168.50.1"
        let merged = try SessionState.saveAtomically(in: store) { persisted in
            VPNController.sessionStateForSave(
                currentState: controllerState,
                persistedState: persisted)
        }
        #expect(
            merged.physicalGateway == "192.168.50.1",
            "Atomic controller saves should retain newly captured recovery fields.")
        #expect(
            merged.requestedTunnelMode == .full,
            "Atomic controller saves should preserve a concurrent CLI mode request.")
    }

    @Test
    func sessionStateRejectsUnknownFields() throws {
        let session = makeSessionState(
            pid: 1008,
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

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(session)
        var object = try #require(
            try JSONSerialization.jsonObject(with: data) as? [String: Any],
            "Encoded session state should be a JSON object.")
        #expect(
            object["schemaVersion"] as? Int == 4,
            "Session state should encode only the current schema version.")
        object["unexpected"] = true
        let unexpectedData = try JSONSerialization.data(withJSONObject: object)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        #expect(throws: (any Error).self, "Session state should reject unknown fields.") {
            _ = try decoder.decode(SessionState.self, from: unexpectedData)
        }

        var missingVersion = object
        missingVersion.removeValue(forKey: "unexpected")
        missingVersion.removeValue(forKey: "schemaVersion")
        let missingVersionData = try JSONSerialization.data(withJSONObject: missingVersion)
        #expect(
            throws: (any Error).self, "Session state should require the current schema version."
        ) {
            _ = try decoder.decode(SessionState.self, from: missingVersionData)
        }

        var unsupportedVersion = missingVersion
        unsupportedVersion["schemaVersion"] = 3
        let unsupportedVersionData = try JSONSerialization.data(withJSONObject: unsupportedVersion)
        #expect(
            throws: (any Error).self, "Session state should reject unsupported schema versions."
        ) {
            _ = try decoder.decode(SessionState.self, from: unsupportedVersionData)
        }

        var missingProcessStartTime = missingVersion
        missingProcessStartTime["schemaVersion"] = 4
        missingProcessStartTime.removeValue(forKey: "processStartTime")
        let missingProcessStartTimeData = try JSONSerialization.data(
            withJSONObject: missingProcessStartTime)
        #expect(
            throws: (any Error).self,
            "Session state should require a complete controller process identity."
        ) {
            _ = try decoder.decode(SessionState.self, from: missingProcessStartTimeData)
        }

        var processStartTimeObject = try #require(
            missingVersion["processStartTime"] as? [String: Any],
            "Encoded process start time should be a JSON object.")
        processStartTimeObject["legacyTicks"] = 1
        var unexpectedProcessIdentity = missingVersion
        unexpectedProcessIdentity["schemaVersion"] = 4
        unexpectedProcessIdentity["processStartTime"] = processStartTimeObject
        let unexpectedProcessIdentityData = try JSONSerialization.data(
            withJSONObject: unexpectedProcessIdentity)
        #expect(
            throws: (any Error).self, "Session state should reject unknown process identity fields."
        ) {
            _ = try decoder.decode(SessionState.self, from: unexpectedProcessIdentityData)
        }

        var removedRemoteRoutes = missingVersion
        removedRemoteRoutes["schemaVersion"] = 4
        removedRemoteRoutes["remoteIPv4Routes"] = ["203.0.113.10/32"]
        let removedRemoteRoutesData = try JSONSerialization.data(
            withJSONObject: removedRemoteRoutes)
        #expect(
            throws: (any Error).self, "Session state should reject removed remote-route fields."
        ) {
            _ = try decoder.decode(SessionState.self, from: removedRemoteRoutesData)
        }

        var removedRefresh = missingVersion
        removedRefresh["schemaVersion"] = 4
        removedRefresh["requestedConfigurationRefresh"] = true
        let removedRefreshData = try JSONSerialization.data(withJSONObject: removedRefresh)
        #expect(
            throws: (any Error).self,
            "Session state should reject the removed split-configuration refresh field."
        ) {
            _ = try decoder.decode(SessionState.self, from: removedRefreshData)
        }

        var nestedSession = session
        nestedSession.managedRemoteIPv4Routes = [
            ManagedIPv4Route(
                destination: "203.0.113.10/32",
                nextHopKind: .gateway,
                nextHopValue: "192.168.1.1",
                interfaceName: "en0",
                isInterfaceScoped: false)
        ]
        let nestedData = try encoder.encode(nestedSession)
        var nestedObject = try #require(
            try JSONSerialization.jsonObject(with: nestedData) as? [String: Any],
            "Encoded managed route state should be a JSON object.")
        var nestedRoutes = try #require(
            nestedObject["managedRemoteIPv4Routes"] as? [[String: Any]],
            "Encoded managed route state should contain routes.")
        try #require(
            !nestedRoutes.isEmpty,
            "Encoded managed route state should contain at least one route.")
        var missingScopeObject = nestedObject
        var missingScopeRoutes = nestedRoutes
        missingScopeRoutes[0].removeValue(forKey: "isInterfaceScoped")
        missingScopeObject["managedRemoteIPv4Routes"] = missingScopeRoutes
        let missingScopeData = try JSONSerialization.data(withJSONObject: missingScopeObject)
        #expect(
            throws: (any Error).self,
            "Session state should reject managed routes without explicit interface scope."
        ) {
            _ = try decoder.decode(SessionState.self, from: missingScopeData)
        }
        nestedRoutes[0]["unexpected"] = true
        nestedObject["managedRemoteIPv4Routes"] = nestedRoutes
        let unexpectedNestedData = try JSONSerialization.data(withJSONObject: nestedObject)
        #expect(
            throws: (any Error).self, "Session state should reject unknown managed-route fields."
        ) {
            _ = try decoder.decode(SessionState.self, from: unexpectedNestedData)
        }
    }

    @Test
    func sessionStateSavePreservesPendingModeSwitch() throws {
        let currentSession = makeSessionState(
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
            tunnelMode: .split,
            cleanupNeeded: true
        )

        var persistedSession = currentSession
        persistedSession.requestedTunnelMode = .full
        let preservedSession = VPNController.sessionStateForSave(
            currentState: currentSession,
            persistedState: persistedSession
        )
        #expect(
            preservedSession.requestedTunnelMode == .full,
            "Routine controller saves should preserve a pending mode switch until it is consumed.")

        var staleDeferredSession = currentSession
        staleDeferredSession.requestedTunnelMode = .full
        staleDeferredSession.lastEvent = "MODE_SWITCH_DEFERRED"
        staleDeferredSession.lastInfo = "Mode switch deferred."
        var newerPersistedSession = currentSession
        newerPersistedSession.requestedTunnelMode = .split
        let replacedDeferredSession = VPNController.sessionStateForSave(
            currentState: staleDeferredSession,
            persistedState: newerPersistedSession
        )
        #expect(
            replacedDeferredSession.requestedTunnelMode == .split,
            "Routine controller saves should retain the latest persisted mode request.")
        #expect(
            replacedDeferredSession.lastEvent == nil && replacedDeferredSession.lastInfo == nil,
            "Replacing a deferred request should clear status text for the superseded request.")

        let cancelledDeferredSession = VPNController.sessionStateForSave(
            currentState: staleDeferredSession,
            persistedState: currentSession
        )
        #expect(
            cancelledDeferredSession.requestedTunnelMode == nil,
            "Routine controller saves should honor persisted cancellation of a deferred request.")
        #expect(
            cancelledDeferredSession.lastEvent == nil && cancelledDeferredSession.lastInfo == nil,
            "Cancelling a deferred request should clear its status text.")

        let reaffirmedFullSession = staleDeferredSession.requestingModeSwitch(to: .full)
        #expect(
            reaffirmedFullSession.requestedTunnelMode == .full,
            "A newer mode request should replace the deferred request.")
        #expect(
            reaffirmedFullSession.lastEvent == nil && reaffirmedFullSession.lastInfo == nil,
            "A newer mode request should clear superseded deferred status text.")

        let explicitlyCancelledSession = staleDeferredSession.requestingModeSwitch(to: staleDeferredSession.tunnelMode)
        #expect(
            explicitlyCancelledSession.requestedTunnelMode == .split,
            "Requesting the active mode should serialize cancellation as the desired final mode.")
        #expect(
            explicitlyCancelledSession.lastEvent == nil
                && explicitlyCancelledSession.lastInfo == nil,
            "Cancelling a deferred mode switch should clear its status text.")

        let intentionallyClearedSession = VPNController.sessionStateAfterConsumingModeRequest(
            currentState: currentSession,
            persistedState: persistedSession,
            consumedMode: .full
        )
        #expect(
            intentionallyClearedSession.requestedTunnelMode == nil,
            "Mode-switch completion saves should be able to clear a pending request.")

        var satisfiedSession = currentSession
        satisfiedSession.tunnelMode = .full
        let alreadySatisfiedSession = VPNController.sessionStateAfterConsumingModeRequest(
            currentState: satisfiedSession,
            persistedState: persistedSession,
            consumedMode: .full
        )
        #expect(
            alreadySatisfiedSession.requestedTunnelMode == nil,
            "Completing a mode request should clear it when its target is active.")

        let supersededCompletionSession = VPNController.sessionStateAfterConsumingModeRequest(
            currentState: satisfiedSession,
            persistedState: newerPersistedSession,
            consumedMode: .full
        )
        #expect(
            supersededCompletionSession.requestedTunnelMode == .split,
            "Completing an older request should retain a newer request for the opposite mode.")

        let completedSplitSession = VPNController.sessionStateAfterConsumingModeRequest(
            currentState: currentSession,
            persistedState: newerPersistedSession,
            consumedMode: .split
        )
        #expect(
            completedSplitSession.requestedTunnelMode == nil,
            "Completing the pending split request should clear it.")

        var cancelledFullToSplitSession = currentSession
        cancelledFullToSplitSession.tunnelMode = .full
        cancelledFullToSplitSession.requestedTunnelMode = .full
        let completedCancelledSplitSession = VPNController.sessionStateAfterConsumingModeRequest(
            currentState: currentSession,
            persistedState: cancelledFullToSplitSession,
            consumedMode: .split
        )
        #expect(
            completedCancelledSplitSession.requestedTunnelMode == .full,
            "Completing full-to-split should retain a newer request that cancels back to full.")

        var cancelledSplitToFullSession = currentSession
        cancelledSplitToFullSession.requestedTunnelMode = .split
        let completedCancelledFullSession = VPNController.sessionStateAfterConsumingModeRequest(
            currentState: satisfiedSession,
            persistedState: cancelledSplitToFullSession,
            consumedMode: .full
        )
        #expect(
            completedCancelledFullSession.requestedTunnelMode == .split,
            "Completing split-to-full should retain a newer request that cancels back to split.")
    }

    @Test
    func sessionStatePhysicalNetworkMigration() throws {
        let currentSession = makeSessionState(
            pid: 1006,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: [],
            originalSearchDomains: [],
            originalDefaultSearchDomains: [],
            originalIPv6Mode: "Automatic",
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )

        let sameServiceMigration = VPNController.sessionStateForPhysicalNetworkChange(
            currentState: currentSession,
            physicalNetwork: PhysicalNetwork(gateway: "172.20.192.1", interfaceName: "en0"),
            physicalDNSConfiguration: PhysicalDNSConfiguration(
                serviceName: "Wi-Fi",
                dnsServers: [],
                searchDomains: ["case.edu"],
                ipv6Mode: "Off"),
            activeDefaultSearchDomains: ["case.edu"]
        )
        #expect(
            sameServiceMigration.changed,
            "Physical network migration should detect gateway changes on the same service.")
        #expect(
            !sameServiceMigration.shouldRestorePreviousService,
            "Same-service gateway changes should not restore the service before split repair.")
        #expect(
            sameServiceMigration.state.physicalGateway == "172.20.192.1",
            "Physical network migration should update the captured gateway.")
        #expect(
            sameServiceMigration.state.originalIPv6Mode == "Automatic",
            "Same-service migration should preserve the pre-VPN IPv6 mode instead of recording managed Off as original."
        )
        #expect(
            sameServiceMigration.state.originalSearchDomains == ["case.edu"],
            "Physical network migration should capture current service search domains.")

        let sameGatewayDNSMigration = VPNController.sessionStateForPhysicalNetworkChange(
            currentState: currentSession,
            physicalNetwork: PhysicalNetwork(gateway: "172.20.10.1", interfaceName: "en0"),
            physicalDNSConfiguration: PhysicalDNSConfiguration(
                serviceName: "Wi-Fi",
                dnsServers: ["192.168.50.1"],
                searchDomains: ["lan"],
                ipv6Mode: "Off"),
            activeDefaultSearchDomains: ["lan"]
        )
        #expect(
            sameGatewayDNSMigration.changed,
            "Physical network migration should detect DNS changes even when gateway and interface are unchanged."
        )
        #expect(
            !sameGatewayDNSMigration.shouldRestorePreviousService,
            "Same-service DNS changes should not restore the service before split repair.")
        #expect(
            sameGatewayDNSMigration.state.originalDNSServers == ["192.168.50.1"],
            "Physical network migration should refresh the captured DNS servers.")
        #expect(
            sameGatewayDNSMigration.state.originalIPv6Mode == "Automatic",
            "Same-service DNS changes should preserve the pre-VPN IPv6 mode instead of recording managed Off as original."
        )
        #expect(
            !sameGatewayDNSMigration.transportAffecting,
            "A DNS-only change with the same gateway and interface must not be transport-affecting, so it triggers a resolver refresh without an OpenVPN reconnect."
        )

        let newServiceMigration = VPNController.sessionStateForPhysicalNetworkChange(
            currentState: currentSession,
            physicalNetwork: PhysicalNetwork(gateway: "172.21.0.1", interfaceName: "en19"),
            physicalDNSConfiguration: PhysicalDNSConfiguration(
                serviceName: "iPhone USB",
                dnsServers: ["172.21.0.1"],
                searchDomains: [],
                ipv6Mode: "Link-local only"),
            activeDefaultSearchDomains: []
        )
        #expect(
            newServiceMigration.changed,
            "Physical network migration should detect service changes.")
        #expect(
            newServiceMigration.shouldRestorePreviousService,
            "Service changes should restore the previously managed service before moving split policy."
        )
        #expect(
            newServiceMigration.state.physicalInterface == "en19",
            "Physical network migration should update the captured interface.")
        #expect(
            newServiceMigration.state.physicalServiceName == "iPhone USB",
            "Physical network migration should update the active service name.")
        #expect(
            newServiceMigration.state.originalIPv6Mode == "Link-local only",
            "Service changes should capture the new service IPv6 mode for cleanup.")
        #expect(
            newServiceMigration.transportAffecting,
            "A gateway/interface change must be transport-affecting so the OpenVPN transport reconnects after the physical network moves."
        )
    }

    @Test
    func fullTunnelMigrationFreezesDNSLedger() throws {
        var fullSession = makeSessionState(
            pid: 1106,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["208.67.220.220", "208.67.222.222"],
            originalSearchDomains: ["personal.example"],
            originalDefaultSearchDomains: ["case.edu"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        fullSession.fullTunnelDNSServers = ["129.22.4.32", "129.22.104.132"]

        let stableCapture = VPNController.sessionStateForPhysicalNetworkChange(
            currentState: fullSession,
            physicalNetwork: PhysicalNetwork(gateway: "172.20.10.1", interfaceName: "en0"),
            physicalDNSConfiguration: PhysicalDNSConfiguration(
                serviceName: "Wi-Fi",
                dnsServers: ["129.22.4.32", "129.22.104.132"],
                searchDomains: ["case.edu"],
                ipv6Mode: "Off"),
            activeDefaultSearchDomains: ["case.edu"]
        )
        #expect(
            !stableCapture.changed,
            "Full tunnel must not treat its own CWRU DNS override as a physical-network change.")
        #expect(
            stableCapture.state.originalDNSServers == ["208.67.220.220", "208.67.222.222"],
            "Full tunnel must keep the real physical DNS ledger instead of recording the CWRU override."
        )

        let roamingCapture = VPNController.sessionStateForPhysicalNetworkChange(
            currentState: fullSession,
            physicalNetwork: PhysicalNetwork(gateway: "172.20.192.1", interfaceName: "en0"),
            physicalDNSConfiguration: PhysicalDNSConfiguration(
                serviceName: "Wi-Fi",
                dnsServers: ["129.22.4.32", "129.22.104.132"],
                searchDomains: ["case.edu"],
                ipv6Mode: "Off"),
            activeDefaultSearchDomains: ["case.edu"]
        )
        #expect(
            roamingCapture.changed,
            "Full tunnel must still detect a physical gateway change on the same service.")
        #expect(
            roamingCapture.state.physicalGateway == "172.20.192.1",
            "Full tunnel migration should update the captured gateway when it changes.")
        #expect(
            roamingCapture.state.originalDNSServers == fullSession.originalDNSServers,
            "Full tunnel must preserve the user's service-level DNS settings across a gateway change."
        )
        #expect(
            roamingCapture.state.originalSearchDomains == fullSession.originalSearchDomains,
            "Full tunnel must preserve the user's service-level search domains across a gateway change.")
        #expect(roamingCapture.state.originalDefaultSearchDomains == nil)

        let system = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.20.192.1",
            physicalInterface: "en0",
            physicalDNSServers: ["129.22.4.32", "129.22.104.132"],
            physicalSearchDomains: ["case.edu"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"]
        )
        try Shell.withCommandHandler({ try system.handle($0) }) {
            let manager = makeRouteManager()
            try manager.restoreDNSConfiguration(using: roamingCapture.state)
            let configuration = try manager.currentDNSConfiguration(using: roamingCapture.state)
            let restored = try #require(configuration)
            #expect(restored.dnsServers == fullSession.originalDNSServers)
            #expect(restored.searchDomains == fullSession.originalSearchDomains)
        }

        let newServiceCapture = VPNController.sessionStateForPhysicalNetworkChange(
            currentState: fullSession,
            physicalNetwork: PhysicalNetwork(gateway: "172.21.0.1", interfaceName: "en19"),
            physicalDNSConfiguration: PhysicalDNSConfiguration(
                serviceName: "iPhone USB",
                dnsServers: ["172.21.0.1"],
                searchDomains: [],
                ipv6Mode: "Link-local only"),
            activeDefaultSearchDomains: []
        )
        #expect(
            newServiceCapture.state.originalDNSServers == ["172.21.0.1"],
            "Full tunnel must capture the new service's real DNS when the physical service changes."
        )
    }

    @Test
    func newSessionCannotOverwriteRecoveryState() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-session-create")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory)
        let session = makeSessionState(
            pid: Int32.max - 20, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalServiceName: "Wi-Fi", originalDNSServers: [], originalSearchDomains: [],
            originalIPv6Mode: "Automatic", tunName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        try session.create(to: store)
        var replacement = session
        replacement.pid -= 1
        #expect(throws: SessionStateError.self) { try replacement.create(to: store) }
        #expect(SessionState.load(from: store)?.pid == session.pid)
    }
}
