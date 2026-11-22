import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct SessionStatePersistenceTests {
    @Test
    func unchangedSessionSavePreservesTheLedgerFile() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-session-save")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory.appendingPathComponent("state"))
        var session = makeSessionState(
            pid: 1008, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Automatic",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        try session.save(in: store)
        let path = store.url.appendingPathComponent(SessionState.fileName).path
        let initial = try FileManager.default.attributesOfItem(atPath: path)[.systemFileNumber] as? NSNumber
        try #require(initial != nil)
        try session.save(in: store)
        #expect(try FileManager.default.attributesOfItem(atPath: path)[.systemFileNumber] as? NSNumber == initial)

        session.modeRequest = ModeRequest(id: UUID(), mode: .full)
        try session.save(in: store)
        #expect(SessionState.load(from: store)?.requestedTunnelMode == .full)
        #expect(try FileManager.default.attributesOfItem(atPath: path)[.systemFileNumber] as? NSNumber != initial)
    }

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
            lastEventName: nil,
            diagnosticDetail: nil,
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0", physicalServiceID: "service-en0",
            physicalServiceName: nil,
            originalDNSServers: nil,
            originalSearchDomains: nil,
            originalIPv6Mode: nil,
            tunnelName: nil,
            vpnIPv4: nil,
            serverHost: nil,
            connectedServerAddress: nil,
            tunnelMode: .split,

            appliedSplitIPv4Routes: nil,
            appliedScopedDNSDomains: nil,
            cleanupNeeded: false
        )

        session.markRecoveryRequired(message: "Cleanup failed.")

        #expect(
            session.phase == .failed,
            "markRecoveryRequired should set the session phase to failed.")
        #expect(
            session.lastEventName == "RECOVERY_REQUIRED",
            "markRecoveryRequired should persist a recovery event marker.")
        #expect(
            session.diagnosticDetail == "Cleanup failed.",
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
            RuntimePaths.privilegedStateDirectory.path == "/private/var/db/cwru-ovpn",
            "Privileged recovery state must live in persistent root-owned storage."
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
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.appliedScopedDNSDomains = (0..<400).map {
            "\(String(repeating: "a", count: 220))\($0).case.edu"
        }

        do {
            try session.save(in: store)
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

        guard case .missing = SessionState.loadResult(from: store) else {
            Issue.record("An absent recovery ledger should be reported as missing.")
            return
        }
        #expect(!FileManager.default.fileExists(atPath: stateDirectory.path))
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
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        try base.save(in: store)
        _ = try SessionState.saveAtomically(in: store) { persisted in
            var requestState = try #require(
                persisted,
                "Atomic request update should load the current session.")
            requestState.modeRequest = ModeRequest(id: UUID(), mode: .full)
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
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(session)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        var unexpected = object
        unexpected["unexpected"] = true
        let unexpectedData = try JSONSerialization.data(withJSONObject: unexpected)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        #expect(throws: (any Error).self, "Session state should reject unknown fields.") {
            _ = try decoder.decode(SessionState.self, from: unexpectedData)
        }

        var missingService = object
        missingService.removeValue(forKey: "physicalServiceID")
        let missingServiceData = try JSONSerialization.data(withJSONObject: missingService)
        #expect(throws: DecodingError.self) { _ = try decoder.decode(SessionState.self, from: missingServiceData) }

        var missingProcessStartTime = object
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
            object["processStartTime"] as? [String: Any],
            "Encoded process start time should be a JSON object.")
        processStartTimeObject["unexpected"] = 1
        var unexpectedProcessIdentity = object
        unexpectedProcessIdentity["processStartTime"] = processStartTimeObject
        let unexpectedProcessIdentityData = try JSONSerialization.data(
            withJSONObject: unexpectedProcessIdentity)
        #expect(
            throws: (any Error).self, "Session state should reject unknown process identity fields."
        ) {
            _ = try decoder.decode(SessionState.self, from: unexpectedProcessIdentityData)
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
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )

        var persistedSession = currentSession
        persistedSession.modeRequest = ModeRequest(id: UUID(), mode: .full)
        let preservedSession = VPNController.sessionStateForSave(
            currentState: currentSession,
            persistedState: persistedSession
        )
        #expect(
            preservedSession.requestedTunnelMode == .full,
            "Routine controller saves should preserve a pending mode switch until it is consumed.")

        var staleDeferredSession = currentSession
        staleDeferredSession.modeRequest = ModeRequest(id: UUID(), mode: .full)
        staleDeferredSession.lastEventName = "MODE_SWITCH_DEFERRED"
        staleDeferredSession.diagnosticDetail = "Mode switch deferred."
        var newerPersistedSession = currentSession
        newerPersistedSession.modeRequest = ModeRequest(id: UUID(), mode: .split)
        let replacedDeferredSession = VPNController.sessionStateForSave(
            currentState: staleDeferredSession,
            persistedState: newerPersistedSession
        )
        #expect(
            replacedDeferredSession.requestedTunnelMode == .split,
            "Routine controller saves should retain the latest persisted mode request.")
        #expect(
            replacedDeferredSession.lastEventName == nil && replacedDeferredSession.diagnosticDetail == nil,
            "Replacing a deferred request should clear status text for the superseded request.")

        let cancelledDeferredSession = VPNController.sessionStateForSave(
            currentState: staleDeferredSession,
            persistedState: currentSession
        )
        #expect(
            cancelledDeferredSession.requestedTunnelMode == nil,
            "Routine controller saves should honor persisted cancellation of a deferred request.")
        #expect(
            cancelledDeferredSession.lastEventName == nil && cancelledDeferredSession.diagnosticDetail == nil,
            "Cancelling a deferred request should clear its status text.")

        let reaffirmedFullSession = staleDeferredSession.requestingModeSwitch(to: .full)
        #expect(
            reaffirmedFullSession.requestedTunnelMode == .full,
            "A newer mode request should replace the deferred request.")
        #expect(
            reaffirmedFullSession.lastEventName == nil && reaffirmedFullSession.diagnosticDetail == nil,
            "A newer mode request should clear superseded deferred status text.")

        let explicitlyCancelledSession = staleDeferredSession.requestingModeSwitch(to: staleDeferredSession.tunnelMode)
        #expect(
            explicitlyCancelledSession.requestedTunnelMode == .split,
            "Requesting the active mode should serialize cancellation as the desired final mode.")
        #expect(
            explicitlyCancelledSession.lastEventName == nil
                && explicitlyCancelledSession.diagnosticDetail == nil,
            "Cancelling a deferred mode switch should clear its status text.")

        var superseded = explicitlyCancelledSession
        let earlier = try #require(reaffirmedFullSession.modeRequest)
        let pending = superseded.modeRequest
        superseded.finish(earlier, outcome: .applied)
        #expect(superseded.modeRequest == pending)
        #expect(superseded.modeReceipts.last?.id == earlier.id)
    }

    @Test
    func physicalIPv6BaselineFollowsNetworkOwnership() throws {
        for mode in [AppTunnelMode.split, .full] {
            var session = makeSessionState(
                pid: 1007, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
                physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
                originalDNSServers: [], originalSearchDomains: [], originalDefaultSearchDomains: [],
                originalIPv6Mode: "Automatic", tunnelName: "utun7", tunnelMode: mode, cleanupNeeded: true)
            if mode == .full { session.recordIPv6Override() }
            let system = MockSystem(
                serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
                physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: ["utun7"])
            let manager = RouteManager(serviceStore: system, commandRunner: CommandRunner(handler: system.handle))
            let configuration = try #require(try manager.serviceStore.activeService(for: "en0"))
            let migration = VPNController.sessionStateForPhysicalNetworkChange(
                currentState: session,
                physicalNetwork: PhysicalNetwork(gateway: "192.168.1.1", interfaceName: "en0"),
                physicalDNSConfiguration: configuration, activeDefaultSearchDomains: [])

            #expect(migration.changed == (mode == .split))
            #expect(!migration.transportAffecting)
            #expect(!migration.shouldRestorePreviousService)
            try manager.restoreService(.ipv6, using: migration.state)
            #expect(try manager.ipv6Mode(forServiceID: "service-en0") == (mode == .split ? "Off" : "Automatic"))
            if mode == .split {
                #expect(!system.recordedCommands.contains { $0.contains("IPv6 ") })
            }
        }
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
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )

        let sameServiceMigration = VPNController.sessionStateForPhysicalNetworkChange(
            currentState: currentSession,
            physicalNetwork: PhysicalNetwork(gateway: "172.20.192.1", interfaceName: "en0"),
            physicalDNSConfiguration: PhysicalServiceConfiguration(
                serviceID: "service-en0", serviceName: "Wi-Fi",
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
            sameServiceMigration.state.originalIPv6Mode == "Off",
            "Split mode should capture the current physical IPv6 mode because it does not manage that setting."
        )
        #expect(
            sameServiceMigration.state.originalSearchDomains == ["case.edu"],
            "Physical network migration should capture current service search domains.")

        let sameGatewayDNSMigration = VPNController.sessionStateForPhysicalNetworkChange(
            currentState: currentSession,
            physicalNetwork: PhysicalNetwork(gateway: "172.20.10.1", interfaceName: "en0"),
            physicalDNSConfiguration: PhysicalServiceConfiguration(
                serviceID: "service-en0", serviceName: "Wi-Fi",
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
            sameGatewayDNSMigration.state.originalIPv6Mode == "Off",
            "Split mode should refresh the physical IPv6 baseline alongside DNS settings."
        )
        #expect(
            !sameGatewayDNSMigration.transportAffecting,
            "A DNS-only change with the same gateway and interface must not be transport-affecting, so it triggers a resolver refresh without an OpenVPN reconnect."
        )

        let newServiceMigration = VPNController.sessionStateForPhysicalNetworkChange(
            currentState: currentSession,
            physicalNetwork: PhysicalNetwork(gateway: "172.21.0.1", interfaceName: "en19"),
            physicalDNSConfiguration: PhysicalServiceConfiguration(
                serviceID: "service-en19", serviceName: "iPhone USB",
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
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        fullSession.recordDNSOverride(servers: ["129.22.4.32", "129.22.104.132"], domains: ["case.edu"])
        fullSession.pendingDNSWithdrawal.servers = ["129.22.4.32", "129.22.104.132"]

        let stableCapture = VPNController.sessionStateForPhysicalNetworkChange(
            currentState: fullSession,
            physicalNetwork: PhysicalNetwork(gateway: "172.20.10.1", interfaceName: "en0"),
            physicalDNSConfiguration: PhysicalServiceConfiguration(
                serviceID: "service-en0", serviceName: "Wi-Fi",
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
            physicalDNSConfiguration: PhysicalServiceConfiguration(
                serviceID: "service-en0", serviceName: "Wi-Fi",
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
        try CommandRunner.withCommandHandler(system: system, system.handle) {
            let manager = makeRouteManager()
            try manager.restoreService(.dns, using: roamingCapture.state)
            let restored = try manager.currentDNSSettings(using: roamingCapture.state)
            #expect(restored.dnsServers == fullSession.originalDNSServers)
            #expect(restored.searchDomains == fullSession.originalSearchDomains)
        }

        let newServiceCapture = VPNController.sessionStateForPhysicalNetworkChange(
            currentState: fullSession,
            physicalNetwork: PhysicalNetwork(gateway: "172.21.0.1", interfaceName: "en19"),
            physicalDNSConfiguration: PhysicalServiceConfiguration(
                serviceID: "service-en19", serviceName: "iPhone USB",
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
            originalIPv6Mode: "Automatic", tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        try session.create(in: store)
        var replacement = session
        replacement.pid -= 1
        #expect(throws: SessionStateError.self) { try replacement.create(in: store) }
        #expect(SessionState.load(from: store)?.pid == session.pid)
    }
}
