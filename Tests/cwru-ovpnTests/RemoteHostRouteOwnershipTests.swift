import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct RemoteHostRouteOwnershipTests {
    @Test
    func transportEndpointRotationPreparesOnlyTheActivePeer() throws {
        var state = makeSessionState(
            pid: 1076, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.0.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Automatic",
            tunnelName: "utun7", tunnelMode: .full, cleanupNeeded: true)
        state.serverIP = "207.182.159.130"
        let peers = ["207.182.159.131", "207.182.159.132", "67.219.145.198", "207.182.159.130"]
        var persisted = state
        let mock = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.0.1", physicalInterface: "en0",
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"], initialRoutes: [
                .init(destination: "0.0.0.0/1", gateway: "10.8.0.1", interfaceName: "utun7"),
                .init(destination: "128.0.0.0/1", gateway: "10.8.0.1", interfaceName: "utun7"),
            ])
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/sbin/route", invocation.arguments.contains("add") {
                let destination = invocation.arguments[3]
                #expect(persisted.managedRemoteIPv4Routes?.contains {
                    IPRoute.canonicalIPv4($0.destination) == IPRoute.canonicalIPv4(destination)
                } == true)
            }
            return try mock.handle(invocation)
        }) {
            let manager = makeRouteManager()
            for peer in peers {
                try manager.prepareTransportEndpoint(peer, using: &state) { prepared in
                    persisted = prepared
                    try persistPreparedState(prepared)
                }
                #expect(state.serverIP == "207.182.159.130")
                #expect(state.transportServerIP == peer)
                #expect(state.managedRemoteIPv4Routes?.filter { $0.nextHopKind == .gateway }.map(\.destination) == ["\(peer)/32"])
                let entries = try manager.ipv4RoutingTableEntries()
                #expect(entries.filter { $0.interfaceName == "utun7" }.count == 2)
                for old in peers where old != peer {
                    #expect(!entries.contains { IPRoute.canonicalIPv4($0.destination)?.routeString == "\(old)/32" && $0.interfaceName == "en0" })
                }
            }
        }
    }

    @Test(arguments: ["wrong-interface", "persistence-failure"])
    func endpointPreparationRejectsUnverifiedEgressAndPersistence(scenario: String) throws {
        var state = makeSessionState(
            pid: 1077, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.0.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Automatic",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        let mock = MockSystem(serviceName: "Wi-Fi", physicalGateway: "192.168.0.1", physicalInterface: "en0",
                              physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Automatic",
                              tunnelInterfaces: ["utun7"])
        try CommandRunner.withCommandHandler({ invocation in
            if scenario == "wrong-interface", invocation.launchPath == "/sbin/route",
               invocation.arguments == ["-n", "get", "207.182.159.131"] {
                return CommandResult(exitCode: 0, stdout: "gateway: 10.0.0.1\ninterface: en1\n", stderr: "")
            }
            return try mock.handle(invocation)
        }) {
            _ = #expect(throws: RouteManagerError.self) {
                try makeRouteManager().prepareTransportEndpoint("207.182.159.131", using: &state) { prepared in
                    if scenario == "persistence-failure" { throw RouteManagerError.failedToSecureControlChannel }
                    try persistPreparedState(prepared)
                }
            }
        }
        if scenario == "persistence-failure" {
            #expect(mock.recordedCommands.allSatisfy { !$0.contains(" add ") && !$0.contains(" delete ") })
        } else {
            #expect(state.managedRemoteIPv4Routes?.first?.destination == "207.182.159.131/32")
        }
    }

    @Test(arguments: ["success", "foreign", "missing-add", "ignored-delete"])
    func physicalRouteRefreshPreservesOwnershipAndRejectsIncompleteRepair(scenario: String) throws {
        var state = makeSessionState(
            pid: 1078, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.0.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Automatic",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.transportServerIP = "207.182.159.130"
        state.managedRemoteIPv4Routes = [ManagedIPv4Route(
            destination: "207.182.159.130/32", nextHopKind: .gateway, nextHopValue: "192.168.0.1",
            interfaceName: "en0", isInterfaceScoped: false)]
        let mock = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.0.1", physicalInterface: "en0",
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            ignoredRouteDeletes: scenario == "ignored-delete" ? ["207.182.159.130"] : [],
            initialRoutes: [
                .init(destination: "207.182.159.130/32",
                      gateway: scenario == "foreign" ? "192.168.0.2" : "192.168.0.1",
                      interfaceName: "en0", flags: "UGHS"),
                .init(destination: "129.22.0.0/16", gateway: "link#22", interfaceName: "utun7", flags: "USc"),
                .init(destination: "8.8.4.4/32", gateway: "192.168.0.1", interfaceName: "en0", flags: "UGHS"),
            ])
        try CommandRunner.withCommandHandler({ invocation in
            if scenario == "missing-add", invocation.launchPath == "/sbin/route",
               invocation.arguments.contains("add"), invocation.arguments.contains("207.182.159.130") {
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }
            return try mock.handle(invocation)
        }) {
            let manager = makeRouteManager()
            if scenario == "success" || scenario == "foreign" {
                try manager.refreshPhysicalRoutes(using: &state, persistPreparedState: persistPreparedState)
            } else {
                #expect(throws: RouteManagerError.self) {
                    try manager.refreshPhysicalRoutes(using: &state, persistPreparedState: persistPreparedState)
                }
            }
            let entries = try manager.ipv4RoutingTableEntries()
            #expect(entries.contains { $0.destination == "129.22.0.0/16" && $0.interfaceName == "utun7" })
            #expect(entries.contains { $0.destination == "8.8.4.4/32" && $0.gateway == "192.168.0.1" })
            if scenario == "foreign" {
                #expect(
                    entries.filter { $0.destination == "207.182.159.130/32" }.map(\.gateway) == ["192.168.0.1"],
                    "Refresh must secure the control-channel route by the same rule as setup, replacing a foreign route.")
                #expect(
                    state.replacedRemoteIPv4Routes == [ManagedIPv4Route(
                        destination: "207.182.159.130/32", nextHopKind: .gateway, nextHopValue: "192.168.0.2",
                        interfaceName: "en0", isInterfaceScoped: false)],
                    "A foreign route replaced during refresh must be recorded for restoration.")
            }
            if scenario == "success" {
                #expect(mock.recordedCommands.contains("/sbin/route -n delete -host 207.182.159.130 192.168.0.1"))
                #expect(mock.recordedCommands.contains("/sbin/route -n add -host 207.182.159.130 192.168.0.1"))
            }
        }
    }

    @Test
    func physicalRouteRefreshIgnoresGatewayNeighborEntriesOnOtherInterfaces() throws {
        var state = makeSessionState(
            pid: 1079, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.0.1", physicalInterface: "en0", physicalServiceName: "Ethernet",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Automatic",
            tunnelName: "utun7", tunnelMode: .full, cleanupNeeded: true)
        state.transportServerIP = "207.182.159.130"
        let serverRoute = ManagedIPv4Route(
            destination: "207.182.159.130/32", nextHopKind: .gateway, nextHopValue: "192.168.0.1",
            interfaceName: "en0", isInterfaceScoped: false)
        let gatewayRoute = ManagedIPv4Route(destination: "192.168.0.1/32", viaInterface: "en0")
        state.managedRemoteIPv4Routes = [serverRoute, gatewayRoute]
        let mock = MockSystem(
            serviceName: "Ethernet", physicalGateway: "192.168.0.1", physicalInterface: "en0",
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                .init(destination: "207.182.159.130/32", gateway: "192.168.0.1", interfaceName: "en0", flags: "UGHS"),
                .init(destination: "192.168.0.1/32", gateway: "link#1", interfaceName: "en0", flags: "UHS"),
                .init(destination: "192.168.0.1", gateway: "aa:bb:cc:dd:ee:ff", interfaceName: "en1", flags: "UHLWIir"),
            ])
        try CommandRunner.withCommandHandler(mock.handle) {
            let manager = makeRouteManager()
            try manager.refreshPhysicalRoutes(using: &state, persistPreparedState: persistPreparedState)
            let entries = try manager.ipv4RoutingTableEntries()
            for route in [serverRoute, gatewayRoute] {
                #expect(
                    manager.ownedManagedIPv4RouteExists(route, in: entries, requiresHostFlag: true),
                    "Refresh must reinstall \(route.destination) while another interface holds a neighbor entry for the gateway.")
            }
            #expect(state.managedRemoteIPv4Routes == [serverRoute, gatewayRoute])
            #expect(state.replacedRemoteIPv4Routes == nil)
            #expect(mock.recordedCommands.contains("/sbin/route -n delete -host 192.168.0.1 -interface en0"))
            #expect(mock.recordedCommands.contains("/sbin/route -n add -host 192.168.0.1 -interface en0"))
        }
    }

    @Test
    func splitTunnelProtectsRemoteHostRoutesAfterRepair() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1081,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["172.20.10.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.133"

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalDNSServers: ["172.20.10.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "192.168.0.1",
                    interfaceName: "en0",
                    flags: "UGHSI"),
                MockSystem.RouteRecord(
                    destination: "67.219.145.198/32",
                    gateway: "192.168.0.1",
                    interfaceName: "en0",
                    flags: "UGHSI"),
            ])

        try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            let changed = try RouteManager(splitTunnelPolicy: configuration)
                .ensureRemoteHostRoutes(
                    using: &session,
                    mode: .split,
                    context: "split route repair",
                    persistPreparedState: persistPreparedState)
            #expect(
                changed,
                "Split repair should rewrite stale VPN remote host routes through the current physical gateway."
            )
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 207.182.159.133 192.168.0.1 -ifscope en0"),
            "Split repair should delete a scoped server route through a stale physical gateway before replacing it."
        )
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 207.182.159.133 172.20.10.1"),
            "Split repair should protect the active VPN server host route through the current physical gateway."
        )
        #expect(
            !mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 67.219.145.198 172.20.10.1"),
            "Pre-existing host routes must not become VPN control-channel exceptions.")
        #expect(
            session.replacedRemoteIPv4Routes?.contains(
                ManagedIPv4Route(
                    destination: "207.182.159.133/32",
                    nextHopKind: .gateway,
                    nextHopValue: "192.168.0.1",
                    interfaceName: "en0",
                    isInterfaceScoped: true)) == true,
            "Split repair should ledger the stale scoped route for exact restoration on cleanup.")
        #expect(
            session.managedRemoteIPv4Routes?.contains(
                ManagedIPv4Route(
                    destination: "207.182.159.133/32",
                    nextHopKind: .gateway,
                    nextHopValue: "172.20.10.1",
                    interfaceName: "en0",
                    isInterfaceScoped: false)) == true,
            "Split repair should ledger the replacement route as cwru-ovpn-owned.")
    }

    @Test
    func remoteCIDRHostRouteIsAcceptedWithoutHostFlag() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1094,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.133"
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "192.168.1.1",
                    interfaceName: "en0",
                    flags: "UGSc")
            ])

        let changed = try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration)
                .ensureRemoteHostRoutes(
                    using: &session,
                    mode: .split,
                    context: "CIDR host route repair",
                    persistPreparedState: persistPreparedState)
        }

        #expect(
            !changed,
            "A static physical /32 should already protect the VPN endpoint even when netstat omits the H flag."
        )
        #expect(
            session.managedRemoteIPv4Routes == nil && session.replacedRemoteIPv4Routes == nil,
            "An existing safe OpenVPN /32 must not be claimed or recorded for restoration.")
        #expect(
            !mockSystem.recordedCommands.contains(where: {
                $0.hasPrefix("/sbin/route -n delete -host 207.182.159.133")
                    || $0.hasPrefix("/sbin/route -n add -host 207.182.159.133")
            }),
            "An existing safe OpenVPN /32 must not be replaced.")
    }

    @Test
    func remoteHostRouteMigrationRespectsPhysicalInterface() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1091,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en1",
            physicalServiceName: "Ethernet",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.133"
        let managedRoute = ManagedIPv4Route(
            destination: "207.182.159.133/32",
            nextHopKind: .gateway,
            nextHopValue: "192.168.1.1",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let replacedRoute = ManagedIPv4Route(
            destination: "207.182.159.133/32",
            nextHopKind: .gateway,
            nextHopValue: "192.168.0.1",
            interfaceName: "en0",
            isInterfaceScoped: false)
        session.managedRemoteIPv4Routes = [managedRoute]
        session.replacedRemoteIPv4Routes = [replacedRoute]

        let mockSystem = MockSystem(
            serviceName: "Ethernet",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en1",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "192.168.1.1",
                    interfaceName: "en0",
                    flags: "UGHS")
            ])

        try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            let changed = try RouteManager(splitTunnelPolicy: configuration)
                .ensureRemoteHostRoutes(
                    using: &session,
                    mode: .split,
                    context: "same-gateway interface migration",
                    persistPreparedState: persistPreparedState)
            #expect(
                changed,
                "A same-gateway physical-interface change should replace the stale host route.")
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 207.182.159.133 192.168.1.1"),
            "Remote route migration should delete only the stale physical-interface instance.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 207.182.159.133 192.168.1.1"),
            "Remote route migration should reinstall the host route through the current physical interface."
        )
        #expect(
            !mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 207.182.159.133 192.168.0.1"),
            "Remote route migration should defer restoration while the same endpoint remains active."
        )
        #expect(
            session.replacedRemoteIPv4Routes == [replacedRoute],
            "Remote route migration should retain the prior owner for final cleanup.")
        #expect(
            session.managedRemoteIPv4Routes?.contains(
                ManagedIPv4Route(
                    destination: "207.182.159.133/32",
                    nextHopKind: .gateway,
                    nextHopValue: "192.168.1.1",
                    interfaceName: "en1",
                    isInterfaceScoped: false)
            ) == true,
            "Remote route migration should ledger only the current-interface route as app-owned.")
    }

    @Test
    func remoteRouteReplacementKeepsRecoveryLedgerOnDeleteFailure() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1090,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["172.20.10.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.133"
        let oldRoute = ManagedIPv4Route(
            destination: "207.182.159.133/32",
            nextHopKind: .gateway,
            nextHopValue: "192.168.0.1",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let desiredRoute = ManagedIPv4Route(
            destination: "207.182.159.133/32",
            nextHopKind: .gateway,
            nextHopValue: "172.20.10.1",
            interfaceName: "en0",
            isInterfaceScoped: false)
        session.managedRemoteIPv4Routes = [oldRoute]
        var persistedLedgers: [[ManagedIPv4Route]] = []

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalDNSServers: ["172.20.10.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            ignoredRouteDeletes: ["207.182.159.133"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "192.168.0.1",
                    interfaceName: "en0",
                    flags: "UGHS")
            ])

        do {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                _ = try RouteManager(splitTunnelPolicy: configuration)
                    .ensureRemoteHostRoutes(
                        using: &session,
                        mode: .split,
                        context: "failed replacement",
                        persistPreparedState: { persisted in
                            persistedLedgers.append(persisted.managedRemoteIPv4Routes ?? [])
                        })
            }
            try #require(
                Bool(false),
                "Remote route replacement should fail if the exact old route survives deletion.")
        } catch RouteManagerError.failedToDeleteManagedRoute(let destination) {
            #expect(
                destination == oldRoute.destination,
                "Remote route replacement should identify the undeleted route.")
        }

        #expect(
            Set(session.managedRemoteIPv4Routes ?? []) == Set([oldRoute]),
            "A failed stale-route reconciliation must preserve the existing recovery ledger.")
        #expect(
            !persistedLedgers.contains { $0.contains(desiredRoute) },
            "A failed stale-route reconciliation must not stage a replacement route.")
        #expect(
            !mockSystem.recordedCommands.contains(where: {
                $0.hasPrefix("/sbin/route -n add -host 207.182.159.133 ")
            }),
            "A replacement must not proceed after the old route failed post-delete verification.")
    }

    @Test
    func remoteRouteLedgerRejectsThirdLogicalKeyBeforeMutation() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1097,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["172.20.10.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.135"
        let deferredRoutes = [
            ManagedIPv4Route(
                destination: "207.182.159.133/32",
                nextHopKind: .gateway,
                nextHopValue: "192.168.0.1",
                interfaceName: "en0",
                isInterfaceScoped: false),
            ManagedIPv4Route(
                destination: "207.182.159.134/32",
                nextHopKind: .gateway,
                nextHopValue: "192.168.0.1",
                interfaceName: "en0",
                isInterfaceScoped: false),
        ]
        session.replacedRemoteIPv4Routes = deferredRoutes

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalDNSServers: ["172.20.10.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "207.182.159.135/32",
                    gateway: "192.168.0.1",
                    interfaceName: "en0",
                    flags: "UGHS")
            ])

        do {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                _ = try RouteManager(splitTunnelPolicy: configuration)
                    .secureRemoteServerHostRoute(
                        using: &session,
                        persistPreparedState: persistPreparedState
                    )
            }
            try #require(
                Bool(false), "A third remote-route ledger key should fail before mutation.")
        } catch RouteManagerError.failedToSecureControlChannel {
        }

        #expect(
            session.managedRemoteIPv4Routes == nil
                && session.replacedRemoteIPv4Routes == deferredRoutes,
            "A rejected remote-route ledger expansion must leave recovery state unchanged.")
        #expect(
            !mockSystem.recordedCommands.contains(where: {
                $0.hasPrefix("/sbin/route -n delete -host 207.182.159.135")
                    || $0.hasPrefix("/sbin/route -n add -host 207.182.159.135")
            }),
            "A rejected remote-route ledger expansion must not mutate the route table.")
    }

    @Test
    func remoteRouteReplacementRejectsAmbiguousScopedOwnership() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1098,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["172.20.10.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.133"

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalDNSServers: ["172.20.10.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "172.20.10.1",
                    interfaceName: "en0",
                    flags: "UGHS"),
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "172.20.10.1",
                    interfaceName: "en0",
                    flags: "UGHSI"),
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "192.168.0.1",
                    interfaceName: "en0",
                    flags: "UGHSI"),
            ])

        do {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                _ = try RouteManager(splitTunnelPolicy: configuration)
                    .ensureRemoteHostRoutes(
                        using: &session,
                        mode: .split,
                        context: "ambiguous route ownership",
                        persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false), "Ambiguous scoped route ownership should fail before mutation.")
        } catch RouteManagerError.failedToSecureControlChannel {
        }

        #expect(
            session.managedRemoteIPv4Routes == nil
                && session.replacedRemoteIPv4Routes == nil,
            "Ambiguous scoped route ownership must leave recovery state unchanged.")
        #expect(
            !mockSystem.recordedCommands.contains(where: {
                $0.hasPrefix("/sbin/route -n delete -host 207.182.159.133")
                    || $0.hasPrefix("/sbin/route -n add -host 207.182.159.133")
            }),
            "Ambiguous scoped route ownership must not mutate the route table.")
    }

    @Test
    func remoteRouteReplacementRejectsDuplicateStaticOwner() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1099,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["172.20.10.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.133"
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalDNSServers: ["172.20.10.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "192.168.0.1",
                    interfaceName: "en0",
                    flags: "UGHS"),
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "192.168.0.1",
                    interfaceName: "en0",
                    flags: "UGHCS"),
            ])

        do {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                _ = try RouteManager(splitTunnelPolicy: configuration)
                    .ensureRemoteHostRoutes(
                        using: &session,
                        mode: .split,
                        context: "duplicate owner",
                        persistPreparedState: persistPreparedState)
            }
            try #require(Bool(false), "Duplicate static route owners should fail before mutation.")
        } catch RouteManagerError.failedToSecureControlChannel {
        }

        #expect(
            session.managedRemoteIPv4Routes == nil
                && session.replacedRemoteIPv4Routes == nil,
            "Duplicate static route owners must leave recovery state unchanged.")
        #expect(
            !mockSystem.recordedCommands.contains(where: {
                $0.hasPrefix("/sbin/route -n delete -host 207.182.159.133")
                    || $0.hasPrefix("/sbin/route -n add -host 207.182.159.133")
            }),
            "Duplicate static route owners must be rejected before route mutation.")
    }

    @Test
    func remoteRouteReconciliationRestoresPreviousOwner() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1091,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["172.20.10.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.134"
        let staleManagedRoute = ManagedIPv4Route(
            destination: "207.182.159.133/32",
            nextHopKind: .gateway,
            nextHopValue: "172.20.10.1",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let previousRoute = ManagedIPv4Route(
            destination: "207.182.159.133/32",
            nextHopKind: .gateway,
            nextHopValue: "192.168.0.1",
            interfaceName: "en0",
            isInterfaceScoped: false)
        session.managedRemoteIPv4Routes = [staleManagedRoute]
        session.replacedRemoteIPv4Routes = [previousRoute]
        var persistedState: SessionState?

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalDNSServers: ["172.20.10.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: staleManagedRoute.destination,
                    gateway: staleManagedRoute.nextHopValue,
                    interfaceName: "en0",
                    flags: "UGHS")
            ])

        let changed = try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration)
                .reconcileManagedRemoteHostRoutes(
                    using: &session,
                    mode: .split
                ) { persistedState = $0 }
        }

        #expect(
            changed,
            "Remote-route reconciliation should remove endpoints that are absent from the new connection snapshot."
        )
        #expect(
            session.managedRemoteIPv4Routes == nil,
            "A verified stale remote-route deletion should remove its managed ledger entry.")
        #expect(
            session.replacedRemoteIPv4Routes == nil,
            "A verified restoration should remove the replaced-owner ledger entry.")
        #expect(
            persistedState?.managedRemoteIPv4Routes == nil
                && persistedState?.replacedRemoteIPv4Routes == nil,
            "Remote-route reconciliation should persist the finalized ledger only after route verification."
        )
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 207.182.159.133 172.20.10.1"),
            "Remote-route reconciliation should delete the exact stale app-owned route.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 207.182.159.133 192.168.0.1"),
            "Remote-route reconciliation should restore the route owner displaced by the prior connection."
        )
    }

    @Test
    func preservedRemoteRouteSiblingRestoresAfterEndpointChange() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1095,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["172.20.10.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.134"
        let priorSibling = ManagedIPv4Route(
            destination: "207.182.159.133/32",
            nextHopKind: .gateway,
            nextHopValue: "172.20.10.1",
            interfaceName: "en0",
            isInterfaceScoped: true)
        session.replacedRemoteIPv4Routes = [priorSibling]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalDNSServers: ["172.20.10.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "172.20.10.1",
                    interfaceName: "en0",
                    flags: "UGHS")
            ])

        let changed = try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration)
                .reconcileManagedRemoteHostRoutes(
                    using: &session,
                    mode: .split,
                    persistPreparedState: persistPreparedState)
        }

        #expect(
            changed,
            "Endpoint reconciliation should restore a removed sibling from the prior endpoint scope."
        )
        #expect(
            session.replacedRemoteIPv4Routes == nil,
            "Endpoint reconciliation should clear a verified prior-sibling recovery entry.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 207.182.159.133 172.20.10.1 -ifscope en0"),
            "Endpoint reconciliation should restore the prior scoped sibling exactly.")
        #expect(
            !mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 207.182.159.133 172.20.10.1"),
            "Endpoint reconciliation must preserve the prior unscoped route that the app never owned."
        )
    }

    @Test
    func fullTunnelEndpointChangeDefersStaleRouteSibling() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1096,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["172.20.10.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.134"
        session.managedRemoteIPv4Routes = [
            ManagedIPv4Route(
                destination: "207.182.159.133/32",
                nextHopKind: .gateway,
                nextHopValue: "172.20.10.1",
                interfaceName: "en0",
                isInterfaceScoped: false)
        ]
        session.replacedRemoteIPv4Routes = [
            ManagedIPv4Route(
                destination: "207.182.159.133/32",
                nextHopKind: .gateway,
                nextHopValue: "192.168.0.1",
                interfaceName: "en0",
                isInterfaceScoped: true)
        ]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalDNSServers: ["172.20.10.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "172.20.10.1",
                    interfaceName: "en0",
                    flags: "UGHS")
            ])

        let fullChanged = try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration)
                .reconcileManagedRemoteHostRoutes(
                    using: &session,
                    mode: .full,
                    persistPreparedState: persistPreparedState)
        }

        #expect(
            fullChanged,
            "Full-tunnel endpoint reconciliation should remove a stale app-owned route.")
        #expect(
            session.managedRemoteIPv4Routes == nil,
            "Full-tunnel endpoint reconciliation should clear the stale managed route after verified deletion."
        )
        #expect(
            session.replacedRemoteIPv4Routes?.count == 1,
            "Full-tunnel endpoint reconciliation should preserve stale prior-endpoint recovery entries for cleanup."
        )
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 207.182.159.133 172.20.10.1"),
            "Full-tunnel endpoint reconciliation should delete the exact stale app-owned route.")
        #expect(
            !mockSystem.recordedCommands.contains(where: {
                $0.hasPrefix("/sbin/route -n add -host 207.182.159.133 ")
            }),
            "Full-tunnel endpoint reconciliation must not restore an obsolete physical route.")

        session.tunnelMode = .split
        let splitChanged = try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration)
                .reconcileManagedRemoteHostRoutes(
                    using: &session,
                    mode: .split,
                    persistPreparedState: persistPreparedState)
        }
        #expect(
            splitChanged,
            "Split-tunnel reconciliation should restore a deferred prior-endpoint route sibling.")
        #expect(
            session.replacedRemoteIPv4Routes == nil,
            "Split-tunnel reconciliation should clear a verified deferred recovery entry.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 207.182.159.133 192.168.0.1 -ifscope en0"),
            "Split-tunnel reconciliation should restore the deferred prior-endpoint route sibling exactly."
        )
    }

    @Test
    func remoteRouteCleanupRestoresPreviousOwner() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1082,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["172.20.10.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.133"

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalDNSServers: ["172.20.10.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "192.168.0.1",
                    interfaceName: "en0",
                    flags: "UGHS"),
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "192.168.0.1",
                    interfaceName: "en0",
                    flags: "UGHSI"),
            ])

        let healthy = try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            _ = try RouteManager(splitTunnelPolicy: configuration)
                .ensureRemoteHostRoutes(
                    using: &session,
                    mode: .split,
                    context: "ownership cleanup",
                    persistPreparedState: persistPreparedState)
            return try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
        }

        #expect(
            healthy,
            "Cleanup should remain healthy after restoring a replaced remote host route.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 207.182.159.133 192.168.0.1"),
            "Remote-route replacement should delete the unscoped prior owner without an interface-scope modifier."
        )
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 207.182.159.133 192.168.0.1 -ifscope en0"),
            "Remote-route replacement should independently delete the scoped prior owner.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 207.182.159.133 172.20.10.1"),
            "Cleanup should delete only the cwru-ovpn-owned remote host route.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 207.182.159.133 192.168.0.1"),
            "Cleanup should restore the exact remote host route that existed before repair.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 207.182.159.133 192.168.0.1 -ifscope en0"),
            "Cleanup should restore the scoped prior owner alongside the unscoped route.")
    }

    @Test
    func remoteRouteCleanupDoesNotRestoreTunnelRoute() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1084,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["172.20.10.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.133"

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalDNSServers: ["172.20.10.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7",
                    flags: "UGHS")
            ])

        let healthy = try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            _ = try RouteManager(splitTunnelPolicy: configuration)
                .ensureRemoteHostRoutes(
                    using: &session,
                    mode: .split,
                    context: "tunnel ownership cleanup",
                    persistPreparedState: persistPreparedState)
            return try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
        }

        #expect(
            healthy,
            "Cleanup should remain healthy after replacing a tunnel-owned remote host route.")
        #expect(
            session.replacedRemoteIPv4Routes?.isEmpty ?? true,
            "Tunnel-owned remote host routes must not be recorded for restoration.")
        #expect(
            !mockSystem.recordedCommands.contains(where: {
                $0.hasPrefix("/sbin/route -n add -host 207.182.159.133 ") && $0.contains("10.8.0.1")
            }),
            "Cleanup must not restore a remote host route into a dead tunnel.")
    }

    @Test
    func cleanupRemovesManagedRemoteHostRoutes() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1011,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.serverIP = "67.219.145.197"
        session.managedRemoteIPv4Routes = [
            ManagedIPv4Route(
                destination: "67.219.145.197/32",
                nextHopKind: .gateway,
                nextHopValue: "192.168.1.1",
                interfaceName: "en0",
                isInterfaceScoped: false)
        ]
        session.replacedRemoteIPv4Routes = [
            ManagedIPv4Route(
                destination: "67.219.145.197/32",
                nextHopKind: .gateway,
                nextHopValue: "192.168.0.1",
                interfaceName: "en0",
                isInterfaceScoped: true)
        ]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "67.219.145.197",
                    gateway: "192.168.1.1",
                    interfaceName: "en0",
                    flags: "UGHS")
            ])

        let healthy = try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
        }

        #expect(
            healthy,
            "Cleanup should finish healthy after restoring a replaced scoped remote route.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 67.219.145.197 192.168.1.1"),
            "Cleanup should remove only the managed remote host route matching the current server.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 67.219.145.197 192.168.0.1 -ifscope en0"),
            "Cleanup should restore the exact scoped remote route replaced during repair.")
    }

    @Test
    func fullTunnelCleanupRemovesGatewayHostRoute() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1051,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.managedRemoteIPv4Routes = [
            ManagedIPv4Route(
                destination: "192.168.1.1/32",
                nextHopKind: .interface,
                nextHopValue: "en0",
                interfaceName: "en0",
                isInterfaceScoped: false)
        ]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "192.168.1.1/32",
                    gateway: "link#1",
                    interfaceName: "en0",
                    flags: "UHS")
            ])

        try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            _ = try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 192.168.1.1 -interface en0"),
            "Cleanup should remove the full-tunnel gateway host route it recorded installing.")
    }

    @Test
    func fullTunnelDoesNotRestoreDynamicGatewayNeighbor() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1053,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "192.168.1.1/32",
                    gateway: "aa:bb:cc:dd:ee:ff",
                    interfaceName: "en0",
                    flags: "UHLWIir")
            ])

        let cleanupHealthy = try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            _ = try RouteManager(splitTunnelPolicy: configuration)
                .securePhysicalGatewayHostRoute(
                    using: &session,
                    persistPreparedState: persistPreparedState)
            #expect(
                session.replacedRemoteIPv4Routes == nil,
                "A dynamic gateway neighbor must not be recorded as a restorable static route.")
            return try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
        }

        #expect(
            cleanupHealthy,
            "Cleanup should remain healthy after installing the gateway host route alongside a dynamic neighbor."
        )
        #expect(
            !mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 192.168.1.1 -interface en0 -ifscope en0"),
            "Full tunnel must leave the kernel-managed dynamic gateway neighbor alone.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 192.168.1.1 -interface en0"),
            "Full tunnel should install the static gateway host route despite the dynamic neighbor."
        )
        #expect(
            !mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 192.168.1.1 -interface en0 -ifscope en0"),
            "Cleanup must not recreate a dynamic neighbor as a static scoped route.")

        var unrepresentableSession = session
        unrepresentableSession.managedRemoteIPv4Routes = nil
        unrepresentableSession.replacedRemoteIPv4Routes = nil
        let unrepresentableSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "192.168.1.1/32",
                    gateway: "aa:bb:cc:dd:ee:ff",
                    interfaceName: "en0",
                    flags: "UHLSI")
            ])
        do {
            try CommandRunner.withCommandHandler({ try unrepresentableSystem.handle($0) }) {
                _ = try RouteManager(splitTunnelPolicy: configuration)
                    .securePhysicalGatewayHostRoute(
                        using: &unrepresentableSession,
                        persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false), "An unrepresentable static route owner should fail before mutation.")
        } catch RouteManagerError.failedToSecureControlChannel {
        }
        #expect(
            unrepresentableSession.managedRemoteIPv4Routes == nil
                && unrepresentableSession.replacedRemoteIPv4Routes == nil,
            "An unrepresentable static route owner must leave recovery state unchanged.")
        #expect(
            !unrepresentableSystem.recordedCommands.contains(where: {
                $0.hasPrefix("/sbin/route -n delete -host 192.168.1.1")
                    || $0.hasPrefix("/sbin/route -n add -host 192.168.1.1")
            }),
            "An unrepresentable static route owner must not mutate the route table.")
    }

    @Test
    func fullTunnelGatewayEnsureIgnoresKernelCacheEntries() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1055,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.132"

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "192.168.1.1/32",
                    gateway: "link#14",
                    interfaceName: "en0",
                    flags: "UCS"),
                MockSystem.RouteRecord(
                    destination: "192.168.1.1",
                    gateway: "aa:bb:cc:dd:ee:ff",
                    interfaceName: "en0",
                    flags: "UHLWIir"),
                MockSystem.RouteRecord(
                    destination: "207.182.159.132/32",
                    gateway: "192.168.1.1",
                    interfaceName: "en0",
                    flags: "UGHS"),
            ])

        try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            let changed = try RouteManager(splitTunnelPolicy: configuration)
                .ensureRemoteHostRoutes(
                    using: &session,
                    mode: .full,
                    context: "gateway neighbor check",
                    persistPreparedState: persistPreparedState)
            #expect(
                !changed,
                "A settled gateway route with a dynamic neighbor must not require any route mutation."
            )
        }

        #expect(
            session.managedRemoteIPv4Routes == nil && session.replacedRemoteIPv4Routes == nil,
            "Kernel cache entries must not enter the remote route recovery ledger.")
        #expect(
            !mockSystem.recordedCommands.contains(where: {
                $0.hasPrefix("/sbin/route -n delete") || $0.hasPrefix("/sbin/route -n add")
            }),
            "Kernel cache entries for the gateway must not trigger route table mutations.")
    }

    @Test
    func dynamicNeighborDoesNotSatisfyRestoredRemoteRoute() throws {
        let manager = RouteManager(splitTunnelPolicy: SplitTunnelPolicy.fixed)
        let restoredRoute = ManagedIPv4Route(
            destination: "192.168.1.1/32",
            nextHopKind: .interface,
            nextHopValue: "en0",
            interfaceName: "en0",
            isInterfaceScoped: true)
        var session = makeSessionState(
            pid: 1054,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.replacedRemoteIPv4Routes = [restoredRoute]
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            physicalIfconfigOutput: """
                en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
                inet 192.168.1.24 netmask 0xffffff00 broadcast 192.168.1.255
                """,
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "192.168.1.1/32",
                    gateway: "aa:bb:cc:dd:ee:ff",
                    interfaceName: "en0",
                    flags: "UHLWIir")
            ])

        try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            let entries = try manager.ipv4RoutingTableEntries()
            #expect(
                try !manager.cleanupReplacedRemoteHostRoutesRestored(using: session, in: entries),
                "A dynamic neighbor must not satisfy a restored static route ledger entry.")
            #expect(
                throws: (any Error).self,
                "A dynamic neighbor must not suppress restoration of a replaced static route."
            ) {
                try manager.restoreManagedIPv4RouteIfMissing(restoredRoute)
            }
        }
    }

    @Test
    func fullTunnelCleanupValidationDetectsGatewayHostRouteResidue() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )

        var session = makeSessionState(
            pid: 1052,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.managedRemoteIPv4Routes = [
            ManagedIPv4Route(
                destination: "192.168.1.1/32",
                nextHopKind: .interface,
                nextHopValue: "en0",
                interfaceName: "en0",
                isInterfaceScoped: false)
        ]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            ignoredRouteDeletes: ["192.168.1.1"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "192.168.1.1/32",
                    gateway: "link#1",
                    interfaceName: "en0",
                    flags: "UHS")
            ])

        let cleanupHealthy = try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
        }

        #expect(
            !cleanupHealthy,
            "Cleanup validation should fail when the recorded full-tunnel gateway host route remains."
        )
    }

    @Test
    func staleRemoteHostRouteLedgerSweep() throws {
        let staleRoute = ManagedIPv4Route(
            destination: "207.182.159.132/32",
            nextHopKind: .gateway,
            nextHopValue: "172.30.1.1",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let liveRoute = ManagedIPv4Route(
            destination: "207.182.159.131/32",
            nextHopKind: .gateway,
            nextHopValue: "172.30.1.1",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        let session = makeSessionState(
            pid: getpid(),
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.30.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.30.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "207.182.159.132/32",
                    gateway: "172.30.1.1",
                    interfaceName: "en0",
                    flags: "UGHS"),
                MockSystem.RouteRecord(
                    destination: "207.182.159.131/32",
                    gateway: "172.30.1.1",
                    interfaceName: "en0",
                    flags: "UGHS"),
            ])

        try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            let ledger = try #require(
                TestDependencies.remoteHostRouteLedger,
                "Remote route ledger fixture is unavailable.")
            let currentStartTime = try #require(
                processStartTime(getpid()),
                "Could not determine the current process identity for the remote-route ledger test."
            )
            let currentExecutablePath = try ExecutionIdentity.currentExecutablePath()
            try ledger.recordOwnedRoutes(
                [staleRoute],
                pid: getpid(),
                processStartTime: currentStartTime,
                executablePath: "/tmp/reused-pid-owner")
            try ledger.recordOwnedRoutes(
                [liveRoute],
                pid: getpid(),
                processStartTime: currentStartTime,
                executablePath: currentExecutablePath)
            try RouteManager(splitTunnelPolicy: configuration).cleanupStaleLedgeredRemoteHostRoutes(
                excluding: Set(session.managedRemoteIPv4Routes ?? []))

            #expect(
                mockSystem.recordedCommands.contains(
                    "/sbin/route -n delete -host 207.182.159.132 172.30.1.1"),
                "The ledger sweep should delete a stale remote host route left by a dead session.")
            #expect(
                !mockSystem.recordedCommands.contains(
                    "/sbin/route -n delete -host 207.182.159.131 172.30.1.1"),
                "The ledger sweep must not delete a remote host route owned by a live process.")
            let retainedLedgerRoutes = try ledger.entries().map(\.route)
            #expect(
                retainedLedgerRoutes == [liveRoute],
                "The ledger sweep should remove stale entries while keeping live-owner entries.")

            try ledger.removeRoutes([liveRoute])
            let emptiedLedger = try ledger.entries()
            #expect(
                emptiedLedger.isEmpty,
                "Removing the last ledger entry should empty the ledger.")
        }
    }

    @Test
    func remoteRouteLedgerValidatorRules() throws {
        func host(_ address: String, gateway: String? = nil, interfaceName: String = "en0", scoped: Bool = false) -> ManagedIPv4Route {
            ManagedIPv4Route(
                destination: "\(address)/32",
                nextHopKind: gateway == nil ? .interface : .gateway,
                nextHopValue: gateway ?? interfaceName,
                interfaceName: interfaceName,
                isInterfaceScoped: scoped)
        }
        let server = host("203.0.113.10", gateway: "192.168.1.1")
        let gatewayRoute = host("192.168.1.1")
        let cases: [(managed: [ManagedIPv4Route], replaced: [ManagedIPv4Route], valid: Bool, reason: String)] = [
            ([], [], true, "an empty ledger is valid"),
            ([server, gatewayRoute], [], true, "one gateway-kind and one interface-kind managed route are allowed"),
            ([server, host("203.0.113.11", gateway: "192.168.1.1")], [], false, "two gateway-kind managed routes are rejected"),
            ([host("203.0.113.10", gateway: "192.168.1.1", scoped: true)], [], false, "interface-scoped managed routes are rejected"),
            ([host("203.0.113.10", gateway: "192.168.1.1", interfaceName: "utun7")], [], false, "managed routes on virtual interfaces are rejected"),
            ([server], [server], false, "a route cannot be both managed and replaced"),
            ([], [host("203.0.113.10", gateway: "10.0.0.1"), host("203.0.113.10", gateway: "10.0.0.2")], false,
             "replaced routes must be distinct per destination, interface, and scope"),
            ([], [host("203.0.113.10", gateway: "10.0.0.1"), host("203.0.113.10", gateway: "10.0.0.2", scoped: true)], true,
             "an unscoped and a scoped replaced route may share a destination and interface"),
            ([], [host("203.0.113.10"), host("203.0.113.10", interfaceName: "en1"), host("203.0.113.10", interfaceName: "en2")], false,
             "replaced routes may span at most two destination and interface pairs"),
            ([], [ManagedIPv4Route(destination: "203.0.113.0/24", nextHopKind: .gateway, nextHopValue: "10.0.0.1", interfaceName: "en0", isInterfaceScoped: false)],
             false, "only host routes may be ledgered"),
        ]
        for testCase in cases {
            #expect(
                RouteManager.remoteIPv4RouteLedgerIsValid(managed: testCase.managed, replaced: testCase.replaced) == testCase.valid,
                Comment(rawValue: testCase.reason))
        }
    }

    @Test
    func remoteHostRouteLedgerRejectsInvalidPersistence() throws {
        let stateDirectory = temporaryDirectory(named: "cwru-ovpn-invalid-remote-ledger")
        defer { try? FileManager.default.removeItem(at: stateDirectory) }
        let ledgerDirectory = stateDirectory.appendingPathComponent("ledger", isDirectory: true)
        let ledger = RemoteHostRouteLedger(store: StateDirectory(directory: ledgerDirectory))
        try writeOwnedFixture(
            Data("not-json".utf8),
            in: ledgerDirectory,
            name: "remote-host-routes.json")
        #expect(
            throws: (any Error).self,
            "A damaged remote-host route ledger must fail closed instead of appearing empty."
        ) {
            _ = try ledger.entries()
        }

        let route = ManagedIPv4Route(
            destination: "203.0.113.10/32",
            nextHopKind: .gateway,
            nextHopValue: "192.168.1.1",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let entry = RemoteHostRouteLedgerEntry(
            route: route,
            pid: 42,
            processStartTime: ProcessStartTime(seconds: 1, microseconds: 0),
            executablePath: "/tmp/cwru-ovpn"
        )
        let encodedEntry = try JSONEncoder().encode(entry)
        var entryObject = try #require(
            try JSONSerialization.jsonObject(with: encodedEntry) as? [String: Any],
            "Encoded remote-host route ledger entries should be JSON objects.")
        for identityKey in ["processStartTime", "executablePath"] {
            var incompleteEntry = entryObject
            incompleteEntry.removeValue(forKey: identityKey)
            let incompleteLedger = try JSONSerialization.data(withJSONObject: [incompleteEntry])
            try writeOwnedFixture(
                incompleteLedger,
                in: ledgerDirectory,
                name: "remote-host-routes.json")
            #expect(
                throws: (any Error).self,
                "Remote-host route ledger entries should require \(identityKey)."
            ) {
                _ = try ledger.entries()
            }
        }

        entryObject["unexpected"] = true
        let unknownKeyLedger = try JSONSerialization.data(withJSONObject: [entryObject])
        try writeOwnedFixture(
            unknownKeyLedger,
            in: ledgerDirectory,
            name: "remote-host-routes.json")
        #expect(
            throws: (any Error).self,
            "Remote-host route ledger entries should reject unknown fields."
        ) {
            _ = try ledger.entries()
        }
    }
}
