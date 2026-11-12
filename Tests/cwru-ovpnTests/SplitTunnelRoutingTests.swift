import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct SplitTunnelRoutingTests {
    @Test(arguments: [String?.none, "default", "2001:4860::/32"])
    func splitHealthChecksIPv6RoutesWithoutATunnelIPv6Address(destination: String?) throws {
        let policy = SplitTunnelPolicy(ipv4Routes: [], dnsDomains: [], dnsServers: [])
        let session = makeSessionState(
            pid: 75, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true, vpnIPv6: nil)
        let mock = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: [], ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"], initialIPv6Routes: destination.map { [$0: "utun7"] } ?? [:])
        try CommandRunner.withCommandHandler({ try mock.handle($0) }) {
            let manager = RouteManager(splitTunnelPolicy: policy)
            let checks = manager.splitTunnelHealthChecks(using: session)
            #expect(checks.first { $0.name == "ipv6-routes" }?.status == (destination == nil ? .pass : .fail))
            #expect(mock.recordedCommands.allSatisfy { !$0.contains(" add ") && !$0.contains(" delete ") && !$0.contains(" -set") })
        }
    }

    @Test(arguments: ["ipv4", "ipv6"])
    func splitSetupRequiresRoutesToRemainInstalled(family: String) throws {
        let policy = SplitTunnelPolicy(ipv4Routes: ["129.22.0.0/16"], ipv6Routes: ["2606:ea00::/32"],
                                       dnsDomains: ["case.edu"], dnsServers: ["129.22.4.32"])
        var session = makeSessionState(
            pid: 73, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: [], originalIPv6Mode: "Automatic",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        let mock = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: [], ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])
        let missingRoute = family == "ipv4" ? "129.22.0.0/16" : "2606:ea00::/32"
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/sbin/route", invocation.arguments.contains("add"),
               invocation.arguments.contains(missingRoute) {
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }
            return try mock.handle(invocation)
        }) {
            let manager = RouteManager(splitTunnelPolicy: policy)
            #expect(throws: RouteManagerError.self) {
                try manager.applySplitTunnel(using: &session, persistPreparedState: persistPreparedState)
            }
        }
    }

    @Test
    func splitMonitorRejectsATunnelDefaultRoute() throws {
        let policy = SplitTunnelPolicy(ipv4Routes: [], dnsDomains: [], dnsServers: [])
        let session = makeSessionState(
            pid: 74, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        let mock = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "utun7",
            physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: [], ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"])
        try CommandRunner.withCommandHandler({ try mock.handle($0) }) {
            let manager = RouteManager(splitTunnelPolicy: policy)
            #expect(throws: RouteManagerError.self) {
                try manager.monitorSplitTunnel(using: session)
            }
            #expect(manager.splitTunnelHealthChecks(using: session).first { $0.name == "routes" }?.status == .fail)
        }
    }

    @Test
    func settlingSplitTunnelAllowsOnlyTheCurrentSafeControlRoute() throws {
        let policy = SplitTunnelPolicy(ipv4Routes: ["129.22.0.0/16"], dnsDomains: [], dnsServers: [])
        var session = makeSessionState(
            pid: 72, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        session.serverIP = "129.22.9.9"
        session.managedRemoteIPv4Routes = [ManagedIPv4Route(
            destination: "129.22.9.9/32", nextHopKind: .gateway, nextHopValue: "192.168.1.1",
            interfaceName: "en0", isInterfaceScoped: false)]
        for scenario in ["safe", "stale", "gateway", "interface", "scoped", "dynamic", "unowned", "host-flag", "wider", "narrower", "missing", "ipv4-default", "ipv6-default"] {
            var state = session
            if scenario == "stale" { state.serverIP = "129.22.9.10" }
            if scenario == "unowned" { state.managedRemoteIPv4Routes = nil }
            let flags: String
            switch scenario {
            case "host-flag": flags = "UGS"
            case "scoped": flags = "UGHSI"
            case "dynamic": flags = "UGH"
            default: flags = "UGHS"
            }
            var routes = [MockSystem.RouteRecord(
                destination: scenario == "wider" ? "129.22.9.0/24" : "129.22.9.9/32",
                gateway: scenario == "gateway" ? "192.168.1.254" : "192.168.1.1",
                interfaceName: scenario == "interface" ? "en1" : "en0", flags: flags)]
            if scenario != "missing" {
                routes.append(MockSystem.RouteRecord(destination: "129.22.0.0/16", gateway: "link#9", interfaceName: "utun7"))
            }
            if scenario == "narrower" {
                routes.append(MockSystem.RouteRecord(destination: "129.22.4.0/24", gateway: "192.168.1.254", interfaceName: "en0"))
            }
            let mock = MockSystem(
                serviceName: "Wi-Fi", physicalGateway: "192.168.1.1",
                physicalInterface: scenario == "ipv4-default" ? "utun7" : "en0",
                physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: [], ipv6Mode: "Off",
                tunnelInterfaces: ["utun7"], initialRoutes: routes,
                initialIPv6Routes: scenario == "ipv6-default" ? ["default": "utun7"] : [:])
            try CommandRunner.withCommandHandler({ try mock.handle($0) }) {
                let manager = RouteManager(splitTunnelPolicy: policy)
                if ["safe", "unowned", "host-flag"].contains(scenario) {
                    try manager.validateNetworkSafetyWhileSettling(using: state)
                } else {
                    #expect(throws: RouteManagerError.self) {
                        try manager.validateNetworkSafetyWhileSettling(using: state)
                    }
                }
            }
            #expect(mock.recordedCommands.allSatisfy { !$0.contains(" add ") && !$0.contains(" delete ") && !$0.contains(" -set") })
        }
    }

    @Test(arguments: ["UGHS", "UGSc"])
    func splitLifecyclePreservesAnExistingSafeControlRoute(flags: String) throws {
        let policy = SplitTunnelPolicy(ipv4Routes: ["129.22.0.0/16"], dnsDomains: [], dnsServers: [])
        var state = makeSessionState(
            pid: 76, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.serverIP = "129.22.9.9"
        state.appliedSplitIPv4Routes = policy.ipv4Routes
        let controlRoute = MockSystem.RouteRecord(destination: "129.22.9.9/32", gateway: state.physicalGateway,
                                                  interfaceName: state.physicalInterface, flags: flags)
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: state.physicalGateway, physicalInterface: state.physicalInterface,
            physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: [], ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"], initialRoutes: [controlRoute,
                .init(destination: "129.22.0.0/16", gateway: "link#9", interfaceName: "utun7")])
        try CommandRunner.withCommandHandler(system.handle) {
            let manager = RouteManager(splitTunnelPolicy: policy)
            #expect(try !manager.ensureRemoteHostRoutes(using: &state, mode: .split,
                                                        context: "split connection", persistPreparedState: persistPreparedState))
            #expect(state.managedRemoteIPv4Routes == nil)
            #expect(state.replacedRemoteIPv4Routes == nil)
            #expect(manager.splitTunnelRoutingIsSafe(tunnelName: "utun7", using: state,
                                                      ipv4Entries: try manager.ipv4RoutingTableEntries(),
                                                      ipv6Entries: try manager.ipv6RoutingTableEntries()))
            try manager.validateNetworkSafetyWhileSettling(using: state)
            #expect(try manager.cleanup(using: state))
            #expect(try manager.ipv4RoutingTableEntries().contains {
                $0.destination == controlRoute.destination && $0.gateway == controlRoute.gateway
                    && $0.interfaceName == controlRoute.interfaceName && $0.flags == flags
            })
            #expect(system.recordedCommands.allSatisfy {
                !$0.hasPrefix("/sbin/route -n add -host 129.22.9.9")
                    && !$0.hasPrefix("/sbin/route -n delete -host 129.22.9.9")
            })
        }
    }

    @Test
    func splitTunnelSetupAndRepair() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-split")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy.fixed

        var session = makeSessionState(
            pid: 1001,
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
        session.pushedDNSServers = ["129.22.4.32"]
        session.pushedSearchDomains = ["case.edu"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["129.22.4.32"],
            physicalSearchDomains: ["case.edu"],
            ipv6Mode: "Automatic",
            activeDefaultDNSServers: ["129.22.4.32"],
            activeDefaultSearchDomains: ["case.edu"],
            tunnelInterfaces: ["utun7"],
            activeResolverPublicationDelayReads: 2,
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "0.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "10.8.0.0/24",
                    gateway: "10.8.0.10",
                    interfaceName: "utun7"),
            ])

        _ = try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            #expect(
                session.appliedSplitIPv4Routes == SplitTunnelPolicy.fixedIPv4Routes,
                "Applying split tunnel should persist the fixed CWRU IPv4 routes.")
            #expect(
                session.appliedDNSDomains == SplitTunnelPolicy.fixedResolverDomains,
                "Applying split tunnel should persist only fixed CWRU DNS domains and reverse zones."
            )

            let resolverFile = testResolverFileURL(for: "case.edu")
            let reverseResolverFile = testResolverFileURL(for: "22.129.in-addr.arpa")
            let resolverContents = try String(contentsOf: resolverFile, encoding: .utf8)
            #expect(
                resolverContents.contains("nameserver 129.22.4.32"),
                "Applying split tunnel should install scoped resolver files with CWRU DNS servers.")
            #expect(
                FileManager.default.fileExists(atPath: reverseResolverFile.path),
                "Applying split tunnel should install reverse-zone resolver files for split routes."
            )
            #expect(
                !FileManager.default.fileExists(
                    atPath: testResolverFileURL(for: "0.8.10.in-addr.arpa").path),
                "Applying split tunnel must not scope a server-assigned private reverse zone to CWRU DNS."
            )
            #expect(
                mockSystem.recordedCommands.contains(
                    "/sbin/route -n delete -net 0.0.0.0/1 10.8.0.1"),
                "Applying split tunnel should remove a gateway-shaped lower-half route from the tunnel interface."
            )
            #expect(
                mockSystem.recordedCommands.contains(
                    "/sbin/route -n delete -net 128.0.0.0/1 10.8.0.1"),
                "Applying split tunnel should remove a gateway-shaped upper-half route from the tunnel interface."
            )
            for installedResolver in [resolverFile, reverseResolverFile] {
                #expect(
                    throws: Never.self,
                    "Applying split tunnel should install resolver files with the hardened owner and 0644 mode."
                ) {
                    try assertInstalledFile(
                        path: installedResolver.path, userID: getuid(), groupID: getgid(), mode: 0o644)
                }
            }
        }
        #expect(
            !addsDefaultCoverage(mockSystem.recordedCommands),
            "Applying split tunnel must leave default coverage to the system's own routes.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 129.22.0.0/16 -interface utun7"),
            "Applying split tunnel should route fixed CWRU CIDRs through the tunnel interface.")
        let commands = mockSystem.recordedCommands
        let dnsRestoreIndex = try #require(
            commands.firstIndex(of: "/usr/sbin/networksetup -setdnsservers Wi-Fi 1.1.1.1"))
        let tunnelDefaultRemovalIndex = try #require(
            commands.firstIndex(of: "/sbin/route -n delete -net 0.0.0.0/1 10.8.0.1"))
        let publicationReads = commands[dnsRestoreIndex..<tunnelDefaultRemovalIndex]
            .filter { $0 == "/usr/sbin/scutil --dns" }.count
        #expect(
            publicationReads == 3,
            "Applying split tunnel must restore physical DNS and observe its publication before removing tunnel default coverage."
        )
    }

    private func addsDefaultCoverage(_ commands: [String]) -> Bool {
        let defaultCoverage = ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"].compactMap(IPRoute.canonicalIPv4)
        return commands.contains { command in
            let words = command.split(separator: " ").map(String.init)
            guard words.starts(with: ["/sbin/route", "-n", "add"]), words.count > 3 else {
                return false
            }
            if words[3] == "default" {
                return true
            }
            guard words[3] == "-net", words.count > 4, let destination = IPRoute.canonicalIPv4(words[4]) else {
                return false
            }
            return defaultCoverage.contains(destination)
        }
    }

    @Test
    func splitTunnelPreservesConflictingPhysicalRoute() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1083,
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
                    destination: "129.22.0.0/16",
                    gateway: "192.168.1.254",
                    interfaceName: "en0",
                    flags: "UGS")
            ])
        var physicalRoutePreserved = false
        do {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                let manager = RouteManager(splitTunnelPolicy: configuration)
                do {
                    try manager.applySplitTunnel(
                        using: &session, persistPreparedState: persistPreparedState)
                } catch {
                    physicalRoutePreserved = try manager.ipv4RouteExists(
                        "129.22.0.0/16",
                        on: "en0",
                        in: manager.ipv4RoutingTableEntries())
                    throw error
                }
            }
            try #require(
                Bool(false),
                "Split tunnel should fail closed instead of replacing an unrelated physical route.")
        } catch RouteManagerError.refusingToReplaceExistingRoute(let route) {
            #expect(
                route == "129.22.0.0/16" && physicalRoutePreserved,
                "Split tunnel should preserve a conflicting physical route and report its destination."
            )
        }
        #expect(
            !mockSystem.recordedCommands.contains {
                $0.hasPrefix("/sbin/route -n delete -net 129.22.0.0/16")
            },
            "Split tunnel must never delete an unrelated physical route by destination alone.")
    }

    @Test
    func splitTunnelRejectsMoreSpecificPhysicalOverrides() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            ipv6Routes: ["2606:ea00::/32"],
            dnsDomains: [],
            dnsServers: [])
        var session = makeSessionState(
            pid: 1084,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: nil,
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true)
        session.vpnIPv6 = "2606:ea00::10"
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        session.appliedSplitIPv6Routes = ["2606:ea00::/32"]
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(destination: "129.22.0.0/16", gateway: "link#9", interfaceName: "utun7"),
                MockSystem.RouteRecord(destination: "129.22.4.0/24", gateway: "192.168.1.254", interfaceName: "en0"),
            ],
            initialIPv6RouteRecords: [
                MockSystem.RouteRecord(destination: "2606:ea00::/32", gateway: "utun7", interfaceName: "utun7"),
                MockSystem.RouteRecord(destination: "2606:ea00:4::/48", gateway: "fe80::1", interfaceName: "en0"),
            ])

        try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            let manager = RouteManager(splitTunnelPolicy: configuration)
            let ipv4Overrides = manager.protectedSplitIPv4RouteOverrides(
                on: "utun7", using: session, in: try manager.ipv4RoutingTableEntries())
            let ipv6Overrides = manager.protectedSplitIPv6RouteOverrides(
                on: "utun7", using: session, in: try manager.ipv6RoutingTableEntries())
            #expect(ipv4Overrides == ["129.22.4.0/24"])
            #expect(ipv6Overrides == ["2606:ea00:4::/48"])
            #expect(throws: RouteManagerError.self) {
                _ = try manager.monitorSplitTunnel(using: session)
            }
        }
    }

    @Test
    func splitTunnelRequiresTunnelInterface() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var splitSession = makeSessionState(
            pid: 1021,
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
        splitSession.tunnelName = nil

        do {
            try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                using: &splitSession, persistPreparedState: persistPreparedState)
            try #require(
                Bool(false),
                "Split tunnel should reject CONNECTED state without a tunnel interface.")
        } catch RouteManagerError.missingTunnelInterface {
        }

        var fullSession = splitSession
        fullSession.tunnelMode = .full
        do {
            try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                using: &fullSession, persistPreparedState: persistPreparedState)
            try #require(
                Bool(false), "Full tunnel should reject CONNECTED state without a tunnel interface."
            )
        } catch RouteManagerError.missingTunnelInterface {
        }
    }

    @Test
    func splitTunnelIPv4RequiresTunnelIPv4Address() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1017,
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
        session.vpnIPv4 = nil

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])

        do {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Split tunnel should reject IPv4 routes when the tunnel has no IPv4 address.")
        } catch RouteManagerError.missingTunnelIPv4Address {
            #expect(
                mockSystem.recordedCommands.isEmpty,
                "Split tunnel should reject missing tunnel IPv4 before mutating network state.")
        }

    }

    @Test
    func splitTunnelIPv6SetupAndRepair() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-ipv6")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy.fixed

        var session = makeSessionState(
            pid: 1013,
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
        session.vpnIPv6 = "2606:ea00::100"
        session.pushedDNSServers = ["129.22.4.32"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])
        var checks: [SplitTunnelHealthCheck] = []
        try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                let manager = RouteManager(splitTunnelPolicy: configuration)
                try manager.applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
                checks = manager.splitTunnelHealthChecks(using: session)
            }
        }

        #expect(
            session.appliedSplitIPv6Routes == SplitTunnelPolicy.fixedIPv6Routes,
            "Applying IPv6 split tunnel should persist the fixed CWRU IPv6 route.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -inet6 2606:ea00::/32 -interface utun7"),
            "Applying IPv6 split tunnel should route the fixed CWRU IPv6 prefix through the tunnel interface."
        )
        #expect(
            !mockSystem.recordedCommands.contains("/usr/sbin/networksetup -setv6off Wi-Fi"),
            "Applying IPv6 split tunnel should leave physical-service IPv6 unchanged.")
        #expect(
            session.appliedDNSDomains?.contains("0.0.a.e.6.0.6.2.ip6.arpa") == true,
            "Applying IPv6 split tunnel should persist IPv6 reverse resolver zones.")

        #expect(
            checks.contains { $0.name == "ipv6-routes" && $0.status == .pass },
            "IPv6 split tunnel health should report split IPv6 routes.")
    }

    @Test
    func splitTunnelSkipsIPv6WithoutTunnelIPv6Address() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            ipv6Routes: ["2606:ea00::/32"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1014,
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
        session.vpnIPv6 = nil
        session.pushedDNSServers = ["129.22.4.32"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])

        try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                using: &session, persistPreparedState: persistPreparedState)
        }
        #expect(
            session.appliedSplitIPv6Routes == [],
            "Split tunnel should persist no IPv6 routes when the tunnel has no IPv6 address.")
        #expect(
            !mockSystem.recordedCommands.contains(
                "/sbin/route -n add -inet6 2606:ea00::/32 -interface utun7"),
            "Split tunnel should not install the fixed IPv6 route when the tunnel has no IPv6 address."
        )
        #expect(
            session.appliedDNSDomains?.contains("0.0.a.e.6.0.6.2.ip6.arpa") != true,
            "Split tunnel should not install an IPv6 reverse resolver zone when the IPv6 route is inactive."
        )
    }

    @Test
    func splitTunnelIgnoresKernelManagedRoutes() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-kernel-routes")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            ipv6Routes: ["2606:ea00::/32"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1031,
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
        session.pushedDNSServers = ["129.22.4.32"]

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
                    destination: "10.8.0.0/24",
                    gateway: "10.8.0.10",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "169.254.0.0/16",
                    gateway: "link#1",
                    interfaceName: "utun7",
                    flags: "UGScI"),
                MockSystem.RouteRecord(
                    destination: "224.0.0.0/4",
                    gateway: "link#1",
                    interfaceName: "utun7",
                    flags: "UGScI"),
            ],
            initialIPv6RouteRecords: [
                MockSystem.RouteRecord(
                    destination: "fe80::%utun7/64",
                    gateway: "fe80::%utun7",
                    interfaceName: "utun7",
                    flags: "UGScI"),
                MockSystem.RouteRecord(
                    destination: "ff02::%utun7/32",
                    gateway: "fe80::%utun7",
                    interfaceName: "utun7",
                    flags: "UGScI"),
            ])

        try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
        }

        #expect(
            !mockSystem.recordedCommands.contains {
                $0.hasPrefix("/sbin/route -n delete") && $0.contains("fe80::")
            },
            "Split privacy check must not delete the tunnel's link-local IPv6 route.")
        #expect(
            !mockSystem.recordedCommands.contains {
                $0.hasPrefix("/sbin/route -n delete") && $0.contains("ff02::")
            },
            "Split privacy check must not delete the tunnel's IPv6 multicast route.")
        #expect(
            !mockSystem.recordedCommands.contains {
                $0.hasPrefix("/sbin/route -n delete -net 169.254.0.0/16")
            },
            "Split privacy check must not delete IPv4 link-local routes on the tunnel.")
        #expect(
            !mockSystem.recordedCommands.contains {
                $0.hasPrefix("/sbin/route -n delete -net 224.0.0.0/4")
            },
            "Split privacy check must not delete IPv4 multicast routes on the tunnel.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -net 10.8.0.0/24 10.8.0.10"),
            "Split privacy check must delete a non-policy connected subnet while retaining scoped kernel routes."
        )
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -inet6 2606:ea00::/32 -interface utun7"),
            "Split tunnel should still route the built-in CWRU IPv6 prefix through the tunnel.")
    }

    @Test
    func splitTunnelRemovesNonPolicyConnectedRoutes() throws {
        let resolverDirectory = temporaryDirectory(
            named: "cwru-ovpn-resolver-tunnel-gateway-routes")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1032,
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
            cleanupNeeded: true,
            vpnIPv4: "100.96.5.101"
        )
        session.pushedDNSServers = ["129.22.4.32"]

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
                    destination: "100.96.5.96/28",
                    gateway: "100.96.5.101",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "100.96.5.97/32",
                    gateway: "link#1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "8.8.8.8/32",
                    gateway: "link#1",
                    interfaceName: "utun7"),
            ])

        try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -net 100.96.5.96/28 100.96.5.101"),
            "Split tunnel must remove a non-policy OpenVPN connected subnet route.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 100.96.5.97 -interface utun7"),
            "Split tunnel must remove a non-policy OpenVPN gateway host route.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 8.8.8.8 -interface utun7"),
            "Split tunnel should still remove unrelated public routes on the exact tunnel interface."
        )
    }

    @Test
    func splitTunnelRejectsUnremovablePublicHostRoute() throws {
        let resolverDirectory = temporaryDirectory(
            named: "cwru-ovpn-resolver-public-tunnel-gateway-route")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1033,
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
            cleanupNeeded: true,
            vpnIPv4: "100.96.5.101"
        )
        session.pushedDNSServers = ["129.22.4.32"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            ignoredRouteDeletes: ["8.8.8.8"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "8.8.8.8/32",
                    gateway: "link#1",
                    interfaceName: "utun7")
            ])

        _ = try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                #expect(
                    throws: (any Error).self,
                    "Split tunnel should fail closed if a public non-CWRU gateway route remains on the tunnel."
                ) {
                    try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                        using: &session, persistPreparedState: persistPreparedState)
                }
            }
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 8.8.8.8 -interface utun7"),
            "Split tunnel must attempt to remove a public non-CWRU host route.")
    }

    @Test
    func splitTunnelSkipsFixedIPv6WithoutTunnelIPv6() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-no-tunnel-ipv6")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            ipv6Routes: ["2606:ea00::/32"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1032,
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
        session.vpnIPv6 = nil
        session.pushedDNSServers = ["129.22.4.32"]

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
                    destination: "10.8.0.0/24",
                    gateway: "10.8.0.10",
                    interfaceName: "utun7")
            ])

        try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
        }

        #expect(
            session.appliedSplitIPv6Routes == [],
            "Split tunnel should skip the fixed CWRU IPv6 route when the tunnel has no IPv6 address."
        )
        #expect(
            !mockSystem.recordedCommands.contains(
                "/sbin/route -n add -inet6 2606:ea00::/32 -interface utun7"),
            "Split tunnel should not add IPv6 routes when the tunnel has no IPv6 address.")
        #expect(
            session.appliedDNSDomains?.contains("0.0.a.e.6.0.6.2.ip6.arpa") != true,
            "Split tunnel should not install an IPv6 reverse resolver zone when the IPv6 route is inactive."
        )
        #expect(
            !mockSystem.recordedCommands.contains("/usr/sbin/networksetup -setv6off Wi-Fi"),
            "Split tunnel should leave physical-service IPv6 unchanged when the tunnel has no IPv6 address."
        )
    }

    @Test
    func splitTunnelAllowsPublicIPv6OutsideCWRUTunnel() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-ipv6-outside-cwru")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1034,
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
        session.pushedDNSServers = ["129.22.4.32"]

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
                    destination: "10.8.0.0/24",
                    gateway: "10.8.0.10",
                    interfaceName: "utun7")
            ])

        var checks: [SplitTunnelHealthCheck] = []
        try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                let manager = RouteManager(splitTunnelPolicy: configuration)
                try manager.applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
                checks = manager.splitTunnelHealthChecks(using: session)
            }
        }

        #expect(
            !mockSystem.recordedCommands.contains("/usr/sbin/networksetup -setv6off Wi-Fi"),
            "Split tunnel should not reset physical IPv6 when public IPv6 stays outside the CWRU tunnel."
        )
        #expect(
            checks.contains {
                $0.name == "ipv6" && $0.status == .pass
                    && $0.detail == "public IPv6 avoids the CWRU tunnel"
            },
            "Split health should accept public IPv6 outside the CWRU tunnel.")
    }

    @Test
    func splitTunnelAllowsManualPhysicalIPv6Mode() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-manual-ipv6-split")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        let policyManager = RouteManager(splitTunnelPolicy: configuration)

        #expect(
            !policyManager.tunnelIPv6ModeIsUnsupported(nil),
            "Absent IPv6 mode should be allowed because there is nothing to manage.")
        #expect(
            !policyManager.tunnelIPv6ModeIsUnsupported("Automatic"),
            "Automatic IPv6 mode should be allowed for split tunnel.")
        #expect(
            !policyManager.tunnelIPv6ModeIsUnsupported("Link-local only"),
            "Link-local IPv6 mode should be allowed for split tunnel.")
        #expect(
            !policyManager.tunnelIPv6ModeIsUnsupported("Off"),
            "Off IPv6 mode should be allowed for split tunnel.")
        #expect(
            policyManager.tunnelIPv6ModeIsUnsupported("Manual"),
            "Manual IPv6 mode should still be classified as unsupported for full-tunnel IPv6 management."
        )

        var session = makeSessionState(
            pid: 1012,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Manual",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNSServers = ["129.22.4.32"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Manual",
            tunnelInterfaces: ["utun7"])

        try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                let manager = RouteManager(splitTunnelPolicy: configuration)
                try manager.applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
        }
        #expect(
            !mockSystem.recordedCommands.contains("/usr/sbin/networksetup -setv6off Wi-Fi"),
            "Split tunnel should not disable Manual physical IPv6.")
    }

    @Test
    func splitTunnelIgnoresPhysicalIPv6DriftFromOff() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1013,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["10.8.0.2"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        session.appliedDNSDomains = []

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
                    destination: "129.22.0.0/16",
                    gateway: "link#1",
                    interfaceName: "utun7")
            ])

        try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
            let stillConnected = try RouteManager(splitTunnelPolicy: configuration)
                .monitorSplitTunnel(
                    using: session)
            #expect(
                stillConnected,
                "Route monitor should keep the session connected when physical IPv6 changes outside split ownership."
            )
        }

        #expect(
            !mockSystem.recordedCommands.contains("/usr/sbin/networksetup -setv6off Wi-Fi"),
            "Route monitor should not manage physical IPv6 in split mode.")
    }

    @Test
    func routeMonitorRepairsGatewayShapedTunnelDefaults() throws {
        let resolverDirectory = temporaryDirectory(
            named: "cwru-ovpn-resolver-monitor-gateway-defaults")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        let session = makeSessionState(
            pid: 1015,
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
                    destination: "0.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
            ])

        let stillConnected = try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).monitorSplitTunnel(using: session)
            }
        }

        #expect(
            stillConnected,
            "Route monitor should repair gateway-shaped tunnel default routes without disconnecting."
        )
        #expect(
            mockSystem.recordedCommands.contains("/sbin/route -n delete -net 0.0.0.0/1 10.8.0.1"),
            "Route monitor should delete the lower gateway-shaped tunnel default by exact next hop."
        )
        #expect(
            mockSystem.recordedCommands.contains("/sbin/route -n delete -net 128.0.0.0/1 10.8.0.1"),
            "Route monitor should delete the upper gateway-shaped tunnel default by exact next hop."
        )
        #expect(
            !addsDefaultCoverage(mockSystem.recordedCommands),
            "Route monitor must not replace tunnel defaults with any other default coverage.")
    }

    @Test
    func splitTunnelRejectsPublicIPv6OnCWRUTunnel() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            ipv6Routes: ["2606:ea00::/32"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        let routeManager = RouteManager(splitTunnelPolicy: configuration)
        let maliciousAssignedRoute = IPRoute.canonicalIPv6("2600:abcd::/64")!
        let maliciousAssignedSession = makeSessionState(
            pid: 1115,
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
            cleanupNeeded: true,
            vpnIPv6: "2600:abcd::2"
        )
        #expect(
            !routeManager.splitIPv6RouteIsAllowed(
                maliciousAssignedRoute,
                using: maliciousAssignedSession),
            "Split tunnel must reject a server-assigned public IPv6 connected prefix outside the fixed CWRU policy."
        )

        let cwruAssignedRoute = IPRoute.canonicalIPv6("2606:ea00:1::/64")!
        let cwruAssignedSession = makeSessionState(
            pid: 1116,
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
            cleanupNeeded: true,
            vpnIPv6: "2606:ea00:1::2"
        )
        #expect(
            routeManager.splitIPv6RouteIsAllowed(
                cwruAssignedRoute,
                using: cwruAssignedSession),
            "Split tunnel should retain a connected IPv6 prefix contained by the fixed CWRU policy."
        )

        func applySplit(
            _ mockSystem: MockSystem,
            resolverName: String
        ) throws -> SessionState {
            let resolverDirectory = temporaryDirectory(named: resolverName)
            defer { try? FileManager.default.removeItem(at: resolverDirectory) }

            var session = makeSessionState(
                pid: 1014,
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

            try withResolverDirectory(resolverDirectory) {
                try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                    try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                        using: &session, persistPreparedState: persistPreparedState)
                }
            }
            return session
        }

        let physicalIPv6 = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"]
        )
        _ = try applySplit(
            physicalIPv6,
            resolverName: "cwru-ovpn-resolver-public-ipv6-physical")
        #expect(
            !physicalIPv6.recordedCommands.contains("/usr/sbin/networksetup -setv6off Wi-Fi"),
            "Split tunnel should not disable physical IPv6 when non-CWRU public IPv6 stays outside CWRU."
        )

        let externalTunnelIPv6 = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            externalIPv6TunnelInterface: "utun99"
        )
        _ = try applySplit(
            externalTunnelIPv6,
            resolverName: "cwru-ovpn-resolver-public-ipv6-other-tunnel")
        #expect(
            !externalTunnelIPv6.recordedCommands.contains("/usr/sbin/networksetup -setv6off Wi-Fi"),
            "Split tunnel should not disable physical IPv6 when non-CWRU public IPv6 uses another tunnel."
        )

        let cwruTunnelIPv6 = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            ignoredRouteDeletes: ["::/1", "8000::/1"],
            initialIPv6Routes: ["::/1": "utun7", "8000::/1": "utun7"]
        )
        do {
            _ = try applySplit(
                cwruTunnelIPv6,
                resolverName: "cwru-ovpn-resolver-public-ipv6-cwru-tunnel")
            try #require(
                Bool(false),
                "Split tunnel should reject public IPv6 that remains routed over the CWRU tunnel.")
        } catch RouteManagerError.failedToDeleteManagedRoute(let route) {
            #expect(route == "::/1")
        }
        #expect(
            !cwruTunnelIPv6.recordedCommands.contains("/usr/sbin/networksetup -setv6off Wi-Fi"),
            "Split tunnel should not try to repair public IPv6 leakage by disabling physical IPv6.")
    }

    @Test
    func splitTunnelRejectsServerAssignedNonPolicySubnets() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            ipv6Routes: ["2606:ea00::/32"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        let routeManager = RouteManager(splitTunnelPolicy: configuration)
        #expect(
            !routeManager.splitIPv4RouteIsAllowed(IPRoute.canonicalIPv4("192.168.50.0/24")!),
            "Split tunnel must reject a server-assigned private IPv4 subnet outside the fixed CWRU policy."
        )
        #expect(
            !routeManager.splitIPv4RouteIsAllowed(IPRoute.canonicalIPv4("169.254.50.0/24")!),
            "Split tunnel must reject a non-scoped server-assigned IPv4 link-local subnet.")
        #expect(
            routeManager.splitIPv4RouteIsAllowed(IPRoute.canonicalIPv4("129.22.44.0/24")!),
            "Split tunnel should retain a connected IPv4 prefix contained by the fixed CWRU policy."
        )

        var maliciousIPv6Session = makeSessionState(
            pid: 1118,
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
            cleanupNeeded: true,
            vpnIPv6: "fd42:1234:5678::2"
        )
        maliciousIPv6Session.appliedSplitIPv6Routes = ["fd42:1234:5678::/64"]
        #expect(
            !routeManager.splitIPv6RouteIsAllowed(
                IPRoute.canonicalIPv6("fd42:1234:5678::/64")!,
                using: maliciousIPv6Session),
            "Split tunnel must reject a server-assigned ULA subnet outside the fixed CWRU policy.")
        #expect(
            !routeManager.splitIPv6RouteIsAllowed(
                IPRoute.canonicalIPv6("fe80::/64")!,
                using: maliciousIPv6Session),
            "Split tunnel must reject a non-scoped server-assigned IPv6 link-local subnet.")

        var ipv4OnlySession = maliciousIPv6Session
        ipv4OnlySession.vpnIPv6 = nil
        ipv4OnlySession.appliedSplitIPv6Routes = ["2606:ea00::/32"]
        #expect(
            !routeManager.splitIPv6RouteIsAllowed(
                IPRoute.canonicalIPv6("2606:ea00::/32")!,
                using: ipv4OnlySession),
            "Split tunnel must not let recovery state authorize IPv6 policy when the tunnel has no IPv6 address."
        )
    }

    @Test
    func splitTunnelPreservesRecoveryOwnershipAfterResolverInstallFailure() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-install-failure")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1025,
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

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])

        try withResolverDirectory(resolverDirectory) {
            do {
                try "nameserver 9.9.9.9\ndomain case.edu\n".write(
                    to: testResolverFileURL(for: "case.edu"), atomically: true, encoding: .utf8)
                try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                    try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                        using: &session, persistPreparedState: persistPreparedState)
                }
                try #require(
                    Bool(false), "Split tunnel should fail when scoped resolver installation fails."
                )
            } catch {
                #expect(
                    !mockSystem.recordedCommands.contains(
                        "/sbin/route -n delete -net 129.22.0.0/16 -interface utun7"),
                    "The caller owns rollback or cleanup after a failed preparation."
                )
                #expect(
                    !mockSystem.recordedCommands.contains(
                        "/usr/sbin/networksetup -setv6automatic Wi-Fi"),
                    "Split tunnel cleanup should not reset physical IPv6 when it was not changed.")
                mockSystem.releaseTunnelInterface(named: "utun7")
                let healthy = try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                    let manager = RouteManager(splitTunnelPolicy: configuration)
                    let healthy = try manager.cleanup(using: session)
                    #expect(try !manager.ipv4RoutingTableEntries().contains { $0.interfaceName == "utun7" })
                    return healthy
                }
                #expect(healthy)
                #expect(!mockSystem.recordedCommands.contains(
                    "/sbin/route -n delete -net 129.22.0.0/16 -interface utun7"))
            }
        }
    }

    @Test
    func splitTunnelRemovesUnexpectedVPNRoutes() throws {
        let resolverDirectory = temporaryDirectory(
            named: "cwru-ovpn-resolver-unexpected-vpn-routes")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            ipv6Routes: ["2606:ea00::/32"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1022,
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

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            blockedIPv6ProbeDestinations: ["2001:4860:4860::8888", "3000::1", "9000::1"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "8.8.8.8/32",
                    gateway: "link#1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "10.8.0.0/24",
                    gateway: "link#1",
                    interfaceName: "utun7"),
            ],
            initialIPv6Routes: [
                "2001:4860:4860::8888/128": "utun7"
            ])

        try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 8.8.8.8 -interface utun7"),
            "Split tunnel should delete non-CWRU IPv4 routes from the exact VPN tunnel.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -net -inet6 2001:4860:4860::8888 -prefixlen 128 -interface utun7"
            ),
            "Split tunnel should delete non-CWRU IPv6 routes from the exact VPN tunnel.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -net 10.8.0.0/24 -interface utun7"),
            "Split tunnel must delete non-policy tunnel-internal routes even when they contain the assigned VPN address."
        )
    }
}
