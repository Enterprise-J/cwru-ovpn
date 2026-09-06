import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct SplitTunnelRoutingTests {
    @Test
    func settlingSplitTunnelAllowsOnlyTheCurrentOwnedControlRoute() throws {
        let policy = SplitTunnelPolicy(ipv4Routes: ["129.22.0.0/16"], dnsDomains: [], dnsServers: [])
        var session = makeSessionState(
            pid: 72, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        session.serverIP = "129.22.9.9"
        session.managedRemoteIPv4Routes = [ManagedIPv4Route(
            destination: "129.22.9.9/32", nextHopKind: .gateway, nextHopValue: "192.168.1.1",
            interfaceName: "en0", isInterfaceScoped: false)]
        for scenario in ["safe", "stale", "gateway", "unowned", "host-flag", "narrower", "missing", "ipv4-default", "ipv6-default"] {
            var state = session
            if scenario == "stale" { state.serverIP = "129.22.9.10" }
            if scenario == "unowned" { state.managedRemoteIPv4Routes = nil }
            var routes = [MockSystem.RouteRecord(
                destination: "129.22.9.9/32",
                gateway: scenario == "gateway" ? "192.168.1.254" : "192.168.1.1",
                interfaceName: "en0", flags: scenario == "host-flag" ? "UGS" : "UGHS")]
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
            try Shell.withCommandHandler({ try mock.handle($0) }) {
                let manager = RouteManager(splitTunnelPolicy: policy)
                if scenario == "safe" {
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

    @Test
    func mockedSplitTunnelFlow() throws {
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
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNSServers = ["129.22.4.32"]
        session.pushedSearchDomains = ["case.edu"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            activeDefaultDNSServers: ["129.22.4.32"],
            activeDefaultSearchDomains: ["case.edu"],
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
                MockSystem.RouteRecord(
                    destination: "10.8.0.0/24",
                    gateway: "10.8.0.10",
                    interfaceName: "utun7"),
            ])

        _ = try withResolverDirectory(resolverDirectory) {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
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
                    "/usr/sbin/chown root:wheel \(resolverFile.path)"),
                "Applying split tunnel should enforce root:wheel ownership on resolver files.")
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
            #expect(
                mockSystem.recordedCommands.contains("/bin/chmod 0644 \(resolverFile.path)"),
                "Applying split tunnel should enforce 0644 mode on resolver files.")
            #expect(
                mockSystem.recordedCommands.contains(
                    "/usr/sbin/chown root:wheel \(reverseResolverFile.path)"),
                "Applying split tunnel should enforce root:wheel ownership on reverse-zone resolver files."
            )
            #expect(
                mockSystem.recordedCommands.contains("/bin/chmod 0644 \(reverseResolverFile.path)"),
                "Applying split tunnel should enforce 0644 mode on reverse-zone resolver files.")
        }
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 0.0.0.0/1 192.168.1.1 -ifscope en0"),
            "Applying split tunnel should add the lower-half default route override.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 129.22.0.0/16 -interface utun7"),
            "Applying split tunnel should route fixed CWRU CIDRs through the tunnel interface.")
        #expect(
            mockSystem.recordedCommands.contains("/usr/sbin/scutil --dns"),
            "Applying split tunnel should verify that the active default resolver is not using CWRU scoped DNS."
        )
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
            tunName: "utun7",
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
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                let manager = RouteManager(splitTunnelPolicy: configuration)
                do {
                    try manager.applySplitTunnel(
                        using: &session, persistPreparedState: persistPreparedState)
                } catch {
                    physicalRoutePreserved = try manager.routeExists(
                        "129.22.0.0/16",
                        on: "en0",
                        in: manager.routingTableEntries())
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
            tunName: "utun7",
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

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            let manager = RouteManager(splitTunnelPolicy: configuration)
            let ipv4Overrides = try manager.protectedSplitIPv4RouteOverrides(on: "utun7", using: session)
            let ipv6Overrides = try manager.protectedSplitIPv6RouteOverrides(on: "utun7", using: session)
            #expect(ipv4Overrides == ["129.22.4.0/24"])
            #expect(ipv6Overrides == ["2606:ea00:4::/48"])
            #expect(throws: RouteManagerError.self) {
                _ = try manager.monitorAndRepair(using: session)
            }
        }
    }

    @Test
    func splitTunnelReplacesOnlyStaleManagedDefaultsAfterGatewayChange() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-gateway-change")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1085,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.20.10.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["172.20.10.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.managedSplitDefaultRoutes = [
            ManagedIPv4Route(
                destination: "0.0.0.0/1",
                nextHopKind: .gateway,
                nextHopValue: "192.168.1.1",
                interfaceName: "en0",
                isInterfaceScoped: true),
            ManagedIPv4Route(
                destination: "128.0.0.0/1",
                nextHopKind: .gateway,
                nextHopValue: "192.168.1.1",
                interfaceName: "en0",
                isInterfaceScoped: true),
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
                    destination: "0.0.0.0/1",
                    gateway: "192.168.1.1",
                    interfaceName: "en0",
                    flags: "UGScI"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "192.168.1.1",
                    interfaceName: "en0",
                    flags: "UGScI"),
            ])

        try withResolverDirectory(resolverDirectory) {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -net 0.0.0.0/1 192.168.1.1 -ifscope en0"),
            "Gateway migration should delete the exact stale lower-half route owned by cwru-ovpn.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -net 128.0.0.0/1 192.168.1.1 -ifscope en0"),
            "Gateway migration should delete the exact stale upper-half route owned by cwru-ovpn.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 0.0.0.0/1 172.20.10.1 -ifscope en0"),
            "Gateway migration should install the lower-half route through the current gateway.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 128.0.0.0/1 172.20.10.1 -ifscope en0"),
            "Gateway migration should install the upper-half route through the current gateway.")
        #expect(
            Set(session.managedSplitDefaultRoutes ?? [])
                == Set([
                    ManagedIPv4Route(
                        destination: "0.0.0.0/1", nextHopKind: .gateway,
                        nextHopValue: "172.20.10.1",
                        interfaceName: "en0", isInterfaceScoped: true),
                    ManagedIPv4Route(
                        destination: "128.0.0.0/1", nextHopKind: .gateway,
                        nextHopValue: "172.20.10.1",
                        interfaceName: "en0", isInterfaceScoped: true),
                ]),
            "Gateway migration should retain only the current owned split-default routes.")
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
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        splitSession.tunName = nil

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
            tunName: "utun7",
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
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
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
    func mockedSplitTunnelIPv6Flow() throws {
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
            tunName: "utun7",
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
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
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
            tunName: "utun7",
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

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
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
            tunName: "utun7",
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
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
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
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true,
            vpnIPv4: "100.96.5.101",
            vpnGatewayIPv4: "100.96.5.97"
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
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
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
    func splitTunnelRejectsPublicTunnelGatewayRoute() throws {
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
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true,
            vpnIPv4: "100.96.5.101",
            vpnGatewayIPv4: "8.8.8.8"
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
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
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
            "Split tunnel should not exempt a public non-CWRU route just because it matches gw4.")
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
            tunName: "utun7",
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
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
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
            tunName: "utun7",
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
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
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
            tunName: "utun7",
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
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
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
            tunName: "utun7",
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

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            let stillConnected = try RouteManager(splitTunnelPolicy: configuration)
                .monitorAndRepair(
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
        var session = makeSessionState(
            pid: 1015,
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
        session.managedSplitDefaultRoutes = [
            ManagedIPv4Route(
                destination: "0.0.0.0/1",
                nextHopKind: .gateway,
                nextHopValue: "192.168.1.1",
                interfaceName: "en0",
                isInterfaceScoped: true),
            ManagedIPv4Route(
                destination: "128.0.0.0/1",
                nextHopKind: .gateway,
                nextHopValue: "192.168.1.1",
                interfaceName: "en0",
                isInterfaceScoped: true),
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
                    destination: "0.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
            ])

        let stillConnected = try withResolverDirectory(resolverDirectory) {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).monitorAndRepair(using: session)
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
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 0.0.0.0/1 192.168.1.1 -ifscope en0"),
            "Route monitor should restore the lower physical split-default route.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 128.0.0.0/1 192.168.1.1 -ifscope en0"),
            "Route monitor should restore the upper physical split-default route.")
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
            tunName: "utun7",
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
            tunName: "utun7",
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
                tunName: "utun7",
                tunnelMode: .split,
                cleanupNeeded: true
            )

            try withResolverDirectory(resolverDirectory) {
                try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
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
        } catch RouteManagerError.failedToSecureSplitTunnelRoutes {
        } catch RouteManagerError.failedToSecureSplitTunnelIPv6Routes {
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
            tunName: "utun7",
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
    func splitTunnelCleansUpAfterResolverInstallFailure() throws {
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
            tunName: "utun7",
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
            failingCommandFragments: ["/bin/mkdir -p"])

        withResolverDirectory(resolverDirectory) {
            do {
                try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                    try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                        using: &session, persistPreparedState: persistPreparedState)
                }
                try #require(
                    Bool(false), "Split tunnel should fail when scoped resolver installation fails."
                )
            } catch {
                #expect(
                    mockSystem.recordedCommands.contains(
                        "/sbin/route -n delete -net 129.22.0.0/16 -interface utun7"),
                    "Split tunnel cleanup should delete split routes from the exact tunnel after resolver installation failure."
                )
                #expect(
                    !mockSystem.recordedCommands.contains(
                        "/usr/sbin/networksetup -setv6automatic Wi-Fi"),
                    "Split tunnel cleanup should not reset physical IPv6 when it was not changed.")
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
            tunName: "utun7",
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
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
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
