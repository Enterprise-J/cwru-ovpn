import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct FullTunnelIPv4SafetyTests {
    @Test
    func fullTunnelRepairsScopedOnlyDefaultCoverage() throws {
        let configuration = SplitTunnelPolicy(ipv4Routes: [], dnsDomains: ["case.edu"], dnsServers: ["10.8.0.2"])
        var session = makeSessionState(
            pid: 1110, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunName: "utun7", tunnelMode: .full, cleanupNeeded: true, vpnIPv6: nil)
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: [], ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(destination: "0.0.0.0/1", gateway: "link#9", interfaceName: "utun7", flags: "UScI"),
                MockSystem.RouteRecord(destination: "128.0.0.0/1", gateway: "link#9", interfaceName: "utun7", flags: "UScI"),
                MockSystem.RouteRecord(destination: "10.8.0.0/24", gateway: "link#9", interfaceName: "utun7"),
            ],
            initialIPv6Routes: ["::/1": "lo0", "8000::/1": "lo0"])

        try Shell.withCommandHandler({ try system.handle($0) }) {
            let manager = RouteManager(splitTunnelPolicy: configuration)
            #expect(try !manager.fullTunnelIPv4LooksSafe(tunnelName: "utun7", using: session))
            #expect(try manager.publicIPv4RouteState(for: "8.8.8.8", tunnelName: "utun7") == .physical)
            try manager.applyFullTunnelSafety(using: &session, persistPreparedState: persistPreparedState)
            #expect(try manager.fullTunnelIPv4LooksSafe(tunnelName: "utun7", using: session))
            #expect(try manager.publicIPv4RouteState(for: "8.8.8.8", tunnelName: "utun7") == .tunnel)
            let entries = try manager.routingTableEntries()
            #expect(entries.filter { $0.interfaceName == "utun7" && $0.isInterfaceScoped }.count == 2)
        }
        #expect(system.recordedCommands.contains("/sbin/route -n add -net 0.0.0.0/1 -interface utun7"))
        #expect(system.recordedCommands.contains("/sbin/route -n add -net 128.0.0.0/1 -interface utun7"))
        #expect(!system.recordedCommands.contains { $0.contains(" delete ") && $0.contains("-ifscope") })
    }

    @Test(arguments: [0, 1, 2])
    func ipv4SafetyDiagnosticsDistinguishUnavailableFromAbsent(failedRead: Int) throws {
        let session = makeSessionState(
            pid: 1111, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunName: "utun7", tunnelMode: .full, cleanupNeeded: true)
        var routeReads = 0
        let detail = Shell.withCommandHandler({ invocation in
            if invocation.launchPath == "/usr/sbin/netstat" {
                routeReads += 1
                if routeReads == failedRead {
                    return ShellResult(exitCode: 1, stdout: "", stderr: "route inspection unavailable")
                }
            }
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        }) {
            RouteManager(splitTunnelPolicy: .fixed).fullTunnelIPv4SafetyFailureDetail(tunnelName: "utun7", using: session)
        }
        #expect(detail.contains("default route coverage unavailable") == (failedRead == 1))
        #expect(detail.contains("0.0.0.0/1=absent") == (failedRead != 1))
        #expect(detail.contains("unexpected routes unavailable") == (failedRead == 2))
        #expect(detail.contains("unexpected routes none") == (failedRead != 2))
        #expect(detail.contains("route inspection unavailable") == (failedRead != 0))
    }

    @Test
    func settlingFullTunnelChecksCurrentRoutesAndDNSWithoutMutation() throws {
        let policy = SplitTunnelPolicy(ipv4Routes: [], dnsDomains: [], dnsServers: [])
        let state = makeSessionState(
            pid: 71, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["192.168.1.1"], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunName: "utun7", tunnelMode: .full, cleanupNeeded: true)
        for scenario in ["safe", "ipv4", "ipv6", "dns", "missing"] {
            var routes = ["0.0.0.0/1", "128.0.0.0/1"].map {
                MockSystem.RouteRecord(destination: $0, gateway: "link#9", interfaceName: "utun7")
            }
            if scenario == "ipv4" || scenario == "dns" {
                routes.append(MockSystem.RouteRecord(
                    destination: scenario == "ipv4" ? "8.8.8.8/32" : "10.8.0.53/32",
                    gateway: "192.168.1.1", interfaceName: "en0", flags: "UGHS"))
            }
            let mock = MockSystem(
                serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
                physicalDNSServers: ["10.8.0.53"], physicalSearchDomains: [], ipv6Mode: "Off",
                tunnelInterfaces: scenario == "missing" ? [] : ["utun7"],
                initialRoutes: routes,
                initialIPv6Routes: ["::/1": "lo0", "8000::/1": "lo0"],
                initialIPv6RouteRecords: scenario == "ipv6" ? [
                    MockSystem.RouteRecord(destination: "2606:4700::/32", gateway: "fe80::1", interfaceName: "en0"),
                ] : [])
            try Shell.withCommandHandler({ try mock.handle($0) }) {
                let manager = RouteManager(splitTunnelPolicy: policy)
                if scenario == "safe" {
                    try manager.validateNetworkSafetyWhileSettling(using: state)
                } else {
                    do {
                        try manager.validateNetworkSafetyWhileSettling(using: state)
                        Issue.record("Unsafe settling network was accepted: \(scenario)")
                    } catch {
                        let expected: RouteManagerError
                        switch scenario {
                        case "ipv4": expected = .failedToSecureFullTunnelIPv4Routes
                        case "ipv6": expected = .failedToSecureFullTunnelIPv6Routes
                        case "dns": expected = .failedToSecureFullTunnelDNS
                        default: expected = .missingTunnelInterface
                        }
                        #expect(error.localizedDescription == expected.localizedDescription)
                    }
                }
            }
            #expect(mock.recordedCommands.allSatisfy {
                !$0.contains(" -set") && !$0.contains(" add ") && !$0.contains(" delete ")
                    && !$0.contains(" change ") && !$0.contains(" flush")
            })
        }
    }

    @Test
    func mockedFullTunnelModeSwitch() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-full")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu", "cwru.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1002,
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
            vpnIPv6: nil
        )
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        session.appliedDNSDomains = ["case.edu", "22.129.in-addr.arpa"]
        session.fullTunnelDNSServers = ["10.8.0.2"]
        session.fullTunnelSearchDomains = ["case.edu"]
        session.serverIP = "207.182.159.133"

        try withResolverDirectory(resolverDirectory) {
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            try scopedResolverContents(domain: "case.edu", nameServer: "129.22.4.32").write(
                to: testResolverFileURL(for: "case.edu"),
                atomically: true,
                encoding: .utf8)
            try scopedResolverContents(domain: "old.example", nameServer: "129.22.4.32").write(
                to: testResolverFileURL(for: "old.example"),
                atomically: true,
                encoding: .utf8)

            let physicalIPv6Route = MockSystem.RouteRecord(
                destination: "2603:6011:500:481e::/64",
                gateway: "link#14",
                interfaceName: "en0",
                flags: "UC")
            let mockSystem = MockSystem(
                serviceName: "Wi-Fi",
                physicalGateway: "192.168.1.1",
                physicalInterface: "en0",
                physicalDNSServers: ["1.1.1.1"],
                physicalSearchDomains: ["home"],
                ipv6Mode: "Automatic",
                tunnelInterfaces: ["utun7"],
                physicalIPv6RouteSnapshotsAfterIPv6Off: [[physicalIPv6Route], [], []],
                initialRoutes: [
                    MockSystem.RouteRecord(
                        destination: "129.22.0.0/16",
                        gateway: "link#1",
                        interfaceName: "utun7"),
                    MockSystem.RouteRecord(
                        destination: "192.168.1.1/32",
                        gateway: "link#1",
                        interfaceName: "en0",
                        flags: "UHS"),
                    MockSystem.RouteRecord(
                        destination: "192.168.1.1/32",
                        gateway: "link#1",
                        interfaceName: "en0",
                        flags: "UHSI"),
                    MockSystem.RouteRecord(
                        destination: "207.182.159.133/32",
                        gateway: "192.168.1.1",
                        interfaceName: "en0",
                        flags: "UGHS"),
                    MockSystem.RouteRecord(
                        destination: "207.182.159.133/32",
                        gateway: "192.168.0.1",
                        interfaceName: "en0",
                        flags: "UGHSI"),
                ],
                initialIPv6RouteRecords: [physicalIPv6Route])

            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).switchToFullTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }

            #expect(
                mockSystem.ipv6NetstatReadsAfterIPv6Off == 3,
                "Switching to full tunnel should require two consecutive safe IPv6 assessments after transient physical routes disappear."
            )
            let ipv6OffCommand = "/usr/sbin/networksetup -setv6off Wi-Fi"
            let ipv6OffIndex = mockSystem.recordedCommands.firstIndex(of: ipv6OffCommand)
            let stabilizationCommands =
                ipv6OffIndex.map {
                    Array(mockSystem.recordedCommands.dropFirst($0 + 1).prefix(12))
                } ?? []
            #expect(
                stabilizationCommands.count == 12
                    && stabilizationCommands.allSatisfy {
                        $0.hasPrefix("/sbin/route -n get -inet6 ")
                            || $0 == "/usr/sbin/netstat -nrf inet6"
                    },
                "Full-tunnel IPv6 stabilization should perform only read-only route assessments after disabling physical IPv6."
            )

            #expect(
                session.appliedSplitIPv4Routes == ["129.22.0.0/16"],
                "Switching to full tunnel should retain applied split-tunnel IPv4 routes that already use the same tunnel."
            )
            #expect(
                session.appliedSplitIPv6Routes == nil,
                "Switching to full tunnel should preserve the absence of split-tunnel IPv6 routes.")
            #expect(
                session.appliedDNSDomains == ["case.edu", "cwru.edu"],
                "Switching to full tunnel should record the full-tunnel scoped CWRU DNS domains.")
            #expect(
                FileManager.default.fileExists(atPath: testResolverFileURL(for: "case.edu").path),
                "Switching to full tunnel should install scoped CWRU resolvers so CWRU domains resolve via CWRU DNS."
            )
            #expect(
                FileManager.default.fileExists(atPath: testResolverFileURL(for: "cwru.edu").path),
                "Switching to full tunnel should install the cwru.edu scoped resolver.")
            #expect(
                !FileManager.default.fileExists(
                    atPath: testResolverFileURL(for: "old.example").path),
                "Switching to full tunnel should remove resolver domains that are obsolete in the target mode."
            )
            let targetResolverInstall = "/usr/bin/tee \(testResolverFileURL(for: "case.edu").path)"
            let obsoleteResolverRemoval =
                "/bin/rm -f \(testResolverFileURL(for: "old.example").path)"
            let targetResolverInstallIndex = mockSystem.recordedCommands.firstIndex(
                of: targetResolverInstall)
            let obsoleteResolverRemovalIndex = mockSystem.recordedCommands.firstIndex(
                of: obsoleteResolverRemoval)
            #expect(
                targetResolverInstallIndex != nil && obsoleteResolverRemovalIndex != nil
                    && targetResolverInstallIndex! < obsoleteResolverRemovalIndex!,
                "Switching to full tunnel should install target resolver content before removing obsolete resolver files."
            )
            #expect(
                !mockSystem.recordedCommands.contains(
                    "/bin/rm -f \(testResolverFileURL(for: "case.edu").path)"),
                "Switching to full tunnel should not remove a resolver domain retained by the target mode."
            )
            #expect(
                mockSystem.recordedCommands.contains(
                    "/sbin/route -n get -inet6 2001:4860:4860::8888"),
                "Switching to full tunnel should validate that public IPv6 no longer leaves through the physical interface."
            )
            #expect(
                mockSystem.recordedCommands.contains(
                    "/sbin/route -n add -net 0.0.0.0/1 -interface utun7"),
                "Switching to full tunnel should restore captured gateway defaults as tunnel-interface routes."
            )
            let tunnelDefaultIndex = mockSystem.recordedCommands.firstIndex(
                of: "/sbin/route -n add -net 0.0.0.0/1 -interface utun7")
            let secondTunnelDefaultIndex = mockSystem.recordedCommands.firstIndex(
                of: "/sbin/route -n add -net 128.0.0.0/1 -interface utun7")
            let includedRouteDeleteIndex = mockSystem.recordedCommands.firstIndex(
                of: "/sbin/route -n delete -net 129.22.0.0/16 -interface utun7")
            #expect(
                tunnelDefaultIndex != nil && secondTunnelDefaultIndex != nil,
                "Switching to full tunnel should install both tunnel default routes.")
            #expect(
                includedRouteDeleteIndex == nil,
                "Switching to full tunnel should retain split routes that already use the target tunnel."
            )
            let controlRouteProbeIndex = mockSystem.recordedCommands.lastIndex(
                of: "/sbin/route -n get 207.182.159.133")
            #expect(
                !mockSystem.recordedCommands.contains(
                    "/sbin/route -n delete -host 192.168.1.1 -interface en0 -ifscope en0"),
                "Switching to full tunnel should preserve a scoped sibling of an existing safe gateway route."
            )
            #expect(
                mockSystem.recordedCommands.contains(
                    "/sbin/route -n delete -host 207.182.159.133 192.168.0.1 -ifscope en0"),
                "Switching to full tunnel should remove a scoped server route through a stale gateway."
            )
            #expect(
                !mockSystem.recordedCommands.contains(
                    "/sbin/route -n delete -host 207.182.159.133 192.168.1.1"),
                "Switching to full tunnel must preserve an existing safe unscoped server route.")
            #expect(
                !mockSystem.recordedCommands.contains(
                    "/sbin/route -n delete -host 192.168.1.1 -interface en0"),
                "Switching to full tunnel must preserve an existing safe unscoped gateway route.")
            #expect(
                !mockSystem.recordedCommands.contains(
                    "/sbin/route -n add -host 207.182.159.133 192.168.1.1"),
                "Switching to full tunnel must not claim an existing safe server route.")
            #expect(
                !mockSystem.recordedCommands.contains(
                    "/sbin/route -n add -host 192.168.1.1 -interface en0"),
                "Switching to full tunnel must not claim an existing safe gateway route.")
            #expect(
                !mockSystem.recordedCommands.contains(
                    "/sbin/route -n add -host 67.219.145.198 192.168.1.1"),
                "Switching to full tunnel should not trust captured excluded routes as VPN control endpoints."
            )
            #expect(
                controlRouteProbeIndex != nil && tunnelDefaultIndex! < controlRouteProbeIndex!,
                "Switching to full tunnel should verify the unscoped control route after installing tunnel defaults."
            )
            #expect(
                session.fullTunnelDefaultRoutes == [
                    ManagedIPv4Route(
                        destination: "0.0.0.0/1", nextHopKind: .interface, nextHopValue: "utun7",
                        interfaceName: "utun7", isInterfaceScoped: false),
                    ManagedIPv4Route(
                        destination: "128.0.0.0/1", nextHopKind: .interface, nextHopValue: "utun7",
                        interfaceName: "utun7", isInterfaceScoped: false),
                ],
                "Switching to full tunnel should persist normalized tunnel-interface default routes."
            )
            #expect(
                session.managedRemoteIPv4Routes == nil,
                "Switching to full tunnel must not ledger pre-existing safe host routes as app-owned."
            )
            #expect(
                Set(session.replacedRemoteIPv4Routes ?? [])
                    == Set([
                        ManagedIPv4Route(
                            destination: "207.182.159.133/32",
                            nextHopKind: .gateway,
                            nextHopValue: "192.168.0.1",
                            interfaceName: "en0",
                            isInterfaceScoped: true)
                    ]),
                "Switching to full tunnel should ledger only the removed unsafe scoped siblings.")

            let cleanupHealthy = try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
            }
            #expect(
                cleanupHealthy,
                "Cleanup should remain healthy without touching preserved safe route siblings.")
            #expect(
                mockSystem.recordedCommands.contains(
                    "/sbin/route -n add -host 207.182.159.133 192.168.0.1 -ifscope en0"),
                "Cleanup should restore the removed stale-gateway server sibling.")
        }
    }

    @Test
    func mockedFullToSplitModeSwitchPreparesTargetState() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-full-to-split")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy.fixed

        var session = makeSessionState(
            pid: 1028,
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
        session.fullTunnelDNSServers = ["10.8.0.2"]
        session.fullTunnelSearchDomains = ["case.edu"]
        session.appliedDNSDomains = ["case.edu", "old.example"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["10.8.0.2"],
            physicalSearchDomains: ["case.edu"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "0.0.0.0/1", gateway: "link#1", interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1", gateway: "link#1", interfaceName: "utun7"),
            ]
        )

        try withResolverDirectory(resolverDirectory) {
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            try scopedResolverContents(domain: "case.edu", nameServer: "10.8.0.2")
                .write(to: testResolverFileURL(for: "case.edu"), atomically: true, encoding: .utf8)
            try scopedResolverContents(domain: "old.example", nameServer: "10.8.0.2")
                .write(
                    to: testResolverFileURL(for: "old.example"), atomically: true, encoding: .utf8)

            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }

            let fixedRouteAdd = "/sbin/route -n add -net 129.22.0.0/16 -interface utun7"
            let tunnelDefaultDelete = "/sbin/route -n delete -net 0.0.0.0/1 -interface utun7"
            let resolverInstall = "/usr/bin/tee \(testResolverFileURL(for: "case.edu").path)"
            let obsoleteResolverRemoval =
                "/bin/rm -f \(testResolverFileURL(for: "old.example").path)"
            let fixedRouteAddIndex = mockSystem.recordedCommands.firstIndex(of: fixedRouteAdd)
            let tunnelDefaultDeleteIndex = mockSystem.recordedCommands.firstIndex(
                of: tunnelDefaultDelete)
            let resolverInstallIndex = mockSystem.recordedCommands.firstIndex(of: resolverInstall)
            let obsoleteResolverRemovalIndex = mockSystem.recordedCommands.firstIndex(
                of: obsoleteResolverRemoval)
            #expect(
                fixedRouteAddIndex != nil && tunnelDefaultDeleteIndex != nil
                    && fixedRouteAddIndex! < tunnelDefaultDeleteIndex!,
                "Switching to split tunnel should install fixed CWRU routes before removing full-tunnel defaults."
            )
            #expect(
                resolverInstallIndex != nil && obsoleteResolverRemovalIndex != nil
                    && resolverInstallIndex! < obsoleteResolverRemovalIndex!,
                "Switching to split tunnel should install target resolver content before removing obsolete resolver files."
            )
            #expect(
                !mockSystem.recordedCommands.contains(
                    "/bin/rm -f \(testResolverFileURL(for: "case.edu").path)"),
                "Switching to split tunnel should not remove a resolver domain retained by the target mode."
            )
            #expect(
                session.appliedSplitIPv4Routes == SplitTunnelPolicy.fixedIPv4Routes,
                "Switching to split tunnel should persist the complete prepared IPv4 route set.")
            #expect(
                !FileManager.default.fileExists(
                    atPath: testResolverFileURL(for: "old.example").path),
                "Switching to split tunnel should remove resolver domains that are obsolete in the target mode."
            )
        }
    }

    @Test
    func fullTunnelIPv4SafetyInstallsFailClosedRoutes() throws {
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
            originalDNSServers: ["10.8.0.2"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["10.8.0.2"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            activeDefaultDNSServers: ["10.8.0.2"],
            tunnelInterfaces: ["utun7"])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            let manager = RouteManager(
                splitTunnelPolicy: configuration,
                dnsBootstrapServers: ["203.0.113.53", "198.51.100.53"])
            try manager.applyFullTunnelSafety(
                using: &session, persistPreparedState: persistPreparedState)
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 0.0.0.0/1 -interface utun7"),
            "Full tunnel safety should install a fail-closed lower-half IPv4 default route when public IPv4 is physical."
        )
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 128.0.0.0/1 -interface utun7"),
            "Full tunnel safety should install a fail-closed upper-half IPv4 default route when public IPv4 is physical."
        )
        let externalProbeCommands = [
            "/sbin/route -n get 1.1.1.1",
            "/sbin/route -n get 8.8.8.8",
            "/sbin/route -n get \(mockPublicDNSServerB)",
        ]
        #expect(
            !mockSystem.recordedCommands.contains { externalProbeCommands.contains($0) },
            "Full tunnel IPv4 safety should rely on route-table coverage instead of external route probes."
        )
    }

    @Test
    func fullTunnelIPv4SafetyFailureThrows() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1018,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            failingRouteAdds: ["0.0.0.0/1", "128.0.0.0/1"])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should fail closed when fail-closed IPv4 routes cannot be installed.")
        } catch RouteManagerError.failedToSecureFullTunnelIPv4Routes {
        }
    }

    @Test
    func fullTunnelRejectsMoreSpecificPhysicalPublicRoute() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1026,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

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
                    destination: "8.8.8.0/24",
                    gateway: "192.168.1.1",
                    interfaceName: "en0")
            ])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should fail closed when a more-specific public route remains on a physical interface."
            )
        } catch RouteManagerError.failedToSecureFullTunnelIPv4Routes {
        }
    }

    @Test
    func fullTunnelRejectsClonedPhysicalPublicIPv4Route() throws {
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
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

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
                    destination: "8.8.8.8/32",
                    gateway: "aa:bb:cc:dd:ee:ff",
                    interfaceName: "en0",
                    flags: "UHLW",
                    expire: "1200")
            ])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should fail closed when a cloned public host route remains on a physical interface."
            )
        } catch RouteManagerError.failedToSecureFullTunnelIPv4Routes {
        }
    }

    @Test
    func fullTunnelRejectsMoreSpecificExternalIPv4TunnelRoute() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
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
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7", "utun99"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "8.8.8.0/24",
                    gateway: "link#99",
                    interfaceName: "utun99")
            ])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should fail closed when a more-specific public route remains on another tunnel interface."
            )
        } catch RouteManagerError.failedToSecureFullTunnelIPv4Routes {
        }
    }

    @Test
    func fullTunnelAllowsPhysicalServerHostRoute() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1027,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.serverIP = "67.219.145.199"

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
                    destination: "67.219.145.199/32",
                    gateway: "192.168.1.1",
                    interfaceName: "en0"),
                MockSystem.RouteRecord(
                    destination: "67.219.145.199/32",
                    gateway: "192.168.1.1",
                    interfaceName: "en0",
                    flags: "UGHSI"),
            ])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                using: &session, persistPreparedState: persistPreparedState)
        }
        #expect(
            !mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 67.219.145.199 192.168.1.1 -ifscope en0"),
            "Full tunnel should preserve a safe scoped sibling of the unscoped server route.")
    }

    @Test
    func fullTunnelAllowsPhysicalOnLinkPublicSubnet() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1028,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "129.22.0.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.fullTunnelDNSServers = ["10.8.0.2"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "129.22.0.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            physicalIfconfigOutput: """
                en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
                inet 129.22.5.10 netmask 0xffff0000 broadcast 129.22.255.255
                """,
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "129.22.0.0/16",
                    gateway: "link#1",
                    interfaceName: "en0",
                    flags: "UCS")
            ])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                using: &session, persistPreparedState: persistPreparedState)
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 0.0.0.0/1 -interface utun7"),
            "Full tunnel safety should still install fail-closed default routes alongside a public on-link segment."
        )
    }

    @Test
    func fullTunnelAllowsPublicGatewayNeighborEntries() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1099,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "129.22.0.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.fullTunnelDNSServers = ["10.8.0.2"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "129.22.0.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            physicalIfconfigOutput: """
                en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
                inet 129.22.5.10 netmask 0xffff0000 broadcast 129.22.255.255
                """,
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "129.22.0.0/16",
                    gateway: "link#1",
                    interfaceName: "en0",
                    flags: "UCS"),
                MockSystem.RouteRecord(
                    destination: "129.22.0.1/32",
                    gateway: "link#1",
                    interfaceName: "en0",
                    flags: "UHS"),
                MockSystem.RouteRecord(
                    destination: "129.22.0.1",
                    gateway: "aa:bb:cc:dd:ee:ff",
                    interfaceName: "en0",
                    flags: "UHLWIir",
                    expire: "1200"),
                MockSystem.RouteRecord(
                    destination: "129.22.5.20",
                    gateway: "aa:bb:cc:dd:ee:01",
                    interfaceName: "en0",
                    flags: "UHLWI",
                    expire: "900"),
            ])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                using: &session, persistPreparedState: persistPreparedState)
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 0.0.0.0/1 -interface utun7"),
            "Full tunnel safety should secure IPv4 despite kernel neighbor entries on a public-gateway segment."
        )
        #expect(
            !mockSystem.recordedCommands.contains(where: {
                $0.hasPrefix("/sbin/route -n delete -host 129.22.0.1 -interface en0")
                    || $0.hasPrefix("/sbin/route -n delete -host 129.22.5.20")
            }),
            "Full tunnel safety must leave kernel neighbor entries on the physical segment alone.")
    }

    @Test
    func fullTunnelAllowsOwnAddressKernelRoutesOnPublicLAN() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1100,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "129.22.0.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.fullTunnelDNSServers = ["10.8.0.2"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "129.22.0.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            physicalIfconfigOutput: """
                en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
                inet 129.22.5.10 netmask 0xffff0000 broadcast 129.22.255.255
                """,
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "129.22.0.0/16",
                    gateway: "link#1",
                    interfaceName: "en0",
                    flags: "UCS"),
                MockSystem.RouteRecord(
                    destination: "129.22.0.1/32",
                    gateway: "link#1",
                    interfaceName: "en0",
                    flags: "UCS"),
                MockSystem.RouteRecord(
                    destination: "129.22.0.1",
                    gateway: "aa:bb:cc:dd:ee:ff",
                    interfaceName: "en0",
                    flags: "UHLWIir",
                    expire: "1200"),
                MockSystem.RouteRecord(
                    destination: "129.22.5.10/32",
                    gateway: "link#1",
                    interfaceName: "en0",
                    flags: "UCS"),
                MockSystem.RouteRecord(
                    destination: "129.22.5.10",
                    gateway: "aa:bb:cc:dd:ee:10",
                    interfaceName: "lo0",
                    flags: "UHLWI"),
            ])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                using: &session, persistPreparedState: persistPreparedState)
        }

        #expect(
            !mockSystem.recordedCommands.contains(where: { $0.hasPrefix("/sbin/route -n delete -host 129.22.5.10") }),
            "Full tunnel safety must leave the interface's own kernel routes on a public-addressed LAN alone.")
    }

    @Test
    func fullTunnelRejectsOffLinkStaticHostRoute() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1101,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "129.22.0.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.fullTunnelDNSServers = ["10.8.0.2"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "129.22.0.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            physicalIfconfigOutput: """
                en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
                inet 129.22.5.10 netmask 0xffff0000 broadcast 129.22.255.255
                """,
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "129.22.0.0/16",
                    gateway: "link#1",
                    interfaceName: "en0",
                    flags: "UCS"),
                MockSystem.RouteRecord(
                    destination: "8.8.8.8/32",
                    gateway: "link#1",
                    interfaceName: "en0",
                    flags: "UCS"),
            ])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(Bool(false), "A static off-link public host route must fail full-tunnel IPv4 safety.")
        } catch RouteManagerError.failedToSecureFullTunnelIPv4Routes {
        }
    }

    @Test
    func fullTunnelRejectsWidePhysicalOnLinkPublicRoutes() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1098,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "129.22.0.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

        let wideRoutes = [
            (route: "128.0.0.0/1", netmask: "0x80000000"),
            (route: "128.0.0.0/2", netmask: "0xc0000000"),
            (route: "129.22.0.0/15", netmask: "0xfffe0000"),
        ]
        for fixture in wideRoutes {
            let mockSystem = MockSystem(
                serviceName: "Wi-Fi",
                physicalGateway: "129.22.0.1",
                physicalInterface: "en0",
                physicalDNSServers: ["1.1.1.1"],
                physicalSearchDomains: ["home"],
                ipv6Mode: "Off",
                tunnelInterfaces: ["utun7"],
                physicalIfconfigOutput: """
                    en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
                    inet 129.22.5.10 netmask \(fixture.netmask) broadcast 255.255.255.255
                    """,
                initialRoutes: [
                    MockSystem.RouteRecord(
                        destination: fixture.route,
                        gateway: "link#1",
                        interfaceName: "en0",
                        flags: "UCS")
                ])
            do {
                try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                    try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                        using: &session, persistPreparedState: persistPreparedState)
                }
                try #require(
                    Bool(false),
                    "Full tunnel should reject a wide physical on-link route: \(fixture.route)")
            } catch RouteManagerError.failedToSecureFullTunnelIPv4Routes {
            }
        }

        let manager = RouteManager(splitTunnelPolicy: configuration)
        #expect(
            manager.ipv4PrefixLength(fromNetmask: "0xffff0000") == 16,
            "Connected-route parsing should accept contiguous hexadecimal netmasks.")
        #expect(
            manager.ipv4PrefixLength(fromNetmask: "255.255.254.0") == 23,
            "Connected-route parsing should accept contiguous dotted netmasks.")
        #expect(
            manager.ipv4PrefixLength(fromNetmask: "0xff00ff00") == nil,
            "Connected-route parsing should reject noncontiguous netmasks.")
    }

    @Test
    func fullTunnelRejectsCarvedOnLinkPublicSubnet() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1029,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            physicalIfconfigOutput: """
                en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
                inet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255
                """,
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "8.8.8.0/24",
                    gateway: "link#1",
                    interfaceName: "en0",
                    flags: "UCS")
            ])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should fail closed for an on-link public route that does not hold the gateway."
            )
        } catch RouteManagerError.failedToSecureFullTunnelIPv4Routes {
        }
    }

    @Test
    func fullTunnelFailsClosedWithoutServerIP() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1071,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.serverIP = nil
        session.serverHost = nil

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
                    destination: "0.0.0.0/1",
                    gateway: "link#1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "link#1",
                    interfaceName: "utun7"),
            ])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel must fail closed when no VPN server IP is available to verify the control channel."
            )
        } catch RouteManagerError.failedToSecureFullTunnelControlChannel {
        }
    }

    @Test
    func fullTunnelRejectsUntrustedExcludedRemoteHostRoutes() throws {
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
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.serverIP = "67.219.145.199"

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
                    destination: "67.219.145.199/32",
                    gateway: "192.168.1.1",
                    interfaceName: "en0"),
                MockSystem.RouteRecord(
                    destination: "67.219.145.198/32",
                    gateway: "192.168.1.1",
                    interfaceName: "en0"),
                MockSystem.RouteRecord(
                    destination: "207.182.159.132/32",
                    gateway: "192.168.1.1",
                    interfaceName: "en0"),
            ])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should reject physical host routes that came only from untrusted excluded-route output."
            )
        } catch RouteManagerError.failedToSecureFullTunnelIPv4Routes {
        }
    }

    @Test
    func fullTunnelRejectsNonRemotePublicHostRoute() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1029,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.serverIP = "67.219.145.199"

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
                    destination: "8.8.8.8/32",
                    gateway: "192.168.1.1",
                    interfaceName: "en0")
            ])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should reject public host routes that are not VPN remote endpoints.")
        } catch RouteManagerError.failedToSecureFullTunnelIPv4Routes {
        }
    }

    @Test
    func fullTunnelFailsWhenServerRouteResolvesToTunnel() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1041,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.serverIP = "207.182.159.133"

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            blockedIPv6ProbeDestinations: ["2001:4860:4860::8888", "3000::1", "9000::1"],
            failingRouteAdds: ["207.182.159.133"])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).switchToFullTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Switching to full tunnel should fail closed when the VPN server endpoint would route into the tunnel."
            )
        } catch RouteManagerError.failedToSecureFullTunnelControlChannel {
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 0.0.0.0/1 -interface utun7"),
            "A failed full-tunnel switch should leave fail-closed default routes installed rather than leaking traffic."
        )
    }

    @Test
    func fullTunnelPersistsGatewayHostRouteBeforeLaterSafetyFailure() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1046,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.serverIP = nil

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
                    destination: "0.0.0.0/1",
                    gateway: "link#1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "link#1",
                    interfaceName: "utun7"),
            ])
        var persistedState: SessionState?

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                    using: &session
                ) {
                    preparedState in
                    persistedState = preparedState
                }
            }
            try #require(
                Bool(false),
                "Full tunnel should fail when control-channel egress cannot be verified.")
        } catch RouteManagerError.failedToSecureFullTunnelControlChannel {
        }

        #expect(
            persistedState?.managedRemoteIPv4Routes?.contains(
                ManagedIPv4Route(
                    destination: "192.168.1.1/32",
                    nextHopKind: .interface,
                    nextHopValue: "en0",
                    interfaceName: "en0",
                    isInterfaceScoped: false)
            ) == true,
            "Full-tunnel safety should persist the gateway host route before later safety checks can fail."
        )
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n add -host 192.168.1.1 -interface en0"),
            "Full-tunnel safety should pin the physical gateway before the later failure.")
    }

    @Test
    func fullTunnelMonitorPreservesServerHostRoute() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1042,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true,
            vpnIPv6: nil
        )
        session.serverIP = "207.182.159.133"

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
                    destination: "0.0.0.0/1",
                    gateway: "link#1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "link#1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "207.182.159.133/32",
                    gateway: "192.168.1.1",
                    interfaceName: "en0",
                    flags: "UGHS"),
            ])

        var monitorState = session
        var preparedRejectSnapshots: [(routes: Set<String>, commandCount: Int)] = []
        let stillConnected = try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).monitorFullTunnel(
                using: &monitorState
            ) {
                preparedState in
                let routes = Set(preparedState.managedIPv6Routes?.map(\.destination) ?? [])
                preparedRejectSnapshots.append((routes, mockSystem.recordedCommands.count))
            }
        }

        #expect(
            stillConnected,
            "The full-tunnel monitor should report the tunnel is healthy while the server host route is protected."
        )
        #expect(
            !mockSystem.recordedCommands.contains {
                $0.hasPrefix("/sbin/route -n delete -host 207.182.159.133")
            },
            "The full-tunnel monitor must not delete the protected VPN server host route.")
        #expect(
            !mockSystem.recordedCommands.contains(where: {
                $0.hasPrefix("/sbin/route -n add -host 207.182.159.133 ")
            }),
            "The full-tunnel monitor should leave an existing static VPN server host route untouched."
        )
        let rejectRoutesWerePersistedBeforeMutation = ["::/1", "8000::/1"].allSatisfy { route in
            let routeAddress = route == "::/1" ? "::" : "8000::"
            guard
                let addIndex = mockSystem.recordedCommands.firstIndex(
                    of:
                        "/sbin/route -n add -net -inet6 \(routeAddress) -prefixlen 1 -reject ::1%lo0"
                )
            else {
                return false
            }
            return preparedRejectSnapshots.contains {
                $0.routes.contains(route) && $0.commandCount <= addIndex
            }
        }
        #expect(
            rejectRoutesWerePersistedBeforeMutation,
            "The full-tunnel monitor should persist ownership of repair routes before mutating the route table."
        )
    }
}
