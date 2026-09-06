import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct FullTunnelIPv6SafetyTests {
    @Test
    func fullTunnelIPv6CoverageRejectsScopedOnlyRoutes() throws {
        let scoped = try ["::/1", "8000::/1"].map {
            try #require(RouteEntry(line: Substring("\($0) link#9 UScI utun7")))
        }
        let unscoped = try ["::/1", "8000::/1"].map {
            try #require(RouteEntry(line: Substring("\($0) link#9 USc utun7")))
        }
        let manager = RouteManager(splitTunnelPolicy: .fixed)
        #expect(!manager.fullTunnelPublicIPv6RangeIsCovered(tunnelName: "utun7", entries: scoped))
        #expect(manager.fullTunnelPublicIPv6RangeIsCovered(tunnelName: "utun7", entries: unscoped))
        #expect(manager.fullTunnelPublicIPv6RangeIsCovered(tunnelName: "utun7", entries: scoped + unscoped))
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Automatic", tunnelInterfaces: ["utun7"],
            initialIPv6RouteRecords: scoped.map {
                MockSystem.RouteRecord(destination: $0.destination, gateway: $0.gateway, interfaceName: $0.interfaceName, flags: $0.flags)
            })
        try Shell.withCommandHandler({ try system.handle($0) }) {
            let state = try manager.publicIPv6RouteState(for: "2001:4860:4860::8888", tunnelName: "utun7")
            #expect(state == .physical)
        }
    }

    @Test
    func fullTunnelRefusesNAT64Network() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1045,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.0.0.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: [],
            originalSearchDomains: [],
            originalIPv6Mode: "Automatic",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true,
            vpnIPv6: nil
        )
        session.serverIP = "207.182.159.132"

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.0.0.1",
            physicalInterface: "en0",
            physicalDNSServers: [],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            physicalIfconfigOutput: """
                en0: flags=88e3<UP,BROADCAST,SMART,RUNNING,NOARP,SIMPLEX,MULTICAST> mtu 1500
                inet 192.0.0.2 netmask 0xffffffff broadcast 192.0.0.2
                inet6 2607:fb90::2 prefixlen 64 clat46
                nat64 prefix 2607:7700:0:7:0:1:: prefixlen 96
                """)

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(Bool(false), "Full tunnel must refuse a NAT64/CLAT network.")
        } catch RouteManagerError.unsupportedNAT64Network {
        }
        #expect(
            !mockSystem.recordedCommands.contains { $0.hasPrefix("/sbin/route -n add") },
            "A NAT64/CLAT network must be refused before any full-tunnel route is installed.")
        #expect(
            !mockSystem.recordedCommands.contains("/usr/sbin/networksetup -setv6off Wi-Fi"),
            "A NAT64/CLAT network must be refused before physical IPv6 is touched.")
    }

    @Test
    func fullTunnelPreservesPreexistingIPv6BlockRoute() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1084,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: [],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true,
            vpnIPv6: nil
        )
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: [],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialIPv6Routes: ["::/1": "lo0"])

        let healthy = try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            let manager = RouteManager(splitTunnelPolicy: configuration)
            try manager.installBlockedIPv6DefaultRoutes(
                using: &session, persistPreparedState: persistPreparedState)
            return try manager.cleanup(using: session)
        }

        #expect(
            healthy,
            "Cleanup should ignore a pre-existing IPv6 reject route that was not added by cwru-ovpn."
        )
        #expect(
            session.managedIPv6Routes?.contains(
                ManagedIPv6Route(
                    destination: "::/1",
                    nextHopKind: .reject,
                    nextHopValue: "::1%lo0",
                    interfaceName: "lo0",
                    isInterfaceScoped: false)) != true,
            "Pre-existing IPv6 reject routes must not be recorded as cwru-ovpn-owned.")
        #expect(
            !mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -net -inet6 :: -prefixlen 1 -reject ::1%lo0"),
            "Cleanup must not delete a pre-existing IPv6 reject route.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -net -inet6 8000:: -prefixlen 1 -reject ::1%lo0"),
            "Cleanup should still delete the IPv6 reject route that cwru-ovpn added.")
    }

    @Test
    func switchToSplitRemovesFullTunnelIPv6BlockRoutes() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1085,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: [],
            originalSearchDomains: [],
            originalIPv6Mode: "Automatic",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true,
            vpnIPv4: nil,
            vpnIPv6: nil
        )
        session.managedIPv6Routes = [
            ManagedIPv6Route(
                destination: "::/1", nextHopKind: .reject, nextHopValue: "::1%lo0",
                interfaceName: "lo0",
                isInterfaceScoped: false),
            ManagedIPv6Route(
                destination: "8000::/1", nextHopKind: .reject, nextHopValue: "::1%lo0",
                interfaceName: "lo0", isInterfaceScoped: false),
        ]
        session.sessionOwnedBlockedIPv6Routes = ["2000::/4", "3000::/4", "fc00::/7"]
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: [],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialIPv6Routes: [
                "::/1": "lo0",
                "8000::/1": "lo0",
                "2000::/4": "lo0",
                "3000::/4": "lo0",
                "fc00::/7": "lo0",
            ])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                using: &session, persistPreparedState: persistPreparedState)
        }

        #expect(
            session.managedIPv6Routes == nil,
            "Switching to split tunnel should clear the full-tunnel IPv6 ownership ledger after exact cleanup."
        )
        #expect(
            session.sessionOwnedBlockedIPv6Routes == nil,
            "Switching to split tunnel should clear the session-owned block-ipv6 ledger after removal."
        )
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -net -inet6 :: -prefixlen 1 -reject ::1%lo0")
                && mockSystem.recordedCommands.contains(
                    "/sbin/route -n delete -net -inet6 8000:: -prefixlen 1 -reject ::1%lo0"),
            "Switching to split tunnel should remove the managed full-tunnel IPv6 safety routes.")
        for command in [
            "/sbin/route -n delete -net -inet6 2000:: -prefixlen 4 -reject ::1%lo0",
            "/sbin/route -n delete -net -inet6 3000:: -prefixlen 4 -reject ::1%lo0",
            "/sbin/route -n delete -net -inet6 fc00:: -prefixlen 7 -reject ::1%lo0",
        ] {
            #expect(
                mockSystem.recordedCommands.contains(command),
                "Switching to split tunnel should remove the session-owned OpenVPN block-ipv6 reject routes."
            )
        }
        #expect(
            mockSystem.recordedCommands.contains("/usr/sbin/networksetup -setv6automatic Wi-Fi"),
            "Switching to split tunnel should restore the original physical IPv6 mode.")
    }

    @Test
    func switchToSplitPreservesUnmanagedBlockIPv6Routes() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1102,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: [],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true,
            vpnIPv4: nil,
            vpnIPv6: nil
        )
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: [],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialIPv6Routes: [
                "2000::/4": "lo0",
                "3000::/4": "lo0",
                "fc00::/7": "lo0",
            ])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            let manager = RouteManager(splitTunnelPolicy: configuration)
            try manager.applySplitTunnel(
                using: &session, persistPreparedState: persistPreparedState)
            _ = try manager.monitorAndRepair(using: session)
        }

        for command in [
            "/sbin/route -n delete -net -inet6 2000:: -prefixlen 4 -reject ::1%lo0",
            "/sbin/route -n delete -net -inet6 3000:: -prefixlen 4 -reject ::1%lo0",
            "/sbin/route -n delete -net -inet6 fc00:: -prefixlen 7 -reject ::1%lo0",
        ] {
            #expect(
                !mockSystem.recordedCommands.contains(command),
                "Split tunnel must not delete block-ipv6 reject routes the session does not own.")
        }
    }

    @Test
    func cleanupRemovesOpenVPNBlockIPv6Routes() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1100,
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
        session.sessionOwnedBlockedIPv6Routes = ["2000::/4", "3000::/4", "fc00::/7"]
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialIPv6Routes: [
                "2000::/4": "lo0",
                "3000::/4": "lo0",
                "fc00::/7": "lo0",
            ])

        let cleanupHealthy = try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
        }

        #expect(
            cleanupHealthy,
            "Cleanup should validate healthy after removing session-owned OpenVPN block-ipv6 routes."
        )
        for command in [
            "/sbin/route -n delete -net -inet6 2000:: -prefixlen 4 -reject ::1%lo0",
            "/sbin/route -n delete -net -inet6 3000:: -prefixlen 4 -reject ::1%lo0",
            "/sbin/route -n delete -net -inet6 fc00:: -prefixlen 7 -reject ::1%lo0",
        ] {
            #expect(
                mockSystem.recordedCommands.contains(command),
                "Cleanup should remove lingering session-owned OpenVPN block-ipv6 reject routes.")
        }
    }

    @Test
    func sessionOwnedBlockedIPv6RouteCapture() throws {
        #expect(
            VPNController.sessionOwnedBlockedIPv6Routes(
                present: ["2000::/4", "3000::/4", "fc00::/7"],
                preexisting: ["3000::/4"]) == ["2000::/4", "fc00::/7"],
            "Ownership capture should claim only block-ipv6 routes that appeared after the startup snapshot."
        )
        #expect(
            VPNController.sessionOwnedBlockedIPv6Routes(
                present: ["3000::/4"],
                preexisting: ["3000::/4"]) == nil,
            "Ownership capture should stay empty when every present block-ipv6 route preexisted the session."
        )
        #expect(
            VPNController.sessionOwnedBlockedIPv6Routes(
                present: [],
                preexisting: []) == nil,
            "Ownership capture should stay empty when no block-ipv6 routes are present.")
        #expect(
            VPNController.sessionOwnedBlockedIPv6Routes(
                present: ["2000::/4"],
                preexisting: nil) == nil,
            "Ownership capture must claim nothing when the startup snapshot was never taken, so admin-installed routes survive pre-snapshot failures."
        )
    }

    @Test
    func cleanupPreservesUnmanagedOpenVPNBlockIPv6Routes() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        let session = makeSessionState(
            pid: 1101,
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
            initialIPv6Routes: [
                "2000::/4": "lo0",
                "3000::/4": "lo0",
                "fc00::/7": "lo0",
            ])

        let cleanupHealthy = try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
        }

        #expect(
            cleanupHealthy,
            "Cleanup should ignore block-ipv6 reject routes the session does not own.")
        for command in [
            "/sbin/route -n delete -net -inet6 2000:: -prefixlen 4 -reject ::1%lo0",
            "/sbin/route -n delete -net -inet6 3000:: -prefixlen 4 -reject ::1%lo0",
            "/sbin/route -n delete -net -inet6 fc00:: -prefixlen 7 -reject ::1%lo0",
        ] {
            #expect(
                !mockSystem.recordedCommands.contains(command),
                "Cleanup must not delete block-ipv6 reject routes the session does not own.")
        }
    }

    @Test
    func fullTunnelDoesNotDivertPhysicalResolvers() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1047,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "172.19.16.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["208.67.220.220", "208.67.222.222"],
            originalSearchDomains: [],
            originalIPv6Mode: "Off",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true,
            vpnIPv6: nil
        )
        session.serverIP = "207.182.159.132"
        session.fullTunnelDNSServers = ["129.22.4.32", "129.22.104.132"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "172.19.16.1",
            physicalInterface: "en0",
            physicalDNSServers: ["208.67.220.220", "208.67.222.222"],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            activeDefaultDNSServers: ["208.67.220.220", "208.67.222.222"],
            tunnelInterfaces: ["utun7"],
            blockedIPv6ProbeDestinations: Set(RouteManager.fullTunnelIPv6ProbeDestinations),
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "0.0.0.0/1",
                    gateway: "100.96.5.97",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "100.96.5.97",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "207.182.159.132/32",
                    gateway: "172.19.16.1",
                    interfaceName: "en0",
                    flags: "UGHS"),
            ])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                using: &session, persistPreparedState: persistPreparedState)
        }

        #expect(
            !mockSystem.recordedCommands.contains {
                $0.contains("/sbin/route -n add -host 208.67.220.220")
            },
            "Full tunnel must not host-route physical resolvers off the tunnel.")
        #expect(
            !mockSystem.recordedCommands.contains {
                $0.contains("/sbin/route -n add -host 208.67.222.222")
            },
            "Full tunnel must not host-route physical resolvers off the tunnel.")
    }

    @Test
    func fullTunnelIPv6SafetyWaitsForStableRouteState() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1101,
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
            cleanupNeeded: true,
            vpnIPv6: nil
        )
        let physicalRoute = MockSystem.RouteRecord(
            destination: "2000::/3",
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
            physicalIPv6RouteSnapshotsAfterIPv6Off: [[physicalRoute], [], []],
            initialIPv6RouteRecords: [physicalRoute])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(
                splitTunnelPolicy: configuration,
                fullTunnelIPv6SafetyTimeout: .milliseconds(500)
            ).applyFullTunnelSafety(using: &session, persistPreparedState: persistPreparedState)
        }

        #expect(
            mockSystem.ipv6NetstatReadsAfterIPv6Off == 3,
            "Cold full-tunnel safety should wait through a transient physical IPv6 route and require two consecutive safe assessments."
        )
        #expect(
            Set(session.managedIPv6Routes?.map(\.destination) ?? []) == Set(["::/1", "8000::/1"]),
            "Cold full-tunnel safety should retain exact ownership of both IPv6 reject halves after convergence."
        )
    }

    @Test
    func fullTunnelIPv6SafetyRejectsOscillation() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1102,
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
            cleanupNeeded: true,
            vpnIPv6: nil
        )
        let physicalRoute = MockSystem.RouteRecord(
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
            physicalIPv6RouteSnapshotsAfterIPv6Off: [[physicalRoute], []],
            repeatPhysicalIPv6RouteSnapshotsAfterIPv6Off: true,
            initialIPv6RouteRecords: [physicalRoute])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(
                    splitTunnelPolicy: configuration,
                    fullTunnelIPv6SafetyTimeout: .milliseconds(500)
                ).applyFullTunnelSafety(using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full-tunnel IPv6 safety should reject a route table that oscillates between safe and unsafe snapshots."
            )
        } catch RouteManagerError.failedToSecureFullTunnelIPv6Routes {
        }

        #expect(
            mockSystem.ipv6NetstatReadsAfterIPv6Off >= 4,
            "The monotonic stabilization deadline should observe multiple oscillating snapshots before failing closed; observed \(mockSystem.ipv6NetstatReadsAfterIPv6Off)."
        )
    }

    @Test
    func fullTunnelIPv6AssessmentUsesSingleRouteSnapshot() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: [],
            physicalSearchDomains: [],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialIPv6Routes: ["::/1": "lo0", "8000::/1": "lo0"],
            initialIPv6RouteRecords: [
                MockSystem.RouteRecord(
                    destination: "2606:4700::/32",
                    gateway: "link#14",
                    interfaceName: "en0",
                    flags: "UC")
            ])
        let manager = RouteManager(
            splitTunnelPolicy: configuration,
            fullTunnelIPv6SafetyTimeout: .zero)
        let outcome = try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            manager.stabilizedFullTunnelIPv6Safety(tunnelName: "utun7")
        }
        let netstatCountBeforeDetail = mockSystem.recordedCommands.filter {
            $0 == "/usr/sbin/netstat -nrf inet6"
        }.count
        let detail = manager.fullTunnelIPv6SafetyFailureDetail(outcome)
        let netstatCountAfterDetail = mockSystem.recordedCommands.filter {
            $0 == "/usr/sbin/netstat -nrf inet6"
        }.count

        #expect(
            !outcome.isStable && outcome.assessment.unexpectedRoutes == ["2606:4700::/32"],
            "A physical public IPv6 route should remain unsafe in the exact assessment returned to the caller."
        )
        #expect(
            netstatCountBeforeDetail == 1 && netstatCountAfterDetail == 1,
            "The verdict and failure detail should share one IPv6 route-table snapshot without resampling."
        )
        #expect(
            detail.contains("::/1=lo0(::1)")
                && detail.contains("8000::/1=lo0(::1)")
                && detail.contains("2606:4700::/32")
                && !detail.contains("2000::/4")
                && !detail.contains("3000::/4"),
            "Full-tunnel IPv6 failure detail should report only assessment inputs from the decisive snapshot."
        )
    }

    @Test
    func fullTunnelRejectRouteInstallationIsVerified() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1104,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: [],
            originalSearchDomains: [],
            originalIPv6Mode: "Automatic",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true,
            vpnIPv6: nil
        )
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: [],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            failingRouteAdds: ["8000::/1"])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(
                    splitTunnelPolicy: configuration,
                    fullTunnelIPv6SafetyTimeout: .zero
                ).applyFullTunnelSafety(using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should fail immediately when an IPv6 reject half is not installed.")
        } catch RouteManagerError.failedToInstallManagedRoute(let route) {
            #expect(
                route == "8000::/1",
                "Reject-route installation failure should identify the exact missing managed route."
            )
        }
    }

    @Test
    func fullTunnelIPv6SafetyFailureThrows() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1007,
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
            cleanupNeeded: true,
            vpnIPv6: nil
        )

        let physicalRoute = MockSystem.RouteRecord(
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
            ignoreIPv6OffRequests: true,
            initialIPv6RouteRecords: [physicalRoute])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(
                    splitTunnelPolicy: configuration,
                    fullTunnelIPv6SafetyTimeout: .zero
                ).applyFullTunnelSafety(using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should fail closed when public IPv6 still routes over the physical interface."
            )
        } catch RouteManagerError.failedToSecureFullTunnelIPv6Routes {
        }
    }

    @Test
    func fullTunnelRejectsExternalIPv6Tunnel() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1019,
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

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            externalIPv6TunnelInterface: "utun99")

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(
                    splitTunnelPolicy: configuration,
                    fullTunnelIPv6SafetyTimeout: .zero
                ).applyFullTunnelSafety(using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should treat public IPv6 routed over another utun as unsafe.")
        } catch RouteManagerError.failedToSecureFullTunnelIPv6Routes {
        }
    }

    @Test
    func fullTunnelAllowsCoveredExternalIPv6Default() throws {
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
            initialIPv6Routes: [
                "default": "utun99",
                "::/1": "lo0",
                "8000::/1": "lo0",
            ])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                using: &session, persistPreparedState: persistPreparedState)
        }
    }

    @Test
    func fullTunnelRejectsPhysicalPublicIPv6Route() throws {
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
            blockedIPv6ProbeDestinations: ["2001:4860:4860::8888", "3000::1", "9000::1"],
            initialIPv6Routes: [
                "2606:4700::/32": "en0"
            ])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            let manager = RouteManager(splitTunnelPolicy: configuration)
            let unexpectedRoutes = try manager.unexpectedFullTunnelPublicIPv6Routes(
                tunnelName: "utun7",
                entries: manager.ipv6RoutingTableEntries()
            )
            #expect(
                unexpectedRoutes == ["2606:4700::/32"],
                "Full tunnel IPv6 route audit should enumerate public IPv6 routes outside the VPN tunnel."
            )
        }

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(
                    splitTunnelPolicy: configuration,
                    fullTunnelIPv6SafetyTimeout: .zero
                ).applyFullTunnelSafety(using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should fail closed when a public IPv6 route remains on a physical interface."
            )
        } catch RouteManagerError.failedToSecureFullTunnelIPv6Routes {
        }
    }

    @Test
    func fullTunnelRejectsClonedPhysicalPublicIPv6Route() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialIPv6RouteRecords: [
                MockSystem.RouteRecord(
                    destination: "2001:4860:4860::8888/128",
                    gateway: "aa:bb:cc:dd:ee:ff",
                    interfaceName: "en0",
                    flags: "UHLW",
                    expire: "1200")
            ])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            let manager = RouteManager(splitTunnelPolicy: configuration)
            let unexpectedRoutes = try manager.unexpectedFullTunnelPublicIPv6Routes(
                tunnelName: "utun7",
                entries: manager.ipv6RoutingTableEntries()
            )
            #expect(
                unexpectedRoutes == ["2001:4860:4860::8888/128"],
                "Full tunnel IPv6 route audit should enumerate cloned public IPv6 host routes outside the VPN tunnel."
            )
        }
    }

    @Test
    func fullTunnelRejectsExternalTunnelPublicIPv6Route() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1030,
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
            blockedIPv6ProbeDestinations: ["2001:4860:4860::8888", "3000::1", "9000::1"],
            initialIPv6Routes: [
                "2606:4700::/32": "utun99"
            ])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(
                    splitTunnelPolicy: configuration,
                    fullTunnelIPv6SafetyTimeout: .zero
                ).applyFullTunnelSafety(using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should fail closed when a public IPv6 route remains on another tunnel interface."
            )
        } catch RouteManagerError.failedToSecureFullTunnelIPv6Routes {
        }
    }

    @Test
    func fullTunnelUnexpectedIPv6ProbeFailureThrows() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1020,
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

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            unexpectedIPv6ProbeFailures: ["2001:4860:4860::8888"])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applyFullTunnelSafety(
                    using: &session, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full tunnel should not treat unexpected IPv6 route-probe errors as blocked.")
        } catch RouteManagerError.failedToInspectPublicIPv6Routes {
        }
    }

    @Test
    func fullTunnelMonitorWaitsForStableIPv6Routes() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        let session = makeSessionState(
            pid: 1105,
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
            cleanupNeeded: true,
            vpnIPv6: nil
        )
        let physicalRoute = MockSystem.RouteRecord(
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
            physicalIPv6RouteSnapshotsAfterIPv6Off: [[physicalRoute], [], []],
            initialIPv6RouteRecords: [physicalRoute])

        var monitorState = session
        let stillConnected = try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(
                splitTunnelPolicy: configuration,
                fullTunnelIPv6SafetyTimeout: .milliseconds(500)
            ).monitorFullTunnel(using: &monitorState, persistPreparedState: persistPreparedState)
        }
        #expect(
            stillConnected && mockSystem.ipv6NetstatReadsAfterIPv6Off == 3,
            "Full-tunnel monitoring should wait through transient physical IPv6 routes and remain connected after two safe assessments."
        )

        let missingTunnelSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: [])
        var missingTunnelState = session
        let missingTunnel = try Shell.withCommandHandler({ try missingTunnelSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).monitorFullTunnel(
                using: &missingTunnelState, persistPreparedState: persistPreparedState)
        }
        #expect(
            !missingTunnel,
            "Full-tunnel monitoring should return false only when the tunnel interface is missing.")
    }

    @Test
    func fullTunnelRouteMonitorFailsClosedOnIPv6Drift() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        let session = makeSessionState(
            pid: 1016,
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
            cleanupNeeded: true,
            vpnIPv6: nil
        )

        let physicalRoute = MockSystem.RouteRecord(
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
            ignoreIPv6OffRequests: true,
            initialIPv6RouteRecords: [physicalRoute])

        var monitorState = session
        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                _ = try RouteManager(
                    splitTunnelPolicy: configuration,
                    fullTunnelIPv6SafetyTimeout: .zero
                ).monitorFullTunnel(
                    using: &monitorState, persistPreparedState: persistPreparedState)
            }
            try #require(
                Bool(false),
                "Full-tunnel route monitor should fail closed when public IPv6 drifts to the physical interface."
            )
        } catch RouteManagerError.failedToSecureFullTunnelIPv6Routes {
        }
    }
}
