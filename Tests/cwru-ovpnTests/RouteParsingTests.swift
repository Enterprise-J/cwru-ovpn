import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct RouteParsingTests {
    @Test
    func configuredRouteCoverageRequiresUnscopedEntries() throws {
        let manager = RouteManager(splitTunnelPolicy: .fixed)
        let ipv4 = "129.22.0.0/16"
        let ipv6 = "2606:ea00::/32"
        let scopedIPv4 = try #require(RouteEntry(line: "129.22 link#9 UScI utun7"[...]))
        let globalIPv4 = try #require(RouteEntry(line: "129.22 link#9 USc utun7"[...]))
        let scopedIPv6 = try #require(RouteEntry(line: "2606:ea00::/32 link#9 UScI utun7"[...]))
        let globalIPv6 = try #require(RouteEntry(line: "2606:ea00::/32 link#9 USc utun7"[...]))

        #expect(!manager.routeExists(ipv4, on: "utun7", in: [scopedIPv4]))
        #expect(manager.routeExists(ipv4, on: "utun7", in: [globalIPv4]))
        #expect(manager.routeExists(ipv4, on: "utun7", in: [scopedIPv4, globalIPv4]))
        #expect(!manager.ipv6RouteExists(ipv6, on: "utun7", in: [scopedIPv6]))
        #expect(manager.ipv6RouteExists(ipv6, on: "utun7", in: [globalIPv6]))
        #expect(manager.ipv6RouteExists(ipv6, on: "utun7", in: [scopedIPv6, globalIPv6]))

        let scopedOwnedRoute = ManagedIPv4Route(destination: ipv4, nextHopKind: .interface,
                                                nextHopValue: "utun7", interfaceName: "utun7", isInterfaceScoped: true)
        #expect(manager.ownedManagedIPv4RouteExists(scopedOwnedRoute, in: [scopedIPv4], requiresHostFlag: false))
        #expect(!manager.ownedManagedIPv4RouteExists(scopedOwnedRoute, in: [globalIPv4], requiresHostFlag: false))
    }

    @Test
    func routeCanonicalization() throws {
        #expect(
            IPRoute.canonicalIPv4("129.22.0.0/16") == IPRoute.canonicalIPv4("129.22"),
            "Octet-boundary routes should match netstat's shortened labels.")
        #expect(
            IPRoute.canonicalIPv4("129.22.32.0/20") == IPRoute.canonicalIPv4("129.22.32/20"),
            "Non-octet-boundary routes should match netstat labels with explicit prefixes.")
        #expect(
            IPRoute.canonicalIPv4("129.22.32.0/20") != IPRoute.canonicalIPv4("129.22.48.0/20"),
            "Distinct networks should not canonicalize to the same route.")
        #expect(
            IPRoute.canonicalIPv4("default") == nil,
            "Non-IPv4 route labels should not canonicalize as split-tunnel routes.")
        for malformed in ["+1.2.3.4/32", "01.2.3.4/32", "1.2.3.256", "1..2.3", "1.2.3.4.5"] {
            #expect(
                IPRoute.canonicalIPv4(malformed) == nil,
                "Octets must be plain decimal digits without signs or leading zeros: \(malformed)")
        }
    }

    @Test
    func reverseResolverZoneDerivation() throws {
        #expect(
            SplitTunnelPolicy.reverseResolverZones(forIPv4Routes: ["129.22.0.0/16"])
                == ["22.129.in-addr.arpa"],
            "A /16 CIDR should derive a two-label reverse zone.")
        #expect(
            SplitTunnelPolicy.reverseResolverZones(forIPv4Routes: ["10.0.0.0/8"])
                == ["10.in-addr.arpa"],
            "A /8 CIDR should derive a one-label reverse zone.")
        #expect(
            SplitTunnelPolicy.reverseResolverZones(forIPv4Routes: ["129.22.32.0/20"])
                == [],
            "Non-octet prefixes should not derive a reverse zone that would over-scope unrelated PTR queries."
        )
        #expect(
            SplitTunnelPolicy.reverseResolverZones(forIPv4Routes: ["0.0.0.0/0"])
                == [],
            "Routes with no octet boundary should not derive a reverse zone.")

        let resolverDomains = SplitTunnelPolicy.fixedResolverDomains
        #expect(
            resolverDomains.contains("case.edu")
                && resolverDomains.contains("cwru.edu")
                && resolverDomains.contains("22.129.in-addr.arpa")
                && resolverDomains.contains("0.0.a.e.6.0.6.2.ip6.arpa"),
            "The fixed split policy should include forward and reverse CWRU resolver domains.")
    }

    @Test
    func ipv6RouteCanonicalization() throws {
        #expect(
            IPRoute.canonicalIPv6("2606:ea00::/32")?.routeString == "2606:ea00::/32",
            "Canonical IPv6 should preserve a well-formed prefix.")
        #expect(
            IPRoute.canonicalIPv6("fe80::1%en0/64")?.routeString == "fe80::/64",
            "Canonical IPv6 should strip the zone identifier and mask host bits.")
        #expect(
            IPRoute.canonicalIPv6("default")?.routeString == "::/0",
            "Canonical IPv6 should treat 'default' as ::/0.")
        #expect(
            IPRoute.canonicalIPv6("2606:EA00:0000::1/128")?.routeString == "2606:ea00::1/128",
            "Canonical IPv6 should normalize uppercase and zero-compressed forms.")
        #expect(
            IPRoute.canonicalIPv6("2606:ea00::abcd/64")?.routeString == "2606:ea00::/64",
            "Canonical IPv6 should clear host bits below the prefix length.")
        #expect(
            IPRoute.canonicalIPv6("2606:ea00::/129") == nil,
            "Canonical IPv6 should reject a prefix length above 128.")
        #expect(
            IPRoute.canonicalIPv6("not-an-address") == nil,
            "Canonical IPv6 should reject malformed input.")

        let linkLocal = try #require(IPRoute.canonicalIPv6("fe80::/10"))
        let multicast = try #require(IPRoute.canonicalIPv6("ff00::/8"))
        let tunnelLinkLocal = try #require(IPRoute.canonicalIPv6("fe80::%utun7/64"))
        let tunnelMulticast = try #require(IPRoute.canonicalIPv6("ff02::%utun7/32"))
        let cwru = try #require(
            IPRoute.canonicalIPv6("2606:ea00::/32"),
            "Canonical IPv6 fixtures should parse.")
        #expect(
            IPRoute.ipv6Route(linkLocal, contains: tunnelLinkLocal),
            "fe80::/10 should contain a tunnel link-local /64.")
        #expect(
            IPRoute.ipv6Route(multicast, contains: tunnelMulticast),
            "ff00::/8 should contain a tunnel multicast /32.")
        #expect(
            !IPRoute.ipv6Route(linkLocal, contains: cwru),
            "fe80::/10 should not contain a global CWRU prefix.")
        #expect(
            routeTouchesPublicGlobalUnicast("2606:4700::/32"),
            "Public global IPv6 routes should be treated as full-tunnel privacy-relevant.")
        #expect(
            routeTouchesPublicGlobalUnicast("::/0"),
            "The IPv6 default route should be treated as touching public global unicast.")
        #expect(
            !routeTouchesPublicGlobalUnicast("fe80::/10"),
            "IPv6 link-local routes should not be treated as public global unicast.")
        #expect(
            !routeTouchesPublicGlobalUnicast("fc00::/7"),
            "IPv6 ULA routes should not be treated as public global unicast.")
    }

    @Test
    func routeTableLineParsing() throws {
        let permanent = parseRouteTableLine("2606:ea00::/32   fe80::1%utun7   USc   utun7")
        #expect(
            permanent?.destination == "2606:ea00::/32" && permanent?.interfaceName == "utun7",
            "Route parsing should read destination and Netif for a permanent route.")
        let withExpire = parseRouteTableLine(
            "fe80::5%utun7   aa:bb:cc:dd:ee:ff   UHLWI   utun7   1198")
        #expect(
            withExpire?.interfaceName == "utun7",
            "Route parsing should read Netif from its fixed column, not the trailing Expire value.")
        let ipv4WithExpire = parseRouteTableLine(
            "192.168.1.1   aa:bb:cc:dd:ee:ff   UHLWIir   en0   1200")
        #expect(
            ipv4WithExpire?.interfaceName == "en0",
            "Route parsing should read Netif for IPv4 rows that carry an Expire value.")
        let unscopedHost = try #require(
            RouteEntry(line: Substring("207.182.159.130/32 192.168.1.1 UGSc en0")))
        let scopedHost = try #require(
            RouteEntry(line: Substring("207.182.159.130 192.168.1.1 UGHSI en0")))
        let managedHost = try #require(
            RouteEntry(line: Substring("192.168.1.1/32 link#14 UHS en0")))
        let cloneSibling = try #require(
            RouteEntry(line: Substring("192.168.1.1/32 link#14 UCS en0")))
        let dynamicSibling = try #require(
            RouteEntry(line: Substring("192.168.1.1 aa:bb:cc:dd:ee:ff UHLWIir en0 1200")),
            "IPv4 host route fixtures should parse."
        )
        #expect(
            unscopedHost.isHost && !unscopedHost.isInterfaceScoped,
            "A canonical IPv4 /32 should be treated as a host route without requiring the H flag.")
        #expect(
            scopedHost.isHost && scopedHost.isInterfaceScoped,
            "The I flag should identify an interface-scoped host route.")
        let gatewayHostRoute = ManagedIPv4Route(
            destination: "192.168.1.1/32",
            nextHopKind: .interface,
            nextHopValue: "en0",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let manager = RouteManager(splitTunnelPolicy: SplitTunnelPolicy.fixed)
        #expect(
            !manager.ipv4RouteEntryIsRestorable(unscopedHost),
            "A static canonical /32 without an explicit host flag must not be captured for restoration."
        )
        #expect(
            manager.ownedManagedIPv4RouteExists(
                gatewayHostRoute,
                in: [managedHost],
                requiresHostFlag: true),
            "A static host route should satisfy its managed route ledger entry.")
        #expect(
            !manager.ownedManagedIPv4RouteExists(
                gatewayHostRoute,
                in: [cloneSibling, dynamicSibling],
                requiresHostFlag: true),
            "Kernel clone and dynamic neighbor siblings must not satisfy a managed host route ledger entry."
        )
        #expect(
            parseRouteTableLine("Destination Gateway Flags Netif Expire") == nil,
            "Route parsing should reject the header row.")
        #expect(
            parseRouteTableLine("Internet6:") == nil,
            "Route parsing should reject section headers.")
    }

    @Test
    func ipv4ManagedInterfaceRouteDeletionRespectsNextHop() throws {
        let manager = RouteManager(splitTunnelPolicy: SplitTunnelPolicy.fixed)
        let interfaceRoute = ManagedIPv4Route(
            destination: "192.168.1.1/32",
            nextHopKind: .interface,
            nextHopValue: "en0",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let gatewayRoute = ManagedIPv4Route(
            destination: "192.168.1.1/32",
            nextHopKind: .gateway,
            nextHopValue: "192.168.1.254",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.254",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "192.168.1.1/32",
                    gateway: "192.168.1.254",
                    interfaceName: "en0",
                    flags: "UGHS")
            ])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            let initialEntries = try manager.routingTableEntries()
            #expect(
                !manager.ipv4RouteExists(interfaceRoute, in: initialEntries),
                "An interface-owned ledger entry must not match a gateway route on the same interface."
            )
            #expect(
                manager.ipv4RouteExists(gatewayRoute, in: initialEntries),
                "A gateway-owned ledger entry should match its exact next hop and interface.")
            try manager.deleteManagedIPv4RouteIfPresent(interfaceRoute, verifyRemoval: true)
            let retainedEntries = try manager.routingTableEntries()
            #expect(
                manager.ipv4RouteExists(gatewayRoute, in: retainedEntries),
                "Deleting an interface-owned ledger entry must preserve a gateway route with the same destination and interface."
            )
        }

        #expect(
            !mockSystem.recordedCommands.contains(where: { $0.hasPrefix("/sbin/route -n delete") }),
            "Exact interface-route cleanup should not issue a delete for a different next hop.")
    }

    @Test
    func ipv4ManagedGatewayRouteDeletionRespectsScope() throws {
        let manager = RouteManager(splitTunnelPolicy: SplitTunnelPolicy.fixed)
        let unscopedRoute = ManagedIPv4Route(
            destination: "207.182.159.133/32",
            nextHopKind: .gateway,
            nextHopValue: "192.168.1.1",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let scopedRoute = ManagedIPv4Route(
            destination: "207.182.159.133/32",
            nextHopKind: .gateway,
            nextHopValue: "192.168.1.1",
            interfaceName: "en0",
            isInterfaceScoped: true)
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
                    destination: scopedRoute.destination,
                    gateway: scopedRoute.nextHopValue,
                    interfaceName: scopedRoute.interfaceName,
                    flags: "UGHSI"),
                MockSystem.RouteRecord(
                    destination: unscopedRoute.destination,
                    gateway: unscopedRoute.nextHopValue,
                    interfaceName: unscopedRoute.interfaceName,
                    flags: "UGHS"),
            ])

        #expect(
            scopedRoute != unscopedRoute,
            "Interface scope must participate in managed IPv4 route identity.")
        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try manager.deleteManagedIPv4RouteIfPresent(scopedRoute, verifyRemoval: true)
            var entries = try manager.routingTableEntries()
            #expect(
                !manager.ipv4RouteExists(scopedRoute, in: entries),
                "Scoped cleanup should remove only the scoped gateway route.")
            #expect(
                manager.ipv4RouteExists(unscopedRoute, in: entries),
                "Scoped cleanup must preserve an otherwise identical unscoped route.")
            try manager.deleteManagedIPv4RouteIfPresent(unscopedRoute, verifyRemoval: true)
            entries = try manager.routingTableEntries()
            #expect(
                !manager.ipv4RouteExists(unscopedRoute, in: entries),
                "Unscoped cleanup should remove the remaining unscoped route.")
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 207.182.159.133 192.168.1.1 -ifscope en0"),
            "Scoped IPv4 cleanup should use the recorded interface scope.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 207.182.159.133 192.168.1.1"),
            "Unscoped IPv4 cleanup should omit the interface-scope modifier.")
    }

    @Test
    func detectPhysicalNetworkUsesNetifColumn() throws {
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "10.8.0.1",
            physicalInterface: "utun7",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "default",
                    gateway: "192.168.1.1",
                    interfaceName: "en0",
                    expire: "1200")
            ])

        let physicalNetwork = try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: SplitTunnelPolicy.fixed).detectPhysicalNetwork()
        }

        #expect(
            physicalNetwork.gateway == "192.168.1.1" && physicalNetwork.interfaceName == "en0",
            "Physical network detection should read Netif from its fixed netstat column when route get default points at a tunnel."
        )
    }
}
