import Darwin
import Foundation

struct SplitTunnelPolicy {
    static let fixedIPv4Routes = [
        "129.22.0.0/16",
        "192.5.109.0/24",
        "192.5.110.0/24",
        "192.5.111.0/24",
        "192.5.112.0/24",
        "192.5.113.0/24",
    ]
    static let fixedIPv6Routes = ["2606:ea00::/32"]
    static let fixedDNSDomains = ["case.edu", "cwru.edu"]
    static let fixedDNSServers = [
        "129.22.4.32",
        "129.22.104.132",
        "129.22.4.31",
        "129.22.104.25",
    ]
    static let fixedHealthCheckHosts = ["129.22.4.32", "129.22.104.132"]
    static let fixed = SplitTunnelPolicy(
        ipv4Routes: fixedIPv4Routes,
        ipv6Routes: fixedIPv6Routes,
        dnsDomains: fixedDNSDomains,
        dnsServers: fixedDNSServers
    )

    let ipv4Routes: [String]
    let ipv6Routes: [String]
    let dnsDomains: [String]
    let dnsServers: [String]

    static let fixedResolverDomains: [String] = {
        fixed.resolverDomains(forIPv4Routes: fixed.ipv4Routes, ipv6Routes: fixed.ipv6Routes)
    }()

    init(ipv4Routes: [String],
         ipv6Routes: [String] = [],
         dnsDomains: [String],
         dnsServers: [String]) {
        self.ipv4Routes = ipv4Routes
        self.ipv6Routes = ipv6Routes
        self.dnsDomains = dnsDomains
        self.dnsServers = dnsServers
    }

    func resolverDomains(forIPv4Routes routes: [String],
                         ipv6Routes: [String]) -> [String] {
        (dnsDomains
            + Self.reverseResolverZones(forIPv4Routes: routes)
            + Self.reverseResolverZones(forIPv6Routes: ipv6Routes)).uniqued()
    }

    static func reverseResolverZones(forIPv4Routes routes: [String]) -> [String] {
        var zones = Set<String>()
        for cidr in routes {
            guard let canonical = IPRoute.canonicalIPv4(cidr),
                  let zone = IPRoute.reverseResolverZone(forIPv4Address: canonical.networkAddress,
                                                         prefixLength: canonical.prefixLength) else {
                continue
            }
            zones.insert(zone)
        }
        return zones.sorted()
    }

    static func reverseResolverZones(forIPv6Routes routes: [String]) -> [String] {
        var zones = Set<String>()
        for cidr in routes {
            guard let canonical = IPRoute.canonicalIPv6(cidr),
                  let zone = IPRoute.reverseResolverZone(forIPv6AddressBytes: canonical.networkBytes,
                                                         prefixLength: canonical.prefixLength) else {
                continue
            }
            zones.insert(zone)
        }
        return zones.sorted()
    }

    static func isCWRUDomain(_ value: String) -> Bool {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return fixedDNSDomains.contains { domain in
            normalized == domain || normalized.hasSuffix(".\(domain)")
        }
    }
}
