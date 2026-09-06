import Foundation
import Darwin

struct PhysicalNetwork {
    let gateway: String
    let interfaceName: String
}

struct PhysicalDNSConfiguration {
    let serviceName: String
    let dnsServers: [String]
    let searchDomains: [String]
    let ipv6Mode: String?
}

struct ManagedIPv4Route: Codable, Equatable, Hashable {
    enum NextHopKind: String, Codable {
        case gateway
        case interface
    }

    let destination: String
    let nextHopKind: NextHopKind
    let nextHopValue: String
    let interfaceName: String
    let isInterfaceScoped: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case destination
        case nextHopKind
        case nextHopValue
        case interfaceName
        case isInterfaceScoped
    }

    init(destination: String,
         nextHopKind: NextHopKind,
         nextHopValue: String,
         interfaceName: String,
         isInterfaceScoped: Bool) {
        self.destination = destination
        self.nextHopKind = nextHopKind
        self.nextHopValue = nextHopValue
        self.interfaceName = interfaceName
        self.isInterfaceScoped = isInterfaceScoped
    }

    init(destination: String, viaInterface interfaceName: String) {
        self.init(destination: destination,
                  nextHopKind: .interface,
                  nextHopValue: interfaceName,
                  interfaceName: interfaceName,
                  isInterfaceScoped: false)
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownJSONKeys(in: decoder,
                                  allowedBy: CodingKeys.self,
                                  context: "managed IPv4 route")
        let container = try decoder.container(keyedBy: CodingKeys.self)
        destination = try container.decode(String.self, forKey: .destination)
        nextHopKind = try container.decode(NextHopKind.self, forKey: .nextHopKind)
        nextHopValue = try container.decode(String.self, forKey: .nextHopValue)
        interfaceName = try container.decode(String.self, forKey: .interfaceName)
        isInterfaceScoped = try container.decode(Bool.self, forKey: .isInterfaceScoped)
    }
}

struct ManagedIPv6Route: Codable, Equatable, Hashable {
    enum NextHopKind: String, Codable {
        case interface
        case reject
    }

    let destination: String
    let nextHopKind: NextHopKind
    let nextHopValue: String
    let interfaceName: String
    let isInterfaceScoped: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case destination
        case nextHopKind
        case nextHopValue
        case interfaceName
        case isInterfaceScoped
    }

    init(destination: String,
         nextHopKind: NextHopKind,
         nextHopValue: String,
         interfaceName: String,
         isInterfaceScoped: Bool) {
        self.destination = destination
        self.nextHopKind = nextHopKind
        self.nextHopValue = nextHopValue
        self.interfaceName = interfaceName
        self.isInterfaceScoped = isInterfaceScoped
    }

    init(destination: String, viaInterface interfaceName: String) {
        self.init(destination: destination,
                  nextHopKind: .interface,
                  nextHopValue: interfaceName,
                  interfaceName: interfaceName,
                  isInterfaceScoped: false)
    }

    init(blocking destination: String) {
        self.init(destination: destination,
                  nextHopKind: .reject,
                  nextHopValue: "::1%lo0",
                  interfaceName: "lo0",
                  isInterfaceScoped: false)
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownJSONKeys(in: decoder,
                                  allowedBy: CodingKeys.self,
                                  context: "managed IPv6 route")
        let container = try decoder.container(keyedBy: CodingKeys.self)
        destination = try container.decode(String.self, forKey: .destination)
        nextHopKind = try container.decode(NextHopKind.self, forKey: .nextHopKind)
        nextHopValue = try container.decode(String.self, forKey: .nextHopValue)
        interfaceName = try container.decode(String.self, forKey: .interfaceName)
        isInterfaceScoped = try container.decode(Bool.self, forKey: .isInterfaceScoped)
    }
}

struct ActiveDNSResolver {
    var domain: String?
    var nameServers: [String] = []
    var searchDomains: [String] = []

    var hasContent: Bool {
        domain != nil || !nameServers.isEmpty || !searchDomains.isEmpty
    }
}

struct ActiveDefaultResolverLeakState {
    var usesVPNNameServers = false
    var overlapsVPNSearchDomains = false

    var needsRepair: Bool {
        usesVPNNameServers || overlapsVPNSearchDomains
    }
}

enum PublicRouteState: String {
    case blocked
    case tunnel
    case physical
    case other
}

struct FullTunnelIPv6ProbeAssessment {
    let destination: String
    let state: PublicRouteState?
}

struct FullTunnelIPv6SafetyAssessment {
    let probes: [FullTunnelIPv6ProbeAssessment]
    let coverage: [String]
    let unexpectedRoutes: [String]?
    let inspectionError: Error?

    var isSafe: Bool {
        inspectionError == nil
            && probes.allSatisfy { $0.state == .tunnel || $0.state == .blocked }
            && unexpectedRoutes?.isEmpty == true
    }
}

struct FullTunnelIPv6SafetyOutcome {
    let assessment: FullTunnelIPv6SafetyAssessment
    let consecutiveSafeAssessments: Int
    let isStable: Bool
}

enum SplitTunnelCheckStatus: String {
    case pass = "PASS"
    case warn = "WARN"
    case fail = "FAIL"
}

struct SplitTunnelHealthCheck {
    let status: SplitTunnelCheckStatus
    let name: String
    let detail: String
}

enum RouteManagerError: LocalizedError {
    case couldNotDeterminePhysicalGateway
    case failedToRestoreFullTunnelRoutes
    case failedToSecureFullTunnelIPv4Routes
    case failedToSecureFullTunnelControlChannel
    case failedToSecureFullTunnelDNS
    case failedToSecureFullTunnelIPv6Routes
    case failedToSecureSplitTunnelRoutes
    case failedToSecureSplitTunnelIPv6Routes
    case failedToIsolateSplitTunnelDNS
    case dnsMutationMayHaveOccurred(String)
    case missingSplitTunnelDNSServers
    case refusingToReplaceUnmanagedResolverFile(String)
    case failedToInspectPublicIPv4Routes
    case failedToInspectPublicIPv6Routes
    case missingTunnelIPv4Address
    case missingTunnelIPv6Address
    case missingTunnelInterface
    case invalidTunnelInterface
    case unsupportedPhysicalIPv6Mode(String)
    case unsupportedNAT64Network
    case refusingToReplaceExistingRoute(String)
    case failedToDeleteManagedRoute(String)
    case failedToInstallManagedRoute(String)
    case failedToRestoreManagedRoute(String)

    var errorDescription: String? {
        switch self {
        case .couldNotDeterminePhysicalGateway:
            return "Could not determine a non-VPN default gateway. If this Mac is offline or behind a captive portal, join the network and finish any sign-in, then retry."
        case .failedToRestoreFullTunnelRoutes:
            return "Failed to restore full-tunnel default routes."
        case .failedToSecureFullTunnelIPv4Routes:
            return "Failed to secure full-tunnel IPv4 traffic."
        case .failedToSecureFullTunnelControlChannel:
            return "The VPN control channel would route into the tunnel instead of the physical network."
        case .failedToSecureFullTunnelDNS:
            return "No DNS server could be proven to route through the full tunnel."
        case .failedToSecureFullTunnelIPv6Routes:
            return "Failed to secure full-tunnel IPv6 traffic."
        case .failedToSecureSplitTunnelRoutes:
            return "Failed to secure split-tunnel routing."
        case .failedToSecureSplitTunnelIPv6Routes:
            return "Failed to secure split-tunnel IPv6 traffic."
        case .failedToIsolateSplitTunnelDNS:
            return "Split-tunnel DNS isolation could not be enforced."
        case .dnsMutationMayHaveOccurred(let detail):
            return "DNS state may have changed before the operation failed: \(detail)"
        case .missingSplitTunnelDNSServers:
            return "The fixed scoped DNS policy has no DNS servers."
        case .refusingToReplaceUnmanagedResolverFile(let domain):
            return "A resolver file for '\(domain)' already exists and was not created by cwru-ovpn. Remove or back up /etc/resolver/\(domain) and reconnect."
        case .failedToInspectPublicIPv4Routes:
            return "Could not inspect public IPv4 routing safely."
        case .failedToInspectPublicIPv6Routes:
            return "Could not inspect public IPv6 routing safely."
        case .missingTunnelIPv4Address:
            return "The fixed split-tunnel IPv4 policy requires a tunnel IPv4 address."
        case .missingTunnelIPv6Address:
            return "The fixed split-tunnel IPv6 policy requires a tunnel IPv6 address."
        case .missingTunnelInterface:
            return "The VPN reported CONNECTED, but no tunnel interface was available."
        case .invalidTunnelInterface:
            return "Encountered an unexpected tunnel interface name."
        case .unsupportedPhysicalIPv6Mode(let mode):
            return "Physical-service IPv6 mode \"\(mode)\" is unsupported because it cannot be safely disabled and restored. Use Automatic, Link-local, or Off."
        case .unsupportedNAT64Network:
            return "Full tunnel is not supported on IPv6-only networks that reach IPv4 through NAT64/CLAT, because the translation path cannot be closed without cutting the VPN transport. Use split tunnel on this network."
        case .refusingToReplaceExistingRoute(let route):
            return "Refusing to replace a pre-existing route for \(route) that is not owned by cwru-ovpn."
        case .failedToDeleteManagedRoute(let route):
            return "Failed to delete the cwru-ovpn-owned route \(route)."
        case .failedToInstallManagedRoute(let route):
            return "Failed to install the cwru-ovpn-managed route \(route)."
        case .failedToRestoreManagedRoute(let route):
            return "Failed to restore the route that cwru-ovpn temporarily replaced for \(route)."
        }
    }
}

struct RouteManager {
    let splitTunnelPolicy: SplitTunnelPolicy
    let dnsBootstrapServers: [String]
    let fullTunnelIPv6SafetyTimeout: Duration
    let shell: Shell
    let resolverDirectory: URL
    let resolverFileOwnership: (userID: uid_t, groupID: gid_t)
    let remoteHostRouteLedger: RemoteHostRouteLedger
    let eventLogDirectory: URL?
    static let rootUserID = uid_t(0)
    static let wheelGroupID = gid_t(0)
    static let resolverFileMode = mode_t(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
    static let maxResolverFileBytes = 4096
    static let resolverManagedMarker = "# Managed by cwru-ovpn; removed on disconnect. Do not edit."
    static let splitTunnelPublicIPv6ProbeDestinations = [
        "2001:4860:4860::8888",
        "3000::1",
    ]
    static let fullTunnelIPv4DefaultRoutes = [
        "0.0.0.0/1",
        "128.0.0.0/1",
    ].compactMap(IPRoute.canonicalIPv4)
    static let fullTunnelIPv6DefaultRoutes = ["::/1", "8000::/1"]
    static let openVPNBlockedIPv6Routes = [
        "2000::/4",
        "3000::/4",
        "fc00::/7",
    ].compactMap(IPRoute.canonicalIPv6)
    static let fullTunnelIPv6ProbeDestinations = [
        "2001:4860:4860::8888",
        "3000::1",
        "9000::1",
    ]
    static let requiredConsecutiveFullTunnelIPv6SafetyAssessments = 2
    static let fullTunnelIPv6SafetyRetryIntervalMicroseconds: useconds_t = 50_000
    static let nonTransitIPv4Routes = [
        "169.254.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
    ].compactMap(IPRoute.canonicalIPv4)
    static let nonTransitIPv6Routes = [
        "fe80::/10",
        "ff00::/8",
        "::1/128",
    ].compactMap(IPRoute.canonicalIPv6)
    static let nonPublicIPv4Routes = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ].compactMap(IPRoute.canonicalIPv4)
    static let publicGlobalIPv6Route = IPRoute.canonicalIPv6("2000::/3")!
    static let documentationIPv6Route = IPRoute.canonicalIPv6("2001:db8::/32")!

    init(dnsBootstrapServers: [String] = [],
         shell: Shell = Shell(),
         resolverDirectory: URL = ResolverPaths.directory,
         resolverFileOwnership: (userID: uid_t, groupID: gid_t) = (rootUserID, wheelGroupID),
         remoteHostRouteLedger: RemoteHostRouteLedger = RemoteHostRouteLedger(),
         eventLogDirectory: URL? = nil) {
        self.init(splitTunnelPolicy: .fixed,
                  dnsBootstrapServers: dnsBootstrapServers,
                  shell: shell,
                  resolverDirectory: resolverDirectory,
                  resolverFileOwnership: resolverFileOwnership,
                  remoteHostRouteLedger: remoteHostRouteLedger,
                  eventLogDirectory: eventLogDirectory)
    }

    init(appliedState session: SessionState,
         shell: Shell = Shell(),
         resolverDirectory: URL = ResolverPaths.directory,
         resolverFileOwnership: (userID: uid_t, groupID: gid_t) = (rootUserID, wheelGroupID),
         remoteHostRouteLedger: RemoteHostRouteLedger = RemoteHostRouteLedger(),
         eventLogDirectory: URL? = nil) {
        self.init(splitTunnelPolicy: SplitTunnelPolicy(ipv4Routes: session.appliedSplitIPv4Routes ?? [],
                                                       ipv6Routes: session.appliedSplitIPv6Routes ?? [],
                                                       dnsDomains: session.appliedDNSDomains ?? [],
                                                       dnsServers: []),
        shell: shell,
        resolverDirectory: resolverDirectory,
        resolverFileOwnership: resolverFileOwnership,
        remoteHostRouteLedger: remoteHostRouteLedger,
        eventLogDirectory: eventLogDirectory)
    }

    init(splitTunnelPolicy: SplitTunnelPolicy,
         dnsBootstrapServers: [String] = [],
         fullTunnelIPv6SafetyTimeout: Duration = .milliseconds(2500),
         shell: Shell,
         resolverDirectory: URL,
         resolverFileOwnership: (userID: uid_t, groupID: gid_t) = (rootUserID, wheelGroupID),
         remoteHostRouteLedger: RemoteHostRouteLedger,
         eventLogDirectory: URL? = nil) {
        self.splitTunnelPolicy = splitTunnelPolicy
        self.dnsBootstrapServers = dnsBootstrapServers
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter(SplitTunnelPolicy.isValidIPAddress)
        self.fullTunnelIPv6SafetyTimeout = fullTunnelIPv6SafetyTimeout
        self.shell = shell
        self.resolverDirectory = resolverDirectory.standardizedFileURL
        self.resolverFileOwnership = resolverFileOwnership
        self.remoteHostRouteLedger = remoteHostRouteLedger
        self.eventLogDirectory = eventLogDirectory?.standardizedFileURL
    }

    func resolverFileURL(for domain: String) -> URL {
        ResolverPaths.fileURL(for: domain, in: resolverDirectory)
    }

    func appendEventLog(note: String, phase: SessionState.Phase? = nil) {
        EventLog.append(note: note, phase: phase, in: eventLogDirectory)
    }

    func detectPhysicalNetwork() throws -> PhysicalNetwork {
        let defaultRoute = try shell.run("/sbin/route", arguments: ["-n", "get", "default"], allowNonZero: true)
        let parsed = parseGatewayAndInterface(defaultRoute.stdout)
        if let gateway = parsed.gateway,
           let interfaceName = parsed.interfaceName,
           let network = Self.physicalNetwork(gateway: gateway, interfaceName: interfaceName) {
            return network
        }

        for entry in try routingTableEntries() where entry.destination == "default" {
            if let network = Self.physicalNetwork(gateway: entry.gateway, interfaceName: entry.interfaceName) {
                return network
            }
        }

        throw RouteManagerError.couldNotDeterminePhysicalGateway
    }

    private static func physicalNetwork(gateway: String, interfaceName: String) -> PhysicalNetwork? {
        guard SplitTunnelPolicy.isValidIPv4Address(gateway),
              SplitTunnelPolicy.isSafeInterfaceName(interfaceName),
              !SplitTunnelPolicy.isVirtualInterfaceName(interfaceName) else {
            return nil
        }
        return PhysicalNetwork(gateway: gateway, interfaceName: interfaceName)
    }

    func assertFullTunnelSupported(physicalInterface: String, ipv6Mode: String?) throws {
        if tunnelIPv6ModeIsUnsupported(ipv6Mode) {
            throw RouteManagerError.unsupportedPhysicalIPv6Mode(ipv6Mode ?? "unknown")
        }
        if physicalInterfaceUsesCLAT(physicalInterface) {
            throw RouteManagerError.unsupportedNAT64Network
        }
    }

    func capturePhysicalDNSConfiguration(for interfaceName: String) throws -> PhysicalDNSConfiguration? {
        guard let serviceName = try serviceName(for: interfaceName) else {
            return nil
        }
        guard SplitTunnelPolicy.isSafeNetworkServiceName(serviceName) else {
            return nil
        }

        return try dnsConfiguration(forServiceNamed: serviceName)
    }

    func applySplitTunnel(using state: inout SessionState,
                          persistPreparedState: (SessionState) throws -> Void) throws {
        let gateway = state.physicalGateway
        let physicalInterface = state.physicalInterface
        guard SplitTunnelPolicy.isSafeInterfaceName(physicalInterface) else {
            throw RouteManagerError.couldNotDeterminePhysicalGateway
        }
        guard let tunnelName = state.tunName, !tunnelName.isEmpty else {
            throw RouteManagerError.missingTunnelInterface
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)

        if state.tunnelMode == .full,
           tunnelIPv6ModeIsUnsupported(state.originalIPv6Mode) {
            throw RouteManagerError.unsupportedPhysicalIPv6Mode(state.originalIPv6Mode ?? "unknown")
        }

        var mutatedNetwork = false
        var staleDNSDomainsForCleanup: [String] = []
        var installedResolverDomainsThisAttempt: [String] = []

        do {
            try reconcileManagedRemoteHostRoutes(using: &state, mode: .split, persistPreparedState: persistPreparedState)
            let applyIPv6 = splitTunnelShouldApplyIPv6(using: state)
            let desiredSplitRoutes = policyIPv4Routes()
            let desiredSplitIPv6Routes = applyIPv6 ? policyIPv6Routes() : []
            try validateTunnelIPv4SupportIfNeeded(for: desiredSplitRoutes, using: state)

            let staleSplitRoutes = cleanupSplitIPv4Routes(using: state)
            let staleSplitIPv6Routes = cleanupSplitIPv6Routes(using: state)
            let staleDNSDomains = cleanupDNSDomains(using: state)
            let desiredDNSDomains = dnsDomains(forSplitIPv4Routes: desiredSplitRoutes,
                                               splitIPv6Routes: desiredSplitIPv6Routes)
            staleDNSDomainsForCleanup = staleDNSDomains
            state.appliedSplitIPv4Routes = (staleSplitRoutes + desiredSplitRoutes).uniqued()
            state.appliedSplitIPv6Routes = (staleSplitIPv6Routes + desiredSplitIPv6Routes).uniqued()
            state.appliedDNSDomains = (staleDNSDomains + desiredDNSDomains).uniqued()
            try persistPreparedState(state)

            let desiredSplitDefaultRoutes = Set([
                ManagedIPv4Route(destination: "0.0.0.0/1",
                                 nextHopKind: .gateway,
                                 nextHopValue: gateway,
                                 interfaceName: physicalInterface,
                                 isInterfaceScoped: true),
                ManagedIPv4Route(destination: "128.0.0.0/1",
                                 nextHopKind: .gateway,
                                 nextHopValue: gateway,
                                 interfaceName: physicalInterface,
                                 isInterfaceScoped: true)
            ])
            let staleManagedSplitDefaultRoutes = (state.managedSplitDefaultRoutes ?? [])
                .filter { !desiredSplitDefaultRoutes.contains($0) }
            mutatedNetwork = true
            for route in staleManagedSplitDefaultRoutes {
                try deleteManagedIPv4RouteIfPresent(route, verifyRemoval: true)
            }
            if !staleManagedSplitDefaultRoutes.isEmpty {
                let currentRoutes = (state.managedSplitDefaultRoutes ?? [])
                    .filter(desiredSplitDefaultRoutes.contains)
                state.managedSplitDefaultRoutes = currentRoutes.isEmpty ? nil : currentRoutes
                try persistPreparedState(state)
            }

            for route in desiredSplitRoutes {
                let managedRoute = ManagedIPv4Route(destination: route, viaInterface: validatedTunnelName)
                if try managedIPv4RouteNeedsInstallation(managedRoute) {
                    try addIPv4Route(managedRoute, allowNonZero: false)
                }
            }
            for route in desiredSplitIPv6Routes {
                let managedRoute = ManagedIPv6Route(destination: route, viaInterface: validatedTunnelName)
                if try managedIPv6RouteNeedsInstallation(managedRoute) {
                    _ = try addIPv6Route(managedRoute, allowNonZero: false)
                }
            }

            installedResolverDomainsThisAttempt = desiredDNSDomains
            try installResolverFiles(forDomains: desiredDNSDomains, nameServers: policyDNSServers())

            try removeOpenVPNDefaultRoutes(tunnelName: validatedTunnelName,
                                           verifyRemoval: true,
                                           ownedBlockedIPv6Routes: sessionOwnedBlockedIPv6Routes(using: state))
            if state.tunnelMode == .full {
                try restorePhysicalIPv6Configuration(using: state)
            }
            for route in state.managedIPv6Routes ?? [] {
                try deleteManagedIPv6RouteIfPresent(route,
                                                    verifyRemoval: true)
            }
            state.managedIPv6Routes = nil
            state.sessionOwnedBlockedIPv6Routes = nil
            try persistPreparedState(state)
            let desiredSplitRouteSet = Set(desiredSplitRoutes)
            let desiredSplitIPv6RouteSet = Set(desiredSplitIPv6Routes)
            for route in staleSplitRoutes where !desiredSplitRouteSet.contains(route) {
                try deleteManagedIPv4RouteIfPresent(ManagedIPv4Route(destination: route, viaInterface: validatedTunnelName),
                                                    verifyRemoval: true)
            }
            for route in staleSplitIPv6Routes where !desiredSplitIPv6RouteSet.contains(route) {
                try deleteIPv6RouteIfPresent(route,
                                             interfaceName: validatedTunnelName,
                                             verifyRemoval: true)
            }

            try installManagedSplitDefaultRoute("0.0.0.0/1",
                                                gateway: gateway,
                                                interfaceName: physicalInterface,
                                                using: &state,
                                                persistPreparedState: persistPreparedState)
            try installManagedSplitDefaultRoute("128.0.0.0/1",
                                                gateway: gateway,
                                                interfaceName: physicalInterface,
                                                using: &state,
                                                persistPreparedState: persistPreparedState)

            try restoreDNSConfiguration(using: state)
            try removeObsoleteResolverFiles(retaining: desiredDNSDomains)
            try flushDNS()

            state.appliedSplitIPv4Routes = desiredSplitRoutes
            state.appliedSplitIPv6Routes = desiredSplitIPv6Routes
            state.appliedDNSDomains = desiredDNSDomains
            try persistPreparedState(state)

            if try repairSplitTunnelState(using: state) {
                try flushDNS()
            }

            state.appliedDNSDomains = cleanupDNSDomains(using: state)
        } catch {
            if mutatedNetwork {
                _ = try? cleanup(using: state)
                _ = try? removeResolverFiles(for: (staleDNSDomainsForCleanup + installedResolverDomainsThisAttempt).uniqued())
            }
            throw error
        }
    }

    func applyFullTunnelSafety(using state: inout SessionState,
                               persistPreparedState: (SessionState) throws -> Void) throws {
        guard let tunnelName = state.tunName, !tunnelName.isEmpty else {
            throw RouteManagerError.missingTunnelInterface
        }

        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)
        try assertFullTunnelSupported(physicalInterface: state.physicalInterface, ipv6Mode: state.originalIPv6Mode)
        do {
            try ensureRemoteHostRoutes(using: &state,
                                       mode: .full,
                                       context: "full-tunnel setup",
                                       persistPreparedState: persistPreparedState)
        } catch {
            try? installFailClosedTunnelDefaultRoutes(tunnelName: validatedTunnelName)
            throw error
        }
        try persistPreparedState(state)
        if !(try fullTunnelIPv4LooksSafe(tunnelName: validatedTunnelName, using: state)) {
            try installFailClosedTunnelDefaultRoutes(tunnelName: validatedTunnelName)
            guard try fullTunnelIPv4LooksSafe(tunnelName: validatedTunnelName, using: state) else {
                appendEventLog(note: fullTunnelIPv4SafetyFailureDetail(tunnelName: validatedTunnelName,
                                                                        using: state))
                throw RouteManagerError.failedToSecureFullTunnelIPv4Routes
            }
        }
        try assertFullTunnelControlChannelEgressesPhysically(using: state, tunnelName: validatedTunnelName)
        state.fullTunnelDNSServers = try applyFullTunnelDNSConfigurationIfAvailable(using: state)
        state.appliedDNSDomains = fullTunnelScopedDNSDomains()
        try persistPreparedState(state)

        if state.vpnIPv6.map(SplitTunnelPolicy.isValidIPv6Address) ?? false {
            try reconcileManagedIPv6Routes(retaining: [], using: &state, persistPreparedState: persistPreparedState)
        } else {
            try reconcileManagedIPv6Routes(retaining: Set(Self.fullTunnelIPv6DefaultRoutes.map(ManagedIPv6Route.init(blocking:))),
                                           using: &state,
                                           persistPreparedState: persistPreparedState)
            try installBlockedIPv6DefaultRoutes(using: &state, persistPreparedState: persistPreparedState)
        }
        try disablePhysicalIPv6IfEnabled(using: state)
        try persistPreparedState(state)

        let ipv6Safety = stabilizedFullTunnelIPv6Safety(tunnelName: validatedTunnelName)
        guard ipv6Safety.isStable else {
            appendEventLog(note: fullTunnelIPv6SafetyFailureDetail(ipv6Safety))
            if let inspectionError = ipv6Safety.assessment.inspectionError {
                throw inspectionError
            }
            throw RouteManagerError.failedToSecureFullTunnelIPv6Routes
        }
    }

    func switchToFullTunnel(using state: inout SessionState,
                            persistPreparedState: (SessionState) throws -> Void) throws {
        guard let tunnelName = state.tunName, !tunnelName.isEmpty else {
            throw RouteManagerError.missingTunnelInterface
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)
        try assertFullTunnelSupported(physicalInterface: state.physicalInterface, ipv6Mode: state.originalIPv6Mode)

        do {
            try ensureRemoteHostRoutes(using: &state,
                                       mode: .full,
                                       context: "mode switch to full-tunnel",
                                       persistPreparedState: persistPreparedState)
            try persistPreparedState(state)

            let routesToRestore = fullTunnelDefaultRoutes(tunnelName: validatedTunnelName)
            try installFailClosedTunnelDefaultRoutes(tunnelName: validatedTunnelName)

            if !(try fullTunnelRoutesMatch(routesToRestore)) {
                throw RouteManagerError.failedToRestoreFullTunnelRoutes
            }

            for route in state.managedSplitDefaultRoutes ?? [] {
                try deleteManagedIPv4RouteIfPresent(route, verifyRemoval: true)
            }

            try applyFullTunnelSafety(using: &state, persistPreparedState: persistPreparedState)
            try removeObsoleteResolverFiles(retaining: cleanupDNSDomains(using: state))

            state.fullTunnelDefaultRoutes = routesToRestore
            state.fullTunnelSearchDomains = effectiveFullTunnelSearchDomains(using: state)
            state.managedSplitDefaultRoutes = nil
            try persistPreparedState(state)
        } catch {
            try? installFailClosedTunnelDefaultRoutes(tunnelName: validatedTunnelName)
            throw error
        }
    }

    func captureCurrentFullTunnelDefaultRoutes(tunnelName: String) throws -> [ManagedIPv4Route] {
        let entries = try routingTableEntries()
        return Self.fullTunnelIPv4DefaultRoutes.compactMap { destination in
            entries.last { $0.interfaceName == tunnelName && IPRoute.canonicalIPv4($0.destination) == destination }
                .flatMap(managedIPv4Route(from:))
        }
    }

    func captureActiveDefaultSearchDomains() -> [String] {
        guard let output = try? shell.run("/usr/sbin/scutil", arguments: ["--dns"], allowNonZero: true).stdout else {
            return []
        }

        return parseActiveDNSResolvers(output)
            .filter { $0.domain == nil }
            .flatMap(\.searchDomains)
            .filter(SplitTunnelPolicy.isValidDomainName)
            .uniqued()
    }

    static let bootstrapDigHome = "/var/empty"

    static func resolveHostUsingBootstrap(host: String,
                                          servers: [String],
                                          timeoutSeconds: Int,
                                          shell: Shell = Shell()) -> String? {
        guard !servers.isEmpty,
              !SplitTunnelPolicy.isValidIPAddress(host),
              SplitTunnelPolicy.isValidDomainName(host) else {
            return nil
        }

        for server in servers {
            guard let result = try? shell.run("/usr/bin/dig",
                                              arguments: ["+short",
                                                          "+time=\(timeoutSeconds)",
                                                          "+tries=1",
                                                          "@\(server)",
                                                          host,
                                                          "A"],
                                              allowNonZero: true,
                                              environmentOverrides: ["HOME": bootstrapDigHome]) else {
                continue
            }
            for rawLine in result.stdout.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
                let candidate = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                if SplitTunnelPolicy.isValidIPv4Address(candidate),
                   !Self.isUnusableRemoteIPv4Address(candidate) {
                    return candidate
                }
            }
        }
        return nil
    }

    func monitorAndRepair(using state: SessionState) throws -> Bool {
        guard let tunnelName = state.tunName else {
            return false
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)

        guard tunnelInterfaceIsPresent(named: validatedTunnelName) else {
            return false
        }

        let splitIPv4Routes = cleanupSplitIPv4Routes(using: state)
        let splitIPv6Routes = cleanupSplitIPv6Routes(using: state)
        try validateTunnelIPv4SupportIfNeeded(for: splitIPv4Routes, using: state)
        try validateTunnelIPv6SupportIfNeeded(for: splitIPv6Routes, using: state)

        let routingTable = try routingTableEntries()
        var needsRepair = false
        var shouldFlushDNS = false

        for route in splitIPv4Routes {
            if !routeExists(route, on: validatedTunnelName, in: routingTable) {
                needsRepair = true
                break
            }
        }
        if !needsRepair {
            let ipv6RoutingTable = try ipv6RoutingTableEntries()
            for route in splitIPv6Routes {
                if !ipv6RouteExists(route, on: validatedTunnelName, in: ipv6RoutingTable) {
                    needsRepair = true
                    break
                }
            }
        }

        if currentDefaultInterface(in: routingTable) == validatedTunnelName {
            needsRepair = true
        }
        if !needsRepair,
           (state.managedSplitDefaultRoutes ?? []).contains(where: { !ipv4RouteExists($0, in: routingTable) }) {
            needsRepair = true
        }
        if tunnelIPv4DefaultHalfRouteExists(on: validatedTunnelName, in: routingTable) {
            needsRepair = true
        }
        let ownedBlockedIPv6Routes = sessionOwnedBlockedIPv6Routes(using: state)
        if !needsRepair,
           !ownedBlockedIPv6Routes.isEmpty,
           openVPNBlockedIPv6RoutesPresent(ownedBlockedIPv6Routes, in: try ipv6RoutingTableEntries()) {
            needsRepair = true
        }

        if needsRepair {
            do {
                try removeOpenVPNDefaultRoutes(tunnelName: validatedTunnelName,
                                               verifyRemoval: true,
                                               ownedBlockedIPv6Routes: ownedBlockedIPv6Routes)
                for route in state.managedSplitDefaultRoutes ?? [] where try managedIPv4RouteNeedsInstallation(route) {
                    try addIPv4Route(route, allowNonZero: false)
                }
                for route in splitIPv4Routes {
                    let managedRoute = ManagedIPv4Route(destination: route, viaInterface: validatedTunnelName)
                    if try managedIPv4RouteNeedsInstallation(managedRoute) {
                        try addIPv4Route(managedRoute, allowNonZero: false)
                    }
                }
                for route in splitIPv6Routes {
                    let managedRoute = ManagedIPv6Route(destination: route, viaInterface: validatedTunnelName)
                    if try managedIPv6RouteNeedsInstallation(managedRoute) {
                        _ = try addIPv6Route(managedRoute, allowNonZero: false)
                    }
                }
                appendEventLog(note: "Route health check repaired split-tunnel routing drift.",
                               phase: state.phase)
            } catch {
                try? installSplitTunnelRouting(using: state,
                                               tunnelName: validatedTunnelName)
                throw error
            }
            shouldFlushDNS = true
        }

        if try repairSplitTunnelState(using: state) {
            shouldFlushDNS = true
        }
        if shouldFlushDNS {
            try flushDNS()
        }

        return true
    }

    func unexpectedFullTunnelPublicIPv6Routes(tunnelName: String, entries: [RouteEntry]) -> [String] {
        let publicIPv6Covered = fullTunnelPublicIPv6RangeIsCovered(tunnelName: tunnelName, entries: entries)
        return entries.compactMap { entry in
            guard entry.interfaceName != tunnelName,
                  entry.interfaceName != "lo0",
                  let route = IPRoute.canonicalIPv6(entry.destination),
                  Self.ipv6RouteTouchesPublicGlobalUnicast(route),
                  !(publicIPv6Covered && route.prefixLength == 0) else {
                return nil
            }
            return route.routeString
        }
    }

    func fullTunnelPublicIPv6RangeIsCovered(tunnelName: String,
                                            entries: [RouteEntry]) -> Bool {
        Self.fullTunnelIPv6DefaultRoutes.allSatisfy { destination in
            guard let expectedRoute = IPRoute.canonicalIPv6(destination) else {
                return false
            }
            return entries.contains { entry in
                guard let route = IPRoute.canonicalIPv6(entry.destination),
                      route == expectedRoute,
                      !entry.isInterfaceScoped else {
                    return false
                }
                return entry.interfaceName == tunnelName || entry.interfaceName == "lo0"
            }
        }
    }

    func monitorFullTunnel(using state: inout SessionState,
                           persistPreparedState: @escaping (SessionState) throws -> Void) throws -> Bool {
        guard let tunnelName = state.tunName else {
            return false
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)
        guard tunnelInterfaceIsPresent(named: validatedTunnelName) else {
            return false
        }

        try applyFullTunnelSafety(using: &state, persistPreparedState: persistPreparedState)
        return true
    }

    func validateNetworkSafetyWhileSettling(using state: SessionState) throws {
        guard let tunnelName = state.tunName,
              tunnelInterfaceIsPresent(named: try validatedTunnelInterfaceName(tunnelName)) else {
            throw RouteManagerError.missingTunnelInterface
        }
        switch state.tunnelMode {
        case .full:
            guard try fullTunnelIPv4LooksSafe(tunnelName: tunnelName, using: state) else {
                throw RouteManagerError.failedToSecureFullTunnelIPv4Routes
            }
            guard assessFullTunnelIPv6Safety(tunnelName: tunnelName).isSafe else {
                throw RouteManagerError.failedToSecureFullTunnelIPv6Routes
            }
            let output = try shell.run("/usr/sbin/scutil", arguments: ["--dns"]).stdout
            let servers = parseActiveDNSResolvers(output).filter { $0.domain == nil }.flatMap(\.nameServers)
            let safeServers = try dnsServersRoutedThroughTunnel(servers, tunnelName: tunnelName)
            guard !servers.isEmpty, safeServers.count == servers.count else {
                throw RouteManagerError.failedToSecureFullTunnelDNS
            }
        case .split:
            let ipv4Table = try routingTableEntries()
            let ipv6Table = try ipv6RoutingTableEntries()
            guard !ipv4Table.contains(where: { $0.destination == "default" && $0.interfaceName == tunnelName }),
                  !ipv6Table.contains(where: { $0.destination == "default" && $0.interfaceName == tunnelName }),
                  cleanupSplitIPv4Routes(using: state).allSatisfy({ routeExists($0, on: tunnelName, in: ipv4Table) }),
                  cleanupSplitIPv6Routes(using: state).allSatisfy({ ipv6RouteExists($0, on: tunnelName, in: ipv6Table) }),
                  try protectedSplitIPv4RouteOverrides(on: tunnelName, using: state).isEmpty,
                  try protectedSplitIPv6RouteOverrides(on: tunnelName, using: state).isEmpty,
                  try unexpectedSplitIPv4RouteEntries(on: tunnelName, using: state).isEmpty,
                  try unexpectedSplitIPv6Routes(on: tunnelName, using: state).isEmpty else {
                throw RouteManagerError.failedToSecureSplitTunnelRoutes
            }
            guard try !activeDefaultResolverLeakState(using: state).needsRepair,
                  try cleanupDNSDomains(using: state).allSatisfy({
                      try resolverFileStatus(for: $0, nameServers: policyDNSServers()) == .matching
                  }) else {
                throw RouteManagerError.failedToIsolateSplitTunnelDNS
            }
        }
    }

    @discardableResult
    func cleanup(using state: SessionState) throws -> Bool {
        var cleanupErrors: [Error] = []
        performCleanupAttempt(using: state, errors: &cleanupErrors)

        if try validateCleanupState(using: state) {
            return true
        }

        performCleanupAttempt(using: state, errors: &cleanupErrors)
        if try validateCleanupState(using: state) {
            return true
        }

        if let firstError = cleanupErrors.first {
            throw firstError
        }

        return false
    }

    func flushDNS() throws {
        _ = try shell.run("/usr/bin/dscacheutil", arguments: ["-flushcache"], allowNonZero: true, requirePrivileges: true)
        _ = try shell.run("/usr/bin/killall", arguments: ["-HUP", "mDNSResponder"], allowNonZero: true, requirePrivileges: true)
    }

    func refreshDHCPLeaseIfAvailable(using state: SessionState) {
        let interfaceName = state.physicalInterface
        guard SplitTunnelPolicy.isSafeInterfaceName(interfaceName),
              let probe = try? shell.run("/usr/sbin/ipconfig",
                                         arguments: ["getpacket", interfaceName],
                                         allowNonZero: true,
                                         requirePrivileges: true),
              probe.exitCode == 0 else {
            return
        }

        _ = try? shell.run("/usr/sbin/ipconfig",
                           arguments: ["set", interfaceName, "DHCP"],
                           allowNonZero: true,
                           requirePrivileges: true)
    }

    func splitTunnelHealthChecks(using state: SessionState) -> [SplitTunnelHealthCheck] {
        var checks: [SplitTunnelHealthCheck] = []
        let splitIPv4Routes = cleanupSplitIPv4Routes(using: state)
        let splitIPv6Routes = cleanupSplitIPv6Routes(using: state)

        if let tunnelName = state.tunName,
           let validatedTunnelName = try? validatedTunnelInterfaceName(tunnelName),
           tunnelInterfaceIsPresent(named: validatedTunnelName) {
            do {
                let table = try routingTableEntries()
                let missingRoutes = splitIPv4Routes.filter {
                    !routeExists($0, on: validatedTunnelName, in: table)
                }
                let overrides = try protectedSplitIPv4RouteOverrides(on: validatedTunnelName,
                                                                     using: state)
                if !overrides.isEmpty {
                    checks.append(SplitTunnelHealthCheck(
                        status: .fail,
                        name: "routes",
                        detail: "physical routes override protected destinations: \(overrides.joined(separator: ", "))"
                    ))
                } else if missingRoutes.isEmpty {
                    checks.append(SplitTunnelHealthCheck(
                        status: .pass,
                        name: "routes",
                        detail: "\(splitIPv4Routes.count) split route\(splitIPv4Routes.count == 1 ? "" : "s") on \(validatedTunnelName)"
                    ))
                } else {
                    checks.append(SplitTunnelHealthCheck(
                        status: .fail,
                        name: "routes",
                        detail: "missing on \(validatedTunnelName): \(missingRoutes.joined(separator: ", "))"
                    ))
                }
            } catch {
                checks.append(SplitTunnelHealthCheck(
                    status: .warn,
                    name: "routes",
                    detail: "could not inspect IPv4 routing table: \(error.localizedDescription)"
                ))
            }
        } else {
            checks.append(SplitTunnelHealthCheck(
                status: .fail,
                name: "routes",
                detail: "tunnel interface is missing"
            ))
        }

        if !splitIPv6Routes.isEmpty {
            if let tunnelName = state.tunName,
               let validatedTunnelName = try? validatedTunnelInterfaceName(tunnelName),
               tunnelInterfaceIsPresent(named: validatedTunnelName) {
                do {
                    let table = try ipv6RoutingTableEntries()
                    let missingRoutes = splitIPv6Routes.filter {
                        !ipv6RouteExists($0, on: validatedTunnelName, in: table)
                    }
                    let overrides = try protectedSplitIPv6RouteOverrides(on: validatedTunnelName,
                                                                         using: state)
                    if !overrides.isEmpty {
                        checks.append(SplitTunnelHealthCheck(
                            status: .fail,
                            name: "ipv6-routes",
                            detail: "physical routes override protected destinations: \(overrides.joined(separator: ", "))"
                        ))
                    } else if missingRoutes.isEmpty {
                        checks.append(SplitTunnelHealthCheck(
                            status: .pass,
                            name: "ipv6-routes",
                            detail: "\(splitIPv6Routes.count) split IPv6 route\(splitIPv6Routes.count == 1 ? "" : "s") on \(validatedTunnelName)"
                        ))
                    } else {
                        checks.append(SplitTunnelHealthCheck(
                            status: .fail,
                            name: "ipv6-routes",
                            detail: "missing on \(validatedTunnelName): \(missingRoutes.joined(separator: ", "))"
                        ))
                    }
                } catch {
                    checks.append(SplitTunnelHealthCheck(
                        status: .warn,
                        name: "ipv6-routes",
                        detail: "could not inspect IPv6 routing table: \(error.localizedDescription)"
                    ))
                }
            } else {
                checks.append(SplitTunnelHealthCheck(
                    status: .fail,
                    name: "ipv6-routes",
                    detail: "tunnel interface is missing"
                ))
            }
        }

        do {
            let leakState = try activeDefaultResolverLeakState(using: state)
            if leakState.usesVPNNameServers {
                checks.append(SplitTunnelHealthCheck(
                    status: .fail,
                    name: "dns",
                    detail: "default resolver is using CWRU scoped DNS servers"
                ))
            } else if leakState.overlapsVPNSearchDomains {
                checks.append(SplitTunnelHealthCheck(
                    status: .warn,
                    name: "dns",
                    detail: "default resolver still has CWRU search domains"
                ))
            } else {
                checks.append(SplitTunnelHealthCheck(
                    status: .pass,
                    name: "dns",
                    detail: "default resolver is isolated from CWRU scoped DNS"
                ))
            }
        } catch {
            checks.append(SplitTunnelHealthCheck(status: .warn,
                                                name: "dns",
                                                detail: "could not inspect the default resolver: \(error.localizedDescription)"))
        }

        checks.append(resolverFilesHealthCheck(using: state))

        checks.append(ipv6HealthCheck(using: state))

        if let coverageWarning = cwruRouteCoverageHealthCheck(using: state) {
            checks.append(coverageWarning)
        }

        return checks
    }

    func cleanupSplitIPv4Routes(using state: SessionState) -> [String] {
        (state.appliedSplitIPv4Routes ?? [])
            .filter(SplitTunnelPolicy.isValidIPv4CIDR)
    }

    func cleanupSplitIPv6Routes(using state: SessionState) -> [String] {
        (state.appliedSplitIPv6Routes ?? [])
            .filter(SplitTunnelPolicy.isValidIPv6CIDR)
    }

    func cleanupDNSDomains(using state: SessionState) -> [String] {
        (state.appliedDNSDomains ?? []).filter {
            SplitTunnelPolicy.isValidDomainName($0)
                && ResolverPaths.isSafeDomainFileName($0)
        }
    }

    func dnsDomains(forSplitIPv4Routes routes: [String],
                    splitIPv6Routes: [String]) -> [String] {
        splitTunnelPolicy.resolverDomains(forIPv4Routes: routes, ipv6Routes: splitIPv6Routes)
    }

    func staleManagedDNSDomains(using state: SessionState) -> [String] {
        let expectedDomains = Set(cleanupDNSDomains(using: state))
        return managedResolverDomainsInDirectory()
            .filter { !expectedDomains.contains($0) }
    }

    func policyIPv4Routes() -> [String] {
        splitTunnelPolicy.ipv4Routes.compactMap { IPRoute.canonicalIPv4($0)?.routeString }.uniqued()
    }

    func policyIPv6Routes() -> [String] {
        splitTunnelPolicy.ipv6Routes.compactMap { IPRoute.canonicalIPv6($0)?.routeString }.uniqued()
    }

    func validateTunnelIPv6SupportIfNeeded(for routes: [String],
                                           using state: SessionState) throws {
        guard !routes.isEmpty else {
            return
        }
        guard let vpnIPv6 = state.vpnIPv6,
              SplitTunnelPolicy.isValidIPv6Address(vpnIPv6) else {
            throw RouteManagerError.missingTunnelIPv6Address
        }
    }

    func splitTunnelShouldApplyIPv6(using state: SessionState) -> Bool {
        state.vpnIPv6.map(SplitTunnelPolicy.isValidIPv6Address) ?? false
    }

    func validateTunnelIPv4SupportIfNeeded(for routes: [String],
                                           using state: SessionState) throws {
        guard !routes.isEmpty else {
            return
        }
        guard let vpnIPv4 = state.vpnIPv4,
              SplitTunnelPolicy.isValidIPv4Address(vpnIPv4) else {
            throw RouteManagerError.missingTunnelIPv4Address
        }
    }

    func restoreDefaultRouteIfNecessary(using state: SessionState) throws {
        let gateway = state.physicalGateway

        let routingTable = try routingTableEntries()
        let currentDefault = routingTable.first { $0.destination == "default" }

        guard currentDefault.map({ SplitTunnelPolicy.isVirtualInterfaceName($0.interfaceName) }) ?? true else {
            return
        }

        guard physicalGatewayIsOnLink(gateway) else {
            return
        }

        _ = try shell.run("/sbin/route", arguments: ["-n", "delete", "default"], allowNonZero: true, requirePrivileges: true)
        _ = try shell.run("/sbin/route", arguments: ["-n", "add", "default", gateway], allowNonZero: true, requirePrivileges: true)
    }

    func removeOpenVPNDefaultRoutes(tunnelName: String?,
                                    verifyRemoval: Bool,
                                    ownedBlockedIPv6Routes: [CanonicalIPv6Route]) throws {
        let validatedTunnelName: String?
        if let tunnelName, !tunnelName.isEmpty {
            validatedTunnelName = try? validatedTunnelInterfaceName(tunnelName)
        } else {
            validatedTunnelName = nil
        }

        try deleteManagedIPv4DefaultHalf("0.0.0.0/1",
                                         ourTunnel: validatedTunnelName,
                                         verifyRemoval: verifyRemoval)

        var firstError: Error?
        do {
            try deleteManagedIPv4DefaultHalf("128.0.0.0/1",
                                             ourTunnel: validatedTunnelName,
                                             verifyRemoval: verifyRemoval)
        } catch {
            firstError = error
        }

        if let validatedTunnelName {
            do {
                try removeOpenVPNIPv6DefaultRoutes(tunnelName: validatedTunnelName,
                                                   verifyRemoval: verifyRemoval,
                                                   ownedBlockedIPv6Routes: ownedBlockedIPv6Routes)
            } catch {
                firstError = firstError ?? error
            }
        }

        if let firstError {
            throw firstError
        }
    }

    func deleteManagedIPv4DefaultHalf(_ destination: String,
                                      ourTunnel: String?,
                                      verifyRemoval: Bool) throws {
        guard let ourTunnel,
              let canonicalDestination = IPRoute.canonicalIPv4(destination) else {
            return
        }
        let routes = try routingTableEntries().compactMap { entry -> ManagedIPv4Route? in
            guard IPRoute.canonicalIPv4(entry.destination) == canonicalDestination,
                  entry.interfaceName == ourTunnel else {
                return nil
            }
            return managedIPv4Route(from: entry)
        }
        for route in routes {
            try deleteManagedIPv4RouteIfPresent(route, verifyRemoval: verifyRemoval)
        }
    }

    func removeOpenVPNIPv6DefaultRoutes(tunnelName: String,
                                        verifyRemoval: Bool,
                                        ownedBlockedIPv6Routes: [CanonicalIPv6Route]) throws {
        _ = try shell.run("/sbin/route",
                          arguments: ["-n", "delete", "-net", "-inet6", "::", "-prefixlen", "1", "-interface", tunnelName],
                          allowNonZero: true,
                          requirePrivileges: true)
        _ = try shell.run("/sbin/route",
                          arguments: ["-n", "delete", "-net", "-inet6", "8000::", "-prefixlen", "1", "-interface", tunnelName],
                          allowNonZero: true,
                          requirePrivileges: true)
        for route in ownedBlockedIPv6Routes {
            try deleteManagedIPv6RouteIfPresent(openVPNBlockedIPv6Route(route),
                                                verifyRemoval: verifyRemoval)
        }
    }

    func openVPNBlockedIPv6Route(_ route: CanonicalIPv6Route) -> ManagedIPv6Route {
        ManagedIPv6Route(blocking: route.routeString)
    }

    func sessionOwnedBlockedIPv6Routes(using state: SessionState) -> [CanonicalIPv6Route] {
        let owned = Set((state.sessionOwnedBlockedIPv6Routes ?? []).compactMap {
            IPRoute.canonicalIPv6($0)?.routeString
        })
        return Self.openVPNBlockedIPv6Routes.filter { owned.contains($0.routeString) }
    }

    func openVPNBlockedIPv6RoutesPresent(_ routes: [CanonicalIPv6Route],
                                         in entries: [RouteEntry]) -> Bool {
        routes.contains { route in
            ipv6RouteExists(openVPNBlockedIPv6Route(route), in: entries)
        }
    }

    func presentOpenVPNBlockedIPv6Routes() throws -> [String] {
        let entries = try ipv6RoutingTableEntries()
        return Self.openVPNBlockedIPv6Routes
            .filter { ipv6RouteExists(openVPNBlockedIPv6Route($0), in: entries) }
            .map(\.routeString)
    }

    func tunnelInterfaceIsPresent(named tunnelName: String) -> Bool {
        guard let result = try? shell.run("/sbin/ifconfig", arguments: [tunnelName], allowNonZero: true) else {
            return false
        }
        return result.exitCode == 0
    }

    func currentDefaultInterface(in entries: [RouteEntry]) -> String? {
        entries.first { $0.destination == "default" }?.interfaceName
    }

    func restoreDNSConfiguration(using state: SessionState) throws {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return
        }

        try setDNSConfiguration(serviceName: serviceName,
                                dnsServers: state.originalDNSServers ?? [],
                                searchDomains: state.originalSearchDomains ?? [])
    }

    func restorePhysicalDNSConfigurationIfNeeded(using state: SessionState) throws -> Bool {
        guard let serviceName = state.physicalServiceName,
              !serviceName.isEmpty,
              let current = try currentDNSConfiguration(using: state) else {
            return false
        }

        let expectedDNSServers = state.originalDNSServers ?? []
        let expectedSearchDomains = state.originalSearchDomains ?? []
        guard current.dnsServers != expectedDNSServers
                || current.searchDomains != expectedSearchDomains else {
            return false
        }

        do {
            try setDNSConfiguration(serviceName: serviceName,
                                    dnsServers: expectedDNSServers,
                                    searchDomains: expectedSearchDomains)
        } catch {
            throw RouteManagerError.dnsMutationMayHaveOccurred(error.localizedDescription)
        }
        return true
    }

    @discardableResult
    func applyFullTunnelDNSConfigurationIfAvailable(using state: SessionState) throws -> [String] {
        _ = try fullTunnelDNSService(using: state)
        let nameServers = try effectiveFullTunnelDNSServers(using: state)
        let scopedDomains = fullTunnelScopedDNSDomains()
        guard !scopedDomains.isEmpty, !nameServers.isEmpty else {
            try flushDNS()
            return nameServers
        }
        let refreshedResolverFiles = try installFullTunnelResolverFiles(nameServers: nameServers)
        if refreshedResolverFiles {
            appendEventLog(note: "Full tunnel: refreshed scoped resolver files.", phase: state.phase)
        }
        if let current = try currentDNSConfiguration(using: state),
           current.dnsServers == nameServers,
           current.searchDomains == effectiveFullTunnelSearchDomains(using: state) {
            if refreshedResolverFiles {
                try flushDNS()
            }
            return nameServers
        }
        appendEventLog(note: "Full tunnel: applied the physical-service DNS configuration.", phase: state.phase)
        try setFullTunnelDefaultResolver(using: state, nameServers: nameServers)
        try flushDNS()
        return nameServers
    }

    func setFullTunnelDefaultResolver(using state: SessionState, nameServers: [String]) throws {
        let serviceName = try fullTunnelDNSService(using: state)
        guard !nameServers.isEmpty else {
            return
        }
        try setDNSConfiguration(serviceName: serviceName,
                                dnsServers: nameServers,
                                searchDomains: effectiveFullTunnelSearchDomains(using: state))
    }

    private func fullTunnelDNSService(using state: SessionState) throws -> String {
        guard let serviceName = state.physicalServiceName,
              SplitTunnelPolicy.isSafeNetworkServiceName(serviceName) else {
            throw RouteManagerError.failedToSecureFullTunnelDNS
        }
        return serviceName
    }

    func fullTunnelScopedDNSDomains() -> [String] {
        splitTunnelPolicy.resolverDomains(forIPv4Routes: [], ipv6Routes: [])
    }

    func effectiveFullTunnelDNSServers(using state: SessionState) throws -> [String] {
        guard let tunnelName = state.tunName else {
            throw RouteManagerError.missingTunnelInterface
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)
        let learnedServers = firstNonEmptyList(state.fullTunnelDNSServers,
                                               state.pushedDNSServers)
            .filter(SplitTunnelPolicy.isValidIPAddress)
        let policyServers = policyDNSServers().filter(SplitTunnelPolicy.isValidIPAddress)
        if learnedServers.isEmpty && policyServers.isEmpty {
            return []
        }
        let safeLearnedServers = try dnsServersRoutedThroughTunnel(learnedServers,
                                                                  tunnelName: validatedTunnelName)
        if !safeLearnedServers.isEmpty {
            return safeLearnedServers
        }
        let safePolicyServers = try dnsServersRoutedThroughTunnel(
            policyServers,
            tunnelName: validatedTunnelName
        )
        guard !safePolicyServers.isEmpty else {
            throw RouteManagerError.failedToSecureFullTunnelDNS
        }
        return safePolicyServers
    }

    func dnsServersRoutedThroughTunnel(_ servers: [String], tunnelName: String) throws -> [String] {
        var result: [String] = []
        for server in servers {
            let routeState: PublicRouteState
            if SplitTunnelPolicy.isValidIPv4Address(server) {
                routeState = try publicIPv4RouteState(for: server, tunnelName: tunnelName)
            } else if SplitTunnelPolicy.isValidIPv6Address(server) {
                routeState = try publicIPv6RouteState(for: server, tunnelName: tunnelName)
            } else {
                continue
            }
            if routeState == .tunnel {
                result.append(server)
            }
        }
        return result
    }

    func effectiveFullTunnelSearchDomains(using state: SessionState) -> [String] {
        let learnedDomains = firstNonEmptyList(state.fullTunnelSearchDomains,
                                               state.pushedSearchDomains)
            .filter(SplitTunnelPolicy.isValidDomainName)
        if !learnedDomains.isEmpty {
            return learnedDomains
        }

        return fullTunnelScopedDNSDomains().filter(SplitTunnelPolicy.isValidDomainName)
    }

    func setDNSConfiguration(serviceName: String,
                             dnsServers: [String],
                             searchDomains: [String]) throws {
        let dnsArguments = networkSetupListArguments(command: "-setdnsservers",
                                                     serviceName: serviceName,
                                                     values: dnsServers)
        _ = try shell.run("/usr/sbin/networksetup",
                          arguments: dnsArguments,
                          requirePrivileges: true)

        let searchArguments = networkSetupListArguments(command: "-setsearchdomains",
                                                        serviceName: serviceName,
                                                        values: searchDomains)
        _ = try shell.run("/usr/sbin/networksetup",
                          arguments: searchArguments,
                          requirePrivileges: true)
    }

    func networkSetupListArguments(command: String,
                                   serviceName: String,
                                   values: [String]) -> [String] {
        values.isEmpty ? [command, serviceName, "empty"] : [command, serviceName] + values
    }

    func repairSplitTunnelState(using state: SessionState) throws -> Bool {
        var changed = false
        changed = try validatePhysicalDNSRestored(using: state) || changed
        changed = try validateResolverFiles(using: state) || changed
        changed = try validateNoUnexpectedSplitTunnelRoutes(using: state) || changed
        changed = try repairMissingSplitIPv6Routes(using: state) || changed
        changed = try validateSplitTunnelPublicIPv6NotLeaking(using: state) || changed
        changed = try validateActiveDefaultResolverIsolation(using: state) || changed
        return changed
    }

    func validateCleanupState(using state: SessionState) throws -> Bool {
        let routingTable = try routingTableEntries()
        return try cleanupDefaultRouteLooksHealthy(using: state)
            && cleanupManagedDefaultRoutesRemoved(using: state)
            && cleanupPhysicalDNSLooksHealthy(using: state)
            && cleanupResolversRemoved(using: state)
            && cleanupPhysicalIPv6LooksHealthy(using: state)
            && cleanupSplitIPv4RoutesRemoved(using: state, in: routingTable)
            && cleanupSplitIPv6RoutesRemoved(using: state)
            && cleanupRemoteHostRoutesRemoved(using: state, in: routingTable)
            && cleanupReplacedRemoteHostRoutesRestored(using: state, in: routingTable)
    }

    func validatePhysicalDNSRestored(using state: SessionState) throws -> Bool {
        if try restorePhysicalDNSConfigurationIfNeeded(using: state) {
            appendEventLog(note: "Split-tunnel privacy check restored physical-service DNS configuration.",
                           phase: state.phase)
            return true
        }

        return false
    }

    func cleanupPhysicalDNSLooksHealthy(using state: SessionState) throws -> Bool {
        guard let current = try currentDNSConfiguration(using: state) else {
            return true
        }

        return current.dnsServers == (state.originalDNSServers ?? [])
        && current.searchDomains == (state.originalSearchDomains ?? [])
    }

    func cleanupResolversRemoved(using state: SessionState) throws -> Bool {
        for domain in (cleanupDNSDomains(using: state) + managedResolverDomainsInDirectory()).uniqued() {
            let file = resolverFileURL(for: domain)
            if FileManager.default.fileExists(atPath: file.path), resolverFileIsManaged(at: file) {
                return false
            }
        }
        return true
    }

    func validateResolverFiles(using state: SessionState) throws -> Bool {
        let removedStaleResolvers = try removeStaleManagedResolverFiles(using: state)
        let nameServers = policyDNSServers()
        let dnsDomains = cleanupDNSDomains(using: state)
        guard !dnsDomains.isEmpty else {
            return removedStaleResolvers
        }

        for domain in dnsDomains {
            if try resolverFileStatus(for: domain, nameServers: nameServers) != .matching {
                appendEventLog(note: "Split-tunnel privacy check refreshed scoped resolver files.",
                               phase: state.phase)
                try installResolverFiles(using: state)
                return true
            }
        }

        return removedStaleResolvers
    }

    func removeStaleManagedResolverFiles(using state: SessionState) throws -> Bool {
        let staleDomains = staleManagedDNSDomains(using: state)
        guard !staleDomains.isEmpty else {
            return false
        }

        try removeResolverFiles(for: staleDomains)
        appendEventLog(note: "Split-tunnel privacy check removed stale scoped resolver files.",
                       phase: state.phase)
        return true
    }

    func currentDNSConfiguration(using state: SessionState) throws -> PhysicalDNSConfiguration? {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return nil
        }

        return try dnsConfiguration(forServiceNamed: serviceName)
    }

    private func dnsConfiguration(forServiceNamed serviceName: String) throws -> PhysicalDNSConfiguration {
        let dnsServersOutput = try shell.run("/usr/sbin/networksetup",
                                             arguments: ["-getdnsservers", serviceName],
                                             requirePrivileges: true)
        let searchDomainsOutput = try shell.run("/usr/sbin/networksetup",
                                                arguments: ["-getsearchdomains", serviceName],
                                                requirePrivileges: true)

        return PhysicalDNSConfiguration(serviceName: serviceName,
                                        dnsServers: parseNetworkSetupListOutput(dnsServersOutput.stdout),
                                        searchDomains: parseNetworkSetupListOutput(searchDomainsOutput.stdout),
                                        ipv6Mode: try ipv6Mode(forServiceNamed: serviceName))
    }

    func disablePhysicalIPv6IfEnabled(using state: SessionState) throws {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return
        }

        let currentRawMode = try ipv6Mode(forServiceNamed: serviceName)
        if normalizedIPv6Mode(currentRawMode) == "off" {
            return
        }
        guard let currentRawMode,
              !currentRawMode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return
        }
        guard normalizedIPv6Mode(state.originalIPv6Mode) != nil else {
            throw RouteManagerError.failedToSecureFullTunnelIPv6Routes
        }

        _ = try shell.run("/usr/sbin/networksetup",
                          arguments: ["-setv6off", serviceName],
                          requirePrivileges: true)
    }

    func physicalInterfaceUsesCLAT(_ interfaceName: String) -> Bool {
        guard let output = physicalInterfaceConfigurationOutput(interfaceName) else {
            return false
        }
        let lowered = output.lowercased()
        return lowered.contains("clat46") || lowered.contains("nat64 prefix")
    }

    func physicalInterfaceConfigurationOutput(_ interfaceName: String) -> String? {
        guard SplitTunnelPolicy.isSafeInterfaceName(interfaceName),
              let result = try? shell.run("/sbin/ifconfig",
                                          arguments: [interfaceName],
                                          allowNonZero: true),
              result.exitCode == 0 else {
            return nil
        }
        return result.stdout
    }

    func validateNoUnexpectedSplitTunnelRoutes(using state: SessionState) throws -> Bool {
        guard let tunnelName = state.tunName,
              let validatedTunnelName = try? validatedTunnelInterfaceName(tunnelName) else {
            return false
        }

        guard try protectedSplitIPv4RouteOverrides(on: validatedTunnelName, using: state).isEmpty,
              try protectedSplitIPv6RouteOverrides(on: validatedTunnelName, using: state).isEmpty else {
            throw RouteManagerError.failedToSecureSplitTunnelRoutes
        }

        var changed = false
        let unexpectedIPv4Routes = try unexpectedSplitIPv4RouteEntries(on: validatedTunnelName, using: state)
        for route in unexpectedIPv4Routes {
            try deleteIPv4RouteEntryIfPresent(route)
            changed = true
        }

        let unexpectedIPv6Routes = try unexpectedSplitIPv6Routes(on: validatedTunnelName, using: state)
        for route in unexpectedIPv6Routes {
            try deleteIPv6RouteIfPresent(route, interfaceName: validatedTunnelName)
            changed = true
        }

        guard try unexpectedSplitIPv4RouteEntries(on: validatedTunnelName, using: state).isEmpty,
              try unexpectedSplitIPv6Routes(on: validatedTunnelName, using: state).isEmpty else {
            throw RouteManagerError.failedToSecureSplitTunnelRoutes
        }

        if changed {
            let removed = unexpectedIPv4Routes.map { "\($0.destination) via \($0.gateway)" } + unexpectedIPv6Routes
            appendEventLog(note: "Split-tunnel privacy check removed unexpected VPN routes: \(removed.joined(separator: ", ")).",
                           phase: state.phase)
        }
        return changed
    }

    func unexpectedSplitIPv4RouteEntries(on tunnelName: String,
                                         using state: SessionState) throws -> [RouteEntry] {
        return try routingTableEntries().filter { entry in
            guard entry.interfaceName == tunnelName,
                  let route = IPRoute.canonicalIPv4(entry.destination) else {
                return false
            }
            if entry.isInterfaceScoped,
               Self.nonTransitIPv4Routes.contains(where: { IPRoute.ipv4Route($0, contains: route) }) {
                return false
            }
            return !splitIPv4RouteIsAllowed(route)
        }
    }

    func unexpectedSplitIPv6Routes(on tunnelName: String,
                                   using state: SessionState) throws -> [String] {
        return try ipv6RoutingTableEntries().compactMap { entry in
            guard entry.interfaceName == tunnelName,
                  let route = IPRoute.canonicalIPv6(entry.destination) else {
                return nil
            }
            if entry.isInterfaceScoped,
               Self.nonTransitIPv6Routes.contains(where: { IPRoute.ipv6Route($0, contains: route) }) {
                return nil
            }
            return splitIPv6RouteIsAllowed(route, using: state)
                ? nil
                : route.routeString
        }
    }

    func protectedSplitIPv4RouteOverrides(on tunnelName: String,
                                          using state: SessionState) throws -> [String] {
        let protectedRoutes = cleanupSplitIPv4Routes(using: state).compactMap(IPRoute.canonicalIPv4)
        let allowedControlRoutes = Set((state.managedRemoteIPv4Routes ?? []).filter {
            $0.destination == state.serverIP.map { "\($0)/32" }
                && $0.nextHopKind == .gateway
                && $0.nextHopValue == state.physicalGateway
                && $0.interfaceName == state.physicalInterface
                && !$0.isInterfaceScoped
        })
        return try routingTableEntries().compactMap { entry in
            guard entry.interfaceName != tunnelName,
                  let route = IPRoute.canonicalIPv4(entry.destination),
                  protectedRoutes.contains(where: {
                      route.prefixLength > $0.prefixLength && IPRoute.ipv4Route($0, contains: route)
                  }) else {
                return nil
            }
            if entry.hasHostFlag, entry.isStatic,
               let managed = managedIPv4Route(from: entry),
               allowedControlRoutes.contains(managed) {
                return nil
            }
            return route.routeString
        }
    }

    func protectedSplitIPv6RouteOverrides(on tunnelName: String,
                                          using state: SessionState) throws -> [String] {
        let protectedRoutes = cleanupSplitIPv6Routes(using: state).compactMap(IPRoute.canonicalIPv6)
        return try ipv6RoutingTableEntries().compactMap { entry in
            guard entry.interfaceName != tunnelName,
                  let route = IPRoute.canonicalIPv6(entry.destination),
                  protectedRoutes.contains(where: {
                      route.prefixLength > $0.prefixLength && IPRoute.ipv6Route($0, contains: route)
                  }) else {
                return nil
            }
            return route.routeString
        }
    }

    func splitIPv4RouteIsAllowed(_ route: CanonicalIPv4Route) -> Bool {
        policyIPv4Routes()
            .compactMap(IPRoute.canonicalIPv4)
            .contains { IPRoute.ipv4Route($0, contains: route) }
    }

    func splitIPv6RouteIsAllowed(_ route: CanonicalIPv6Route,
                                 using state: SessionState) -> Bool {
        let allowedRoutes = splitTunnelShouldApplyIPv6(using: state)
            ? policyIPv6Routes().compactMap(IPRoute.canonicalIPv6)
            : []
        return allowedRoutes.contains { IPRoute.ipv6Route($0, contains: route) }
    }

    func repairMissingSplitIPv6Routes(using state: SessionState) throws -> Bool {
        let splitIPv6Routes = cleanupSplitIPv6Routes(using: state)
        guard !splitIPv6Routes.isEmpty,
              let tunnelName = state.tunName,
              let validatedTunnelName = try? validatedTunnelInterfaceName(tunnelName) else {
            return false
        }

        let routingTable = try ipv6RoutingTableEntries()
        let missingRoutes = splitIPv6Routes.filter {
            !ipv6RouteExists($0, on: validatedTunnelName, in: routingTable)
        }
        guard !missingRoutes.isEmpty else {
            return false
        }

        try validateTunnelIPv6SupportIfNeeded(for: splitIPv6Routes, using: state)
        for route in missingRoutes {
            _ = try addIPv6Route(ManagedIPv6Route(destination: route, viaInterface: validatedTunnelName), allowNonZero: true)
        }
        appendEventLog(note: "Split-tunnel privacy check repaired IPv6 route drift.",
                       phase: state.phase)
        return true
    }

    func validateSplitTunnelPublicIPv6NotLeaking(using state: SessionState) throws -> Bool {
        guard let tunnelName = state.tunName,
              let validatedTunnelName = try? validatedTunnelInterfaceName(tunnelName) else {
            return false
        }
        let splitIPv6Routes = cleanupSplitIPv6Routes(using: state).compactMap(IPRoute.canonicalIPv6)
        if try splitTunnelPublicIPv6AvoidsTunnel(tunnelName: validatedTunnelName,
                                                 splitIPv6Routes: splitIPv6Routes) {
            return false
        }

        let probeSummary = try splitTunnelPublicIPv6ProbeSummary(tunnelName: validatedTunnelName,
                                                                 splitIPv6Routes: splitIPv6Routes)
        appendEventLog(note: "Split-tunnel privacy check removed CWRU-tunnel public IPv6 routing: \(probeSummary).",
                       phase: state.phase)
        try removeOpenVPNIPv6DefaultRoutes(tunnelName: validatedTunnelName,
                                           verifyRemoval: true,
                                           ownedBlockedIPv6Routes: sessionOwnedBlockedIPv6Routes(using: state))

        guard try splitTunnelPublicIPv6AvoidsTunnel(tunnelName: validatedTunnelName,
                                                    splitIPv6Routes: splitIPv6Routes) else {
            let repairedProbeSummary = try splitTunnelPublicIPv6ProbeSummary(tunnelName: validatedTunnelName,
                                                                             splitIPv6Routes: splitIPv6Routes)
            appendEventLog(note: "Split-tunnel public IPv6 still used the CWRU tunnel after repair: \(repairedProbeSummary).",
                           phase: state.phase)
            throw RouteManagerError.failedToSecureSplitTunnelIPv6Routes
        }

        return true
    }

    func splitTunnelPublicIPv6ProbeSummary(tunnelName: String,
                                           splitIPv6Routes: [CanonicalIPv6Route]) throws -> String {
        var parts: [String] = []
        for destination in Self.splitTunnelPublicIPv6ProbeDestinations {
            if splitIPv6Routes.contains(where: { IPRoute.ipv6Address(destination, isIn: $0) }) {
                parts.append("\(destination)=split")
                continue
            }
            let state = try publicIPv6RouteState(for: destination, tunnelName: tunnelName)
            parts.append("\(destination)=\(state.rawValue)")
        }
        return parts.joined(separator: ", ")
    }

    func validateActiveDefaultResolverIsolation(using state: SessionState) throws -> Bool {
        guard try activeDefaultResolverLeakState(using: state).needsRepair else {
            return false
        }

        appendEventLog(note: "Split-tunnel privacy check restored the active default DNS resolver.",
                       phase: state.phase)
        try restoreDNSConfiguration(using: state)
        try flushDNS()

        let postRepairLeak = try waitForActiveDefaultResolverLeakState(using: state)
        guard !postRepairLeak.needsRepair else {
            throw RouteManagerError.failedToIsolateSplitTunnelDNS
        }

        return true
    }

    func cleanupPhysicalIPv6LooksHealthy(using state: SessionState) throws -> Bool {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return true
        }

        return normalizedIPv6Mode(try ipv6Mode(forServiceNamed: serviceName)) == normalizedIPv6Mode(state.originalIPv6Mode)
    }

    func ipv6HealthCheck(using state: SessionState) -> SplitTunnelHealthCheck {
        let splitIPv6Routes = cleanupSplitIPv6Routes(using: state)
        if !splitIPv6Routes.isEmpty,
           !(state.vpnIPv6.map(SplitTunnelPolicy.isValidIPv6Address) ?? false) {
            return SplitTunnelHealthCheck(status: .fail,
                                          name: "ipv6",
                                          detail: "the fixed split IPv6 policy requires a tunnel IPv6 address")
        }

        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return SplitTunnelHealthCheck(status: .warn,
                                          name: "ipv6",
                                          detail: "physical network service is unknown")
        }

        do {
            let currentRawMode = try ipv6Mode(forServiceNamed: serviceName,
                                              requirePrivileges: false)
            let currentMode = normalizedIPv6Mode(currentRawMode)
            if currentMode == "off" {
                if !splitIPv6Routes.isEmpty {
                    return SplitTunnelHealthCheck(status: .pass,
                                                  name: "ipv6",
                                                  detail: "physical IPv6 is off; split IPv6 is constrained to split routes")
                }
                return SplitTunnelHealthCheck(status: .pass,
                                              name: "ipv6",
                                              detail: "physical IPv6 is off")
            }
            if let tunnelName = state.tunName,
               let validatedTunnelName = try? validatedTunnelInterfaceName(tunnelName),
               try splitTunnelPublicIPv6AvoidsTunnel(tunnelName: validatedTunnelName,
                                                     splitIPv6Routes: splitIPv6Routes.compactMap(IPRoute.canonicalIPv6)) {
                return SplitTunnelHealthCheck(status: .pass,
                                              name: "ipv6",
                                              detail: "public IPv6 avoids the CWRU tunnel")
            }
            return SplitTunnelHealthCheck(status: .fail,
                                          name: "ipv6",
                                          detail: "public IPv6 uses the CWRU tunnel; physical IPv6 is \(currentMode ?? currentRawMode ?? "unknown")")
        } catch {
            return SplitTunnelHealthCheck(status: .warn,
                                          name: "ipv6",
                                          detail: "could not inspect physical IPv6: \(error.localizedDescription)")
        }
    }

    func cwruRouteCoverageHealthCheck(using state: SessionState) -> SplitTunnelHealthCheck? {
        let splitIPv4Routes = cleanupSplitIPv4Routes(using: state).compactMap(IPRoute.canonicalIPv4)
        let missingFixedIPv4Routes = SplitTunnelPolicy.fixedIPv4Routes.filter { route in
            guard let fixedRoute = IPRoute.canonicalIPv4(route) else {
                return false
            }
            return !splitIPv4Routes.contains { splitRoute in
                IPRoute.ipv4Route(splitRoute, contains: fixedRoute)
            }
        }
        let missingFixedIPv6Routes: [String]
        if state.vpnIPv6.map(SplitTunnelPolicy.isValidIPv6Address) ?? false {
            let splitIPv6Routes = cleanupSplitIPv6Routes(using: state).compactMap(IPRoute.canonicalIPv6)
            missingFixedIPv6Routes = SplitTunnelPolicy.fixedIPv6Routes.filter { route in
                guard let fixedRoute = IPRoute.canonicalIPv6(route) else {
                    return false
                }
                return !splitIPv6Routes.contains { splitRoute in
                    IPRoute.ipv6Route(splitRoute, contains: fixedRoute)
                }
            }
        } else {
            missingFixedIPv6Routes = []
        }
        let missingFixedRoutes = missingFixedIPv4Routes + missingFixedIPv6Routes

        guard !missingFixedRoutes.isEmpty else {
            return nil
        }

        return SplitTunnelHealthCheck(
            status: .warn,
            name: "cwru-routes",
            detail: "fixed CWRU routes missing: \(missingFixedRoutes.joined(separator: ", "))"
        )
    }

    func firstNonEmptyList<T>(_ candidates: [T]?...) -> [T] {
        for candidate in candidates {
            if let candidate, !candidate.isEmpty {
                return candidate
            }
        }

        return []
    }

    func cleanupDefaultRouteLooksHealthy(using state: SessionState) throws -> Bool {
        let defaultRoute = try shell.run("/sbin/route", arguments: ["-n", "get", "default"], allowNonZero: true)
        let parsed = parseGatewayAndInterface(defaultRoute.stdout)
        guard let currentInterface = parsed.interfaceName else {
            return !physicalGatewayIsOnLink(state.physicalGateway)
        }

        return !SplitTunnelPolicy.isVirtualInterfaceName(currentInterface)
    }

    func physicalGatewayIsOnLink(_ gateway: String) -> Bool {
        guard SplitTunnelPolicy.isValidIPv4Address(gateway),
              let probe = try? shell.run("/sbin/route",
                                         arguments: ["-n", "get", gateway],
                                         allowNonZero: true) else {
            return false
        }
        let parsed = parseGatewayAndInterface(probe.stdout)
        guard let probeInterface = parsed.interfaceName,
              !SplitTunnelPolicy.isVirtualInterfaceName(probeInterface) else {
            return false
        }
        guard let resolvedGateway = parsed.gateway,
              SplitTunnelPolicy.isValidIPv4Address(resolvedGateway) else {
            return true
        }
        return resolvedGateway == gateway
    }

    func interfaceHasIPv4Address(_ interfaceName: String) -> Bool {
        guard let output = physicalInterfaceConfigurationOutput(interfaceName) else {
            return false
        }
        return output.split(separator: "\n").contains {
            $0.trimmingCharacters(in: .whitespaces).hasPrefix("inet ")
        }
    }

    func replacedRemoteHostRouteIsRestorable(_ route: ManagedIPv4Route) -> Bool {
        switch route.nextHopKind {
        case .gateway:
            return physicalGatewayIsOnLink(route.nextHopValue)
        case .interface:
            return interfaceHasIPv4Address(route.nextHopValue)
        }
    }

    func physicalDefaultRouteIsPresent() -> Bool {
        guard let defaultRoute = try? shell.run("/sbin/route",
                                                arguments: ["-n", "get", "default"],
                                                allowNonZero: true) else {
            return false
        }
        return parseGatewayAndInterface(defaultRoute.stdout).interfaceName != nil
    }

    func cleanupManagedDefaultRoutesRemoved(using state: SessionState) throws -> Bool {
        let ipv4Entries = try routingTableEntries()
        let managedIPv4Routes = (state.managedSplitDefaultRoutes ?? []) + (state.fullTunnelDefaultRoutes ?? [])
        for route in managedIPv4Routes {
            if ipv4RouteExists(route, in: ipv4Entries) {
                return false
            }
        }
        if let tunnelName = state.tunName,
           SplitTunnelPolicy.isSafeInterfaceName(tunnelName),
           tunnelIPv4DefaultHalfRouteExists(on: tunnelName, in: ipv4Entries) {
            return false
        }
        let ipv6Entries = try ipv6RoutingTableEntries()
        for route in state.managedIPv6Routes ?? [] {
            if ipv6RouteExists(route, in: ipv6Entries) {
                return false
            }
        }
        if openVPNBlockedIPv6RoutesPresent(sessionOwnedBlockedIPv6Routes(using: state),
                                           in: ipv6Entries) {
            return false
        }
        if let tunnelName = state.tunName,
           SplitTunnelPolicy.isSafeInterfaceName(tunnelName) {
            for destination in Self.fullTunnelIPv6DefaultRoutes
            where ipv6RouteExists(ManagedIPv6Route(destination: destination, viaInterface: tunnelName), in: ipv6Entries) {
                return false
            }
        }

        return true
    }

    func tunnelIPv4DefaultHalfRouteExists(on tunnelName: String,
                                          in entries: [RouteEntry]) -> Bool {
        let defaultHalves = ["0.0.0.0/1", "128.0.0.0/1"].compactMap(IPRoute.canonicalIPv4)
        return entries.contains { entry in
            guard entry.interfaceName == tunnelName,
                  let destination = IPRoute.canonicalIPv4(entry.destination) else {
                return false
            }
            return defaultHalves.contains(destination)
        }
    }

    func cleanupSplitIPv4RoutesRemoved(using state: SessionState,
                                       in entries: [RouteEntry]) -> Bool {
        guard let tunnelName = state.tunName else {
            return cleanupSplitIPv4Routes(using: state).isEmpty
        }
        for route in cleanupSplitIPv4Routes(using: state) {
            guard let canonicalRoute = IPRoute.canonicalIPv4(route) else {
                continue
            }

            let routeStillPresent = entries.contains { entry in
                guard let entryRoute = IPRoute.canonicalIPv4(entry.destination) else {
                    return false
                }
                return entryRoute == canonicalRoute && entry.interfaceName == tunnelName
            }

            if routeStillPresent {
                return false
            }
        }

        return true
    }

    func cleanupSplitIPv6RoutesRemoved(using state: SessionState) throws -> Bool {
        let cleanupRoutes = cleanupSplitIPv6Routes(using: state)
        guard !cleanupRoutes.isEmpty else {
            return true
        }
        guard let tunnelName = state.tunName else {
            return false
        }

        let entries = try ipv6RoutingTableEntries()
        for route in cleanupRoutes {
            guard let canonicalRoute = IPRoute.canonicalIPv6(route) else {
                continue
            }

            let routeStillPresent = entries.contains { entry in
                guard let entryRoute = IPRoute.canonicalIPv6(entry.destination) else {
                    return false
                }
                return entryRoute == canonicalRoute && entry.interfaceName == tunnelName
            }

            if routeStillPresent {
                return false
            }
        }

        return true
    }

    func cleanupRemoteHostRoutesRemoved(using state: SessionState,
                                                in entries: [RouteEntry]) -> Bool {
        (state.managedRemoteIPv4Routes ?? []).allSatisfy {
            !ownedManagedIPv4RouteExists($0, in: entries, requiresHostFlag: true)
        }
    }

    func cleanupReplacedRemoteHostRoutesRestored(using state: SessionState,
                                                  in entries: [RouteEntry]) -> Bool {
        (state.replacedRemoteIPv4Routes ?? []).allSatisfy {
            ownedManagedIPv4RouteExists($0, in: entries, requiresHostFlag: true)
                || !replacedRemoteHostRouteIsRestorable($0)
        }
    }

    func performCleanupAttempt(using state: SessionState,
                               errors: inout [Error]) {
        let tunnelName = state.tunName.flatMap { try? validatedTunnelInterfaceName($0) }
        for route in cleanupSplitIPv4Routes(using: state) {
            do {
                if let tunnelName {
                    try deleteManagedIPv4RouteIfPresent(ManagedIPv4Route(destination: route, viaInterface: tunnelName))
                }
            } catch {
                errors.append(error)
            }
        }

        for route in cleanupSplitIPv6Routes(using: state) {
            do {
                if let tunnelName {
                    try deleteIPv6RouteIfPresent(route, interfaceName: tunnelName)
                }
            } catch {
                errors.append(error)
            }
        }

        for route in state.managedIPv6Routes ?? [] {
            do {
                try deleteManagedIPv6RouteIfPresent(route)
            } catch {
                errors.append(error)
            }
        }

        do {
            try removeOpenVPNDefaultRoutes(tunnelName: state.tunName,
                                           verifyRemoval: false,
                                           ownedBlockedIPv6Routes: sessionOwnedBlockedIPv6Routes(using: state))
        } catch {
            errors.append(error)
        }

        for route in state.managedSplitDefaultRoutes ?? [] {
            do {
                try deleteManagedIPv4RouteIfPresent(route)
            } catch {
                errors.append(error)
            }
        }

        for route in state.fullTunnelDefaultRoutes ?? [] {
            do {
                try deleteManagedIPv4RouteIfPresent(route)
            } catch {
                errors.append(error)
            }
        }

        var removedRemoteRoutes: [ManagedIPv4Route] = []
        for route in state.managedRemoteIPv4Routes ?? [] {
            do {
                try deleteManagedIPv4RouteIfPresent(route, requiresHostFlag: true)
                removedRemoteRoutes.append(route)
            } catch {
                errors.append(error)
            }
        }
        do {
            try remoteHostRouteLedger.removeRoutes(removedRemoteRoutes)
        } catch {
            errors.append(error)
        }

        for route in state.replacedRemoteIPv4Routes ?? [] {
            do {
                try restoreManagedIPv4RouteIfMissing(route)
            } catch {
                errors.append(error)
            }
        }

        do {
            try restoreDefaultRouteIfNecessary(using: state)
        } catch {
            errors.append(error)
        }

        do {
            try restoreDNSConfiguration(using: state)
        } catch {
            errors.append(error)
        }

        do {
            try restorePhysicalIPv6Configuration(using: state)
        } catch {
            errors.append(error)
        }

        do {
            try removeResolverFiles(using: state)
        } catch {
            errors.append(error)
        }

        do {
            try flushDNS()
        } catch {
            errors.append(error)
        }
    }

    func restorePhysicalIPv6Configuration(using state: SessionState) throws {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return
        }

        let originalMode = normalizedIPv6Mode(state.originalIPv6Mode)
        if normalizedIPv6Mode(try ipv6Mode(forServiceNamed: serviceName)) == originalMode {
            return
        }

        switch originalMode {
        case nil:
            return
        case "automatic":
            _ = try shell.run("/usr/sbin/networksetup",
                              arguments: ["-setv6automatic", serviceName],
                              requirePrivileges: true)
        case "linklocal":
            _ = try shell.run("/usr/sbin/networksetup",
                              arguments: ["-setv6linklocal", serviceName],
                              requirePrivileges: true)
        case "off":
            _ = try shell.run("/usr/sbin/networksetup",
                              arguments: ["-setv6off", serviceName],
                              requirePrivileges: true)
        default:
            return
        }
    }

    func normalizedIPv6Mode(_ value: String?) -> String? {
        guard let value else {
            return nil
        }

        let normalized = value
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()

        switch normalized {
        case "automatic":
            return "automatic"
        case "off":
            return "off"
        case "link-local only", "link local only", "linklocal":
            return "linklocal"
        default:
            return nil
        }
    }

    func tunnelIPv6ModeIsUnsupported(_ mode: String?) -> Bool {
        guard let mode,
              !mode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return false
        }
        return normalizedIPv6Mode(mode) == nil
    }

    func ipv6Mode(forServiceNamed serviceName: String,
                          requirePrivileges: Bool = true) throws -> String? {
        let output = try shell.run("/usr/sbin/networksetup",
                                   arguments: ["-getinfo", serviceName],
                                   requirePrivileges: requirePrivileges)

        for line in output.stdout.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.hasPrefix("IPv6:") {
                return String(trimmed.dropFirst("IPv6:".count)).trimmingCharacters(in: .whitespacesAndNewlines)
            }
        }

        return nil
    }

    func activeDefaultResolverLeakState(using state: SessionState) throws -> ActiveDefaultResolverLeakState {
        let output = try shell.run("/usr/sbin/scutil", arguments: ["--dns"]).stdout

        var vpnNameServers = Set(policyDNSServers())
        vpnNameServers.formUnion(SplitTunnelPolicy.fixedDNSServers)
        vpnNameServers.formUnion((state.pushedDNSServers ?? []).filter(SplitTunnelPolicy.isValidIPAddress))
        vpnNameServers.formUnion((state.fullTunnelDNSServers ?? []).filter(SplitTunnelPolicy.isValidIPAddress))

        var vpnDomains = Set(cleanupDNSDomains(using: state).map { $0.lowercased() })
        vpnDomains.formUnion(SplitTunnelPolicy.fixedDNSDomains.map { $0.lowercased() })
        vpnDomains.formUnion((state.pushedSearchDomains ?? [])
            .filter(SplitTunnelPolicy.isValidDomainName)
            .map { $0.lowercased() })
        vpnDomains.formUnion((state.fullTunnelSearchDomains ?? [])
            .filter(SplitTunnelPolicy.isValidDomainName)
            .map { $0.lowercased() })
        guard !vpnNameServers.isEmpty || !vpnDomains.isEmpty else {
            return ActiveDefaultResolverLeakState()
        }

        let baselineSearchDomains = Set((state.originalDefaultSearchDomains ?? [])
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })

        var leakState = ActiveDefaultResolverLeakState()
        for resolver in parseActiveDNSResolvers(output) where resolver.domain == nil {
            if resolver.nameServers.contains(where: { vpnNameServers.contains($0) }) {
                leakState.usesVPNNameServers = true
            }
            if resolver.searchDomains.contains(where: { domain in
                let normalizedDomain = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                return !baselineSearchDomains.contains(normalizedDomain)
                    && (vpnDomains.contains(normalizedDomain)
                        || SplitTunnelPolicy.isCWRUDomain(normalizedDomain))
            }) {
                leakState.overlapsVPNSearchDomains = true
            }
            if leakState.usesVPNNameServers, leakState.overlapsVPNSearchDomains {
                break
            }
        }

        return leakState
    }

    func waitForActiveDefaultResolverLeakState(using state: SessionState) throws -> ActiveDefaultResolverLeakState {
        let deadline = Date().addingTimeInterval(2.0)
        var latestState = try activeDefaultResolverLeakState(using: state)

        while latestState.needsRepair, Date() < deadline {
            usleep(200_000)
            latestState = try activeDefaultResolverLeakState(using: state)
        }

        return latestState
    }

    func parseActiveDNSResolvers(_ output: String) -> [ActiveDNSResolver] {
        var resolvers: [ActiveDNSResolver] = []
        var current = ActiveDNSResolver()

        for rawLine in output.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line == "DNS configuration (for scoped queries)" {
                break
            }

            if line.hasPrefix("resolver #") {
                if current.hasContent {
                    resolvers.append(current)
                }
                current = ActiveDNSResolver()
                continue
            }

            if line.hasPrefix("domain") {
                if let value = valueAfterColon(in: line),
                   !value.isEmpty {
                    current.domain = value
                }
                continue
            }

            if line.hasPrefix("search domain[") {
                if let value = valueAfterColon(in: line),
                   !value.isEmpty {
                    current.searchDomains.append(value)
                }
                continue
            }

            if line.hasPrefix("nameserver[") {
                if let value = valueAfterColon(in: line),
                   !value.isEmpty {
                    current.nameServers.append(value)
                }
            }
        }

        if current.hasContent {
            resolvers.append(current)
        }

        return resolvers
    }

    func valueAfterColon(in line: String) -> String? {
        line.split(separator: ":", maxSplits: 1)
            .last?
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

}

struct RouteEntry {
    let destination: String
    let gateway: String
    let flags: String
    let interfaceName: String

    var isStatic: Bool {
        flags.contains("S")
    }

    var isHost: Bool {
        if flags.contains("H") {
            return true
        }
        if let ipv4Route = IPRoute.canonicalIPv4(destination) {
            return ipv4Route.prefixLength == 32
        }
        if let ipv6Route = IPRoute.canonicalIPv6(destination) {
            return ipv6Route.prefixLength == 128
        }
        return false
    }

    var hasHostFlag: Bool {
        flags.contains("H")
    }

    var isInterfaceScoped: Bool {
        flags.contains("I")
    }

    var isKernelCacheEntry: Bool {
        !isStatic && (flags.contains("L") || flags.contains("W"))
    }

    var isLinkLayerNeighborEntry: Bool {
        isKernelCacheEntry
            && hasHostFlag
            && flags.contains("L")
            && !gateway.hasPrefix("link#")
            && !SplitTunnelPolicy.isValidIPAddress(gateway)
    }

    init?(line: Substring) {
        let fields = line.split(whereSeparator: \.isWhitespace)
        guard fields.count >= 4 else {
            return nil
        }

        let destination = String(fields[0])
        guard destination != "Routing", destination != "Destination" else {
            return nil
        }

        self.destination = destination
        self.gateway = String(fields[1])
        self.flags = String(fields[2])
        self.interfaceName = String(fields[3])
    }
}
