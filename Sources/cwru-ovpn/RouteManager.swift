import Foundation
import Darwin

struct PhysicalNetwork {
    let gateway: String
    let interfaceName: String
}

struct PhysicalServiceConfiguration {
    let serviceID: String
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
    enum Scope { case ordinary, interface, service }
    var scope = Scope.ordinary
    var port = 53
    var interfaceName: String?
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

enum TunnelHealthCheckStatus: String {
    case pass = "PASS"
    case warn = "WARN"
    case fail = "FAIL"
}

struct TunnelHealthCheck {
    let status: TunnelHealthCheckStatus
    let name: String
    let detail: String
}

enum RouteManagerError: LocalizedError {
    case couldNotDeterminePhysicalGateway
    case missingPhysicalIPv4Address(String)
    case failedToRestoreFullTunnelRoutes
    case failedToSecureFullTunnelIPv4Routes
    case failedToSecureControlChannel
    case failedToSecureFullTunnelDNS
    case failedToSecureFullTunnelIPv6Routes
    case failedToSecureSplitTunnelRoutes
    case failedToSecureSplitTunnelIPv6Routes
    case failedToIsolateSplitTunnelDNS
    case dnsMutationMayHaveOccurred(String)
    case missingPolicyDNSServers
    case refusingToReplaceUnmanagedResolverFile(String)
    case failedToInspectPublicIPv4Routes
    case failedToInspectPublicIPv6Routes
    case failedToInspectPhysicalInterface(String)
    case failedToInspectPhysicalDNS(String)
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

    var mayHaveMutatedDNS: Bool {
        if case .dnsMutationMayHaveOccurred = self {
            return true
        }
        return false
    }

    var errorDescription: String? {
        switch self {
        case .couldNotDeterminePhysicalGateway:
            return "Could not determine a non-VPN default gateway. If this Mac is offline or behind a captive portal, join the network and finish any sign-in, then retry."
        case .missingPhysicalIPv4Address(let interfaceName):
            return "The physical network interface \(interfaceName) has no IPv4 address yet."
        case .failedToRestoreFullTunnelRoutes:
            return "Failed to restore full-tunnel default routes."
        case .failedToSecureFullTunnelIPv4Routes:
            return "Failed to secure full-tunnel IPv4 traffic."
        case .failedToSecureControlChannel:
            return "The VPN control channel would route into the tunnel instead of the physical network."
        case .failedToSecureFullTunnelDNS:
            return "Could not verify that any DNS server routes through the full tunnel."
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
        case .missingPolicyDNSServers:
            return "The fixed scoped DNS policy has no DNS servers."
        case .refusingToReplaceUnmanagedResolverFile(let domain):
            return "A resolver file for '\(domain)' already exists and was not created by cwru-ovpn. Remove or back up /etc/resolver/\(domain) and reconnect."
        case .failedToInspectPublicIPv4Routes:
            return "Could not inspect public IPv4 routing safely."
        case .failedToInspectPublicIPv6Routes:
            return "Could not inspect public IPv6 routing safely."
        case .failedToInspectPhysicalInterface(let interfaceName):
            return "Could not inspect the physical network interface \(interfaceName)."
        case .failedToInspectPhysicalDNS(let detail):
            return "Could not inspect the physical DNS configuration: \(detail)"
        case .missingTunnelIPv4Address:
            return "The fixed split-tunnel IPv4 policy requires a tunnel IPv4 address."
        case .missingTunnelIPv6Address:
            return "The fixed split-tunnel IPv6 policy requires a tunnel IPv6 address."
        case .missingTunnelInterface:
            return "The VPN reported CONNECTED, but no tunnel interface was available."
        case .invalidTunnelInterface:
            return "Encountered an unexpected tunnel interface name."
        case .unsupportedPhysicalIPv6Mode(let mode):
            return "IPv6 mode \"\(mode)\" on the physical network service is not supported because it cannot be safely disabled and restored. Use Automatic, Link-local, or Off."
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
    let campusPolicy: CampusNetworkPolicy

    let dnsBootstrapServers: [String]

    let fullTunnelIPv6SafetyTimeout: Duration
    let dnsPublicationTimeout: Duration

    let serviceStore: any NetworkServiceStore

    let commandRunner: CommandRunner

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

    static let ipv4DefaultHalfRoutes = [
        "0.0.0.0/1",
        "128.0.0.0/1",
    ].compactMap(IPRoute.canonicalIPv4)

    static let ipv6DefaultHalfRoutes = ["::/1", "8000::/1"]

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

    init(campusPolicy: CampusNetworkPolicy = .fixed,
         dnsBootstrapServers: [String] = [],
         fullTunnelIPv6SafetyTimeout: Duration = .milliseconds(2500),
         dnsPublicationTimeout: Duration = .seconds(2),
         serviceStore: any NetworkServiceStore = SystemNetworkServiceStore(),
         commandRunner: CommandRunner = CommandRunner(),
         resolverDirectory: URL = ResolverPaths.directory,
         resolverFileOwnership: (userID: uid_t, groupID: gid_t) = (rootUserID, wheelGroupID),
         remoteHostRouteLedger: RemoteHostRouteLedger = RemoteHostRouteLedger(),
         eventLogDirectory: URL? = nil) {
        self.campusPolicy = campusPolicy
        self.dnsBootstrapServers = dnsBootstrapServers.filter(NetworkValidation.isValidIPAddress)
        self.fullTunnelIPv6SafetyTimeout = fullTunnelIPv6SafetyTimeout
        self.dnsPublicationTimeout = dnsPublicationTimeout
        self.serviceStore = serviceStore
        self.commandRunner = commandRunner
        self.resolverDirectory = resolverDirectory
        self.resolverFileOwnership = resolverFileOwnership
        self.remoteHostRouteLedger = remoteHostRouteLedger
        self.eventLogDirectory = eventLogDirectory?.standardizedFileURL
    }

    func appendEventLog(note: String, phase: SessionState.Phase? = nil) {
        EventLog.append(note: note, phase: phase, in: eventLogDirectory)
    }

    func detectPhysicalNetwork() throws -> PhysicalNetwork {
        if let defaultRoute = try routeLookup(for: "default"), !defaultRoute.isRejected,
           let gateway = defaultRoute.gateway,
           let network = Self.physicalNetwork(gateway: gateway, interfaceName: defaultRoute.interfaceName) {
            return network
        }

        let defaults = try ipv4RoutingTableEntries().filter { $0.destination == "default" && !$0.blocksTraffic }
        let ordinary = defaults.filter { !$0.isInterfaceScoped }
        let candidates = (ordinary.isEmpty ? defaults : ordinary).compactMap {
            Self.physicalNetwork(gateway: $0.gateway, interfaceName: $0.interfaceName)
        }
        if candidates.count == 1 { return candidates[0] }
        let active = try candidates.filter { try serviceStore.activeService(for: $0.interfaceName) != nil }
        if active.count == 1 { return active[0] }
        throw RouteManagerError.couldNotDeterminePhysicalGateway
    }

    private static func physicalNetwork(gateway: String, interfaceName: String) -> PhysicalNetwork? {
        guard NetworkValidation.isValidIPv4Address(gateway),
              NetworkValidation.isSafeInterfaceName(interfaceName),
              !NetworkValidation.isNonPhysicalUplinkInterface(interfaceName) else {
            return nil
        }
        return PhysicalNetwork(gateway: gateway, interfaceName: interfaceName)
    }

    func assertFullTunnelSupported(physicalInterface: String, ipv6Mode: String?) throws {
        if tunnelIPv6ModeIsUnsupported(ipv6Mode) {
            throw RouteManagerError.unsupportedPhysicalIPv6Mode(ipv6Mode ?? "unknown")
        }
        if try physicalInterfaceUsesCLAT(physicalInterface) {
            throw RouteManagerError.unsupportedNAT64Network
        }
    }

    func applySplitTunnel(using state: inout SessionState,
                          persistPreparedState: (SessionState) throws -> Void) throws {
        guard let tunnelName = state.tunnelName, !tunnelName.isEmpty else {
            throw RouteManagerError.missingTunnelInterface
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)

        let desiredSplitRoutes = policyIPv4Routes()
        let desiredSplitIPv6Routes = splitTunnelShouldApplyIPv6(using: state) ? policyIPv6Routes() : []
        try validateTunnelIPv4SupportIfNeeded(for: desiredSplitRoutes, using: state)

        try ensureRemoteHostRoutes(using: &state,
                                   mode: .split,
                                   context: "split-tunnel setup",
                                   persistPreparedState: persistPreparedState)
        let staleSplitRoutes = appliedSplitIPv4Routes(using: state)
        let staleSplitIPv6Routes = appliedSplitIPv6Routes(using: state)
        let staleDNSDomains = appliedScopedDNSDomains(using: state)
        let desiredDNSDomains = campusPolicy.resolverDomains(forIPv4Routes: desiredSplitRoutes,
                                                                  ipv6Routes: desiredSplitIPv6Routes)
        state.appliedSplitIPv4Routes = (staleSplitRoutes + desiredSplitRoutes).uniqued()
        state.appliedSplitIPv6Routes = (staleSplitIPv6Routes + desiredSplitIPv6Routes).uniqued()
        state.appliedScopedDNSDomains = (staleDNSDomains + desiredDNSDomains).uniqued()
        try persistPreparedState(state)

        try installManagedRoutesIfMissing(
            desiredSplitRoutes.map { ManagedIPv4Route(destination: $0, viaInterface: validatedTunnelName) }
        )
        try installManagedRoutesIfMissing(
            desiredSplitIPv6Routes.map { ManagedIPv6Route(destination: $0, viaInterface: validatedTunnelName) }
        )

        let installedResolvers = try installResolverFiles(forDomains: desiredDNSDomains, nameServers: policyDNSServers())

        func retireService(_ change: ServiceMutation) throws {
            state.retire(change)
            try persistPreparedState(state)
        }
        let restoredDNS = try restoreService(.dns, using: state, restored: retireService)
        let removedResolvers = try removeObsoleteResolverFiles(retaining: desiredDNSDomains)
        if restoredDNS || removedResolvers || installedResolvers {
            try flushDNS()
        }
        if !restoredDNS {
            _ = try repairActiveDefaultResolverIsolation(using: state)
        }
        guard try waitForDNSPublicationToMatchPolicy(using: state, retainingResolverDomains: desiredDNSDomains) else {
            throw RouteManagerError.failedToIsolateSplitTunnelDNS
        }

        try removeTunnelDefaultRoutes(tunnelName: validatedTunnelName)
        try restoreService(.ipv6, using: state, restored: retireService)
        state.pendingDNSWithdrawal.servers = []
        state.pendingDNSWithdrawal.searchDomains = []
        for route in state.managedIPv6Routes ?? [] {
            try deleteManagedIPv6RouteIfPresent(route,
                                                verifyRemoval: true)
        }
        state.managedIPv6Routes = nil
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

        state.appliedSplitIPv4Routes = desiredSplitRoutes
        state.appliedSplitIPv6Routes = desiredSplitIPv6Routes
        state.appliedScopedDNSDomains = desiredDNSDomains
        try persistPreparedState(state)

        _ = try repairSplitTunnelState(using: state)
    }

    func applyFullTunnelSafety(using state: inout SessionState,
                               persistPreparedState: (SessionState) throws -> Void) throws {
        guard let tunnelName = state.tunnelName, !tunnelName.isEmpty else {
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
        try assertControlChannelEgressesPhysically(using: state, tunnelName: validatedTunnelName)
        try installBlockedIPv6DefaultRoutes(using: &state, persistPreparedState: persistPreparedState)
        try disablePhysicalIPv6IfEnabled(using: &state, persist: persistPreparedState)
        try persistPreparedState(state)

        let ipv6Safety = stabilizedFullTunnelIPv6Safety(tunnelName: validatedTunnelName)
        guard ipv6Safety.isStable else {
            appendEventLog(note: fullTunnelIPv6SafetyFailureDetail(ipv6Safety))
            if let inspectionError = ipv6Safety.assessment.inspectionError {
                throw inspectionError
            }
            throw RouteManagerError.failedToSecureFullTunnelIPv6Routes
        }
        let expectedServers = try applyFullTunnelDNSConfiguration(using: &state, persistPreparedState: persistPreparedState)
        state.appliedScopedDNSDomains = fullTunnelScopedDNSDomains()
        try persistPreparedState(state)
        try waitForFullDNSPublication(using: state, expectedServers: expectedServers)

    }

    func switchToFullTunnel(using state: inout SessionState,
                            persistPreparedState: (SessionState) throws -> Void) throws {
        guard let tunnelName = state.tunnelName, !tunnelName.isEmpty else {
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

            try applyFullTunnelSafety(using: &state, persistPreparedState: persistPreparedState)
            if try removeObsoleteResolverFiles(retaining: appliedScopedDNSDomains(using: state)) {
                try flushDNS()
            }
        } catch {
            try? installFailClosedTunnelDefaultRoutes(tunnelName: validatedTunnelName)
            throw error
        }
    }

    func captureActiveDefaultSearchDomains() throws -> [String] {
        let output = try commandRunner.run("/usr/sbin/scutil", arguments: ["--dns"]).stdout
        return parseActiveDNSResolvers(output).filter { $0.domain == nil }.flatMap(\.searchDomains).uniqued()
    }

    func monitorFullTunnel(using state: inout SessionState,
                           persistPreparedState: @escaping (SessionState) throws -> Void) throws -> Bool {
        guard let tunnelName = state.tunnelName else {
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
        guard let tunnelName = state.tunnelName,
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
            let expected = try effectiveFullTunnelDNSServers(using: state)
            guard try fullDNSPublicationMatches(using: state, expectedServers: expected) else {
                throw RouteManagerError.failedToSecureFullTunnelDNS
            }
        case .split:
            let ipv4Table = try ipv4RoutingTableEntries()
            let ipv6Table = try ipv6RoutingTableEntries()
            guard splitTunnelRoutingIsSafe(tunnelName: tunnelName, using: state,
                                           ipv4Entries: ipv4Table, ipv6Entries: ipv6Table) else {
                throw RouteManagerError.failedToSecureSplitTunnelRoutes
            }
            guard try dnsPublicationMatchesPolicy(using: state, retainingResolverDomains: appliedScopedDNSDomains(using: state)),
                  try appliedScopedDNSDomains(using: state).allSatisfy({
                      try resolverFileStatus(for: $0, nameServers: policyDNSServers()) == .matching
                  }) else {
                throw RouteManagerError.failedToIsolateSplitTunnelDNS
            }
        }
    }

    func canDeferFullTunnelFailure(_ error: Error, using state: SessionState) -> Bool {
        guard state.tunnelMode == .full,
              let routeError = error as? RouteManagerError,
              case .failedToSecureControlChannel = routeError else {
            return false
        }
        do {
            try validateNetworkSafetyWhileSettling(using: state)
            return true
        } catch {
            return false
        }
    }

    func appliedSplitIPv4Routes(using state: SessionState) -> [String] {
        (state.appliedSplitIPv4Routes ?? [])
            .filter(NetworkValidation.isValidIPv4CIDR)
    }

    func appliedSplitIPv6Routes(using state: SessionState) -> [String] {
        (state.appliedSplitIPv6Routes ?? [])
            .filter(NetworkValidation.isValidIPv6CIDR)
    }

    func appliedScopedDNSDomains(using state: SessionState) -> [String] {
        (state.appliedScopedDNSDomains ?? []).filter {
            NetworkValidation.isValidDomainName($0)
                && ResolverPaths.isSafeDomainFileName($0)
        }
    }

    func staleManagedDNSDomains(using state: SessionState) -> [String] {
        let expectedDomains = Set(appliedScopedDNSDomains(using: state))
        return managedResolverDomainsInDirectory()
            .filter { !expectedDomains.contains($0) }
    }

    func policyIPv4Routes() -> [String] {
        campusPolicy.ipv4Routes.compactMap { IPRoute.canonicalIPv4($0)?.routeString }.uniqued()
    }

    func policyIPv6Routes() -> [String] {
        campusPolicy.ipv6Routes.compactMap { IPRoute.canonicalIPv6($0)?.routeString }.uniqued()
    }

    func policyDNSServers() -> [String] {
        campusPolicy.dnsServers
    }

    func fullTunnelScopedDNSDomains() -> [String] {
        campusPolicy.resolverDomains(forIPv4Routes: [], ipv6Routes: [])
    }

    func validateTunnelIPv6SupportIfNeeded(for routes: [String],
                                           using state: SessionState) throws {
        guard !routes.isEmpty else {
            return
        }
        guard let vpnIPv6 = state.vpnIPv6,
              NetworkValidation.isValidIPv6Address(vpnIPv6) else {
            throw RouteManagerError.missingTunnelIPv6Address
        }
    }

    func splitTunnelShouldApplyIPv6(using state: SessionState) -> Bool {
        state.vpnIPv6.map(NetworkValidation.isValidIPv6Address) ?? false
    }

    func validateTunnelIPv4SupportIfNeeded(for routes: [String],
                                           using state: SessionState) throws {
        guard !routes.isEmpty else {
            return
        }
        guard let vpnIPv4 = state.vpnIPv4,
              NetworkValidation.isValidIPv4Address(vpnIPv4) else {
            throw RouteManagerError.missingTunnelIPv4Address
        }
    }
}
