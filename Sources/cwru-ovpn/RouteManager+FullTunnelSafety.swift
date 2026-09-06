import Foundation
import Darwin

extension RouteManager {
    static func remoteIPv4RouteLedgerIsValid(managed: [ManagedIPv4Route],
                                             replaced: [ManagedIPv4Route]) -> Bool {
        func safeHostRoute(_ route: ManagedIPv4Route) -> Bool {
            guard let destination = IPRoute.canonicalIPv4(route.destination),
                  destination.prefixLength == 32,
                  destination.routeString == route.destination,
                  SplitTunnelPolicy.isSafeInterfaceName(route.interfaceName),
                  !SplitTunnelPolicy.isVirtualInterfaceName(route.interfaceName) else {
                return false
            }
            switch route.nextHopKind {
            case .gateway:
                return SplitTunnelPolicy.isValidIPv4Address(route.nextHopValue)
            case .interface:
                return route.nextHopValue == route.interfaceName
            }
        }

        return managed.filter({ $0.nextHopKind == .gateway }).count <= 1
            && managed.filter({ $0.nextHopKind == .interface }).count <= 1
            && managed.allSatisfy({ safeHostRoute($0) && !$0.isInterfaceScoped })
            && replaced.allSatisfy(safeHostRoute)
            && Set(managed).isDisjoint(with: replaced)
            && Set(replaced.map { "\($0.destination)|\($0.interfaceName)|\($0.isInterfaceScoped)" }).count == replaced.count
            && Set(replaced.map { "\($0.destination)|\($0.interfaceName)" }).count <= 2
    }

    func reconcileManagedIPv6Routes(retaining desiredRoutes: Set<ManagedIPv6Route>,
                                    using state: inout SessionState,
                                    persistPreparedState: (SessionState) throws -> Void) throws {
        let staleRoutes = (state.managedIPv6Routes ?? []).filter { !desiredRoutes.contains($0) }
        for route in staleRoutes {
            try deleteManagedIPv6RouteIfPresent(route, verifyRemoval: true)
        }
        if !staleRoutes.isEmpty {
            let retainedRoutes = (state.managedIPv6Routes ?? []).filter { !staleRoutes.contains($0) }
            state.managedIPv6Routes = retainedRoutes.isEmpty ? nil : retainedRoutes
            try persistPreparedState(state)
        }
    }

    func fullTunnelIPv4LooksSafe(tunnelName: String, using state: SessionState) throws -> Bool {
        try fullTunnelIPv4DefaultRoutesAreCovered(tunnelName: tunnelName)
            && unexpectedFullTunnelPublicIPv4Routes(tunnelName: tunnelName, using: state).isEmpty
    }

    func cleanupStaleLedgeredRemoteHostRoutes(using state: SessionState) throws {
        try cleanupStaleLedgeredRemoteHostRoutes(excluding: Set(state.managedRemoteIPv4Routes ?? []))
    }

    func cleanupStaleLedgeredRemoteHostRoutes(excluding ownedRoutes: Set<ManagedIPv4Route>) throws {
        let staleEntries = try remoteHostRouteLedger.entries().filter { entry in
            !ownedRoutes.contains(entry.route) && remoteHostRouteOwnerIsDead(entry)
        }
        guard !staleEntries.isEmpty else {
            return
        }
        for entry in staleEntries {
            try deleteManagedIPv4RouteIfPresent(entry.route, verifyRemoval: true, requiresHostFlag: true)
        }
        try remoteHostRouteLedger.remove(entries: staleEntries)
        appendEventLog(note: "Removed stale VPN remote host routes left by a previous session: \(staleEntries.map(\.route.destination).joined(separator: ", ")).")
    }

    func remoteHostRouteOwnerIsDead(_ entry: RemoteHostRouteLedgerEntry) -> Bool {
        processIdentityAssessment(entry.pid,
                                  expectedExecutablePath: entry.executablePath,
                                  expectedStartTime: entry.processStartTime).indicatesStaleOwner
    }

    @discardableResult
    func reconcileManagedRemoteHostRoutes(using state: inout SessionState,
                                          mode: AppTunnelMode,
                                          persistPreparedState: (SessionState) throws -> Void) throws -> Bool {
        try cleanupStaleLedgeredRemoteHostRoutes(using: state)
        var desiredRoutes = Set<ManagedIPv4Route>()
        let gateway = state.physicalGateway
        let interfaceName = state.physicalInterface
        if SplitTunnelPolicy.isValidIPv4Address(gateway), SplitTunnelPolicy.isSafeInterfaceName(interfaceName) {
            if let serverRoute = allowedRemoteServerIPv4Route(using: state) {
                desiredRoutes.insert(ManagedIPv4Route(destination: serverRoute.routeString,
                                                      nextHopKind: .gateway,
                                                      nextHopValue: gateway,
                                                      interfaceName: interfaceName,
                                                      isInterfaceScoped: false))
            }
            if mode == .full, let gatewayRoute = IPRoute.canonicalIPv4("\(gateway)/32") {
                desiredRoutes.insert(ManagedIPv4Route(destination: gatewayRoute.routeString, viaInterface: interfaceName))
            }
        }
        let desiredDestinations = Set(desiredRoutes.map(\.destination))
        let staleRoutes = (state.managedRemoteIPv4Routes ?? []).filter { !desiredRoutes.contains($0) }
        let routesToRestore = mode == .full
            ? []
            : (state.replacedRemoteIPv4Routes ?? []).filter { !desiredDestinations.contains($0.destination) }
        guard !staleRoutes.isEmpty || !routesToRestore.isEmpty else {
            return false
        }

        for route in staleRoutes {
            try deleteManagedIPv4RouteIfPresent(route, verifyRemoval: true, requiresHostFlag: true)
        }
        try remoteHostRouteLedger.removeRoutes(staleRoutes)

        for route in routesToRestore {
            try restoreManagedIPv4RouteIfMissing(route)
        }
        if !routesToRestore.isEmpty {
            let restoredEntries = try routingTableEntries()
            if let missingRoute = routesToRestore.first(where: {
                !ownedManagedIPv4RouteExists($0, in: restoredEntries, requiresHostFlag: true)
                    && replacedRemoteHostRouteIsRestorable($0)
            }) {
                throw RouteManagerError.failedToRestoreManagedRoute(missingRoute.destination)
            }
        }

        var updatedState = state
        let retainedManagedRoutes = (state.managedRemoteIPv4Routes ?? []).filter { !staleRoutes.contains($0) }
        let retainedReplacedRoutes = (state.replacedRemoteIPv4Routes ?? []).filter { !routesToRestore.contains($0) }
        updatedState.managedRemoteIPv4Routes = retainedManagedRoutes.isEmpty ? nil : retainedManagedRoutes
        updatedState.replacedRemoteIPv4Routes = retainedReplacedRoutes.isEmpty ? nil : retainedReplacedRoutes
        try persistPreparedState(updatedState)
        state = updatedState
        return true
    }

    @discardableResult
    func ensureRemoteHostRoutes(using state: inout SessionState,
                                mode: AppTunnelMode,
                                context: String,
                                persistPreparedState: (SessionState) throws -> Void) throws -> Bool {
        guard SplitTunnelPolicy.isValidIPv4Address(state.physicalGateway) else {
            throw RouteManagerError.couldNotDeterminePhysicalGateway
        }
        var changed = try reconcileManagedRemoteHostRoutes(using: &state, mode: mode, persistPreparedState: persistPreparedState)
        if mode == .full {
            changed = try securePhysicalGatewayHostRoute(using: &state, persistPreparedState: persistPreparedState) || changed
        }
        changed = try secureRemoteServerHostRoute(using: &state, persistPreparedState: persistPreparedState) || changed
        if changed {
            appendEventLog(note: "Protected VPN remote host routes via the physical gateway after \(context).",
                           phase: state.phase)
        }
        return changed
    }

    @discardableResult
    func securePhysicalGatewayHostRoute(using state: inout SessionState,
                                        persistPreparedState: (SessionState) throws -> Void) throws -> Bool {
        guard let gatewayRoute = IPRoute.canonicalIPv4("\(state.physicalGateway)/32") else {
            throw RouteManagerError.couldNotDeterminePhysicalGateway
        }
        return try secureHostRoute(ManagedIPv4Route(destination: gatewayRoute.routeString, viaInterface: state.physicalInterface),
                                   preservedBy: { $0.isStatic && $0.gateway.hasPrefix("link#") },
                                   using: &state,
                                   persistPreparedState: persistPreparedState)
    }

    @discardableResult
    func secureRemoteServerHostRoute(using state: inout SessionState,
                                     persistPreparedState: (SessionState) throws -> Void) throws -> Bool {
        guard let serverRoute = allowedRemoteServerIPv4Route(using: state) else {
            return false
        }
        let gateway = state.physicalGateway
        let desiredRoute = ManagedIPv4Route(destination: serverRoute.routeString,
                                            nextHopKind: .gateway,
                                            nextHopValue: gateway,
                                            interfaceName: state.physicalInterface,
                                            isInterfaceScoped: false)
        return try secureHostRoute(desiredRoute,
                                   preservedBy: { $0.isHost && $0.isStatic && $0.gateway == gateway },
                                   using: &state,
                                   persistPreparedState: persistPreparedState)
    }

    private func secureHostRoute(_ desiredRoute: ManagedIPv4Route,
                                 preservedBy isPreserved: (RouteEntry) -> Bool,
                                 using state: inout SessionState,
                                 persistPreparedState: (SessionState) throws -> Void) throws -> Bool {
        guard let destination = IPRoute.canonicalIPv4(desiredRoute.destination),
              SplitTunnelPolicy.isSafeInterfaceName(desiredRoute.interfaceName) else {
            throw RouteManagerError.failedToSecureFullTunnelControlChannel
        }
        let interfaceName = desiredRoute.interfaceName
        func desiredEntryCount(in entries: [RouteEntry]) -> Int {
            entries.filter {
                IPRoute.canonicalIPv4($0.destination) == destination
                    && $0.interfaceName == interfaceName
                    && isPreserved($0)
                    && managedIPv4Route(from: $0) == desiredRoute
            }.count
        }
        func scopeKey(_ route: ManagedIPv4Route) -> String {
            "\(route.destination)|\(route.interfaceName)|\(route.isInterfaceScoped)"
        }

        let matchingEntries = try routingTableEntries().filter {
            IPRoute.canonicalIPv4($0.destination) == destination
                && $0.interfaceName == interfaceName
                && !$0.isKernelCacheEntry
        }
        let desiredCount = desiredEntryCount(in: matchingEntries)
        guard desiredCount <= 1 else {
            throw RouteManagerError.failedToSecureFullTunnelControlChannel
        }
        let desiredRouteExists = desiredCount == 1
        let unsafeEntries = matchingEntries.filter { !isPreserved($0) }
        let preservedRoutes = matchingEntries.filter(isPreserved).compactMap(managedIPv4Route(from:))
        let routesToReplace = unsafeEntries.compactMap(managedIPv4Route(from:))
        guard routesToReplace.count == unsafeEntries.count,
              Set(routesToReplace).count == routesToReplace.count,
              Set(preservedRoutes.map(scopeKey)).isDisjoint(with: routesToReplace.map(scopeKey)),
              unsafeEntries.filter(\.isStatic).allSatisfy(ipv4RouteEntryIsRestorable) else {
            throw RouteManagerError.failedToSecureFullTunnelControlChannel
        }
        if desiredRouteExists && routesToReplace.isEmpty {
            return false
        }

        let previouslyManaged = Set(state.managedRemoteIPv4Routes ?? [])
        var replacedRoutes = state.replacedRemoteIPv4Routes ?? []
        for route in unsafeEntries.filter(ipv4RouteEntryIsRestorable).compactMap(managedIPv4Route(from:))
        where !previouslyManaged.contains(route) && !replacedRoutes.contains(route) {
            replacedRoutes.append(route)
        }
        var managedRoutes = state.managedRemoteIPv4Routes ?? []
        if !desiredRouteExists && !managedRoutes.contains(desiredRoute) {
            managedRoutes.append(desiredRoute)
        }
        try validateRemoteIPv4RouteLedger(managed: managedRoutes, replaced: replacedRoutes)
        state.managedRemoteIPv4Routes = managedRoutes.isEmpty ? nil : managedRoutes
        state.replacedRemoteIPv4Routes = replacedRoutes.isEmpty ? nil : replacedRoutes
        try persistPreparedState(state)
        try remoteHostRouteLedger.recordOwnedRoutes(managedRoutes,
                                                    pid: state.pid,
                                                    processStartTime: state.processStartTime,
                                                    executablePath: state.executablePath)

        for entry in unsafeEntries {
            try deleteIPv4RouteEntryIfPresent(entry, verifyRemoval: true)
        }
        if !desiredRouteExists {
            try addIPv4Route(desiredRoute, allowNonZero: true)
        }
        guard desiredEntryCount(in: try routingTableEntries()) == 1 else {
            throw RouteManagerError.failedToSecureFullTunnelControlChannel
        }
        return true
    }

    func ipv4RouteEntryIsRestorable(_ entry: RouteEntry) -> Bool {
        guard let destination = IPRoute.canonicalIPv4(entry.destination) else {
            return false
        }
        return entry.isStatic
            && (destination.prefixLength != 32 || entry.hasHostFlag)
            && (SplitTunnelPolicy.isValidIPv4Address(entry.gateway) || entry.gateway.hasPrefix("link#"))
            && managedIPv4Route(from: entry) != nil
    }

    func assertFullTunnelControlChannelEgressesPhysically(using state: SessionState, tunnelName: String) throws {
        guard let serverIP = state.serverIP, SplitTunnelPolicy.isValidIPv4Address(serverIP) else {
            appendEventLog(note: "Full-tunnel control-channel egress check failed: no valid VPN server IP is available to verify physical egress.")
            throw RouteManagerError.failedToSecureFullTunnelControlChannel
        }

        for (label, address) in [("VPN server", serverIP), ("physical gateway", state.physicalGateway)]
        where SplitTunnelPolicy.isValidIPv4Address(address) {
            let routeState = try publicIPv4RouteState(for: address, tunnelName: tunnelName)
            guard routeState == .physical else {
                appendEventLog(note: "Full-tunnel control-channel egress check failed: \(label) \(address) routes via \(routeState.rawValue) instead of the physical network.")
                throw RouteManagerError.failedToSecureFullTunnelControlChannel
            }
        }
    }

    func fullTunnelIPv4SafetyFailureDetail(tunnelName: String, using state: SessionState) -> String {
        let coverage: String
        do {
            let entries = try routingTableEntries()
            coverage = Self.fullTunnelIPv4DefaultRoutes.map { requiredRoute in
                let interfaces = entries.compactMap { entry -> String? in
                    guard IPRoute.canonicalIPv4(entry.destination) == requiredRoute else {
                        return nil
                    }
                    let scope = entry.isInterfaceScoped ? ", scoped" : ""
                    return "\(entry.interfaceName)(\(entry.gateway)\(scope))"
                }
                return "\(requiredRoute.routeString)=\(interfaces.isEmpty ? "absent" : interfaces.joined(separator: ","))"
            }.joined(separator: ", ")
        } catch {
            coverage = "unavailable (\(error.localizedDescription))"
        }
        let unexpectedSummary: String
        do {
            let unexpectedRoutes = try unexpectedFullTunnelPublicIPv4Routes(tunnelName: tunnelName, using: state)
            unexpectedSummary = unexpectedRoutes.isEmpty ? "none" : unexpectedRoutes.joined(separator: ", ")
        } catch {
            unexpectedSummary = "unavailable (\(error.localizedDescription))"
        }
        let remoteSummary = allowedRemoteServerIPv4Route(using: state)?.routeString ?? "none"
        return "Full-tunnel IPv4 safety failed after repair: default route coverage \(coverage); unexpected routes \(unexpectedSummary); allowed remote endpoints \(remoteSummary)."
    }

    private struct PhysicalRouteContext {
        let gateway: String
        let gatewayAddress: UInt32?
        let interfaceName: String
        let connectedRoute: CanonicalIPv4Route?
        let ownAddresses: Set<UInt32>
        let serverAddress: UInt32?
        let serverRouteIsSafe: Bool
        let safeOnLinkHosts: Set<UInt32>

        func isOnLink(_ address: UInt32) -> Bool {
            ownAddresses.contains(address) || connectedRoute.map { IPRoute.ipv4Address(address, isIn: $0) } == true
        }
    }

    func unexpectedFullTunnelPublicIPv4Routes(tunnelName: String, using state: SessionState) throws -> [String] {
        let entries = try routingTableEntries()
        let gateway = state.physicalGateway
        let interfaceName = state.physicalInterface
        let addresses = physicalIPv4Addresses(interfaceName: interfaceName)
        let serverAddress = allowedRemoteServerIPv4Route(using: state)?.networkAddress
        let safeOnLinkHosts = Set(entries.compactMap { entry -> UInt32? in
            guard entry.isHost, entry.isStatic, !entry.isInterfaceScoped,
                  entry.interfaceName == interfaceName,
                  entry.gateway.hasPrefix("link#"),
                  let route = IPRoute.canonicalIPv4(entry.destination), route.prefixLength == 32 else {
                return nil
            }
            return route.networkAddress
        })
        let serverRouteIsSafe = entries.filter { entry in
            entry.isHost && entry.isStatic && !entry.isInterfaceScoped
                && entry.interfaceName == interfaceName
                && entry.gateway == gateway
                && IPRoute.canonicalIPv4(entry.destination).map { $0.prefixLength == 32 && $0.networkAddress == serverAddress } == true
        }.count == 1
        let context = PhysicalRouteContext(gateway: gateway,
                                           gatewayAddress: IPRoute.canonicalIPv4Address(gateway),
                                           interfaceName: interfaceName,
                                           connectedRoute: physicalConnectedIPv4Route(addresses: addresses, gateway: gateway),
                                           ownAddresses: Set(addresses.map(\.address)),
                                           serverAddress: serverAddress,
                                           serverRouteIsSafe: serverRouteIsSafe,
                                           safeOnLinkHosts: safeOnLinkHosts)
        return entries.compactMap { entry in
            guard entry.interfaceName != tunnelName,
                  let route = IPRoute.canonicalIPv4(entry.destination),
                  !fullTunnelPublicIPv4RouteIsAllowed(route, entry: entry, context: context) else {
                return nil
            }
            return route.routeString
        }
    }

    private func fullTunnelPublicIPv4RouteIsAllowed(_ route: CanonicalIPv4Route,
                                                    entry: RouteEntry,
                                                    context: PhysicalRouteContext) -> Bool {
        guard Self.ipv4RouteTouchesPublicUnicast(route) else {
            return true
        }
        guard route.prefixLength == 32 else {
            return route == context.connectedRoute
                && entry.interfaceName == context.interfaceName
                && entry.gateway.hasPrefix("link#")
                && entry.flags.contains("C")
                && entry.flags.contains("S")
                && !entry.flags.contains("G")
                && !entry.isInterfaceScoped
        }
        let address = route.networkAddress
        if entry.isLinkLayerNeighborEntry {
            if address == context.gatewayAddress {
                return entry.interfaceName == context.interfaceName && context.safeOnLinkHosts.contains(address)
            }
            return context.isOnLink(address)
                && (entry.interfaceName == context.interfaceName
                    || (entry.interfaceName == "lo0" && context.ownAddresses.contains(address)))
        }
        guard entry.isHost, entry.isStatic, entry.interfaceName == context.interfaceName else {
            return false
        }
        if address == context.serverAddress {
            return entry.gateway == context.gateway && (!entry.isInterfaceScoped || context.serverRouteIsSafe)
        }
        guard entry.gateway.hasPrefix("link#"), address == context.gatewayAddress || context.isOnLink(address) else {
            return false
        }
        return !entry.isInterfaceScoped || context.safeOnLinkHosts.contains(address)
    }

    func physicalIPv4Addresses(interfaceName: String) -> [(address: UInt32, prefixLength: Int)] {
        guard let output = physicalInterfaceConfigurationOutput(interfaceName) else {
            return []
        }
        return output.components(separatedBy: .newlines).compactMap { line in
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.first == "inet",
                  fields.count >= 4,
                  let netmaskIndex = fields.firstIndex(of: "netmask"),
                  fields.indices.contains(netmaskIndex + 1),
                  let address = IPRoute.canonicalIPv4Address(String(fields[1])),
                  let prefixLength = ipv4PrefixLength(fromNetmask: String(fields[netmaskIndex + 1])) else {
                return nil
            }
            return (address, prefixLength)
        }
    }

    func physicalConnectedIPv4Route(interfaceName: String, gateway: String) -> CanonicalIPv4Route? {
        physicalConnectedIPv4Route(addresses: physicalIPv4Addresses(interfaceName: interfaceName), gateway: gateway)
    }

    private func physicalConnectedIPv4Route(addresses: [(address: UInt32, prefixLength: Int)],
                                            gateway: String) -> CanonicalIPv4Route? {
        guard let gatewayAddress = IPRoute.canonicalIPv4Address(gateway) else {
            return nil
        }
        let routes = addresses.compactMap { address, prefixLength -> CanonicalIPv4Route? in
            guard prefixLength >= 16 else {
                return nil
            }
            let route = CanonicalIPv4Route(networkAddress: address & IPRoute.ipv4Mask(prefixLength: prefixLength),
                                           prefixLength: prefixLength)
            return IPRoute.ipv4Address(gatewayAddress, isIn: route) ? route : nil
        }.uniqued()
        return routes.count == 1 ? routes[0] : nil
    }

    func ipv4PrefixLength(fromNetmask netmask: String) -> Int? {
        let mask: UInt32
        if netmask.lowercased().hasPrefix("0x") {
            guard let parsed = UInt32(netmask.dropFirst(2), radix: 16) else {
                return nil
            }
            mask = parsed
        } else {
            guard let parsed = IPRoute.canonicalIPv4Address(netmask) else {
                return nil
            }
            mask = parsed
        }
        let prefixLength = mask.nonzeroBitCount
        return mask == IPRoute.ipv4Mask(prefixLength: prefixLength) ? prefixLength : nil
    }

    func allowedRemoteServerIPv4Route(using state: SessionState) -> CanonicalIPv4Route? {
        guard let serverIP = state.serverIP, SplitTunnelPolicy.isValidIPv4Address(serverIP) else {
            return nil
        }
        return IPRoute.canonicalIPv4("\(serverIP)/32")
    }

    func validateRemoteIPv4RouteLedger(managed: [ManagedIPv4Route], replaced: [ManagedIPv4Route]) throws {
        guard Self.remoteIPv4RouteLedgerIsValid(managed: managed, replaced: replaced) else {
            throw RouteManagerError.failedToSecureFullTunnelControlChannel
        }
    }

    func fullTunnelIPv4DefaultRoutesAreCovered(tunnelName: String) throws -> Bool {
        let coveredRoutes = try routingTableEntries().compactMap { entry -> CanonicalIPv4Route? in
            !entry.isInterfaceScoped && entry.interfaceName == tunnelName
                ? IPRoute.canonicalIPv4(entry.destination) : nil
        }
        return Self.fullTunnelIPv4DefaultRoutes.allSatisfy(coveredRoutes.contains)
    }

    static func ipv4RouteTouchesPublicUnicast(_ route: CanonicalIPv4Route) -> Bool {
        !nonPublicIPv4Routes.contains { IPRoute.ipv4Route($0, contains: route) }
    }

    static func ipv6RouteTouchesPublicGlobalUnicast(_ route: CanonicalIPv6Route) -> Bool {
        ipv6RoutesOverlap(route, publicGlobalIPv6Route) && !IPRoute.ipv6Route(documentationIPv6Route, contains: route)
    }

    static func ipv6RoutesOverlap(_ lhs: CanonicalIPv6Route, _ rhs: CanonicalIPv6Route) -> Bool {
        IPRoute.ipv6Route(lhs, contains: rhs) || IPRoute.ipv6Route(rhs, contains: lhs)
    }

    func assessFullTunnelIPv6Safety(tunnelName: String) -> FullTunnelIPv6SafetyAssessment {
        var inspectionError: Error?
        let probes = Self.fullTunnelIPv6ProbeDestinations.map { destination in
            do {
                return FullTunnelIPv6ProbeAssessment(destination: destination,
                                                     state: try publicIPv6RouteState(for: destination, tunnelName: tunnelName))
            } catch {
                inspectionError = inspectionError ?? error
                return FullTunnelIPv6ProbeAssessment(destination: destination, state: nil)
            }
        }

        let entries: [RouteEntry]?
        do {
            entries = try ipv6RoutingTableEntries()
        } catch {
            inspectionError = inspectionError ?? error
            entries = nil
        }

        let coverage: [String]
        let unexpectedRoutes: [String]?
        if let entries {
            coverage = (Self.fullTunnelIPv6DefaultRoutes + ["2000::/3"]).map { destination in
                let routes = entries.compactMap { entry -> String? in
                    guard let route = IPRoute.canonicalIPv6(entry.destination),
                          route == IPRoute.canonicalIPv6(destination) else {
                        return nil
                    }
                    return "\(entry.interfaceName)(\(entry.gateway))"
                }
                return "\(destination)=\(routes.isEmpty ? "absent" : routes.joined(separator: ","))"
            }
            unexpectedRoutes = unexpectedFullTunnelPublicIPv6Routes(tunnelName: tunnelName, entries: entries)
        } else {
            coverage = ["routing-table=error"]
            unexpectedRoutes = nil
        }

        return FullTunnelIPv6SafetyAssessment(probes: probes,
                                              coverage: coverage,
                                              unexpectedRoutes: unexpectedRoutes,
                                              inspectionError: inspectionError)
    }

    func stabilizedFullTunnelIPv6Safety(tunnelName: String) -> FullTunnelIPv6SafetyOutcome {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: fullTunnelIPv6SafetyTimeout)
        var consecutiveSafeAssessments = 0

        while true {
            let assessment = assessFullTunnelIPv6Safety(tunnelName: tunnelName)
            consecutiveSafeAssessments = assessment.isSafe ? consecutiveSafeAssessments + 1 : 0
            let isStable = consecutiveSafeAssessments >= Self.requiredConsecutiveFullTunnelIPv6SafetyAssessments
            if isStable || clock.now >= deadline {
                return FullTunnelIPv6SafetyOutcome(assessment: assessment,
                                                   consecutiveSafeAssessments: consecutiveSafeAssessments,
                                                   isStable: isStable)
            }
            usleep(Self.fullTunnelIPv6SafetyRetryIntervalMicroseconds)
        }
    }

    func fullTunnelIPv6SafetyFailureDetail(_ outcome: FullTunnelIPv6SafetyOutcome) -> String {
        let probes = outcome.assessment.probes.map { "\($0.destination)=\($0.state?.rawValue ?? "error")" }
        let unexpectedSummary = outcome.assessment.unexpectedRoutes.map { $0.isEmpty ? "none" : $0.joined(separator: ", ") }
            ?? "inspection error"
        return "Full-tunnel IPv6 safety did not stabilize before the deadline: probes \(probes.joined(separator: ", ")); coverage \(outcome.assessment.coverage.joined(separator: ", ")); unexpected routes \(unexpectedSummary); consecutive safe assessments \(outcome.consecutiveSafeAssessments)/\(Self.requiredConsecutiveFullTunnelIPv6SafetyAssessments)."
    }

    func splitTunnelPublicIPv6AvoidsTunnel(tunnelName: String, splitIPv6Routes: [CanonicalIPv6Route]) throws -> Bool {
        for destination in Self.splitTunnelPublicIPv6ProbeDestinations
        where !splitIPv6Routes.contains(where: { IPRoute.ipv6Address(destination, isIn: $0) }) {
            if try publicIPv6RouteState(for: destination, tunnelName: tunnelName) == .tunnel {
                return false
            }
        }
        return true
    }

    func publicIPv4RouteState(for destination: String, tunnelName: String) throws -> PublicRouteState {
        let probe = try shell.run("/sbin/route", arguments: ["-n", "get", destination], allowNonZero: true)
        guard probe.exitCode == 0 else {
            throw RouteManagerError.failedToInspectPublicIPv4Routes
        }
        return publicRouteState(probe: probe, tunnelName: tunnelName, loopbackGateway: "127.0.0.1")
    }

    func publicIPv6RouteState(for destination: String, tunnelName: String) throws -> PublicRouteState {
        let probe = try shell.run("/sbin/route", arguments: ["-n", "get", "-inet6", destination], allowNonZero: true)
        if probe.exitCode != 0 {
            let message = probe.stderr + "\n" + probe.stdout
            guard message.contains("not in table") || message.contains("Network is unreachable") else {
                throw RouteManagerError.failedToInspectPublicIPv6Routes
            }
            return .blocked
        }
        return publicRouteState(probe: probe, tunnelName: tunnelName, loopbackGateway: "::1")
    }

    private func publicRouteState(probe: ShellResult, tunnelName: String, loopbackGateway: String) -> PublicRouteState {
        let parsed = parseGatewayAndInterface(probe.stdout)
        if probe.stdout.contains("REJECT") || (parsed.interfaceName == "lo0" && parsed.gateway == loopbackGateway) {
            return .blocked
        }
        guard let interfaceName = parsed.interfaceName else {
            return .other
        }
        if interfaceName == tunnelName {
            return .tunnel
        }
        return SplitTunnelPolicy.isVirtualInterfaceName(interfaceName) ? .other : .physical
    }
}
