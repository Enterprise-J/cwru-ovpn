import Foundation
import Darwin

extension RouteManager {
    func prepareTransportEndpoint(_ address: String,
                                  using state: inout SessionState,
                                  persistPreparedState: (SessionState) throws -> Void) throws {
        guard NetworkValidation.isValidIPv4Address(address) else {
            throw RouteManagerError.failedToSecureControlChannel
        }
        state.transportServerIP = address
        try persistPreparedState(state)
        let mode = state.tunnelMode
        _ = try ensureRemoteHostRoutes(using: &state, mode: mode,
                                       context: "transport endpoint preparation",
                                       persistPreparedState: persistPreparedState)
        try assertControlChannelEgressesPhysically(using: state, tunnelName: state.tunnelName ?? "")
    }

    static func remoteIPv4RouteLedgerIsValid(managed: [ManagedIPv4Route],
                                             replaced: [ManagedIPv4Route]) -> Bool {
        func safeHostRoute(_ route: ManagedIPv4Route) -> Bool {
            guard let destination = IPRoute.canonicalIPv4(route.destination),
                  destination.prefixLength == 32,
                  destination.routeString == route.destination,
                  NetworkValidation.isSafeInterfaceName(route.interfaceName),
                  !NetworkValidation.isVirtualInterfaceName(route.interfaceName) else {
                return false
            }
            switch route.nextHopKind {
            case .gateway:
                return NetworkValidation.isValidIPv4Address(route.nextHopValue)
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
        try cleanupStaleLedgeredRemoteHostRoutes(excluding: Set(state.managedRemoteIPv4Routes ?? []))
        var desiredRoutes = Set<ManagedIPv4Route>()
        let gateway = state.physicalGateway
        let interfaceName = state.physicalInterface
        if NetworkValidation.isValidIPv4Address(gateway), NetworkValidation.isSafeInterfaceName(interfaceName) {
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
            let restoredEntries = try ipv4RoutingTableEntries()
            if let missingRoute = try routesToRestore.first(where: {
                try !ownedManagedIPv4RouteExists($0, in: restoredEntries, requiresHostFlag: true)
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
        guard NetworkValidation.isValidIPv4Address(state.physicalGateway) else {
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
              NetworkValidation.isSafeInterfaceName(desiredRoute.interfaceName) else {
            throw RouteManagerError.failedToSecureControlChannel
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

        let matchingEntries = try ipv4RoutingTableEntries().filter {
            IPRoute.canonicalIPv4($0.destination) == destination
                && $0.interfaceName == interfaceName
                && !$0.isKernelCacheEntry
        }
        let desiredCount = desiredEntryCount(in: matchingEntries)
        guard desiredCount <= 1 else {
            throw RouteManagerError.failedToSecureControlChannel
        }
        let desiredRouteExists = desiredCount == 1
        let unsafeEntries = matchingEntries.filter { !isPreserved($0) }
        let preservedRoutes = matchingEntries.filter(isPreserved).compactMap(managedIPv4Route(from:))
        let routesToReplace = unsafeEntries.compactMap(managedIPv4Route(from:))
        guard routesToReplace.count == unsafeEntries.count,
              Set(routesToReplace).count == routesToReplace.count,
              Set(preservedRoutes.map(scopeKey)).isDisjoint(with: routesToReplace.map(scopeKey)),
              unsafeEntries.filter(\.isStatic).allSatisfy(ipv4RouteEntryIsRestorable) else {
            throw RouteManagerError.failedToSecureControlChannel
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
        guard desiredEntryCount(in: try ipv4RoutingTableEntries()) == 1 else {
            throw RouteManagerError.failedToSecureControlChannel
        }
        return true
    }

    func ipv4RouteEntryIsRestorable(_ entry: RouteEntry) -> Bool {
        guard let destination = IPRoute.canonicalIPv4(entry.destination) else {
            return false
        }
        return entry.isStatic
            && (destination.prefixLength != 32 || entry.hasHostFlag)
            && (NetworkValidation.isValidIPv4Address(entry.gateway) || entry.gateway.hasPrefix("link#"))
            && managedIPv4Route(from: entry) != nil
    }

    func assertControlChannelEgressesPhysically(using state: SessionState, tunnelName: String) throws {
        guard let serverIP = allowedRemoteServerIPv4Route(using: state)?.addressString else {
            appendEventLog(note: "Control-channel egress check failed: no valid VPN server IP is available to verify physical egress.")
            throw RouteManagerError.failedToSecureControlChannel
        }

        for (label, address) in [("VPN server", serverIP), ("physical gateway", state.physicalGateway)]
        where NetworkValidation.isValidIPv4Address(address) {
            let route = try routeLookup(for: address)
            let routeState = publicRouteState(route: route, tunnelName: tunnelName, loopbackGateway: "127.0.0.1")
            guard routeState == .physical, route?.interfaceName == state.physicalInterface else {
                appendEventLog(note: "Control-channel egress check failed: \(label) \(address) routes via \(routeState.rawValue) instead of the physical network.")
                throw RouteManagerError.failedToSecureControlChannel
            }
        }
    }

    func allowedRemoteServerIPv4Route(using state: SessionState) -> CanonicalIPv4Route? {
        guard let serverIP = state.transportServerIP ?? state.serverIP, NetworkValidation.isValidIPv4Address(serverIP) else {
            return nil
        }
        return IPRoute.canonicalIPv4("\(serverIP)/32")
    }

    func validateRemoteIPv4RouteLedger(managed: [ManagedIPv4Route], replaced: [ManagedIPv4Route]) throws {
        guard Self.remoteIPv4RouteLedgerIsValid(managed: managed, replaced: replaced) else {
            throw RouteManagerError.failedToSecureControlChannel
        }
    }
}
