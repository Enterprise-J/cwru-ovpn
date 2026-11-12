import Foundation
import Darwin

extension RouteManager {
    func monitorSplitTunnel(using state: SessionState) throws -> Bool {
        guard let tunnelName = state.tunnelName else {
            return false
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)

        guard tunnelInterfaceIsPresent(named: validatedTunnelName) else {
            return false
        }

        _ = try repairSplitTunnelState(using: state)
        return true
    }

    func repairSplitTunnelState(using state: SessionState) throws -> Bool {
        guard let tunnelName = state.tunnelName else {
            throw RouteManagerError.missingTunnelInterface
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)
        let splitIPv4Routes = appliedSplitIPv4Routes(using: state)
        let splitIPv6Routes = appliedSplitIPv6Routes(using: state)
        try validateTunnelIPv4SupportIfNeeded(for: splitIPv4Routes, using: state)
        try validateTunnelIPv6SupportIfNeeded(for: splitIPv6Routes, using: state)

        var changed = try repairPhysicalDNS(using: state)
        changed = try repairResolverFiles(using: state) || changed
        changed = try repairActiveDefaultResolverIsolation(using: state) || changed
        guard try waitForVPNDNSWithdrawal(using: state, retainingResolverDomains: appliedDNSDomains(using: state)) else {
            throw RouteManagerError.failedToIsolateSplitTunnelDNS
        }

        let routingTable = try ipv4RoutingTableEntries()
        let ipv6RoutingTable = try ipv6RoutingTableEntries()
        let needsRepair = splitIPv4Routes.contains { !ipv4RouteExists($0, on: validatedTunnelName, in: routingTable) }
            || splitIPv6Routes.contains { !ipv6RouteExists($0, on: validatedTunnelName, in: ipv6RoutingTable) }
            || currentDefaultInterface(in: routingTable) == validatedTunnelName
            || tunnelIPv4DefaultHalfRouteExists(on: validatedTunnelName, in: routingTable)
        if needsRepair {
            try installManagedRoutesIfMissing(
                splitIPv4Routes.map { ManagedIPv4Route(destination: $0, viaInterface: validatedTunnelName) }
            )
            try installManagedRoutesIfMissing(
                splitIPv6Routes.map { ManagedIPv6Route(destination: $0, viaInterface: validatedTunnelName) }
            )
            try removeTunnelDefaultRoutes(tunnelName: validatedTunnelName)
            appendEventLog(note: "Route health check repaired split-tunnel routing drift.",
                           phase: state.phase)
            changed = true
        }

        changed = try repairSplitTunnelRouting(on: validatedTunnelName, using: state) || changed
        changed = try repairSplitTunnelPublicIPv6Leak(on: validatedTunnelName, using: state) || changed
        return changed
    }

    func repairPhysicalDNS(using state: SessionState) throws -> Bool {
        guard try restorePhysicalDNSConfigurationIfNeeded(using: state) else {
            return false
        }
        try flushDNS()
        appendEventLog(note: "Restored the physical-service DNS configuration.", phase: state.phase)
        return true
    }

    func repairResolverFiles(using state: SessionState) throws -> Bool {
        let removedStaleResolvers = try removeStaleManagedResolverFiles(using: state)
        let nameServers = policyDNSServers()
        let domains = appliedDNSDomains(using: state)
        let needsRefresh = try domains.contains { domain in
            try resolverFileStatus(for: domain, nameServers: nameServers) != .matching
        }
        if needsRefresh {
            appendEventLog(note: "Split-tunnel privacy check refreshed scoped resolver files.",
                           phase: state.phase)
            try installResolverFiles(forDomains: domains, nameServers: nameServers)
        }
        guard removedStaleResolvers || needsRefresh else {
            return false
        }
        try flushDNS()
        return true
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

    private func repairSplitTunnelRouting(on validatedTunnelName: String, using state: SessionState) throws -> Bool {
        var ipv4Entries = try ipv4RoutingTableEntries()
        var ipv6Entries = try ipv6RoutingTableEntries()
        guard protectedSplitIPv4RouteOverrides(on: validatedTunnelName, using: state, in: ipv4Entries).isEmpty,
              protectedSplitIPv6RouteOverrides(on: validatedTunnelName, using: state, in: ipv6Entries).isEmpty else {
            throw RouteManagerError.failedToSecureSplitTunnelRoutes
        }

        let unexpectedIPv4Routes = unexpectedSplitIPv4RouteEntries(on: validatedTunnelName, in: ipv4Entries)
        let unexpectedIPv6Routes = unexpectedSplitIPv6Routes(on: validatedTunnelName, using: state, in: ipv6Entries)
        if !unexpectedIPv4Routes.isEmpty || !unexpectedIPv6Routes.isEmpty {
            for route in unexpectedIPv4Routes {
                try deleteIPv4RouteEntryIfPresent(route)
            }
            for route in unexpectedIPv6Routes {
                try deleteIPv6RouteIfPresent(route, interfaceName: validatedTunnelName)
            }
            ipv4Entries = try ipv4RoutingTableEntries()
            ipv6Entries = try ipv6RoutingTableEntries()
        }
        guard splitTunnelRoutingIsSafe(tunnelName: validatedTunnelName, using: state,
                                       ipv4Entries: ipv4Entries, ipv6Entries: ipv6Entries) else {
            throw RouteManagerError.failedToSecureSplitTunnelRoutes
        }

        let removed = unexpectedIPv4Routes.map { "\($0.destination) via \($0.gateway)" } + unexpectedIPv6Routes
        guard !removed.isEmpty else {
            return false
        }
        appendEventLog(note: "Split-tunnel privacy check removed unexpected VPN routes: \(removed.joined(separator: ", ")).",
                       phase: state.phase)
        return true
    }

    func splitTunnelRoutingIsSafe(tunnelName: String, using state: SessionState,
                                  ipv4Entries: [RouteEntry], ipv6Entries: [RouteEntry]) -> Bool {
        !ipv4Entries.contains(where: { $0.destination == "default" && $0.interfaceName == tunnelName })
            && !ipv6Entries.contains(where: { $0.destination == "default" && $0.interfaceName == tunnelName })
            && appliedSplitIPv4Routes(using: state).allSatisfy({ ipv4RouteExists($0, on: tunnelName, in: ipv4Entries) })
            && appliedSplitIPv6Routes(using: state).allSatisfy({ ipv6RouteExists($0, on: tunnelName, in: ipv6Entries) })
            && protectedSplitIPv4RouteOverrides(on: tunnelName, using: state, in: ipv4Entries).isEmpty
            && protectedSplitIPv6RouteOverrides(on: tunnelName, using: state, in: ipv6Entries).isEmpty
            && unexpectedSplitIPv4RouteEntries(on: tunnelName, in: ipv4Entries).isEmpty
            && unexpectedSplitIPv6Routes(on: tunnelName, using: state, in: ipv6Entries).isEmpty
    }

    func unexpectedSplitIPv4RouteEntries(on tunnelName: String, in entries: [RouteEntry]) -> [RouteEntry] {
        entries.filter { entry in
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
                                   using state: SessionState,
                                   in entries: [RouteEntry]) -> [String] {
        entries.compactMap { entry in
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
                                          using state: SessionState,
                                          in entries: [RouteEntry]) -> [String] {
        let protectedRoutes = appliedSplitIPv4Routes(using: state).compactMap(IPRoute.canonicalIPv4)
        let controlRoute = allowedRemoteServerIPv4Route(using: state)
        return entries.compactMap { entry in
            guard entry.interfaceName != tunnelName,
                  let route = IPRoute.canonicalIPv4(entry.destination),
                  protectedRoutes.contains(where: {
                      route.prefixLength > $0.prefixLength && IPRoute.ipv4Route($0, contains: route)
                  }) else {
                return nil
            }
            if route == controlRoute, entry.isStatic,
               entry.gateway == state.physicalGateway,
               entry.interfaceName == state.physicalInterface,
               !entry.isInterfaceScoped {
                return nil
            }
            return route.routeString
        }
    }

    func protectedSplitIPv6RouteOverrides(on tunnelName: String,
                                          using state: SessionState,
                                          in entries: [RouteEntry]) -> [String] {
        let protectedRoutes = appliedSplitIPv6Routes(using: state).compactMap(IPRoute.canonicalIPv6)
        return entries.compactMap { entry in
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

    private func repairSplitTunnelPublicIPv6Leak(on validatedTunnelName: String,
                                                 using state: SessionState) throws -> Bool {
        let splitIPv6Routes = appliedSplitIPv6Routes(using: state).compactMap(IPRoute.canonicalIPv6)
        if try splitTunnelPublicIPv6AvoidsTunnel(tunnelName: validatedTunnelName,
                                                 splitIPv6Routes: splitIPv6Routes) {
            return false
        }

        let probeSummary = try splitTunnelPublicIPv6ProbeSummary(tunnelName: validatedTunnelName,
                                                                 splitIPv6Routes: splitIPv6Routes)
        appendEventLog(note: "Split-tunnel privacy check removed CWRU-tunnel public IPv6 routing: \(probeSummary).",
                       phase: state.phase)
        try removeTunnelIPv6DefaultRoutes(tunnelName: validatedTunnelName)

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

    func splitTunnelPublicIPv6AvoidsTunnel(tunnelName: String, splitIPv6Routes: [CanonicalIPv6Route]) throws -> Bool {
        for destination in Self.splitTunnelPublicIPv6ProbeDestinations
        where !splitIPv6Routes.contains(where: { IPRoute.ipv6Address(destination, isIn: $0) }) {
            if try publicIPv6RouteState(for: destination, tunnelName: tunnelName) == .tunnel {
                return false
            }
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

    func repairActiveDefaultResolverIsolation(using state: SessionState) throws -> Bool {
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

    func vpnDNSNameServers(using state: SessionState) -> Set<String> {
        var vpnNameServers = Set(policyDNSServers())
        vpnNameServers.formUnion(SplitTunnelPolicy.fixedDNSServers)
        vpnNameServers.formUnion((state.pushedDNSServers ?? []).filter(NetworkValidation.isValidIPAddress))
        vpnNameServers.formUnion((state.fullTunnelDNSServers ?? []).filter(NetworkValidation.isValidIPAddress))
        return Set(normalizedDNSServers(Array(vpnNameServers)))
    }

    func activeDefaultResolverLeakState(using state: SessionState) throws -> ActiveDefaultResolverLeakState {
        let output = try commandRunner.run("/usr/sbin/scutil", arguments: ["--dns"]).stdout
        return try activeDefaultResolverLeakState(in: parseActiveDNSResolvers(output), using: state)
    }

    func activeDefaultResolverLeakState(in resolvers: [ActiveDNSResolver],
                                        using state: SessionState) throws -> ActiveDefaultResolverLeakState {
        let vpnNameServers = try vpnDNSNameServers(using: state).subtracting(physicalDNSBaseline(using: state))

        var vpnDomains = Set(appliedDNSDomains(using: state).map { $0.lowercased() })
        vpnDomains.formUnion(SplitTunnelPolicy.fixedDNSDomains.map { $0.lowercased() })
        vpnDomains.formUnion((state.pushedSearchDomains ?? [])
            .filter(NetworkValidation.isValidDomainName)
            .map { $0.lowercased() })
        vpnDomains.formUnion((state.fullTunnelSearchDomains ?? [])
            .filter(NetworkValidation.isValidDomainName)
            .map { $0.lowercased() })
        guard !vpnNameServers.isEmpty || !vpnDomains.isEmpty else {
            return ActiveDefaultResolverLeakState()
        }

        let baselineSearchDomains = Set(((state.originalDefaultSearchDomains ?? []) + (state.originalSearchDomains ?? []))
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })

        var leakState = ActiveDefaultResolverLeakState()
        for resolver in resolvers where resolver.domain == nil {
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
        let deadline = ContinuousClock.now + dnsPublicationTimeout
        var latestState = try activeDefaultResolverLeakState(using: state)

        while latestState.needsRepair, ContinuousClock.now < deadline {
            usleep(200_000)
            latestState = try activeDefaultResolverLeakState(using: state)
        }

        return latestState
    }

    func splitTunnelHealthChecks(using state: SessionState) -> [SplitTunnelHealthCheck] {
        var checks: [SplitTunnelHealthCheck] = []
        let splitIPv4Routes = appliedSplitIPv4Routes(using: state)
        let splitIPv6Routes = appliedSplitIPv6Routes(using: state)
        let presentTunnelName = state.tunnelName
            .flatMap { try? validatedTunnelInterfaceName($0) }
            .flatMap { tunnelInterfaceIsPresent(named: $0) ? $0 : nil }

        func routeCheck(name: String,
                        family: String,
                        routes: [String],
                        table: () throws -> [RouteEntry],
                        exists: (String, String, [RouteEntry]) -> Bool,
                        overrides: (String, SessionState, [RouteEntry]) -> [String],
                        unexpected: (String, [RouteEntry]) -> [String]) -> SplitTunnelHealthCheck {
            guard let tunnelName = presentTunnelName else {
                return SplitTunnelHealthCheck(status: .fail, name: name, detail: "tunnel interface is missing")
            }
            do {
                let entries = try table()
                let unexpectedRoutes = (unexpected(tunnelName, entries) + entries.compactMap {
                    $0.destination == "default" && $0.interfaceName == tunnelName ? "default" : nil
                }).uniqued()
                guard unexpectedRoutes.isEmpty else {
                    return SplitTunnelHealthCheck(
                        status: .fail,
                        name: name,
                        detail: "unexpected VPN routes: \(unexpectedRoutes.joined(separator: ", "))")
                }
                let overriding = overrides(tunnelName, state, entries)
                guard overriding.isEmpty else {
                    return SplitTunnelHealthCheck(
                        status: .fail,
                        name: name,
                        detail: "physical routes override protected destinations: \(overriding.joined(separator: ", "))")
                }
                let missing = routes.filter { !exists($0, tunnelName, entries) }
                guard missing.isEmpty else {
                    return SplitTunnelHealthCheck(
                        status: .fail,
                        name: name,
                        detail: "missing on \(tunnelName): \(missing.joined(separator: ", "))")
                }
                return SplitTunnelHealthCheck(
                    status: .pass,
                    name: name,
                    detail: "\(routes.count) split \(family) route\(routes.count == 1 ? "" : "s") on \(tunnelName)")
            } catch {
                return SplitTunnelHealthCheck(
                    status: .warn,
                    name: name,
                    detail: "could not inspect \(family) routing table: \(error.localizedDescription)")
            }
        }

        checks.append(routeCheck(name: "routes",
                                 family: "IPv4",
                                 routes: splitIPv4Routes,
                                 table: ipv4RoutingTableEntries,
                                 exists: ipv4RouteExists,
                                 overrides: protectedSplitIPv4RouteOverrides,
                                 unexpected: { unexpectedSplitIPv4RouteEntries(on: $0, in: $1).map(\.destination) }))
        checks.append(routeCheck(name: "ipv6-routes",
                                 family: "IPv6",
                                 routes: splitIPv6Routes,
                                 table: ipv6RoutingTableEntries,
                                 exists: ipv6RouteExists,
                                 overrides: protectedSplitIPv6RouteOverrides,
                                 unexpected: { unexpectedSplitIPv6Routes(on: $0, using: state, in: $1) }))

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

    func ipv6HealthCheck(using state: SessionState) -> SplitTunnelHealthCheck {
        let splitIPv6Routes = appliedSplitIPv6Routes(using: state)
        if !splitIPv6Routes.isEmpty,
           !(state.vpnIPv6.map(NetworkValidation.isValidIPv6Address) ?? false) {
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
            let currentRawMode = try ipv6Mode(forServiceNamed: serviceName)
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
            if let tunnelName = state.tunnelName,
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
        let splitIPv4Routes = appliedSplitIPv4Routes(using: state).compactMap(IPRoute.canonicalIPv4)
        let missingFixedIPv4Routes = SplitTunnelPolicy.fixedIPv4Routes.filter { route in
            guard let fixedRoute = IPRoute.canonicalIPv4(route) else {
                return false
            }
            return !splitIPv4Routes.contains { splitRoute in
                IPRoute.ipv4Route(splitRoute, contains: fixedRoute)
            }
        }
        let missingFixedIPv6Routes: [String]
        if state.vpnIPv6.map(NetworkValidation.isValidIPv6Address) ?? false {
            let splitIPv6Routes = appliedSplitIPv6Routes(using: state).compactMap(IPRoute.canonicalIPv6)
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
}
