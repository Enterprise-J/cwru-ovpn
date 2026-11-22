import Foundation
import Darwin

extension RouteManager {
    func dnsPublicationMatchesPolicy(using state: SessionState,
                           retainingResolverDomains: [String] = []) throws -> Bool {
        let output = try commandRunner.run("/usr/sbin/scutil", arguments: ["--dns"]).stdout
        let resolvers = parseActiveDNSResolvers(output, includeScoped: true)
        guard try !activeDefaultResolverLeakState(in: resolvers, using: state).needsRepair else {
            return false
        }
        let domains = Set((appliedScopedDNSDomains(using: state)
            + CampusNetworkPolicy.fixedResolverDomains
            + Self.webAuthBootstrapResolverDomains).map { $0.lowercased() })
        let retained = Set(retainingResolverDomains.map { $0.lowercased() })
        let retainedServers = Set(normalizedDNSServers(policyDNSServers()))
        if !retained.isEmpty {
            let ordinary = resolvers.filter { $0.scope == .ordinary }
            guard Self.scopedPublicationMatches(ordinary, domains: retained, servers: retainedServers) else { return false }
        }
        let pending = Set(normalizedDNSServers(state.pendingDNSWithdrawal.servers))
        let baseline = try pending.isEmpty ? Set<String>() : physicalDNSBaseline(using: state)
        let pendingServers = pending.subtracting(baseline)
        let pendingDomains = Set(state.pendingDNSWithdrawal.searchDomains.map(Self.dnsDomainForComparison))
        var physicalDomains = Set(((state.originalSearchDomains ?? []) + (state.originalDefaultSearchDomains ?? [])).map(Self.dnsDomainForComparison))
        if !pendingDomains.isSubset(of: physicalDomains),
           resolvers.contains(where: { $0.domain != nil && !Set($0.searchDomains).isDisjoint(with: pendingDomains) }) {
            physicalDomains.formUnion(try serviceStore.dynamicDNS(serviceID: state.physicalServiceID, dhcpOnly: true).domains.map(Self.dnsDomainForComparison))
        }
        return try !resolvers.contains { resolver in
            guard let domain = resolver.domain, !resolver.nameServers.isEmpty else { return false }
            let published = Set(resolver.nameServers)
            let retainedDomain = retained.contains { domain == $0 || domain.hasSuffix("." + $0) }
            let servesRetainedPolicy = retainedDomain && resolver.port == 53 && published.isSubset(of: retainedServers)
            let hasWithdrawnSearch = !Set(resolver.searchDomains).isDisjoint(with: pendingDomains.subtracting(physicalDomains))
            guard hasWithdrawnSearch || (!servesRetainedPolicy && (domains.contains(domain) || !published.isDisjoint(with: pendingServers))) else { return false }
            return try !unmanagedResolverMatches(domain: domain, nameServers: resolver.nameServers)
        }
    }

    static func scopedPublicationMatches(_ resolvers: [ActiveDNSResolver], domains: Set<String>, servers: Set<String>) -> Bool {
        let published = Set(resolvers.filter { !$0.nameServers.isEmpty }.compactMap(\.domain))
        return domains.isSubset(of: published) && resolvers.allSatisfy { resolver in
            guard let domain = resolver.domain,
                  domains.contains(where: { domain == $0 || domain.hasSuffix("." + $0) }) else { return true }
            return resolver.port == 53 && !resolver.nameServers.isEmpty && resolver.nameServers.allSatisfy(servers.contains)
        }
    }

    func fullDNSPublicationMatches(using state: SessionState, expectedServers: [String]) throws -> Bool {
        guard let tunnel = state.tunnelName, !expectedServers.isEmpty else { return false }
        let output = try commandRunner.run("/usr/sbin/scutil", arguments: ["--dns"]).stdout
        let resolvers = parseActiveDNSResolvers(output, includeScoped: true)
        let ordinary = resolvers.filter { $0.scope == .ordinary }
        guard ordinary.contains(where: { $0.domain == nil && !$0.nameServers.isEmpty }) else { return false }
        let expected = Set(expectedServers)
        let defaults = ordinary.filter { $0.domain == nil }
        guard defaults.allSatisfy({ $0.port == 53 && !$0.nameServers.isEmpty && $0.nameServers.allSatisfy(expected.contains) }),
              Self.scopedPublicationMatches(ordinary, domains: Set(fullTunnelScopedDNSDomains()), servers: expected) else {
            return false
        }
        let published = resolvers.flatMap(\.nameServers).uniqued()
        guard try dnsServersRoutedThroughTunnel(published, tunnelName: tunnel).count == published.count else { return false }
        for resolver in resolvers where resolver.scope != .ordinary {
            guard let interface = resolver.interfaceName else { continue }
            for server in resolver.nameServers {
                let route = try routeLookup(for: server, ipv6: NetworkValidation.isValidIPv6Address(server), interfaceScope: interface)
                if let route, !route.isRejected, route.interfaceName != tunnel { return false }
            }
        }
        return true
    }

    func waitForFullDNSPublication(using state: SessionState, expectedServers: [String]) throws {
        let deadline = ContinuousClock.now + dnsPublicationTimeout
        while try !fullDNSPublicationMatches(using: state, expectedServers: expectedServers) {
            guard ContinuousClock.now < deadline else { throw RouteManagerError.failedToSecureFullTunnelDNS }
            usleep(200_000)
        }
    }

    func waitForDNSPublicationToMatchPolicy(using state: SessionState,
                                 retainingResolverDomains: [String] = []) throws -> Bool {
        let deadline = ContinuousClock.now + dnsPublicationTimeout
        while try !dnsPublicationMatchesPolicy(using: state, retainingResolverDomains: retainingResolverDomains) {
            guard ContinuousClock.now < deadline else {
                return false
            }
            usleep(200_000)
        }
        return true
    }

    @discardableResult
    func cleanup(using initial: SessionState, persist: (SessionState) throws -> Void = { _ in }) throws -> Bool {
        var state = initial
        var cleanupErrors: [Error] = []
        for _ in 0..<2 {
            let dnsWithdrawn = performCleanupAttempt(using: &state, persist: persist, errors: &cleanupErrors)
            do {
                if dnsWithdrawn, try validateCleanupState(using: state) {
                    let remaining = state.managedRemoteIPv4Routes ?? []
                    if !remaining.isEmpty {
                        try remoteHostRouteLedger.remove(entries: remaining.map {
                            RemoteHostRouteLedgerEntry(route: $0, pid: state.pid, processStartTime: state.processStartTime,
                                                       executablePath: state.executablePath)
                        })
                    }
                    return true
                }
            } catch {
                cleanupErrors.append(error)
            }
        }

        if let firstError = cleanupErrors.first {
            throw firstError
        }

        return false
    }

    func withdrawVPNDNS(using state: SessionState, restored: (ServiceMutation) throws -> Void = { _ in }) throws -> Bool {
        var firstError: Error?
        var changed = false
        do {
            changed = try restoreService(.dns, using: state, restored: restored)
        } catch {
            firstError = error
            changed = (error as? RouteManagerError)?.mayHaveMutatedDNS ?? false
        }
        do {
            changed = try !removeResolverFiles(using: state).isEmpty || changed
        } catch {
            firstError = firstError ?? error
            changed = changed || ((error as? RouteManagerError)?.mayHaveMutatedDNS ?? false)
        }
        if changed {
            do {
                try flushDNS()
            } catch {
                firstError = firstError ?? error
            }
        }
        var withdrawn = false
        do {
            withdrawn = try waitForDNSPublicationToMatchPolicy(using: state)
            if !withdrawn {
                appendEventLog(note: "VPN DNS remains published after the withdrawal deadline.",
                               phase: state.phase)
            }
        } catch {
            firstError = firstError ?? error
        }
        if let firstError {
            throw firstError
        }
        return withdrawn
    }

    private func performCleanupAttempt(using state: inout SessionState,
                                       persist: (SessionState) throws -> Void,
                                       errors: inout [Error]) -> Bool {
        func checkpoint(_ update: (inout SessionState) -> Void) throws {
            var next = state
            update(&next)
            try persist(next)
            state = next
        }
        func retireService(_ change: ServiceMutation) throws {
            try checkpoint { $0.retire(change) }
        }
        var dnsWithdrawn = false
        do {
            dnsWithdrawn = try withdrawVPNDNS(using: state, restored: retireService)
        } catch {
            errors.append(error)
        }

        for route in state.managedIPv6Routes ?? [] {
            do {
                try deleteManagedIPv6RouteIfPresent(route)
                guard !ipv6RouteExists(route, in: try ipv6RoutingTableEntries()) else { continue }
                try checkpoint { $0.managedIPv6Routes?.removeAll { $0 == route } }
            } catch {
                errors.append(error)
            }
        }

        for route in state.managedRemoteIPv4Routes ?? [] {
            do {
                try deleteManagedIPv4RouteIfPresent(route, verifyRemoval: true, requiresHostFlag: true)
                let entry = RemoteHostRouteLedgerEntry(route: route, pid: state.pid, processStartTime: state.processStartTime,
                                                       executablePath: state.executablePath)
                try remoteHostRouteLedger.remove(entries: [entry])
                try checkpoint { $0.managedRemoteIPv4Routes?.removeAll { $0 == route } }
            } catch {
                errors.append(error)
            }
        }

        for route in state.replacedRemoteIPv4Routes ?? [] {
            do {
                try restoreManagedIPv4RouteIfMissing(route)
                let routes = try ipv4RoutingTableEntries()
                guard try ownedManagedIPv4RouteExists(route, in: routes, requiresHostFlag: true) || !replacedRemoteHostRouteIsRestorable(route) else {
                    throw RouteManagerError.failedToRestoreManagedRoute(route.destination)
                }
                try checkpoint { $0.replacedRemoteIPv4Routes?.removeAll { $0 == route } }
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
            try restoreService(.ipv6, using: state, restored: retireService)
        } catch {
            errors.append(error)
        }
        return dnsWithdrawn
    }

    func validateCleanupState(using state: SessionState) throws -> Bool {
        let routingTable = try ipv4RoutingTableEntries()
        let ipv6RoutingTable = try ipv6RoutingTableEntries()
        return try cleanupDefaultRouteLooksHealthy(using: state)
            && cleanupManagedIPv6RoutesRemoved(using: state, in: ipv6RoutingTable)
            && cleanupPhysicalDNSLooksHealthy(using: state)
            && dnsPublicationMatchesPolicy(using: state)
            && cleanupResolversRemoved(using: state)
            && cleanupPhysicalIPv6LooksHealthy(using: state)
            && cleanupRemoteHostRoutesRemoved(using: state, in: routingTable)
            && cleanupReplacedRemoteHostRoutesRestored(using: state, in: routingTable)
    }

    func cleanupDefaultRouteLooksHealthy(using state: SessionState) throws -> Bool {
        try routeLookup(for: "default") != nil
            || !physicalGatewayIsOnLink(state.physicalGateway, on: state.physicalInterface)
    }

    func cleanupManagedIPv6RoutesRemoved(using state: SessionState, in entries: [RouteEntry]) -> Bool {
        !(state.managedIPv6Routes ?? []).contains { ipv6RouteExists($0, in: entries) }
    }

    func cleanupPhysicalDNSLooksHealthy(using state: SessionState) throws -> Bool {
        try serviceChangesRestored(.dns, using: state)
    }

    func serviceChangesRestored(_ kind: ServiceProtocol, using state: SessionState) throws -> Bool {
        try state.serviceMutations.filter { $0.kind == kind }.allSatisfy { change in
            try serviceStore.configuration(serviceID: change.serviceID, kind: kind).matches(change.original, for: kind)
        }
    }

    func cleanupResolversRemoved(using state: SessionState) throws -> Bool {
        let scan = scanManagedResolverDirectory()
        if let error = scan.directoryError {
            throw error
        }
        for domain in appliedScopedDNSDomains(using: state)
            + CampusNetworkPolicy.fixedResolverDomains
            + Self.webAuthBootstrapResolverDomains {
            if let error = scan.unreadable[domain] {
                throw error
            }
        }
        return scan.managed.isEmpty
    }

    func cleanupPhysicalIPv6LooksHealthy(using state: SessionState) throws -> Bool {
        try serviceChangesRestored(.ipv6, using: state)
    }

    func cleanupRemoteHostRoutesRemoved(using state: SessionState,
                                        in entries: [RouteEntry]) -> Bool {
        (state.managedRemoteIPv4Routes ?? []).allSatisfy {
            !ownedManagedIPv4RouteExists($0, in: entries, requiresHostFlag: true)
        }
    }

    func cleanupReplacedRemoteHostRoutesRestored(using state: SessionState,
                                                 in entries: [RouteEntry]) throws -> Bool {
        try (state.replacedRemoteIPv4Routes ?? []).allSatisfy {
            try ownedManagedIPv4RouteExists($0, in: entries, requiresHostFlag: true)
                || !replacedRemoteHostRouteIsRestorable($0)
        }
    }

    func restoreDefaultRouteIfNecessary(using state: SessionState) throws {
        let gateway = state.physicalGateway

        let routingTable = try ipv4RoutingTableEntries()
        guard !routingTable.contains(where: { $0.destination == "default" && !$0.isInterfaceScoped }) else {
            return
        }

        guard try physicalGatewayIsOnLink(gateway, on: state.physicalInterface) else {
            return
        }

        _ = try commandRunner.run("/sbin/route", arguments: ["-n", "add", "default", gateway], allowNonZero: true)
    }

    func refreshDHCPLeaseIfAvailable(using state: SessionState) {
        let interfaceName = state.physicalInterface
        guard NetworkValidation.isSafeInterfaceName(interfaceName),
              let probe = try? commandRunner.run("/usr/sbin/ipconfig",
                                                 arguments: ["getpacket", interfaceName],
                                                 allowNonZero: true),
              probe.termination == .exited(0) else {
            return
        }

        _ = try? commandRunner.run("/usr/sbin/ipconfig",
                                   arguments: ["set", interfaceName, "DHCP"],
                                   allowNonZero: true)
    }
}
