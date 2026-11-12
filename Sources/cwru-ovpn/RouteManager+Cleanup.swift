import Foundation
import Darwin

extension RouteManager {
    func vpnDNSIsWithdrawn(using state: SessionState,
                           retainingResolverDomains: [String] = []) throws -> Bool {
        let output = try commandRunner.run("/usr/sbin/scutil", arguments: ["--dns"]).stdout
        let resolvers = parseActiveDNSResolvers(output, includeScoped: true)
        guard try !activeDefaultResolverLeakState(in: resolvers, using: state).needsRepair else {
            return false
        }
        let domains = Set((appliedDNSDomains(using: state)
            + SplitTunnelPolicy.fixedResolverDomains
            + Self.webAuthBootstrapResolverDomains).map { $0.lowercased() })
        let retained = Set(retainingResolverDomains.map { $0.lowercased() })
        let retainedServers = Set(normalizedDNSServers(policyDNSServers()))
        if !retained.isEmpty {
            let published = Set(parseActiveDNSResolvers(output)
                .filter { !$0.nameServers.isEmpty }
                .compactMap { $0.domain?.lowercased() })
            guard retained.isSubset(of: published) else {
                return false
            }
        }
        return try !resolvers.contains { resolver in
            guard let domain = resolver.domain?.lowercased(), !resolver.nameServers.isEmpty else {
                return false
            }
            if retained.contains(domain) {
                return !resolver.nameServers.allSatisfy(retainedServers.contains)
            }
            guard domains.contains(domain) else {
                return false
            }
            return try !unmanagedResolverMatches(domain: domain, nameServers: resolver.nameServers)
        }
    }

    func waitForVPNDNSWithdrawal(using state: SessionState,
                                 retainingResolverDomains: [String] = []) throws -> Bool {
        let deadline = ContinuousClock.now + dnsPublicationTimeout
        while try !vpnDNSIsWithdrawn(using: state, retainingResolverDomains: retainingResolverDomains) {
            guard ContinuousClock.now < deadline else {
                return false
            }
            usleep(200_000)
        }
        return true
    }

    @discardableResult
    func cleanup(using state: SessionState) throws -> Bool {
        var cleanupErrors: [Error] = []
        for _ in 0..<2 {
            let dnsWithdrawn = performCleanupAttempt(using: state, errors: &cleanupErrors)
            do {
                if dnsWithdrawn, try validateCleanupState(using: state) {
                    try remoteHostRouteLedger.removeRoutes(state.managedRemoteIPv4Routes ?? [])
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

    func withdrawVPNDNS(using state: SessionState) throws -> Bool {
        var firstError: Error?
        var changed = false
        do {
            changed = try restorePhysicalDNSConfigurationIfNeeded(using: state)
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
            withdrawn = try waitForVPNDNSWithdrawal(using: state)
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

    func performCleanupAttempt(using state: SessionState,
                               errors: inout [Error]) -> Bool {
        var dnsWithdrawn = false
        do {
            dnsWithdrawn = try withdrawVPNDNS(using: state)
        } catch {
            errors.append(error)
        }

        for route in state.managedIPv6Routes ?? [] {
            do {
                try deleteManagedIPv6RouteIfPresent(route)
            } catch {
                errors.append(error)
            }
        }

        for route in state.managedRemoteIPv4Routes ?? [] {
            do {
                try deleteManagedIPv4RouteIfPresent(route, requiresHostFlag: true)
            } catch {
                errors.append(error)
            }
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
            try restorePhysicalIPv6Configuration(using: state)
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
            && vpnDNSIsWithdrawn(using: state)
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
        guard let current = try currentDNSSettings(using: state) else {
            return true
        }

        return current.dnsServers == normalizedDNSServers(state.originalDNSServers ?? [])
        && current.searchDomains == (state.originalSearchDomains ?? [])
    }

    func cleanupResolversRemoved(using state: SessionState) throws -> Bool {
        let scan = scanManagedResolverDirectory()
        if let error = scan.directoryError {
            throw error
        }
        for domain in appliedDNSDomains(using: state)
            + SplitTunnelPolicy.fixedResolverDomains
            + Self.webAuthBootstrapResolverDomains {
            if let error = scan.unreadable[domain] {
                throw error
            }
        }
        return scan.managed.isEmpty
    }

    func cleanupPhysicalIPv6LooksHealthy(using state: SessionState) throws -> Bool {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return true
        }

        return normalizedIPv6Mode(try ipv6Mode(forServiceNamed: serviceName)) == normalizedIPv6Mode(state.originalIPv6Mode)
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
              probe.exitCode == 0 else {
            return
        }

        _ = try? commandRunner.run("/usr/sbin/ipconfig",
                                   arguments: ["set", interfaceName, "DHCP"],
                                   allowNonZero: true)
    }
}
