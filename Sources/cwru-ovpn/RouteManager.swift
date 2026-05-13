import Foundation
import Darwin

struct PhysicalNetwork: Codable {
    let gateway: String
    let interfaceName: String
}

struct PhysicalDNSConfiguration: Codable {
    let serviceName: String
    let dnsServers: [String]
    let searchDomains: [String]
    let ipv6Mode: String?
}

struct CanonicalIPv4Route: Equatable {
    let networkAddress: UInt32
    let prefixLength: Int
}

struct ManagedIPv4Route: Codable, Equatable {
    enum NextHopKind: String, Codable {
        case gateway
        case interface
    }

    let destination: String
    let nextHopKind: NextHopKind
    let nextHopValue: String
}

private struct ActiveDNSResolver {
    var domain: String?
    var nameServers: [String] = []
    var searchDomains: [String] = []

    var hasContent: Bool {
        domain != nil || !nameServers.isEmpty || !searchDomains.isEmpty
    }
}

private struct ActiveDefaultResolverLeakState {
    var usesVPNNameServers = false
    var overlapsVPNSearchDomains = false

    var needsRepair: Bool {
        usesVPNNameServers || overlapsVPNSearchDomains
    }
}

enum RouteManagerError: LocalizedError {
    case couldNotDeterminePhysicalGateway
    case failedToRestoreFullTunnelRoutes
    case failedToRestoreFullTunnelIPv6Routes
    case failedToIsolateSplitTunnelDNS
    case failedToResolveIncludedHost(String)
    case invalidTunnelInterface

    var errorDescription: String? {
        switch self {
        case .couldNotDeterminePhysicalGateway:
            return "Could not determine a non-VPN default gateway."
        case .failedToRestoreFullTunnelRoutes:
            return "Failed to restore full-tunnel default routes."
        case .failedToRestoreFullTunnelIPv6Routes:
            return "Failed to secure full-tunnel IPv6 traffic."
        case .failedToIsolateSplitTunnelDNS:
            return "Split-tunnel DNS isolation could not be enforced."
        case .failedToResolveIncludedHost(let host):
            return "Could not resolve split-tunnel included host '\(host)' to an IPv4 address."
        case .invalidTunnelInterface:
            return "Encountered an unexpected tunnel interface name."
        }
    }
}

struct RouteManager {
    let configuration: AppConfig.SplitTunnelConfiguration
    private let ipv4Resolver: (String) -> Set<String>

    init(configuration: AppConfig.SplitTunnelConfiguration,
         ipv4Resolver: @escaping (String) -> Set<String> = RouteManager.defaultResolveIPv4Addresses(forHost:)) {
        self.configuration = configuration
        self.ipv4Resolver = ipv4Resolver
    }

    func detectPhysicalNetwork() throws -> PhysicalNetwork {
        let defaultRoute = try Shell.run("/sbin/route", arguments: ["-n", "get", "default"], allowNonZero: true)
        let parsed = parseGatewayAndInterface(defaultRoute.stdout)
        if let gateway = parsed.gateway,
           let interfaceName = parsed.interfaceName,
           !interfaceName.hasPrefix("utun"),
           !interfaceName.hasPrefix("ppp") {
            return PhysicalNetwork(gateway: gateway, interfaceName: interfaceName)
        }

        let table = try Shell.run("/usr/sbin/netstat", arguments: ["-nrf", "inet"])
        for line in table.stdout.split(separator: "\n") {
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.count >= 4, fields[0] == "default" else {
                continue
            }
            let gateway = String(fields[1])
            let interfaceName = String(fields.last!)
            if !interfaceName.hasPrefix("utun") && !interfaceName.hasPrefix("ppp") {
                return PhysicalNetwork(gateway: gateway, interfaceName: interfaceName)
            }
        }

        throw RouteManagerError.couldNotDeterminePhysicalGateway
    }

    func capturePhysicalDNSConfiguration(for interfaceName: String) throws -> PhysicalDNSConfiguration? {
        guard let serviceName = try serviceName(for: interfaceName) else {
            return nil
        }
        guard isSafeNetworkServiceName(serviceName) else {
            return nil
        }

        let dnsServersOutput = try Shell.run("/usr/sbin/networksetup",
                                             arguments: ["-getdnsservers", serviceName],
                                             allowNonZero: true,
                                             requirePrivileges: true)
        let searchDomainsOutput = try Shell.run("/usr/sbin/networksetup",
                                                arguments: ["-getsearchdomains", serviceName],
                                                allowNonZero: true,
                                                requirePrivileges: true)

        return PhysicalDNSConfiguration(serviceName: serviceName,
                                        dnsServers: parseNetworkSetupListOutput(dnsServersOutput.stdout),
                                        searchDomains: parseNetworkSetupListOutput(searchDomainsOutput.stdout),
                                        ipv6Mode: try ipv6Mode(forServiceNamed: serviceName))
    }

    func applySplitTunnel(using state: inout SessionState,
                          persistPreparedState: ((SessionState) throws -> Void)? = nil) throws {
        guard let gateway = state.physicalGateway,
              let tunnelName = state.tunName else {
            return
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)

        var mutatedNetwork = false

        do {
            let staleIncludedRoutes = cleanupIncludedRoutes(using: state)
            let staticIncludedRoutes = configuredIncludedRoutes()
            state.appliedIncludedRoutes = staticIncludedRoutes
            state.appliedResolverDomains = configuration.effectiveResolverDomains(forIncludedRoutes: staticIncludedRoutes)

            mutatedNetwork = true
            try removeOpenVPNDefaultRoutes(tunnelName: validatedTunnelName)
            for route in staleIncludedRoutes {
                try deleteIPv4NetRoute(route, allowNonZero: true)
            }

            try addIPv4NetRoute("0.0.0.0/1", gateway: gateway, allowNonZero: false)
            try addIPv4NetRoute("128.0.0.0/1", gateway: gateway, allowNonZero: false)
            for route in staticIncludedRoutes {
                try addIPv4NetRoute(route, interfaceName: validatedTunnelName, allowNonZero: false)
            }

            try disablePhysicalIPv6IfEnabled(using: state)
            try installResolverFiles(using: state)
            try restoreDNSConfiguration(using: state)
            try flushDNS()

            let resolvedIncludedRoutes = try resolvedIncludedRoutes()
            state.appliedIncludedRoutes = resolvedIncludedRoutes
            state.appliedResolverDomains = configuration.effectiveResolverDomains(forIncludedRoutes: resolvedIncludedRoutes)
            try installResolverFiles(using: state)
            try flushDNS()
            try persistPreparedState?(state)

            let staticRouteSet = Set(staticIncludedRoutes)
            for route in resolvedIncludedRoutes where !staticRouteSet.contains(route) {
                try addIPv4NetRoute(route, interfaceName: validatedTunnelName, allowNonZero: false)
            }

            if try validateSplitTunnelPrivacy(using: state) {
                try flushDNS()
            }

            state.appliedResolverDomains = cleanupResolverDomains(using: state)
            state.routesApplied = true
        } catch {
            if mutatedNetwork {
                state.routesApplied = false
                _ = try? cleanup(using: state)
            }
            throw error
        }
    }

    func applyFullTunnelSafety(using state: SessionState) throws {
        guard let tunnelName = state.tunName, !tunnelName.isEmpty else {
            return
        }

        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)
        if try fullTunnelIPv6LooksSafe(tunnelName: validatedTunnelName) {
            return
        }

        try disablePhysicalIPv6IfEnabled(using: state)

        guard try fullTunnelIPv6LooksSafe(tunnelName: validatedTunnelName) else {
            throw RouteManagerError.failedToRestoreFullTunnelIPv6Routes
        }
    }

    func switchToFullTunnel(using state: inout SessionState,
                            fullTunnelRoutes: [ManagedIPv4Route]) throws {
        guard let tunnelName = state.tunName, !tunnelName.isEmpty else {
            return
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)
        var splitDefaultsRemoved = false

        do {
            for route in cleanupIncludedRoutes(using: state) {
                try deleteIPv4NetRoute(route, allowNonZero: true)
            }

            // Remove split default-route overrides and route all IPv4 traffic via tunnel.
            try deleteIPv4NetRoute("0.0.0.0/1", allowNonZero: true)
            try deleteIPv4NetRoute("128.0.0.0/1", allowNonZero: true)
            splitDefaultsRemoved = true

            let routesToRestore = resolvedFullTunnelDefaultRoutes(from: fullTunnelRoutes, tunnelName: validatedTunnelName)
            for route in routesToRestore {
                switch route.nextHopKind {
                case .gateway:
                    try addIPv4NetRoute(route.destination,
                                        gateway: route.nextHopValue,
                                        allowNonZero: true)
                case .interface:
                    try addIPv4NetRoute(route.destination,
                                        interfaceName: route.nextHopValue,
                                        allowNonZero: true)
                }
            }

            if !(try fullTunnelRoutesMatch(routesToRestore)) {
                throw RouteManagerError.failedToRestoreFullTunnelRoutes
            }

            try restoreFullTunnelDNS(using: state)
            try restorePhysicalIPv6Configuration(using: state)
            try removeResolverFiles(using: state)
            try flushDNS()
            try applyFullTunnelSafety(using: state)

            state.fullTunnelDefaultRoutes = routesToRestore
            state.fullTunnelDNSServers = firstNonEmptyList(state.fullTunnelDNSServers,
                                                           state.pushedDNSServers,
                                                           state.originalDNSServers)
                .filter(AppConfig.SplitTunnelConfiguration.isValidIPAddress)
            state.fullTunnelSearchDomains = firstNonEmptyList(state.fullTunnelSearchDomains,
                                                              state.pushedSearchDomains,
                                                              state.originalSearchDomains)
                .filter(AppConfig.SplitTunnelConfiguration.isValidDomainName)
            state.routesApplied = false
        } catch {
            if splitDefaultsRemoved {
                try? installFailClosedTunnelDefaultRoutes(tunnelName: validatedTunnelName)
            }
            throw error
        }
    }

    func captureCurrentFullTunnelDefaultRoutes(tunnelName: String?) throws -> [ManagedIPv4Route] {
        let entries = try routingTableEntries()
        let destinations = ["0.0.0.0/1", "128.0.0.0/1"]
        var captured: [String: ManagedIPv4Route] = [:]

        for entry in entries {
            guard let canonical = Self.canonicalIPv4Route(entry.destination) else {
                continue
            }

            let destination: String
            if canonical.networkAddress == 0 && canonical.prefixLength == 1 {
                destination = "0.0.0.0/1"
            } else if canonical.networkAddress == 0x80000000 && canonical.prefixLength == 1 {
                destination = "128.0.0.0/1"
            } else {
                continue
            }

            if let tunnelName,
               !tunnelName.isEmpty,
               entry.interfaceName != tunnelName {
                continue
            }

            if AppConfig.SplitTunnelConfiguration.isValidIPAddress(entry.gateway) {
                captured[destination] = ManagedIPv4Route(destination: destination,
                                                         nextHopKind: .gateway,
                                                         nextHopValue: entry.gateway)
            } else if isSafeInterfaceName(entry.interfaceName) {
                captured[destination] = ManagedIPv4Route(destination: destination,
                                                         nextHopKind: .interface,
                                                         nextHopValue: entry.interfaceName)
            }
        }

        return destinations.compactMap { captured[$0] }
    }

    func captureCurrentDNSConfiguration(using state: SessionState) throws -> PhysicalDNSConfiguration? {
        try currentDNSConfiguration(using: state)
    }

    @discardableResult
    func prepareForConnection(using state: SessionState) throws -> Int {
        try removeRemoteHostRoutes(forProfilePath: state.profilePath,
                                   preferredRemoteIP: nil,
                                   resolveDNS: true)
    }

    func physicalNetworkHasChanged(comparedTo state: SessionState) -> Bool {
        guard let originalGateway = state.physicalGateway,
              let originalInterface = state.physicalInterface,
              let current = try? detectPhysicalNetwork() else {
            return false
        }

        return current.gateway != originalGateway || current.interfaceName != originalInterface
    }

    func monitorAndRepair(using state: SessionState) throws -> Bool {
        guard let tunnelName = state.tunName else {
            return false
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)

        guard tunnelInterfaceIsPresent(named: validatedTunnelName) else {
            return false
        }

        guard let gateway = state.physicalGateway else {
            return true
        }

        let routingTable = try routingTableEntries()
        var needsRepair = false
        var shouldFlushDNS = false

        for route in cleanupIncludedRoutes(using: state) {
            if !routeExists(route, on: validatedTunnelName, in: routingTable) {
                needsRepair = true
                break
            }
        }

        if currentDefaultInterface(in: routingTable)?.hasPrefix("utun") == true {
            needsRepair = true
        }

        if needsRepair {
            do {
                try removeOpenVPNDefaultRoutes(tunnelName: validatedTunnelName)
                try installSplitDefaultRoutes(gateway: gateway)
                for route in cleanupIncludedRoutes(using: state) {
                    try deleteIPv4NetRoute(route, allowNonZero: true)
                    try addIPv4NetRoute(route, interfaceName: validatedTunnelName, allowNonZero: true)
                }
            } catch {
                try? installSplitTunnelRouting(using: state,
                                               gateway: gateway,
                                               tunnelName: validatedTunnelName)
                throw error
            }
            shouldFlushDNS = true
        }

        if try validateSplitTunnelPrivacy(using: state) {
            shouldFlushDNS = true
        }
        if shouldFlushDNS {
            try flushDNS()
        }

        return true
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
        _ = try Shell.run("/usr/bin/dscacheutil", arguments: ["-flushcache"], allowNonZero: true, requirePrivileges: true)
        _ = try Shell.run("/usr/bin/killall", arguments: ["-HUP", "mDNSResponder"], allowNonZero: true, requirePrivileges: true)
    }

    private func installResolverFiles(using state: SessionState) throws {
        let nameServers = resolverNameServers(for: state)
        let resolverDomains = cleanupResolverDomains(using: state)
        guard !resolverDomains.isEmpty, !nameServers.isEmpty else {
            return
        }

        _ = try Shell.run("/bin/mkdir", arguments: ["-p", ResolverPaths.directory.path], requirePrivileges: true)

        for domain in resolverDomains {
            let resolverFile = ResolverPaths.fileURL(for: domain)
            let content = resolverContents(for: domain, nameServers: nameServers)
            if getuid() == 0 {
                try content.write(to: resolverFile, atomically: true, encoding: .utf8)
            } else {
                _ = try Shell.run("/usr/bin/tee",
                                  arguments: [resolverFile.path],
                                  input: Data(content.utf8),
                                  requirePrivileges: true)
            }
            try hardenResolverFile(at: resolverFile)
        }
    }

    private func hardenResolverFile(at resolverFile: URL) throws {
        _ = try Shell.run("/usr/sbin/chown",
                          arguments: ["root:wheel", resolverFile.path],
                          requirePrivileges: true)
        _ = try Shell.run("/bin/chmod",
                          arguments: ["0644", resolverFile.path],
                          requirePrivileges: true)
    }

    private func removeResolverFiles(using state: SessionState) throws {
        for domain in cleanupResolverDomains(using: state) {
            _ = try Shell.run("/bin/rm",
                              arguments: ["-f", ResolverPaths.fileURL(for: domain).path],
                              allowNonZero: true,
                              requirePrivileges: true)
        }
    }

    private func resolverContents(for domain: String, nameServers: [String]) -> String {
        var lines = nameServers.map { "nameserver \($0)" }
        lines.append("domain \(domain)")
        lines.append("search_order 1")
        return lines.joined(separator: "\n") + "\n"
    }

    private func resolverNameServers(for state: SessionState) -> [String] {
        let liveServers = (state.pushedDNSServers ?? []).filter(AppConfig.SplitTunnelConfiguration.isValidIPAddress)
        if !liveServers.isEmpty {
            return liveServers
        }
        return configuration.resolverNameServers.filter(AppConfig.SplitTunnelConfiguration.isValidIPAddress)
    }

    private func cleanupIncludedRoutes(using state: SessionState) -> [String] {
        let candidates = state.appliedIncludedRoutes ?? configuredIncludedRoutes()
        return candidates.filter(AppConfig.SplitTunnelConfiguration.isValidCIDR)
    }

    private func cleanupResolverDomains(using state: SessionState) -> [String] {
        let includedRoutes = cleanupIncludedRoutes(using: state)
        let candidates = state.appliedResolverDomains
            ?? configuration.effectiveResolverDomains(forIncludedRoutes: includedRoutes)
        return candidates.filter {
            AppConfig.SplitTunnelConfiguration.isValidDomainName($0)
                && ResolverPaths.isSafeDomainFileName($0)
        }
    }

    private func configuredIncludedRoutes() -> [String] {
        configuration.effectiveIncludedRoutes.filter(AppConfig.SplitTunnelConfiguration.isValidCIDR)
    }

    private func resolvedIncludedRoutes() throws -> [String] {
        var routes = configuredIncludedRoutes()
        for host in configuration.includedHostDomains {
            let addresses = ipv4Resolver(host)
                .filter(AppConfig.SplitTunnelConfiguration.isValidIPv4Address)
                .sorted()
            guard !addresses.isEmpty else {
                throw RouteManagerError.failedToResolveIncludedHost(host)
            }
            routes.append(contentsOf: addresses.map { "\($0)/32" })
        }
        return uniquePreservingOrder(routes)
            .filter(AppConfig.SplitTunnelConfiguration.isValidCIDR)
    }

    private func uniquePreservingOrder(_ values: [String]) -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for value in values {
            if seen.insert(value).inserted {
                result.append(value)
            }
        }
        return result
    }

    private func restoreDefaultRouteIfNecessary(using state: SessionState) throws {
        guard let gateway = state.physicalGateway else {
            return
        }

        let routingTable = try routingTableEntries()
        let currentDefault = routingTable.first { $0.destination == "default" }

        let currentIsTunnelOrMissing = currentDefault?.interfaceName.hasPrefix("utun") == true
            || currentDefault?.interfaceName.hasPrefix("ppp") == true
            || currentDefault == nil
        guard currentIsTunnelOrMissing else {
            return
        }

        // Only restore the captured gateway if it still resolves through a physical interface.
        let probe = try Shell.run("/sbin/route",
                                  arguments: ["-n", "get", gateway],
                                  allowNonZero: true)
        let parsedProbe = parseGatewayAndInterface(probe.stdout)
        guard let probeInterface = parsedProbe.interfaceName,
              !probeInterface.hasPrefix("utun"),
              !probeInterface.hasPrefix("ppp") else {
            return
        }

        _ = try Shell.run("/sbin/route", arguments: ["-n", "delete", "default"], allowNonZero: true, requirePrivileges: true)
        _ = try Shell.run("/sbin/route", arguments: ["-n", "add", "default", gateway], allowNonZero: true, requirePrivileges: true)
    }

    private func removeOpenVPNDefaultRoutes(tunnelName: String?) throws {
        let validatedTunnelName: String?
        if let tunnelName, !tunnelName.isEmpty {
            validatedTunnelName = try? validatedTunnelInterfaceName(tunnelName)
        } else {
            validatedTunnelName = nil
        }

        try deleteIPv4NetRoute("0.0.0.0/1", allowNonZero: true)

        var firstError: Error?
        do {
            try deleteIPv4NetRoute("128.0.0.0/1", allowNonZero: true)
        } catch {
            firstError = error
        }

        if let validatedTunnelName {
            do {
                try removeOpenVPNIPv6DefaultRoutes(tunnelName: validatedTunnelName)
            } catch {
                firstError = firstError ?? error
            }
        }

        if let firstError {
            throw firstError
        }
    }

    private func removeOpenVPNIPv6DefaultRoutes(tunnelName: String) throws {
        _ = try Shell.run("/sbin/route",
                          arguments: ["-n", "delete", "-net", "-inet6", "::", "-prefixlen", "1", "-iface", tunnelName],
                          allowNonZero: true,
                          requirePrivileges: true)
        _ = try Shell.run("/sbin/route",
                          arguments: ["-n", "delete", "-net", "-inet6", "8000::", "-prefixlen", "1", "-iface", tunnelName],
                          allowNonZero: true,
                          requirePrivileges: true)
    }

    private func tunnelInterfaceIsPresent(named tunnelName: String) -> Bool {
        guard let result = try? Shell.run("/sbin/ifconfig", arguments: [tunnelName], allowNonZero: true) else {
            return false
        }
        return result.exitCode == 0
    }

    private func currentDefaultInterface(in entries: [RouteEntry]) -> String? {
        entries.first { $0.destination == "default" }?.interfaceName
    }

    private func restoreDNSConfiguration(using state: SessionState) throws {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return
        }

        try setDNSConfiguration(serviceName: serviceName,
                                dnsServers: state.originalDNSServers ?? [],
                                searchDomains: state.originalSearchDomains ?? [])
    }

    private func restoreFullTunnelDNS(using state: SessionState) throws {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return
        }

        let dnsServers = firstNonEmptyList(state.fullTunnelDNSServers,
                                           state.pushedDNSServers,
                                           state.originalDNSServers)
            .filter(AppConfig.SplitTunnelConfiguration.isValidIPAddress)
        let searchDomains = firstNonEmptyList(state.fullTunnelSearchDomains,
                                              state.pushedSearchDomains,
                                              state.originalSearchDomains)
            .filter(AppConfig.SplitTunnelConfiguration.isValidDomainName)

        try setDNSConfiguration(serviceName: serviceName,
                                dnsServers: dnsServers,
                                searchDomains: searchDomains)
    }

    private func setDNSConfiguration(serviceName: String,
                                     dnsServers: [String],
                                     searchDomains: [String]) throws {
        let dnsArguments = networkSetupListArguments(command: "-setdnsservers",
                                                     serviceName: serviceName,
                                                     values: dnsServers)
        _ = try Shell.run("/usr/sbin/networksetup",
                          arguments: dnsArguments,
                          requirePrivileges: true)

        let searchArguments = networkSetupListArguments(command: "-setsearchdomains",
                                                        serviceName: serviceName,
                                                        values: searchDomains)
        _ = try Shell.run("/usr/sbin/networksetup",
                          arguments: searchArguments,
                          requirePrivileges: true)
    }

    private func networkSetupListArguments(command: String,
                                           serviceName: String,
                                           values: [String]) -> [String] {
        values.isEmpty ? [command, serviceName, "empty"] : [command, serviceName] + values
    }

    @discardableResult
    private func validateSplitTunnelPrivacy(using state: SessionState) throws -> Bool {
        var changed = false
        changed = try validatePhysicalDNSRestored(using: state) || changed
        changed = try validateResolverFiles(using: state) || changed
        changed = try validatePhysicalIPv6Disabled(using: state) || changed
        changed = try validateActiveDefaultResolverIsolation(using: state) || changed
        return changed
    }

    private func validateCleanupState(using state: SessionState) throws -> Bool {
        let routingTable = try routingTableEntries()
        return try cleanupDefaultRouteLooksHealthy(using: state)
            && cleanupPhysicalDNSLooksHealthy(using: state)
            && cleanupResolversRemoved(using: state)
            && cleanupPhysicalIPv6LooksHealthy(using: state)
            && cleanupIncludedRoutesRemoved(using: state, in: routingTable)
            && cleanupRemoteHostRoutesRemoved(using: state, in: routingTable)
    }

    private func validatePhysicalDNSRestored(using state: SessionState) throws -> Bool {
        guard let current = try currentDNSConfiguration(using: state) else {
            return false
        }

        let expectedDNSServers = state.originalDNSServers ?? []
        let expectedSearchDomains = state.originalSearchDomains ?? []

        if current.dnsServers != expectedDNSServers || current.searchDomains != expectedSearchDomains {
            EventLog.append(note: "Split-tunnel privacy check restored physical-service DNS configuration.",
                            phase: state.phase)
            try restoreDNSConfiguration(using: state)
            return true
        }

        return false
    }

    private func cleanupPhysicalDNSLooksHealthy(using state: SessionState) throws -> Bool {
        guard let current = try currentDNSConfiguration(using: state) else {
            return true
        }

        return current.dnsServers == (state.originalDNSServers ?? [])
        && current.searchDomains == (state.originalSearchDomains ?? [])
    }

    private func cleanupResolversRemoved(using state: SessionState) throws -> Bool {
        for domain in cleanupResolverDomains(using: state) {
            if FileManager.default.fileExists(atPath: ResolverPaths.fileURL(for: domain).path) {
                return false
            }
        }
        return true
    }

    private func validateResolverFiles(using state: SessionState) throws -> Bool {
        let nameServers = resolverNameServers(for: state)
        let resolverDomains = cleanupResolverDomains(using: state)
        guard !resolverDomains.isEmpty, !nameServers.isEmpty else {
            return false
        }

        for domain in resolverDomains {
            let path = ResolverPaths.fileURL(for: domain).path
            let expected = resolverContents(for: domain, nameServers: nameServers)
            let current = (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
            if current != expected {
                EventLog.append(note: "Split-tunnel privacy check refreshed scoped resolver files.",
                                phase: state.phase)
                try installResolverFiles(using: state)
                return true
            }
        }

        return false
    }

    private func currentDNSConfiguration(using state: SessionState) throws -> PhysicalDNSConfiguration? {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return nil
        }

        let dnsServersOutput = try Shell.run("/usr/sbin/networksetup",
                                             arguments: ["-getdnsservers", serviceName],
                                             allowNonZero: true,
                                             requirePrivileges: true)
        let searchDomainsOutput = try Shell.run("/usr/sbin/networksetup",
                                                arguments: ["-getsearchdomains", serviceName],
                                                allowNonZero: true,
                                                requirePrivileges: true)

        return PhysicalDNSConfiguration(serviceName: serviceName,
                                        dnsServers: parseNetworkSetupListOutput(dnsServersOutput.stdout),
                                        searchDomains: parseNetworkSetupListOutput(searchDomainsOutput.stdout),
                                        ipv6Mode: try ipv6Mode(forServiceNamed: serviceName))
    }

    private func disablePhysicalIPv6IfEnabled(using state: SessionState) throws {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return
        }

        let currentMode = normalizedIPv6Mode(state.originalIPv6Mode)
        if currentMode == nil || currentMode == "off" {
            return
        }

        _ = try Shell.run("/usr/sbin/networksetup",
                          arguments: ["-setv6off", serviceName],
                          requirePrivileges: true)
    }

    private func validatePhysicalIPv6Disabled(using state: SessionState) throws -> Bool {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return false
        }

        let originalMode = normalizedIPv6Mode(state.originalIPv6Mode)
        guard originalMode != nil, originalMode != "off" else {
            return false
        }

        let currentMode = normalizedIPv6Mode(try ipv6Mode(forServiceNamed: serviceName))
        if currentMode != "off" {
            EventLog.append(note: "Split-tunnel privacy check re-disabled physical-service IPv6.",
                            phase: state.phase)
            try disablePhysicalIPv6IfEnabled(using: state)
            return true
        }

        return false
    }

    private func validateActiveDefaultResolverIsolation(using state: SessionState) throws -> Bool {
        guard activeDefaultResolverLeakState(using: state).needsRepair else {
            return false
        }

        EventLog.append(note: "Split-tunnel privacy check restored the active default DNS resolver.",
                        phase: state.phase)
        try restoreDNSConfiguration(using: state)
        try flushDNS()

        let postRepairLeak = waitForActiveDefaultResolverLeakState(using: state)
        guard !postRepairLeak.usesVPNNameServers else {
            throw RouteManagerError.failedToIsolateSplitTunnelDNS
        }

        return true
    }

    private func cleanupPhysicalIPv6LooksHealthy(using state: SessionState) throws -> Bool {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return true
        }

        return normalizedIPv6Mode(try ipv6Mode(forServiceNamed: serviceName)) == normalizedIPv6Mode(state.originalIPv6Mode)
    }

    private func firstNonEmptyList<T>(_ candidates: [T]?...) -> [T] {
        for candidate in candidates {
            if let candidate, !candidate.isEmpty {
                return candidate
            }
        }

        return []
    }

    private func fullTunnelIPv6LooksSafe(tunnelName: String) throws -> Bool {
        for destination in ["2001:4860:4860::8888", "3000::1"] {
            let probe = try Shell.run("/sbin/route",
                                      arguments: ["-n", "get", "-inet6", destination],
                                      allowNonZero: true)

            if probe.exitCode != 0 {
                continue
            }

            let parsed = parseGatewayAndInterface(probe.stdout)
            if parsed.interfaceName == tunnelName {
                continue
            }

            if probe.stdout.contains("REJECT")
                || (parsed.interfaceName == "lo0" && parsed.gateway == "::1") {
                continue
            }

            if let interfaceName = parsed.interfaceName,
               !interfaceName.hasPrefix("utun"),
               !interfaceName.hasPrefix("ppp") {
                return false
            }
        }

        return true
    }

    private func cleanupDefaultRouteLooksHealthy(using state: SessionState) throws -> Bool {
        let defaultRoute = try Shell.run("/sbin/route", arguments: ["-n", "get", "default"], allowNonZero: true)
        let parsed = parseGatewayAndInterface(defaultRoute.stdout)
        guard let currentInterface = parsed.interfaceName else {
            // No default route is only healthy when we never captured one to restore.
            return state.physicalGateway == nil
        }

        // Cleanup only has to move the default route off the VPN tunnel; roaming can change the gateway.
        return !currentInterface.hasPrefix("utun") && !currentInterface.hasPrefix("ppp")
    }

    private func cleanupIncludedRoutesRemoved(using state: SessionState,
                                              in entries: [RouteEntry]) -> Bool {
        for route in cleanupIncludedRoutes(using: state) {
            guard let canonicalRoute = Self.canonicalIPv4Route(route) else {
                continue
            }

            let routeStillPresent = entries.contains { entry in
                guard let entryRoute = Self.canonicalIPv4Route(entry.destination) else {
                    return false
                }
                return entryRoute == canonicalRoute
                    && (entry.interfaceName.hasPrefix("utun") || entry.interfaceName.hasPrefix("ppp"))
            }

            if routeStillPresent {
                return false
            }
        }

        return true
    }

    private func cleanupRemoteHostRoutesRemoved(using state: SessionState,
                                                in entries: [RouteEntry]) -> Bool {
        let remoteIPs = resolveRemoteIPv4Addresses(fromProfilePath: state.profilePath,
                                                   preferredRemoteIP: state.serverIP,
                                                   resolveDNS: false)
        guard !remoteIPs.isEmpty else {
            return true
        }

        return !entries.contains { entry in
            guard let destination = normalizeHostRouteDestination(entry.destination) else {
                return false
            }
            return remoteIPs.contains(destination)
        }
    }

    private func performCleanupAttempt(using state: SessionState,
                                       errors: inout [Error]) {
        for route in cleanupIncludedRoutes(using: state) {
            do {
                try deleteIPv4NetRoute(route, allowNonZero: true)
            } catch {
                errors.append(error)
            }
        }

        do {
            try removeOpenVPNDefaultRoutes(tunnelName: state.tunName)
        } catch {
            errors.append(error)
        }

        do {
            _ = try removeRemoteHostRoutes(forProfilePath: state.profilePath,
                                           preferredRemoteIP: state.serverIP,
                                           resolveDNS: false)
        } catch {
            errors.append(error)
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

    private func restorePhysicalIPv6Configuration(using state: SessionState) throws {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return
        }

        switch normalizedIPv6Mode(state.originalIPv6Mode) {
        case nil:
            return
        case "automatic":
            _ = try Shell.run("/usr/sbin/networksetup",
                              arguments: ["-setv6automatic", serviceName],
                              requirePrivileges: true)
        case "linklocal":
            _ = try Shell.run("/usr/sbin/networksetup",
                              arguments: ["-setv6linklocal", serviceName],
                              requirePrivileges: true)
        case "off":
            _ = try Shell.run("/usr/sbin/networksetup",
                              arguments: ["-setv6off", serviceName],
                              requirePrivileges: true)
        default:
            return
        }
    }

    private func normalizedIPv6Mode(_ value: String?) -> String? {
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

    private func ipv6Mode(forServiceNamed serviceName: String) throws -> String? {
        let output = try Shell.run("/usr/sbin/networksetup",
                                   arguments: ["-getinfo", serviceName],
                                   allowNonZero: true,
                                   requirePrivileges: true)

        for line in output.stdout.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.hasPrefix("IPv6:") {
                return String(trimmed.dropFirst("IPv6:".count)).trimmingCharacters(in: .whitespacesAndNewlines)
            }
        }

        return nil
    }

    private func activeDefaultResolverLeakState(using state: SessionState) -> ActiveDefaultResolverLeakState {
        guard let output = try? Shell.run("/usr/sbin/scutil", arguments: ["--dns"], allowNonZero: true).stdout else {
            return ActiveDefaultResolverLeakState()
        }

        let vpnNameServers = Set(resolverNameServers(for: state))
        let vpnDomains = Set(cleanupResolverDomains(using: state))
        guard !vpnNameServers.isEmpty || !vpnDomains.isEmpty else {
            return ActiveDefaultResolverLeakState()
        }

        var leakState = ActiveDefaultResolverLeakState()
        for resolver in parseActiveDNSResolvers(output) where resolver.domain == nil {
            if resolver.nameServers.contains(where: { vpnNameServers.contains($0) }) {
                leakState.usesVPNNameServers = true
            }
            if resolver.searchDomains.contains(where: { vpnDomains.contains($0) }) {
                leakState.overlapsVPNSearchDomains = true
            }
            if leakState.usesVPNNameServers, leakState.overlapsVPNSearchDomains {
                break
            }
        }

        return leakState
    }

    private func waitForActiveDefaultResolverLeakState(using state: SessionState,
                                                       timeout: TimeInterval = 2.0,
                                                       pollInterval: useconds_t = 200_000) -> ActiveDefaultResolverLeakState {
        let deadline = Date().addingTimeInterval(timeout)
        var latestState = activeDefaultResolverLeakState(using: state)

        while latestState.usesVPNNameServers, Date() < deadline {
            usleep(pollInterval)
            latestState = activeDefaultResolverLeakState(using: state)
        }

        return latestState
    }

    private func parseActiveDNSResolvers(_ output: String) -> [ActiveDNSResolver] {
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

    private func valueAfterColon(in line: String) -> String? {
        line.split(separator: ":", maxSplits: 1)
            .last?
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    @discardableResult
    private func removeRemoteHostRoutes(forProfilePath profilePath: String,
                                        preferredRemoteIP: String?,
                                        resolveDNS: Bool) throws -> Int {
        let remoteIPs = resolveRemoteIPv4Addresses(fromProfilePath: profilePath,
                                                   preferredRemoteIP: preferredRemoteIP,
                                                   resolveDNS: resolveDNS)
        guard !remoteIPs.isEmpty else {
            return 0
        }

        let routingTable = try routingTableEntries()
        let destinationsToDelete = Set(
            routingTable
                .compactMap { entry -> String? in
                    guard let normalized = normalizeHostRouteDestination(entry.destination),
                          remoteIPs.contains(normalized) else {
                        return nil
                    }
                    return normalized
                }
        )

        for destination in destinationsToDelete {
            _ = try Shell.run("/sbin/route",
                              arguments: ["-n", "delete", "-host", destination],
                              allowNonZero: true,
                              requirePrivileges: true)
        }

        return destinationsToDelete.count
    }

    private func routeExists(_ configuredRoute: String, on interfaceName: String, in entries: [RouteEntry]) -> Bool {
        guard let configuredRoute = Self.canonicalIPv4Route(configuredRoute) else {
            return false
        }

        return entries.contains { entry in
            guard entry.interfaceName == interfaceName,
                  let entryRoute = Self.canonicalIPv4Route(entry.destination) else {
                return false
            }
            return entryRoute == configuredRoute
        }
    }

    private func routingTableEntries() throws -> [RouteEntry] {
        let result = try Shell.run("/usr/sbin/netstat", arguments: ["-nrf", "inet"])
        return result.stdout
            .split(separator: "\n")
            .compactMap(RouteEntry.init(line:))
    }

    private func fullTunnelRoutesMatch(_ routes: [ManagedIPv4Route]) throws -> Bool {
        let entries = try routingTableEntries()

        for route in routes {
            guard let canonicalDestination = Self.canonicalIPv4Route(route.destination) else {
                return false
            }

            let found = entries.contains { entry in
                guard let canonicalEntry = Self.canonicalIPv4Route(entry.destination),
                      canonicalEntry == canonicalDestination else {
                    return false
                }

                switch route.nextHopKind {
                case .gateway:
                    return entry.gateway == route.nextHopValue
                case .interface:
                    return entry.interfaceName == route.nextHopValue
                }
            }

            if !found {
                return false
            }
        }

        return true
    }

    private func installSplitDefaultRoutes(gateway: String) throws {
        try addIPv4NetRoute("0.0.0.0/1", gateway: gateway, allowNonZero: true)
        try addIPv4NetRoute("128.0.0.0/1", gateway: gateway, allowNonZero: true)
    }

    private func installFailClosedTunnelDefaultRoutes(tunnelName: String) throws {
        try addIPv4NetRoute("0.0.0.0/1", interfaceName: tunnelName, allowNonZero: true)
        try addIPv4NetRoute("128.0.0.0/1", interfaceName: tunnelName, allowNonZero: true)
    }

    private func installSplitTunnelRouting(using state: SessionState,
                                           gateway: String,
                                           tunnelName: String) throws {
        try installSplitDefaultRoutes(gateway: gateway)
        for route in cleanupIncludedRoutes(using: state) {
            try addIPv4NetRoute(route, interfaceName: tunnelName, allowNonZero: true)
        }
    }

    private func deleteIPv4NetRoute(_ destination: String, allowNonZero: Bool) throws {
        _ = try Shell.run("/sbin/route",
                          arguments: ["-n", "delete", "-net", destination],
                          allowNonZero: allowNonZero,
                          requirePrivileges: true)
    }

    private func addIPv4NetRoute(_ destination: String,
                                 gateway: String,
                                 allowNonZero: Bool) throws {
        _ = try Shell.run("/sbin/route",
                          arguments: ["-n", "add", "-net", destination, gateway],
                          allowNonZero: allowNonZero,
                          requirePrivileges: true)
    }

    private func addIPv4NetRoute(_ destination: String,
                                 interfaceName: String,
                                 allowNonZero: Bool) throws {
        _ = try Shell.run("/sbin/route",
                          arguments: ["-n", "add", "-net", destination, "-interface", interfaceName],
                          allowNonZero: allowNonZero,
                          requirePrivileges: true)
    }

    private func resolvedFullTunnelDefaultRoutes(from capturedRoutes: [ManagedIPv4Route],
                                                 tunnelName: String) -> [ManagedIPv4Route] {
        let destinations = ["0.0.0.0/1", "128.0.0.0/1"]
        var validated: [String: ManagedIPv4Route] = [:]

        for route in capturedRoutes {
            guard destinations.contains(route.destination) else {
                continue
            }

            switch route.nextHopKind {
            case .gateway:
                guard AppConfig.SplitTunnelConfiguration.isValidIPAddress(route.nextHopValue) else {
                    continue
                }
            case .interface:
                guard isSafeInterfaceName(route.nextHopValue) else {
                    continue
                }
            }

            validated[route.destination] = route
        }

        if destinations.allSatisfy({ validated[$0] != nil }) {
            return destinations.compactMap { validated[$0] }
        }

        return destinations.map {
            ManagedIPv4Route(destination: $0,
                             nextHopKind: .interface,
                             nextHopValue: tunnelName)
        }
    }

    private func isSafeInterfaceName(_ value: String) -> Bool {
        guard !value.isEmpty,
              !value.hasPrefix("-"),
              value.count <= 32 else {
            return false
        }

        return value.allSatisfy { character in
            character.isLetter || character.isNumber || character == "_" || character == "." || character == "-"
        }
    }

    private let safeNetworkServiceNameAllowedCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -./()_+'&")

    private func isSafeNetworkServiceName(_ value: String) -> Bool {
        guard !value.isEmpty,
              !value.hasPrefix("-"),
              value.count <= 128 else {
            return false
        }

        return value.unicodeScalars.allSatisfy { safeNetworkServiceNameAllowedCharacters.contains($0) }
    }

    private func validatedTunnelInterfaceName(_ tunnelName: String) throws -> String {
        guard isSafeInterfaceName(tunnelName) else {
            throw RouteManagerError.invalidTunnelInterface
        }
        return tunnelName
    }

    private func resolveRemoteIPv4Addresses(fromProfilePath profilePath: String,
                                            preferredRemoteIP: String?,
                                            resolveDNS: Bool) -> Set<String> {
        var addresses = Set<String>()
        if let preferredRemoteIP, AppConfig.SplitTunnelConfiguration.isValidIPv4Address(preferredRemoteIP) {
            addresses.insert(preferredRemoteIP)
        }

        guard let profileContents = try? String(contentsOfFile: profilePath, encoding: .utf8) else {
            return addresses
        }

        let remoteHosts = Set(
            profileContents
                .split(separator: "\n")
                .compactMap { line -> String? in
                    let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else {
                        return nil
                    }
                    let fields = trimmed.split(whereSeparator: \.isWhitespace)
                    guard fields.count >= 2, fields[0] == "remote" else {
                        return nil
                    }
                    return String(fields[1])
                }
        )

        for host in remoteHosts {
            if AppConfig.SplitTunnelConfiguration.isValidIPv4Address(host) {
                addresses.insert(host)
                continue
            }

            guard resolveDNS else {
                continue
            }

            addresses.formUnion(ipv4Resolver(host))
        }

        return addresses
    }

    private static func defaultResolveIPv4Addresses(forHost host: String) -> Set<String> {
        if AppConfig.SplitTunnelConfiguration.isValidIPv4Address(host) {
            return [host]
        }

        return resolveIPv4AddressesWithGetaddrinfo(forHost: host)
            .union(resolveIPv4AddressesWithDSCacheUtil(forHost: host))
    }

    private static func resolveIPv4AddressesWithGetaddrinfo(forHost host: String) -> Set<String> {
        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: AF_INET,
            ai_socktype: SOCK_DGRAM,
            ai_protocol: IPPROTO_UDP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )
        var resultPointer: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &resultPointer) == 0,
              let firstResult = resultPointer else {
            return []
        }
        defer { freeaddrinfo(firstResult) }

        var addresses = Set<String>()
        var cursor: UnsafeMutablePointer<addrinfo>? = firstResult
        while let current = cursor {
            if current.pointee.ai_family == AF_INET,
               let addr = current.pointee.ai_addr?.withMemoryRebound(to: sockaddr_in.self, capacity: 1, { $0 }) {
                var ipBuffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                var address = addr.pointee.sin_addr
                if inet_ntop(AF_INET, &address, &ipBuffer, socklen_t(INET_ADDRSTRLEN)) != nil {
                    let length = ipBuffer.firstIndex(of: 0) ?? ipBuffer.endIndex
                    let bytes = ipBuffer[..<length].map { UInt8(bitPattern: $0) }
                    addresses.insert(String(decoding: bytes, as: UTF8.self))
                }
            }
            cursor = current.pointee.ai_next
        }

        return addresses
    }

    private static func resolveIPv4AddressesWithDSCacheUtil(forHost host: String) -> Set<String> {
        guard AppConfig.SplitTunnelConfiguration.isValidDomainName(host),
              let result = try? Shell.run("/usr/bin/dscacheutil",
                                          arguments: ["-q", "host", "-a", "name", host],
                                          allowNonZero: true),
              result.exitCode == 0 else {
            return []
        }

        return ipv4AddressesFromDSCacheUtilOutput(result.stdout)
    }

    private static func ipv4AddressesFromDSCacheUtilOutput(_ output: String) -> Set<String> {
        Set(
            output
                .split(separator: "\n")
                .compactMap { line -> String? in
                    let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard trimmed.hasPrefix("ip_address:") else {
                        return nil
                    }
                    let value = trimmed.dropFirst("ip_address:".count)
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                    return AppConfig.SplitTunnelConfiguration.isValidIPv4Address(value) ? value : nil
                }
        )
    }

    private func normalizeHostRouteDestination(_ destination: String) -> String? {
        if let stripped = destination.split(separator: "/").first,
           AppConfig.SplitTunnelConfiguration.isValidIPv4Address(String(stripped)) {
            return String(stripped)
        }

        return AppConfig.SplitTunnelConfiguration.isValidIPv4Address(destination) ? destination : nil
    }

    private func serviceName(for interfaceName: String) throws -> String? {
        let result = try Shell.run("/usr/sbin/networksetup",
                                   arguments: ["-listnetworkserviceorder"],
                                   requirePrivileges: true)
        let lines = result.stdout
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)

        var index = 0
        while index < lines.count {
            let line = lines[index].trimmingCharacters(in: .whitespacesAndNewlines)
            guard line.hasPrefix("("),
                  let closing = line.firstIndex(of: ")") else {
                index += 1
                continue
            }

            let remainder = line[line.index(after: closing)...].trimmingCharacters(in: .whitespacesAndNewlines)
            let serviceName = remainder.isEmpty ? nil : remainder

            var detailIndex = index + 1
            while detailIndex < lines.count {
                let detailLine = lines[detailIndex].trimmingCharacters(in: .whitespacesAndNewlines)
                if detailLine.isEmpty {
                    detailIndex += 1
                    continue
                }
                if let serviceName,
                   detailLine.contains("(Hardware Port:"),
                   detailLine.contains("Device: \(interfaceName)") {
                    return serviceName
                }
                if detailLine.hasPrefix("(") {
                    break
                }
                detailIndex += 1
            }

            index = detailIndex
        }

        return nil
    }

    private func parseNetworkSetupListOutput(_ output: String) -> [String] {
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              !trimmed.hasPrefix("There aren't any ") else {
            return []
        }

        return trimmed
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    static func canonicalIPv4Route(_ route: String) -> CanonicalIPv4Route? {
        let trimmed = route.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }

        let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let addressPart = String(parts[0])
        let prefixLength: Int
        if parts.count == 2 {
            guard let parsedPrefix = Int(parts[1]),
                  (0...32).contains(parsedPrefix) else {
                return nil
            }
            prefixLength = parsedPrefix
        } else {
            let octets = addressPart.split(separator: ".", omittingEmptySubsequences: false)
            guard (1...4).contains(octets.count) else {
                return nil
            }
            prefixLength = octets.count * 8
        }

        let octets = addressPart.split(separator: ".", omittingEmptySubsequences: false)
        guard !octets.isEmpty, octets.count <= 4 else {
            return nil
        }

        var address: UInt32 = 0
        for index in 0..<4 {
            let octet: UInt32
            if index < octets.count {
                guard let parsedOctet = UInt32(String(octets[index])),
                      parsedOctet <= 255 else {
                    return nil
                }
                octet = parsedOctet
            } else {
                octet = 0
            }
            address = (address << 8) | octet
        }

        let mask: UInt32 = prefixLength == 0 ? 0 : (~UInt32(0) << (32 - prefixLength))
        return CanonicalIPv4Route(networkAddress: address & mask, prefixLength: prefixLength)
    }

    private func parseGatewayAndInterface(_ output: String) -> (gateway: String?, interfaceName: String?) {
        var gateway: String?
        var interfaceName: String?

        for line in output.split(separator: "\n") {
            if line.contains("gateway:") {
                gateway = line.split(whereSeparator: \.isWhitespace).last.map(String.init)
            }
            if line.contains("interface:") {
                interfaceName = line.split(whereSeparator: \.isWhitespace).last.map(String.init)
            }
        }

        return (gateway, interfaceName)
    }
}

private struct RouteEntry {
    let destination: String
    let gateway: String
    let interfaceName: String

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
        self.interfaceName = String(fields.last!)
    }
}
