import Foundation
import Darwin
import SystemConfiguration

extension RouteManager {
    func currentDNSSettings(using state: SessionState) throws -> (dnsServers: [String], searchDomains: [String], enabled: Bool) {
        let config = try serviceStore.configuration(serviceID: state.physicalServiceID, kind: .dns)
        let current = try config.fields()
        return (normalizedDNSServers(current?[kSCPropNetDNSServerAddresses as String] as? [String] ?? []),
                current?[kSCPropNetDNSSearchDomains as String] as? [String] ?? [], config.enabled == true)
    }

    func physicalDNSBaseline(using state: SessionState) throws -> Set<String> {
        if let configured = state.originalDNSServers, !configured.isEmpty { return Set(normalizedDNSServers(configured)) }
        let id = state.physicalServiceID
        let owned = !state.pendingDNSWithdrawal.servers.isEmpty || state.serviceMutations.contains { $0.kind == .dns && $0.serviceID == id }
        return Set(normalizedDNSServers(try serviceStore.dynamicDNS(serviceID: id, dhcpOnly: owned).servers))
    }

    private func update(_ kind: ServiceProtocol, using state: inout SessionState,
                        persist: (SessionState) throws -> Void,
                        transform: (ProtocolConfiguration) throws -> ProtocolConfiguration) throws -> Bool {
        let id = state.physicalServiceID
        let current = try serviceStore.configuration(serviceID: id, kind: kind)
        let desired = try transform(current)
        guard try !current.matches(desired, for: kind) else { return false }
        let index = state.serviceMutations.firstIndex { $0.serviceID == id && $0.kind == kind }
        if let index {
            let prior = state.serviceMutations[index]
            guard try current.matches(prior.desired, for: kind) || current.matches(prior.previous, for: kind)
                    || current.matches(prior.original, for: kind) else {
                throw RouteManagerError.failedToInspectPhysicalDNS("An external change conflicts with the recorded \(kind.rawValue) setting on \(id).")
            }
            state.serviceMutations[index].previous = current
            state.serviceMutations[index].desired = desired
        } else {
            state.serviceMutations.append(ServiceMutation(serviceID: id, kind: kind, original: current,
                                                          previous: current, desired: desired))
        }
        try persist(state)
        try serviceStore.replace(serviceID: id, kind: kind, expected: current, desired: desired)
        return true
    }

    @discardableResult
    func restoreService(_ kind: ServiceProtocol, using state: SessionState,
                        restored: (ServiceMutation) throws -> Void = { _ in }) throws -> Bool {
        var changed = false
        var firstError: Error?
        for change in state.serviceMutations where change.kind == kind {
            do {
                let current = try serviceStore.configuration(serviceID: change.serviceID, kind: kind)
                if try !current.matches(change.original, for: kind) {
                    let previous = try current.matches(change.previous, for: kind)
                    try serviceStore.replace(serviceID: change.serviceID, kind: kind,
                                             expected: previous ? change.previous : change.desired, desired: change.original)
                    changed = true
                }
                try restored(change)
            } catch { firstError = firstError ?? error }
        }
        if let firstError { throw firstError }
        return changed
    }

    func normalizedDNSServers(_ servers: [String]) -> [String] {
        servers.map { server in
            NetworkValidation.isValidIPv6Address(server)
                ? IPRoute.canonicalIPv6(server)?.addressString ?? server
                : server
        }.uniqued()
    }

    @discardableResult
    func applyFullTunnelDNSConfiguration(using state: inout SessionState,
                                         persistPreparedState: (SessionState) throws -> Void) throws -> [String] {
        let nameServers = try effectiveFullTunnelDNSServers(using: state)
        let scopedDomains = fullTunnelScopedDNSDomains()
        guard !scopedDomains.isEmpty, !nameServers.isEmpty else {
            return nameServers
        }
        let searchDomains = effectiveFullTunnelSearchDomains(using: state)
        state.pendingDNSWithdrawal.servers = normalizedDNSServers(state.pendingDNSWithdrawal.servers + nameServers)
        state.pendingDNSWithdrawal.searchDomains = (state.pendingDNSWithdrawal.searchDomains + searchDomains).uniqued()
        state.appliedScopedDNSDomains = (appliedScopedDNSDomains(using: state) + scopedDomains).uniqued()
        try persistPreparedState(state)
        let refreshedResolverFiles = try installResolverFiles(forDomains: scopedDomains, nameServers: nameServers)
        if refreshedResolverFiles {
            appendEventLog(note: "Full tunnel: refreshed scoped resolver files.", phase: state.phase)
        }
        let current = try currentDNSSettings(using: state)
        if current.enabled, current.dnsServers == nameServers, current.searchDomains == searchDomains {
            if refreshedResolverFiles { try flushDNS() }
            return nameServers
        }
        let changed = try update(.dns, using: &state, persist: persistPreparedState) {
            try $0.replacingDNS(servers: nameServers, domains: searchDomains)
        }
        if changed || refreshedResolverFiles { try flushDNS() }
        return nameServers
    }

    func effectiveFullTunnelDNSServers(using state: SessionState) throws -> [String] {
        guard let tunnelName = state.tunnelName else {
            throw RouteManagerError.missingTunnelInterface
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)
        try state.pushedDNS?.validateForSystemDNS()
        let learnedServers = normalizedDNSServers((state.pushedDNS?.addresses ?? [])
            .filter(NetworkValidation.isValidIPAddress))
        let policyServers = normalizedDNSServers(policyDNSServers().filter(NetworkValidation.isValidIPAddress))
        if learnedServers.isEmpty && policyServers.isEmpty {
            return []
        }
        let safeLearnedServers = try dnsServersRoutedThroughTunnel(learnedServers,
                                                                   tunnelName: validatedTunnelName)
        if !learnedServers.isEmpty {
            guard !safeLearnedServers.isEmpty else { throw RouteManagerError.failedToSecureFullTunnelDNS }
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
            if NetworkValidation.isValidIPv4Address(server) {
                routeState = try publicIPv4RouteState(for: server, tunnelName: tunnelName)
            } else if NetworkValidation.isValidIPv6Address(server) {
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
        let learnedDomains = (state.pushedDNS?.searchDomains ?? [])
            .filter(NetworkValidation.isValidDomainName)
        if !learnedDomains.isEmpty {
            return learnedDomains
        }

        return fullTunnelScopedDNSDomains().filter(NetworkValidation.isValidDomainName)
    }

    func flushDNS() throws {
        let commands = [("/usr/bin/dscacheutil", ["-flushcache"]), ("/usr/bin/killall", ["-HUP", "mDNSResponder"])]
        for (launchPath, arguments) in commands {
            let result = try commandRunner.run(launchPath, arguments: arguments, allowNonZero: true)
            if result.termination != .exited(0) {
                appendEventLog(note: "DNS cache flush command \(launchPath) ended with \(result.termination).")
            }
        }
    }

    func parseActiveDNSResolvers(_ output: String, includeScoped: Bool = false) -> [ActiveDNSResolver] {
        var resolvers: [ActiveDNSResolver] = []
        var scope = ActiveDNSResolver.Scope.ordinary
        var current = ActiveDNSResolver()

        for rawLine in output.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.hasPrefix("DNS configuration (for ") {
                if !includeScoped { break }
                scope = line.contains("service") ? .service : .interface
                continue
            }
            if line.hasPrefix("if_index"), let value = valueAfterColon(in: line) {
                if let open = value.lastIndex(of: "("), value.last == ")" {
                    let name = String(value[value.index(after: open)..<value.index(before: value.endIndex)])
                    current.interfaceName = NetworkValidation.isSafeInterfaceName(name) ? name : nil
                }
                continue
            }
            if line.hasPrefix("port "), let value = valueAfterColon(in: line) {
                current.port = Int(value) ?? -1
                continue
            }

            if line.hasPrefix("resolver #") {
                if current.hasContent {
                    current.nameServers = normalizedDNSServers(current.nameServers)
                    resolvers.append(current)
                }
                current = ActiveDNSResolver(scope: scope)
                continue
            }

            if line.hasPrefix("domain") {
                if let value = valueAfterColon(in: line),
                   !value.isEmpty {
                    current.domain = value == "." ? nil : Self.dnsDomainForComparison(value)
                }
                continue
            }

            if line.hasPrefix("search domain[") {
                if let value = valueAfterColon(in: line),
                   !value.isEmpty {
                    current.searchDomains.append(Self.dnsDomainForComparison(value))
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
            current.nameServers = normalizedDNSServers(current.nameServers)
            resolvers.append(current)
        }

        return resolvers
    }

    static func dnsDomainForComparison(_ domain: String) -> String {
        let name = domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return name.hasSuffix(".") ? String(name.dropLast()) : name
    }

    private func valueAfterColon(in line: String) -> String? {
        guard let colon = line.firstIndex(of: ":") else { return nil }
        return line[line.index(after: colon)...].trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func ipv6Mode(forServiceID id: String) throws -> String? {
        let current = try serviceStore.configuration(serviceID: id, kind: .ipv6)
        return try current.enabled == true ? current.fields()?[kSCPropNetIPv6ConfigMethod as String] as? String : "Off"
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

    func disablePhysicalIPv6IfEnabled(using state: inout SessionState, persist: (SessionState) throws -> Void) throws {
        _ = try update(.ipv6, using: &state, persist: persist) { current in
            guard current.enabled == true else { return current }
            guard let mode = try current.fields()?[kSCPropNetIPv6ConfigMethod as String] as? String,
                  normalizedIPv6Mode(mode) != nil else { throw RouteManagerError.failedToSecureFullTunnelIPv6Routes }
            var desired = current
            desired.enabled = false
            return desired
        }
    }

    func physicalInterfaceConfigurationOutput(_ interfaceName: String) throws -> String? {
        guard NetworkValidation.isSafeInterfaceName(interfaceName) else {
            throw RouteManagerError.failedToInspectPhysicalInterface(interfaceName)
        }
        let result = try commandRunner.run("/sbin/ifconfig", arguments: [interfaceName], allowNonZero: true)
        if result.termination != .exited(0) {
            if result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
                == "ifconfig: interface \(interfaceName) does not exist" {
                return nil
            }
            throw CommandError.commandFailed("/sbin/ifconfig \(interfaceName)", result.termination, result.stderr)
        }
        guard result.stdout.hasPrefix("\(interfaceName): flags=") else {
            throw RouteManagerError.failedToInspectPhysicalInterface(interfaceName)
        }
        return result.stdout
    }

    func physicalInterfaceUsesCLAT(_ interfaceName: String) throws -> Bool {
        guard let output = try physicalInterfaceConfigurationOutput(interfaceName) else {
            return false
        }
        let lowered = output.lowercased()
        return lowered.contains("clat46") || lowered.contains("nat64 prefix")
    }
}
