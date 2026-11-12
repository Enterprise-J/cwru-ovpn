import Foundation
import Darwin
import SystemConfiguration

extension RouteManager {
    func capturePhysicalDNSConfiguration(for interfaceName: String) throws -> PhysicalDNSConfiguration? {
        guard let serviceName = try serviceName(for: interfaceName),
              NetworkValidation.isSafeNetworkServiceName(serviceName) else {
            return nil
        }

        let settings = try dnsSettings(forServiceNamed: serviceName)
        return PhysicalDNSConfiguration(serviceName: serviceName,
                                        dnsServers: settings.dnsServers,
                                        searchDomains: settings.searchDomains,
                                        ipv6Mode: try ipv6Mode(forServiceNamed: serviceName))
    }

    func serviceName(for interfaceName: String) throws -> String? {
        let result = try commandRunner.run("/usr/sbin/networksetup",
                                           arguments: ["-listnetworkserviceorder"])
        let lines = result.stdout
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }

        var serviceName: String?
        for line in lines {
            if line.contains("(Hardware Port:") {
                if let serviceName, Self.networkServiceDeviceName(from: line) == interfaceName {
                    return serviceName
                }
            } else if line.hasPrefix("("), let closing = line.firstIndex(of: ")") {
                let remainder = line[line.index(after: closing)...].trimmingCharacters(in: .whitespacesAndNewlines)
                serviceName = remainder.isEmpty ? nil : remainder
            }
        }
        return nil
    }

    static func networkServiceDeviceName(from detailLine: String) -> String? {
        guard let markerRange = detailLine.range(of: "Device:") else {
            return nil
        }
        var value = detailLine[markerRange.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        if let comma = value.firstIndex(of: ",") {
            value = String(value[..<comma]).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        while value.last == ")" {
            value.removeLast()
            value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return value.isEmpty ? nil : value
    }

    func parseNetworkSetupListOutput(_ output: String) -> [String] {
        let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("There aren't any ") else {
            return []
        }
        return trimmed
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    func currentDNSSettings(using state: SessionState) throws -> (dnsServers: [String], searchDomains: [String])? {
        guard let serviceName = state.physicalServiceName, !serviceName.isEmpty else {
            return nil
        }

        return try dnsSettings(forServiceNamed: serviceName)
    }

    func physicalDNSBaseline(using state: SessionState) throws -> Set<String> {
        let configured = state.originalDNSServers ?? []
        guard configured.isEmpty else {
            return Set(normalizedDNSServers(configured))
        }
        return Set(normalizedDNSServers(try dynamicDNSLookup(state.physicalInterface, state.physicalServiceName)))
    }

    static func queryDynamicDNSServers(interfaceName: String, serviceName: String?) throws -> [String] {
        var arguments = ["inspect-dns", "--interface", interfaceName]
        if let serviceName {
            arguments += ["--service", serviceName]
        }
        let result = try CommandRunner().run(ExecutionIdentity.currentExecutablePath(), arguments: arguments)
        return try JSONDecoder().decode([String].self, from: Data(result.stdout.utf8))
    }

    static func dynamicDNSServers(interfaceName: String, serviceName: String?) throws -> [String] {
        guard let preferences = SCPreferencesCreate(nil, "cwru-ovpn" as CFString, nil),
              let currentSet = SCNetworkSetCopyCurrent(preferences),
              let services = SCNetworkSetCopyServices(currentSet) as? [SCNetworkService],
              let store = SCDynamicStoreCreate(nil, "cwru-ovpn" as CFString, nil, nil) else {
            throw RouteManagerError.failedToInspectPhysicalDNS(String(cString: SCErrorString(SCError())))
        }
        let matchingServices = services.filter { service in
            guard serviceName == nil || SCNetworkServiceGetName(service) as String? == serviceName,
                  let interface = SCNetworkServiceGetInterface(service) else {
                return false
            }
            return SCNetworkInterfaceGetBSDName(interface) as String? == interfaceName
        }
        guard matchingServices.count <= 1 else {
            throw RouteManagerError.failedToInspectPhysicalDNS("Multiple network services match the physical interface.")
        }
        guard let service = matchingServices.first else {
            return []
        }
        guard let serviceID = SCNetworkServiceGetServiceID(service) else {
            throw RouteManagerError.failedToInspectPhysicalDNS("The physical network service has no identifier.")
        }
        let key = SCDynamicStoreKeyCreateNetworkServiceEntity(nil, kSCDynamicStoreDomainState, serviceID, kSCEntNetDNS)
        guard let values = SCDynamicStoreCopyMultiple(store, [key] as CFArray, nil) as? [String: Any] else {
            throw RouteManagerError.failedToInspectPhysicalDNS(String(cString: SCErrorString(SCError())))
        }
        return try dynamicDNSServers(in: values[key as String])
    }

    static func dynamicDNSServers(in value: Any?) throws -> [String] {
        guard let value else {
            return []
        }
        guard let dictionary = value as? [String: Any] else {
            throw RouteManagerError.failedToInspectPhysicalDNS("The DNS state is not a dictionary.")
        }
        guard let serverValue = dictionary[kSCPropNetDNSServerAddresses as String] else {
            return []
        }
        guard let servers = serverValue as? [String] else {
            throw RouteManagerError.failedToInspectPhysicalDNS("The DNS server list is not an array of strings.")
        }
        return servers
    }

    func normalizedDNSServers(_ servers: [String]) -> [String] {
        servers.map { server in
            NetworkValidation.isValidIPv6Address(server)
                ? IPRoute.canonicalIPv6(server)?.addressString ?? server
                : server
        }.uniqued()
    }

    private func dnsSettings(forServiceNamed serviceName: String) throws -> (dnsServers: [String], searchDomains: [String]) {
        let dnsServersOutput = try commandRunner.run("/usr/sbin/networksetup",
                                                     arguments: ["-getdnsservers", serviceName])
        let searchDomainsOutput = try commandRunner.run("/usr/sbin/networksetup",
                                                        arguments: ["-getsearchdomains", serviceName])
        return (normalizedDNSServers(parseNetworkSetupListOutput(dnsServersOutput.stdout)),
                parseNetworkSetupListOutput(searchDomainsOutput.stdout))
    }

    func setDNSConfiguration(serviceName: String,
                             dnsServers: [String],
                             searchDomains: [String]) throws {
        let dnsArguments = networkSetupListArguments(command: "-setdnsservers",
                                                     serviceName: serviceName,
                                                     values: dnsServers)
        _ = try commandRunner.run("/usr/sbin/networksetup",
                                  arguments: dnsArguments)

        let searchArguments = networkSetupListArguments(command: "-setsearchdomains",
                                                        serviceName: serviceName,
                                                        values: searchDomains)
        _ = try commandRunner.run("/usr/sbin/networksetup",
                                  arguments: searchArguments)
    }

    func networkSetupListArguments(command: String,
                                   serviceName: String,
                                   values: [String]) -> [String] {
        values.isEmpty ? [command, serviceName, "empty"] : [command, serviceName] + values
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
              let current = try currentDNSSettings(using: state) else {
            return false
        }

        let expectedDNSServers = normalizedDNSServers(state.originalDNSServers ?? [])
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
    func applyFullTunnelDNSConfiguration(using state: inout SessionState,
                                         persistPreparedState: (SessionState) throws -> Void) throws -> [String] {
        let serviceName = try fullTunnelDNSService(using: state)
        let nameServers = try effectiveFullTunnelDNSServers(using: state)
        let scopedDomains = fullTunnelScopedDNSDomains()
        guard !scopedDomains.isEmpty, !nameServers.isEmpty else {
            return nameServers
        }
        let searchDomains = effectiveFullTunnelSearchDomains(using: state)
        state.fullTunnelDNSServers = normalizedDNSServers((state.fullTunnelDNSServers ?? []) + nameServers)
        state.fullTunnelSearchDomains = ((state.fullTunnelSearchDomains ?? []) + searchDomains).uniqued()
        state.appliedDNSDomains = (appliedDNSDomains(using: state) + scopedDomains).uniqued()
        try persistPreparedState(state)
        let refreshedResolverFiles = try installResolverFiles(forDomains: scopedDomains, nameServers: nameServers)
        if refreshedResolverFiles {
            appendEventLog(note: "Full tunnel: refreshed scoped resolver files.", phase: state.phase)
        }
        if let current = try currentDNSSettings(using: state),
           current.dnsServers == nameServers,
           current.searchDomains == searchDomains {
            if refreshedResolverFiles {
                try flushDNS()
            }
            return nameServers
        }
        appendEventLog(note: "Full tunnel: applied the physical-service DNS configuration.", phase: state.phase)
        try setDNSConfiguration(serviceName: serviceName, dnsServers: nameServers, searchDomains: searchDomains)
        try flushDNS()
        return nameServers
    }

    private func fullTunnelDNSService(using state: SessionState) throws -> String {
        guard let serviceName = state.physicalServiceName,
              NetworkValidation.isSafeNetworkServiceName(serviceName) else {
            throw RouteManagerError.failedToSecureFullTunnelDNS
        }
        return serviceName
    }

    func effectiveFullTunnelDNSServers(using state: SessionState) throws -> [String] {
        guard let tunnelName = state.tunnelName else {
            throw RouteManagerError.missingTunnelInterface
        }
        let validatedTunnelName = try validatedTunnelInterfaceName(tunnelName)
        let learnedServers = normalizedDNSServers((state.pushedDNSServers ?? [])
            .filter(NetworkValidation.isValidIPAddress))
        let policyServers = normalizedDNSServers(policyDNSServers().filter(NetworkValidation.isValidIPAddress))
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
        let learnedDomains = (state.pushedSearchDomains ?? [])
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
            if result.exitCode != 0 {
                appendEventLog(note: "DNS cache flush command \(launchPath) exited with status \(result.exitCode).")
            }
        }
    }

    func parseActiveDNSResolvers(_ output: String, includeScoped: Bool = false) -> [ActiveDNSResolver] {
        var resolvers: [ActiveDNSResolver] = []
        var current = ActiveDNSResolver()

        for rawLine in output.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if !includeScoped, line.hasPrefix("DNS configuration (for ") {
                break
            }

            if line.hasPrefix("resolver #") {
                if current.hasContent {
                    current.nameServers = normalizedDNSServers(current.nameServers)
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
            current.nameServers = normalizedDNSServers(current.nameServers)
            resolvers.append(current)
        }

        return resolvers
    }

    private func valueAfterColon(in line: String) -> String? {
        line.split(separator: ":", maxSplits: 1)
            .last?
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func ipv6Mode(forServiceNamed serviceName: String) throws -> String? {
        let output = try commandRunner.run("/usr/sbin/networksetup",
                                           arguments: ["-getinfo", serviceName])

        for line in output.stdout.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.hasPrefix("IPv6:") {
                return String(trimmed.dropFirst("IPv6:".count)).trimmingCharacters(in: .whitespacesAndNewlines)
            }
        }

        return nil
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

        _ = try commandRunner.run("/usr/sbin/networksetup",
                                  arguments: ["-setv6off", serviceName])
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
            _ = try commandRunner.run("/usr/sbin/networksetup",
                                      arguments: ["-setv6automatic", serviceName])
        case "linklocal":
            _ = try commandRunner.run("/usr/sbin/networksetup",
                                      arguments: ["-setv6linklocal", serviceName])
        case "off":
            _ = try commandRunner.run("/usr/sbin/networksetup",
                                      arguments: ["-setv6off", serviceName])
        default:
            return
        }
    }

    func physicalInterfaceConfigurationOutput(_ interfaceName: String) throws -> String? {
        guard NetworkValidation.isSafeInterfaceName(interfaceName) else {
            throw RouteManagerError.failedToInspectPhysicalInterface(interfaceName)
        }
        let result = try commandRunner.run("/sbin/ifconfig", arguments: [interfaceName], allowNonZero: true)
        if result.exitCode != 0 {
            if result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
                == "ifconfig: interface \(interfaceName) does not exist" {
                return nil
            }
            throw CommandError.commandFailed("/sbin/ifconfig \(interfaceName)", result.exitCode, result.stderr)
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
