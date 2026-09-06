import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

enum MockSystemError: LocalizedError {
    case missingTeeInput
    case unexpectedCommand(String)

    var errorDescription: String? {
        switch self {
        case .missingTeeInput:
            return "tee should receive a destination path and input data."
        case .unexpectedCommand(let command):
            return "Unexpected shell command in mocked integration test: \(command)"
        }
    }
}

final class MockSystem {
    struct RouteRecord {
        let destination: String
        let gateway: String
        let interfaceName: String
        let flags: String
        let expire: String?

        init(
            destination: String, gateway: String, interfaceName: String, flags: String = "UGSc",
            expire: String? = nil
        ) {
            self.destination = destination
            self.gateway = gateway
            self.interfaceName = interfaceName
            self.flags = flags
            self.expire = expire
        }
    }

    private let serviceName: String
    private var defaultGateway: String
    private var defaultInterface: String
    private var dnsServers: [String]
    private var searchDomains: [String]
    private var activeDefaultDNSServers: [String]
    private var activeDefaultSearchDomains: [String]
    private var ipv6Mode: String
    private let tunnelInterfaces: Set<String>
    private let blockedIPv6ProbeDestinations: Set<String>
    private let unexpectedIPv6ProbeFailures: Set<String>
    private let externalIPv6TunnelInterface: String?
    private let failingRouteAdds: Set<String>
    private let failingCommandFragments: Set<String>
    private let ignoredRouteDeletes: Set<String>
    private let dnsCacheFlushAppliesDNSConfiguration: Bool
    private let activeDefaultResolverClearsAfterScutilReads: Int?
    private let ignoreIPv6OffRequests: Bool
    private let physicalIPv6RouteSnapshotsAfterIPv6Off: [[RouteRecord]]?
    private let repeatPhysicalIPv6RouteSnapshotsAfterIPv6Off: Bool
    private let physicalIfconfigOutput: String?
    private var routes: [RouteRecord]
    private var ipv6Routes: [RouteRecord]
    private var scutilDNSReadCount = 0
    private var ipv6OffNetstatReadCount = 0
    private var physicalIPv6SnapshotPrepared = false

    var recordedCommands: [String] = []
    var scutilInputs: [String] = []
    var ipv6NetstatReadsAfterIPv6Off: Int { ipv6OffNetstatReadCount }

    init(
        serviceName: String,
        physicalGateway: String,
        physicalInterface: String,
        physicalDNSServers: [String],
        physicalSearchDomains: [String],
        ipv6Mode: String,
        activeDefaultDNSServers: [String]? = nil,
        activeDefaultSearchDomains: [String]? = nil,
        tunnelInterfaces: Set<String>,
        blockedIPv6ProbeDestinations: Set<String> = [],
        unexpectedIPv6ProbeFailures: Set<String> = [],
        externalIPv6TunnelInterface: String? = nil,
        failingRouteAdds: Set<String> = [],
        failingCommandFragments: Set<String> = [],
        ignoredRouteDeletes: Set<String> = [],
        dnsCacheFlushAppliesDNSConfiguration: Bool = true,
        activeDefaultResolverClearsAfterScutilReads: Int? = nil,
        ignoreIPv6OffRequests: Bool = false,
        physicalIPv6RouteSnapshotsAfterIPv6Off: [[RouteRecord]]? = nil,
        repeatPhysicalIPv6RouteSnapshotsAfterIPv6Off: Bool = false,
        physicalIfconfigOutput: String? = nil,
        initialRoutes: [RouteRecord] = [],
        initialIPv6Routes: [String: String] = [:],
        initialIPv6RouteRecords: [RouteRecord] = []
    ) {
        self.serviceName = serviceName
        self.defaultGateway = physicalGateway
        self.defaultInterface = physicalInterface
        self.dnsServers = physicalDNSServers
        self.searchDomains = physicalSearchDomains
        self.activeDefaultDNSServers = activeDefaultDNSServers ?? physicalDNSServers
        self.activeDefaultSearchDomains = activeDefaultSearchDomains ?? physicalSearchDomains
        self.ipv6Mode = ipv6Mode
        self.tunnelInterfaces = tunnelInterfaces
        self.blockedIPv6ProbeDestinations = blockedIPv6ProbeDestinations
        self.unexpectedIPv6ProbeFailures = unexpectedIPv6ProbeFailures
        self.externalIPv6TunnelInterface = externalIPv6TunnelInterface
        self.failingRouteAdds = failingRouteAdds
        self.failingCommandFragments = failingCommandFragments
        self.ignoredRouteDeletes = ignoredRouteDeletes
        self.dnsCacheFlushAppliesDNSConfiguration = dnsCacheFlushAppliesDNSConfiguration
        self.activeDefaultResolverClearsAfterScutilReads =
            activeDefaultResolverClearsAfterScutilReads
        self.ignoreIPv6OffRequests = ignoreIPv6OffRequests
        self.physicalIPv6RouteSnapshotsAfterIPv6Off = physicalIPv6RouteSnapshotsAfterIPv6Off
        self.repeatPhysicalIPv6RouteSnapshotsAfterIPv6Off =
            repeatPhysicalIPv6RouteSnapshotsAfterIPv6Off
        self.physicalIfconfigOutput = physicalIfconfigOutput
        self.routes =
            [
                RouteRecord(
                    destination: "default",
                    gateway: physicalGateway,
                    interfaceName: physicalInterface)
            ] + initialRoutes
        self.ipv6Routes =
            initialIPv6Routes.map { destination, interfaceName in
                RouteRecord(
                    destination: destination,
                    gateway: interfaceName == "lo0" ? "::1" : "fe80::%\(interfaceName)",
                    interfaceName: interfaceName,
                    flags: interfaceName == "lo0" ? "UGRS" : "UGSc")
            } + initialIPv6RouteRecords
    }

    func handle(_ invocation: ShellInvocation) throws -> ShellResult {
        let command = ([invocation.launchPath] + invocation.arguments).joined(separator: " ")
        recordedCommands.append(command)
        if failingCommandFragments.contains(where: { command.contains($0) }) {
            return ShellResult(exitCode: 1, stdout: "", stderr: "mock command failure")
        }

        switch invocation.launchPath {
        case "/sbin/route":
            return handleRoute(arguments: invocation.arguments)
        case "/usr/sbin/netstat":
            return ShellResult(
                exitCode: 0, stdout: netstatOutput(arguments: invocation.arguments), stderr: "")
        case "/usr/sbin/networksetup":
            return handleNetworkSetup(arguments: invocation.arguments)
        case "/usr/sbin/scutil":
            return handleScutil(invocation)
        case "/usr/bin/dscacheutil":
            return handleDSCacheUtil(arguments: invocation.arguments)
        case "/usr/sbin/ipconfig":
            return handleIPConfig(arguments: invocation.arguments)
        case "/usr/bin/killall":
            applyDNSConfigurationAfterFlushIfNeeded()
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        case "/bin/mkdir":
            if invocation.arguments.count == 2, invocation.arguments[0] == "-p" {
                try FileManager.default.createDirectory(
                    atPath: invocation.arguments[1],
                    withIntermediateDirectories: true,
                    attributes: nil)
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }
        case "/usr/sbin/chown":
            if invocation.arguments.count == 2 {
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }
        case "/bin/chmod":
            if invocation.arguments.count == 2 {
                let mode = Int(invocation.arguments[0], radix: 8) ?? 0o644
                try FileManager.default.setAttributes(
                    [.posixPermissions: mode],
                    ofItemAtPath: invocation.arguments[1])
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }
        case "/usr/bin/tee":
            guard let path = invocation.arguments.first, let input = invocation.input else {
                throw MockSystemError.missingTeeInput
            }
            let url = URL(fileURLWithPath: path)
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try input.write(to: url, options: .atomic)
            return ShellResult(
                exitCode: 0, stdout: String(decoding: input, as: UTF8.self), stderr: "")
        case "/bin/rm":
            if let path = invocation.arguments.last {
                try? FileManager.default.removeItem(atPath: path)
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }
        case "/sbin/ifconfig":
            let interfaceName = invocation.arguments.first ?? ""
            if interfaceName == defaultInterface, let physicalIfconfigOutput {
                return ShellResult(exitCode: 0, stdout: physicalIfconfigOutput, stderr: "")
            }
            return ShellResult(
                exitCode: tunnelInterfaces.contains(interfaceName) ? 0 : 1, stdout: "", stderr: "")
        default:
            break
        }

        throw MockSystemError.unexpectedCommand(
            ([invocation.launchPath] + invocation.arguments).joined(separator: " ")
        )
    }

    private func handleIPConfig(arguments: [String]) -> ShellResult {
        guard arguments.count >= 2 else {
            return ShellResult(exitCode: 1, stdout: "", stderr: "unsupported ipconfig command")
        }

        switch arguments[0] {
        case "getpacket":
            guard arguments[1] == defaultInterface else {
                return ShellResult(exitCode: 1, stdout: "", stderr: "no DHCP packet")
            }
            return ShellResult(
                exitCode: 0,
                stdout: "yiaddr = 192.168.1.50\nserver_identifier = \(defaultGateway)\n",
                stderr: "")
        case "set":
            guard arguments.count == 3,
                arguments[1] == defaultInterface,
                arguments[2] == "DHCP"
            else {
                return ShellResult(exitCode: 1, stdout: "", stderr: "unsupported ipconfig set")
            }
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        default:
            return ShellResult(exitCode: 1, stdout: "", stderr: "unsupported ipconfig command")
        }
    }

    private func handleDSCacheUtil(arguments: [String]) -> ShellResult {
        if arguments == ["-flushcache"] {
            applyDNSConfigurationAfterFlushIfNeeded()
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        }

        return ShellResult(exitCode: 1, stdout: "", stderr: "unsupported dscacheutil command")
    }

    private func applyDNSConfigurationAfterFlushIfNeeded() {
        guard dnsCacheFlushAppliesDNSConfiguration else {
            return
        }
        activeDefaultDNSServers = dnsServers
        activeDefaultSearchDomains = searchDomains
    }

    private func handleRoute(arguments: [String]) -> ShellResult {
        if arguments == ["-n", "get", "default"] {
            return ShellResult(
                exitCode: 0,
                stdout:
                    "route to: default\ngateway: \(defaultGateway)\ninterface: \(defaultInterface)\n",
                stderr: "")
        }

        if arguments.count == 4, arguments[0] == "-n", arguments[1] == "get",
            arguments[2] == "-inet6"
        {
            preparePhysicalIPv6RouteSnapshotAfterIPv6OffIfNeeded()
            if unexpectedIPv6ProbeFailures.contains(arguments[3]) {
                return ShellResult(
                    exitCode: 1, stdout: "", stderr: "route: mocked routing socket failure")
            }
            if blockedIPv6ProbeDestinations.contains(arguments[3]) {
                return ShellResult(
                    exitCode: 0,
                    stdout:
                        "route to: \(arguments[3])\ngateway: ::1\ninterface: lo0\nflags: <UP,GATEWAY,REJECT,DONE,STATIC>\n",
                    stderr: "")
            }
            guard let interfaceName = routedIPv6Interface(for: arguments[3]) else {
                return ShellResult(
                    exitCode: 1, stdout: "",
                    stderr: "route: writing to routing socket: not in table")
            }
            if interfaceName == "lo0" {
                return ShellResult(
                    exitCode: 0,
                    stdout:
                        "route to: \(arguments[3])\ngateway: ::1\ninterface: lo0\nflags: <UP,GATEWAY,REJECT,DONE,STATIC>\n",
                    stderr: "")
            }
            return ShellResult(
                exitCode: 0,
                stdout:
                    "route to: \(arguments[3])\ngateway: fe80::%\(interfaceName)\ninterface: \(interfaceName)\n",
                stderr: "")
        }

        if arguments.count == 3, arguments[0] == "-n", arguments[1] == "get" {
            let destination = arguments[2]
            if SplitTunnelPolicy.isValidIPv4Address(destination),
                let interfaceName = routedIPv4Interface(for: destination)
            {
                return ShellResult(
                    exitCode: 0,
                    stdout:
                        "route to: \(destination)\ngateway: link#1\ninterface: \(interfaceName)\n",
                    stderr: "")
            }
            return ShellResult(
                exitCode: 0,
                stdout:
                    "route to: \(destination)\ngateway: \(destination)\ninterface: \(defaultInterface)\n",
                stderr: "")
        }

        if arguments.count >= 4, arguments[0] == "-n", arguments[1] == "add" {
            if arguments[2] == "default", arguments.count >= 4 {
                defaultGateway = arguments[3]
                upsertRoute(
                    destination: "default", gateway: defaultGateway, interfaceName: defaultInterface
                )
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-inet6", arguments.count >= 5 {
                let destination = arguments[3]
                let rawNextHop = arguments.last ?? defaultInterface
                let scopedInterface = rawNextHop.split(separator: "%", maxSplits: 1).dropFirst()
                    .first.map(
                        String.init)
                let interfaceName =
                    arguments.contains("-reject")
                    ? "lo0"
                    : arguments.firstIndex(of: "-interface")
                        .flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
                        ?? scopedInterface
                        ?? rawNextHop
                let gateway =
                    arguments.contains("-reject")
                    ? "::1"
                    : arguments.contains("-interface") ? "link#1" : rawNextHop
                upsertIPv6Route(
                    destination: destination,
                    gateway: gateway,
                    interfaceName: interfaceName,
                    flags: arguments.contains("-reject") ? "UGRS" : "UGSc")
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-net",
                arguments.count >= 8,
                arguments[3] == "-inet6"
            {
                let prefixLength = arguments[6]
                let destination = "\(arguments[4])/\(prefixLength)"
                if failingRouteAdds.contains(destination) {
                    return ShellResult(exitCode: 1, stdout: "", stderr: "mock route add failure")
                }
                let rawNextHop = arguments.last ?? defaultInterface
                let scopedInterface = rawNextHop.split(separator: "%", maxSplits: 1).dropFirst()
                    .first.map(
                        String.init)
                let interfaceName =
                    arguments.contains("-reject") ? "lo0" : scopedInterface ?? defaultInterface
                let gateway = arguments.contains("-reject") ? "::1" : rawNextHop
                if ipv6Routes.contains(where: {
                    $0.destination == destination && $0.interfaceName == interfaceName
                }) {
                    return ShellResult(
                        exitCode: 1, stdout: "",
                        stderr: "route: writing to routing socket: File exists")
                }
                ipv6Routes.append(
                    RouteRecord(
                        destination: destination,
                        gateway: gateway,
                        interfaceName: interfaceName,
                        flags: arguments.contains("-reject") ? "UGRS" : "UGSc"))
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-host", arguments.count >= 5 {
                let destination = arguments[3]
                if failingRouteAdds.contains(destination) {
                    return ShellResult(exitCode: 1, stdout: "", stderr: "mock route add failure")
                }
                if arguments[4] == "-interface", arguments.count >= 6 {
                    upsertRoute(
                        destination: "\(destination)/32",
                        gateway: "link#1",
                        interfaceName: arguments[5],
                        flags: arguments.contains("-ifscope") ? "UHSI" : "UHS")
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }
                let scopedInterface = arguments.firstIndex(of: "-ifscope")
                    .flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
                upsertRoute(
                    destination: "\(destination)/32",
                    gateway: arguments[4],
                    interfaceName: scopedInterface ?? defaultInterface,
                    flags: scopedInterface == nil ? "UGHS" : "UGHSI")
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-net", arguments.count >= 4 {
                let destination = arguments[3]
                if failingRouteAdds.contains(destination) {
                    return ShellResult(exitCode: 1, stdout: "", stderr: "mock route add failure")
                }
                if let interfaceIndex = arguments.firstIndex(of: "-interface"),
                    interfaceIndex + 1 < arguments.count
                {
                    upsertRoute(
                        destination: destination,
                        gateway: "link#1",
                        interfaceName: arguments[interfaceIndex + 1],
                        flags: arguments.contains("-ifscope") ? "UGScI" : "UGSc")
                } else if arguments.count >= 5 {
                    let scopedInterface = arguments.firstIndex(of: "-ifscope")
                        .flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
                    upsertRoute(
                        destination: destination,
                        gateway: arguments[4],
                        interfaceName: scopedInterface ?? defaultInterface,
                        flags: scopedInterface == nil ? "UGSc" : "UGScI")
                }
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }
        }

        if arguments.count >= 3, arguments[0] == "-n", arguments[1] == "delete" {
            if arguments[2] == "default" {
                routes.removeAll { $0.destination == "default" }
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-net",
                arguments.count >= 8,
                arguments[3] == "-inet6"
            {
                let prefixLength = arguments[6]
                let destination = "\(arguments[4])/\(prefixLength)"
                if ignoredRouteDeletes.contains(destination) {
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }
                let interfaceName =
                    arguments.firstIndex(of: "-interface")
                    .flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
                    ?? arguments.firstIndex(of: "-ifscope")
                    .flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
                    ?? (arguments.contains("-reject") ? "lo0" : nil)
                let gateway =
                    arguments.count >= 8 && !arguments[7].hasPrefix("-")
                    ? arguments[7]
                    : nil
                let requestedScope = arguments.contains("-ifscope")
                ipv6Routes.removeAll { route in
                    route.destination == destination
                        && route.flags.contains("I") == requestedScope
                        && (interfaceName == nil || route.interfaceName == interfaceName)
                        && (gateway == nil
                            || route.gateway == gateway
                            || route.gateway.split(separator: "%", maxSplits: 1).first.map(
                                String.init) == gateway)
                }
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-net", arguments.count >= 4 {
                if ignoredRouteDeletes.contains(arguments[3]) {
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }
                let destination = arguments[3]
                let interfaceName =
                    arguments.firstIndex(of: "-interface")
                    .flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
                    ?? arguments.firstIndex(of: "-ifscope")
                    .flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
                let gateway =
                    arguments.count >= 5 && !arguments[4].hasPrefix("-")
                    ? arguments[4]
                    : nil
                let requestedScope = arguments.contains("-ifscope")
                routes.removeAll { route in
                    route.destination == destination
                        && route.flags.contains("I") == requestedScope
                        && (gateway == nil || route.gateway == gateway)
                        && (interfaceName == nil || route.interfaceName == interfaceName)
                }
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-host", arguments.count >= 4 {
                let destination = arguments[3]
                if ignoredRouteDeletes.contains(destination) {
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }
                let interfaceName =
                    arguments.firstIndex(of: "-interface")
                    .flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
                    ?? arguments.firstIndex(of: "-ifscope")
                    .flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
                let gateway =
                    arguments.count >= 5 && !arguments[4].hasPrefix("-")
                    ? arguments[4]
                    : nil
                let requestedScope = arguments.contains("-ifscope")
                routes.removeAll { route in
                    (route.destination == destination || route.destination == "\(destination)/32")
                        && route.flags.contains("I") == requestedScope
                        && (gateway == nil || route.gateway == gateway)
                        && (interfaceName == nil || route.interfaceName == interfaceName)
                }
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }
        }

        return ShellResult(exitCode: 0, stdout: "", stderr: "")
    }

    private func handleNetworkSetup(arguments: [String]) -> ShellResult {
        guard let command = arguments.first else {
            return ShellResult(exitCode: 1, stdout: "", stderr: "missing networksetup command")
        }

        switch command {
        case "-getdnsservers":
            return ShellResult(
                exitCode: 0,
                stdout: dnsServers.isEmpty
                    ? "There aren't any DNS Servers set on \(serviceName).\n"
                    : dnsServers.joined(separator: "\n") + "\n",
                stderr: "")
        case "-getsearchdomains":
            return ShellResult(
                exitCode: 0,
                stdout: searchDomains.isEmpty
                    ? "There aren't any Search Domains set on \(serviceName).\n"
                    : searchDomains.joined(separator: "\n") + "\n",
                stderr: "")
        case "-setdnsservers":
            dnsServers =
                arguments.dropFirst(2).first == "empty" ? [] : Array(arguments.dropFirst(2))
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        case "-setsearchdomains":
            searchDomains =
                arguments.dropFirst(2).first == "empty" ? [] : Array(arguments.dropFirst(2))
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        case "-setv6off":
            if !ignoreIPv6OffRequests {
                ipv6Mode = "Off"
                ipv6OffNetstatReadCount = 0
                physicalIPv6SnapshotPrepared = false
            }
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        case "-setv6automatic":
            ipv6Mode = "Automatic"
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        case "-setv6linklocal":
            ipv6Mode = "Link-local only"
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        case "-getinfo":
            return ShellResult(
                exitCode: 0,
                stdout: "IPv6: \(ipv6Mode)\n",
                stderr: "")
        case "-listnetworkserviceorder":
            return ShellResult(
                exitCode: 0,
                stdout: """
                    An asterisk (*) denotes that a network service is disabled.
                    (1) \(serviceName)
                    (Hardware Port: Wi-Fi, Device: \(defaultInterface))

                    """,
                stderr: "")
        default:
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        }
    }

    private func handleScutil(_ invocation: ShellInvocation) -> ShellResult {
        if invocation.arguments.isEmpty, let input = invocation.input {
            let script = String(decoding: input, as: UTF8.self)
            scutilInputs.append(script)
        }

        guard invocation.arguments == ["--dns"] else {
            return ShellResult(exitCode: 1, stdout: "", stderr: "unsupported scutil command")
        }

        scutilDNSReadCount += 1
        if let activeDefaultResolverClearsAfterScutilReads,
            scutilDNSReadCount > activeDefaultResolverClearsAfterScutilReads
        {
            activeDefaultDNSServers = dnsServers
            activeDefaultSearchDomains = searchDomains
        }

        var lines = ["DNS configuration", "", "resolver #1"]
        for (index, domain) in activeDefaultSearchDomains.enumerated() {
            lines.append("  search domain[\(index)] : \(domain)")
        }
        for (index, server) in activeDefaultDNSServers.enumerated() {
            lines.append("  nameserver[\(index)] : \(server)")
        }
        lines.append("")
        lines.append("DNS configuration (for scoped queries)")

        return ShellResult(
            exitCode: 0,
            stdout: lines.joined(separator: "\n") + "\n",
            stderr: "")
    }

    private func upsertRoute(
        destination: String, gateway: String, interfaceName: String, flags: String = "UGSc"
    ) {
        let isInterfaceScoped = flags.contains("I")
        routes.removeAll {
            $0.destination == destination
                && (destination == "default"
                    || ($0.interfaceName == interfaceName
                        && $0.flags.contains("I") == isInterfaceScoped))
        }
        routes.append(
            RouteRecord(
                destination: destination, gateway: gateway, interfaceName: interfaceName,
                flags: flags))
    }

    private func upsertIPv6Route(
        destination: String,
        gateway: String,
        interfaceName: String,
        flags: String
    ) {
        let isInterfaceScoped = flags.contains("I")
        ipv6Routes.removeAll {
            $0.destination == destination
                && $0.interfaceName == interfaceName
                && $0.flags.contains("I") == isInterfaceScoped
        }
        ipv6Routes.append(
            RouteRecord(
                destination: destination,
                gateway: gateway,
                interfaceName: interfaceName,
                flags: flags))
    }

    private func routedIPv6Interface(for destination: String) -> String? {
        if let externalIPv6TunnelInterface {
            return externalIPv6TunnelInterface
        }
        let specificRoute =
            ipv6Routes
            .compactMap { record -> (prefixLength: Int, interfaceName: String)? in
                guard let route = IPRoute.canonicalIPv6(record.destination),
                    !record.flags.contains("I"),
                    IPRoute.ipv6Address(destination, isIn: route)
                else {
                    return nil
                }
                return (route.prefixLength, record.interfaceName)
            }
            .max { $0.prefixLength < $1.prefixLength }
        if let specificRoute {
            return specificRoute.interfaceName
        }
        if ipv6Mode == "Off" {
            return nil
        }
        return defaultInterface
    }

    private func routedIPv4Interface(for destination: String) -> String? {
        guard let address = IPRoute.canonicalIPv4Address(destination) else {
            return defaultInterface
        }
        let specificRoute =
            routes
            .compactMap { record -> (prefixLength: Int, interfaceName: String)? in
                guard let route = IPRoute.canonicalIPv4(record.destination),
                    !record.flags.contains("I"),
                    IPRoute.ipv4Address(address, isIn: route)
                else {
                    return nil
                }
                return (route.prefixLength, record.interfaceName)
            }
            .max { $0.prefixLength < $1.prefixLength }
        if let specificRoute {
            return specificRoute.interfaceName
        }
        return defaultInterface
    }

    private func netstatOutput(arguments: [String]) -> String {
        if arguments.contains("inet6") {
            preparePhysicalIPv6RouteSnapshotAfterIPv6OffIfNeeded()
            let header = """
                Routing tables

                Internet6:
                Destination        Gateway            Flags               Netif Expire
                """

            let rows = ipv6Routes.map { route in
                "\(route.destination)\t\(route.gateway)\t\(route.flags)\t\(route.interfaceName)"
            }

            completePhysicalIPv6RouteSnapshotAfterIPv6OffIfNeeded()
            return header + "\n" + rows.joined(separator: "\n") + "\n"
        }

        let header = """
            Routing tables

            Internet:
            Destination        Gateway            Flags               Netif Expire
            """

        let rows = routes.map { route in
            [
                route.destination,
                route.gateway,
                route.flags,
                route.interfaceName,
                route.expire,
            ].compactMap { $0 }.joined(separator: "\t")
        }

        return header + "\n" + rows.joined(separator: "\n") + "\n"
    }

    private func preparePhysicalIPv6RouteSnapshotAfterIPv6OffIfNeeded() {
        guard ipv6Mode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "off",
            let snapshots = physicalIPv6RouteSnapshotsAfterIPv6Off,
            !snapshots.isEmpty,
            !physicalIPv6SnapshotPrepared
        else {
            return
        }
        let index =
            repeatPhysicalIPv6RouteSnapshotsAfterIPv6Off
            ? ipv6OffNetstatReadCount % snapshots.count
            : min(ipv6OffNetstatReadCount, snapshots.count - 1)
        ipv6Routes.removeAll { record in
            guard record.interfaceName == defaultInterface,
                let route = IPRoute.canonicalIPv6(record.destination)
            else {
                return false
            }
            return RouteManager.ipv6RouteTouchesPublicGlobalUnicast(route)
        }
        ipv6Routes.append(contentsOf: snapshots[index])
        physicalIPv6SnapshotPrepared = true
    }

    private func completePhysicalIPv6RouteSnapshotAfterIPv6OffIfNeeded() {
        guard physicalIPv6SnapshotPrepared else {
            return
        }
        ipv6OffNetstatReadCount += 1
        physicalIPv6SnapshotPrepared = false
    }
}
