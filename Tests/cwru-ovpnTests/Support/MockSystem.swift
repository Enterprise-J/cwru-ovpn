import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

enum MockSystemError: LocalizedError {
    case unexpectedCommand(String)

    var errorDescription: String? {
        switch self {
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
    private var tunnelInterfaces: Set<String>
    private let blockedIPv6ProbeDestinations: Set<String>
    private let unexpectedIPv6ProbeFailures: Set<String>
    private let externalIPv6TunnelInterface: String?
    private let failingRouteAdds: Set<String>
    private let failingCommandFragments: Set<String>
    private let ignoredRouteDeletes: Set<String>
    private let activeResolverPublicationDelayReads: Int?
    private var pendingResolverPublicationReads: Int?
    private let supplementalResolverPublicationDelayReads: Int?
    private var pendingSupplementalPublicationReads: Int?
    private var observedSupplementalResolvers: [String: [String]] = [:]
    private var activeSupplementalResolvers: [String: [String]] = [:]
    private let ignoreIPv6OffRequests: Bool
    private let physicalIPv6RouteSnapshotsAfterIPv6Off: [[RouteRecord]]?
    private let repeatPhysicalIPv6RouteSnapshotsAfterIPv6Off: Bool
    private let physicalIfconfigOutput: String?
    private var routes: [RouteRecord]
    private var ipv6Routes: [RouteRecord]
    private var ipv6OffNetstatReadCount = 0
    private var physicalIPv6SnapshotPrepared = false

    var recordedCommands: [String] = []
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
        activeResolverPublicationDelayReads: Int? = 1,
        supplementalResolverPublicationDelayReads: Int? = 0,
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
        self.activeResolverPublicationDelayReads = activeResolverPublicationDelayReads
        self.supplementalResolverPublicationDelayReads = supplementalResolverPublicationDelayReads
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

    func releaseTunnelInterface(named interfaceName: String) {
        tunnelInterfaces.remove(interfaceName)
        routes.removeAll { $0.interfaceName == interfaceName }
        ipv6Routes.removeAll { $0.interfaceName == interfaceName }
    }

    func handle(_ invocation: CommandInvocation) throws -> CommandResult {
        let command = ([invocation.launchPath] + invocation.arguments).joined(separator: " ")
        recordedCommands.append(command)
        if failingCommandFragments.contains(where: { command.contains($0) }) {
            return CommandResult(exitCode: 1, stdout: "", stderr: "mock command failure")
        }

        switch invocation.launchPath {
        case "/sbin/route":
            return handleRoute(arguments: invocation.arguments)
        case "/usr/sbin/netstat":
            return CommandResult(
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
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case "/sbin/ifconfig":
            let interfaceName = invocation.arguments.first ?? ""
            if interfaceName == defaultInterface || tunnelInterfaces.contains(interfaceName) {
                let output = interfaceName == defaultInterface ? physicalIfconfigOutput : nil
                return CommandResult(exitCode: 0,
                                     stdout: output ?? "\(interfaceName): flags=8863<UP,BROADCAST>\n",
                                     stderr: "")
            }
            return CommandResult(
                exitCode: 1, stdout: "", stderr: "ifconfig: interface \(interfaceName) does not exist\n")
        default:
            break
        }

        throw MockSystemError.unexpectedCommand(
            ([invocation.launchPath] + invocation.arguments).joined(separator: " ")
        )
    }

    private func handleIPConfig(arguments: [String]) -> CommandResult {
        guard arguments.count >= 2 else {
            return CommandResult(exitCode: 1, stdout: "", stderr: "unsupported ipconfig command")
        }

        switch arguments[0] {
        case "getpacket":
            guard arguments[1] == defaultInterface else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "no DHCP packet")
            }
            return CommandResult(
                exitCode: 0,
                stdout: "yiaddr = 192.168.1.50\nserver_identifier = \(defaultGateway)\n",
                stderr: "")
        case "set":
            guard arguments.count == 3,
                arguments[1] == defaultInterface,
                arguments[2] == "DHCP"
            else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "unsupported ipconfig set")
            }
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        default:
            return CommandResult(exitCode: 1, stdout: "", stderr: "unsupported ipconfig command")
        }
    }

    private func handleDSCacheUtil(arguments: [String]) -> CommandResult {
        if arguments == ["-flushcache"] {
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        }

        return CommandResult(exitCode: 1, stdout: "", stderr: "unsupported dscacheutil command")
    }

    private func scheduleResolverPublication() {
        pendingResolverPublicationReads = activeResolverPublicationDelayReads
    }

    private func publishResolverConfigurationIfDue() {
        guard let remainingReads = pendingResolverPublicationReads else {
            return
        }
        guard remainingReads == 0 else {
            pendingResolverPublicationReads = remainingReads - 1
            return
        }
        activeDefaultDNSServers = dnsServers
        activeDefaultSearchDomains = searchDomains
        pendingResolverPublicationReads = nil
    }

    private func publishSupplementalResolversIfDue() {
        var configured: [String: [String]] = [:]
        if let directory = TestDependencies.resolverDirectory,
           let files = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) {
            for file in files where !file.lastPathComponent.hasPrefix(".") {
                guard let contents = try? String(contentsOf: file, encoding: .utf8) else {
                    continue
                }
                var domain = file.lastPathComponent
                var servers: [String] = []
                for line in contents.split(whereSeparator: \.isNewline) {
                    let fields = line.split(whereSeparator: \.isWhitespace)
                    guard fields.count >= 2 else {
                        continue
                    }
                    if fields[0] == "domain" {
                        domain = String(fields[1])
                    } else if fields[0] == "nameserver", servers.count < 3 {
                        servers.append(String(fields[1]))
                    }
                }
                configured[domain] = servers
            }
        }
        if configured != observedSupplementalResolvers {
            observedSupplementalResolvers = configured
            pendingSupplementalPublicationReads = supplementalResolverPublicationDelayReads
        }
        guard let remainingReads = pendingSupplementalPublicationReads else {
            return
        }
        guard remainingReads == 0 else {
            pendingSupplementalPublicationReads = remainingReads - 1
            return
        }
        activeSupplementalResolvers = observedSupplementalResolvers
        pendingSupplementalPublicationReads = nil
    }

    private func handleRoute(arguments: [String]) -> CommandResult {
        if arguments == ["-n", "get", "default"] {
            return CommandResult(
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
                return CommandResult(
                    exitCode: 1, stdout: "", stderr: "route: mocked routing socket failure")
            }
            if blockedIPv6ProbeDestinations.contains(arguments[3]) {
                return CommandResult(
                    exitCode: 0,
                    stdout:
                        "route to: \(arguments[3])\ngateway: ::1\ninterface: lo0\nflags: <UP,GATEWAY,REJECT,DONE,STATIC>\n",
                    stderr: "")
            }
            guard let interfaceName = routedIPv6Interface(for: arguments[3]) else {
                return CommandResult(
                    exitCode: 0, stdout: "",
                    stderr: "route: writing to routing socket: not in table\n")
            }
            if interfaceName == "lo0" {
                return CommandResult(
                    exitCode: 0,
                    stdout:
                        "route to: \(arguments[3])\ngateway: ::1\ninterface: lo0\nflags: <UP,GATEWAY,REJECT,DONE,STATIC>\n",
                    stderr: "")
            }
            return CommandResult(
                exitCode: 0,
                stdout:
                    "route to: \(arguments[3])\ngateway: fe80::%\(interfaceName)\ninterface: \(interfaceName)\n",
                stderr: "")
        }

        if arguments.count >= 3, arguments[0] == "-n", arguments[1] == "get", arguments[2] != "-inet6" {
            let destination = arguments[2]
            let interfaceScope = arguments.firstIndex(of: "-ifscope")
                .flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
            if NetworkValidation.isValidIPv4Address(destination),
                let interfaceName = routedIPv4Interface(for: destination, interfaceScope: interfaceScope)
            {
                return CommandResult(
                    exitCode: 0,
                    stdout:
                        "route to: \(destination)\ngateway: link#1\ninterface: \(interfaceName)\n",
                    stderr: "")
            }
            return CommandResult(
                exitCode: 0, stdout: "", stderr: "route: writing to routing socket: not in table\n")
        }

        if arguments.count >= 4, arguments[0] == "-n", arguments[1] == "add" {
            if arguments[2] == "default", arguments.count >= 4 {
                defaultGateway = arguments[3]
                upsertRoute(
                    destination: "default", gateway: defaultGateway, interfaceName: defaultInterface
                )
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
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
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-net",
                arguments.count >= 8,
                arguments[3] == "-inet6"
            {
                let prefixLength = arguments[6]
                let destination = "\(arguments[4])/\(prefixLength)"
                if failingRouteAdds.contains(destination) {
                    return CommandResult(exitCode: 1, stdout: "", stderr: "mock route add failure")
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
                    return CommandResult(
                        exitCode: 1, stdout: "",
                        stderr: "route: writing to routing socket: File exists")
                }
                ipv6Routes.append(
                    RouteRecord(
                        destination: destination,
                        gateway: gateway,
                        interfaceName: interfaceName,
                        flags: arguments.contains("-reject") ? "UGRS" : "UGSc"))
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-host", arguments.count >= 5 {
                let destination = arguments[3]
                if failingRouteAdds.contains(destination) {
                    return CommandResult(exitCode: 1, stdout: "", stderr: "mock route add failure")
                }
                if arguments[4] == "-interface", arguments.count >= 6 {
                    upsertRoute(
                        destination: "\(destination)/32",
                        gateway: "link#1",
                        interfaceName: arguments[5],
                        flags: arguments.contains("-ifscope") ? "UHSI" : "UHS")
                    return CommandResult(exitCode: 0, stdout: "", stderr: "")
                }
                let scopedInterface = arguments.firstIndex(of: "-ifscope")
                    .flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
                upsertRoute(
                    destination: "\(destination)/32",
                    gateway: arguments[4],
                    interfaceName: scopedInterface ?? defaultInterface,
                    flags: scopedInterface == nil ? "UGHS" : "UGHSI")
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-net", arguments.count >= 4 {
                let destination = arguments[3]
                if failingRouteAdds.contains(destination) {
                    return CommandResult(exitCode: 1, stdout: "", stderr: "mock route add failure")
                }
                if let interfaceIndex = arguments.firstIndex(of: "-interface"),
                    interfaceIndex + 1 < arguments.count
                {
                    upsertRoute(
                        destination: destination,
                        gateway: "link#1",
                        interfaceName: arguments[interfaceIndex + 1],
                        flags: arguments.contains("-ifscope") ? "UGScI" : "UGSc")
                }
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }
        }

        if arguments.count >= 3, arguments[0] == "-n", arguments[1] == "delete" {
            if arguments[2] == "default" {
                routes.removeAll { $0.destination == "default" }
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-net",
                arguments.count >= 8,
                arguments[3] == "-inet6"
            {
                let prefixLength = arguments[6]
                let destination = "\(arguments[4])/\(prefixLength)"
                if ignoredRouteDeletes.contains(destination) {
                    return CommandResult(exitCode: 0, stdout: "", stderr: "")
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
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-net", arguments.count >= 4 {
                if ignoredRouteDeletes.contains(arguments[3]) {
                    return CommandResult(exitCode: 0, stdout: "", stderr: "")
                }
                let destination = arguments[3]
                let interfaceName =
                    arguments.firstIndex(of: "-interface")
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
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments[2] == "-host", arguments.count >= 4 {
                let destination = arguments[3]
                if ignoredRouteDeletes.contains(destination) {
                    return CommandResult(exitCode: 0, stdout: "", stderr: "")
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
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }
        }

        return CommandResult(exitCode: 0, stdout: "", stderr: "")
    }

    private func handleNetworkSetup(arguments: [String]) -> CommandResult {
        guard let command = arguments.first else {
            return CommandResult(exitCode: 1, stdout: "", stderr: "missing networksetup command")
        }

        switch command {
        case "-getdnsservers":
            return CommandResult(
                exitCode: 0,
                stdout: dnsServers.isEmpty
                    ? "There aren't any DNS Servers set on \(serviceName).\n"
                    : dnsServers.joined(separator: "\n") + "\n",
                stderr: "")
        case "-getsearchdomains":
            return CommandResult(
                exitCode: 0,
                stdout: searchDomains.isEmpty
                    ? "There aren't any Search Domains set on \(serviceName).\n"
                    : searchDomains.joined(separator: "\n") + "\n",
                stderr: "")
        case "-setdnsservers":
            dnsServers =
                arguments.dropFirst(2).first == "empty" ? [] : Array(arguments.dropFirst(2))
            scheduleResolverPublication()
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case "-setsearchdomains":
            searchDomains =
                arguments.dropFirst(2).first == "empty" ? [] : Array(arguments.dropFirst(2))
            scheduleResolverPublication()
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case "-setv6off":
            if !ignoreIPv6OffRequests {
                ipv6Mode = "Off"
                ipv6OffNetstatReadCount = 0
                physicalIPv6SnapshotPrepared = false
            }
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case "-setv6automatic":
            ipv6Mode = "Automatic"
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case "-setv6linklocal":
            ipv6Mode = "Link-local only"
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case "-getinfo":
            return CommandResult(
                exitCode: 0,
                stdout: "IPv6: \(ipv6Mode)\n",
                stderr: "")
        case "-listnetworkserviceorder":
            return CommandResult(
                exitCode: 0,
                stdout: """
                    An asterisk (*) denotes that a network service is disabled.
                    (1) \(serviceName)
                    (Hardware Port: Wi-Fi, Device: \(defaultInterface))

                    """,
                stderr: "")
        default:
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        }
    }

    private func handleScutil(_ invocation: CommandInvocation) -> CommandResult {
        guard invocation.arguments == ["--dns"] else {
            return CommandResult(exitCode: 1, stdout: "", stderr: "unsupported scutil command")
        }

        publishResolverConfigurationIfDue()
        publishSupplementalResolversIfDue()

        var lines = ["DNS configuration", "", "resolver #1"]
        for (index, domain) in activeDefaultSearchDomains.enumerated() {
            lines.append("  search domain[\(index)] : \(domain)")
        }
        for (index, server) in activeDefaultDNSServers.enumerated() {
            lines.append("  nameserver[\(index)] : \(server)")
        }
        for (index, domain) in activeSupplementalResolvers.keys.sorted().enumerated() {
            lines.append("")
            lines.append("resolver #\(index + 2)")
            lines.append("  domain : \(domain)")
            for (serverIndex, server) in (activeSupplementalResolvers[domain] ?? []).enumerated() {
                lines.append("  nameserver[\(serverIndex)] : \(server)")
            }
            lines.append("  flags : Supplemental, Request A records, Request AAAA records")
            lines.append("  order : 1")
        }
        lines.append("")
        lines.append("DNS configuration (for scoped queries)")

        return CommandResult(
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

    private func routedIPv4Interface(for destination: String, interfaceScope: String? = nil) -> String? {
        guard let address = IPRoute.canonicalIPv4Address(destination) else {
            return defaultInterface
        }
        let specificRoute =
            routes
            .compactMap { record -> (prefixLength: Int, interfaceName: String)? in
                guard let route = IPRoute.canonicalIPv4(record.destination),
                    interfaceScope.map({ record.interfaceName == $0 }) ?? !record.flags.contains("I"),
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
        if let interfaceScope {
            return routes.contains { $0.interfaceName == interfaceScope } ? interfaceScope : nil
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
