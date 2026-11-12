import Foundation
import Darwin

extension RouteManager {
    private enum RouteCommand: String {
        case add
        case delete
    }

    func ipv4RouteExists(_ configuredRoute: String, on interfaceName: String, in entries: [RouteEntry]) -> Bool {
        guard let configuredRoute = IPRoute.canonicalIPv4(configuredRoute) else {
            return false
        }
        return entries.contains {
            !$0.isInterfaceScoped && $0.interfaceName == interfaceName
                && IPRoute.canonicalIPv4($0.destination) == configuredRoute
        }
    }

    func ipv6RouteExists(_ configuredRoute: String, on interfaceName: String, in entries: [RouteEntry]) -> Bool {
        guard let configuredRoute = IPRoute.canonicalIPv6(configuredRoute) else {
            return false
        }
        return entries.contains {
            !$0.isInterfaceScoped && $0.interfaceName == interfaceName
                && IPRoute.canonicalIPv6($0.destination) == configuredRoute
        }
    }

    func ipv4RoutingTableEntries() throws -> [RouteEntry] {
        try routeTable(family: "inet")
    }

    func ipv6RoutingTableEntries() throws -> [RouteEntry] {
        try routeTable(family: "inet6")
    }

    private func routeTable(family: String) throws -> [RouteEntry] {
        try commandRunner.run("/usr/sbin/netstat", arguments: ["-nrf", family]).stdout
            .split(separator: "\n")
            .compactMap(RouteEntry.init(line:))
    }

    func fullTunnelRoutesMatch(_ routes: [ManagedIPv4Route]) throws -> Bool {
        let entries = try ipv4RoutingTableEntries()
        return routes.allSatisfy { route in
            route.nextHopKind == .interface
                && route.nextHopValue == route.interfaceName
                && ipv4RouteExists(route, in: entries)
        }
    }

    func installFailClosedTunnelDefaultRoutes(tunnelName: String) throws {
        for route in fullTunnelDefaultRoutes(tunnelName: tunnelName) {
            try addIPv4Route(route, allowNonZero: true)
        }
    }

    func installBlockedIPv6DefaultRoutes(using state: inout SessionState,
                                         persistPreparedState: (SessionState) throws -> Void) throws {
        for destination in Self.ipv6DefaultHalfRoutes {
            try installManagedBlockedIPv6Route(destination, using: &state, persistPreparedState: persistPreparedState)
        }
    }

    func installManagedRoutesIfMissing(_ routes: [ManagedIPv4Route]) throws {
        guard !routes.isEmpty else {
            return
        }
        let entries = try ipv4RoutingTableEntries()
        let missingRoutes = try routes.filter { try managedIPv4RouteNeedsInstallation($0, in: entries) }
        guard !missingRoutes.isEmpty else {
            return
        }
        for route in missingRoutes {
            try addIPv4Route(route, allowNonZero: false)
        }
        let installedEntries = try ipv4RoutingTableEntries()
        if let missing = routes.first(where: { !ipv4RouteExists($0, in: installedEntries) }) {
            throw RouteManagerError.failedToInstallManagedRoute(missing.destination)
        }
    }

    func installManagedRoutesIfMissing(_ routes: [ManagedIPv6Route]) throws {
        guard !routes.isEmpty else {
            return
        }
        let entries = try ipv6RoutingTableEntries()
        let missingRoutes = try routes.filter { try managedIPv6RouteNeedsInstallation($0, in: entries) }
        guard !missingRoutes.isEmpty else {
            return
        }
        for route in missingRoutes {
            _ = try addIPv6Route(route, allowNonZero: false)
        }
        let installedEntries = try ipv6RoutingTableEntries()
        if let missing = routes.first(where: { !ipv6RouteExists($0, in: installedEntries) }) {
            throw RouteManagerError.failedToInstallManagedRoute(missing.destination)
        }
    }

    func managedIPv4Route(from entry: RouteEntry) -> ManagedIPv4Route? {
        guard let destination = IPRoute.canonicalIPv4(entry.destination)?.routeString else {
            return nil
        }
        if NetworkValidation.isValidIPv4Address(entry.gateway) {
            return ManagedIPv4Route(destination: destination,
                                    nextHopKind: .gateway,
                                    nextHopValue: entry.gateway,
                                    interfaceName: entry.interfaceName,
                                    isInterfaceScoped: entry.isInterfaceScoped)
        }
        guard NetworkValidation.isSafeInterfaceName(entry.interfaceName) else {
            return nil
        }
        return ManagedIPv4Route(destination: destination,
                                nextHopKind: .interface,
                                nextHopValue: entry.interfaceName,
                                interfaceName: entry.interfaceName,
                                isInterfaceScoped: entry.isInterfaceScoped)
    }

    func ipv4RouteExists(_ route: ManagedIPv4Route, in entries: [RouteEntry]) -> Bool {
        entries.contains { managedIPv4Route(from: $0) == route }
    }

    func ownedManagedIPv4RouteExists(_ route: ManagedIPv4Route,
                                     in entries: [RouteEntry],
                                     requiresHostFlag: Bool) -> Bool {
        entries.contains {
            $0.isStatic && (!requiresHostFlag || $0.hasHostFlag) && managedIPv4Route(from: $0) == route
        }
    }

    func ipv4RouteEntryMatches(_ candidate: RouteEntry, ownershipOf expected: RouteEntry) -> Bool {
        IPRoute.canonicalIPv4(candidate.destination) == IPRoute.canonicalIPv4(expected.destination)
            && candidate.gateway == expected.gateway
            && candidate.interfaceName == expected.interfaceName
            && candidate.isInterfaceScoped == expected.isInterfaceScoped
            && candidate.isStatic == expected.isStatic
            && candidate.hasHostFlag == expected.hasHostFlag
    }

    private func ipv4RouteArguments(_ command: RouteCommand, _ route: ManagedIPv4Route) -> [String]? {
        guard let canonical = IPRoute.canonicalIPv4(route.destination) else {
            return nil
        }
        let isHost = canonical.prefixLength == 32
        var arguments = ["-n", command.rawValue, isHost ? "-host" : "-net", isHost ? canonical.addressString : canonical.routeString]
        switch route.nextHopKind {
        case .gateway:
            arguments.append(route.nextHopValue)
        case .interface:
            arguments += ["-interface", route.nextHopValue]
        }
        if route.isInterfaceScoped {
            arguments += ["-ifscope", route.interfaceName]
        }
        return arguments
    }

    func addIPv4Route(_ route: ManagedIPv4Route, allowNonZero: Bool) throws {
        guard let arguments = ipv4RouteArguments(.add, route) else {
            throw RouteManagerError.failedToInstallManagedRoute(route.destination)
        }
        _ = try commandRunner.run("/sbin/route", arguments: arguments, allowNonZero: allowNonZero)
    }

    func refreshPhysicalRoutes(using state: inout SessionState,
                               persistPreparedState: (SessionState) throws -> Void) throws {
        let routes = (state.managedRemoteIPv4Routes ?? []).filter { $0.interfaceName == state.physicalInterface }
        guard !routes.isEmpty else {
            return
        }
        for route in routes {
            try deleteManagedIPv4RouteIfPresent(route, verifyRemoval: true, requiresHostFlag: true)
        }
        try ensureRemoteHostRoutes(using: &state,
                                   mode: state.tunnelMode,
                                   context: "an interface IPv4 change",
                                   persistPreparedState: persistPreparedState)
    }

    func deleteManagedIPv4RouteIfPresent(_ route: ManagedIPv4Route,
                                         verifyRemoval: Bool = false,
                                         requiresHostFlag: Bool = false) throws {
        guard ownedManagedIPv4RouteExists(route, in: try ipv4RoutingTableEntries(), requiresHostFlag: requiresHostFlag),
              let arguments = ipv4RouteArguments(.delete, route) else {
            return
        }
        _ = try commandRunner.run("/sbin/route", arguments: arguments, allowNonZero: true)
        if verifyRemoval,
           ownedManagedIPv4RouteExists(route, in: try ipv4RoutingTableEntries(), requiresHostFlag: requiresHostFlag) {
            throw RouteManagerError.failedToDeleteManagedRoute(route.destination)
        }
    }

    func deleteIPv4RouteEntryIfPresent(_ entry: RouteEntry, verifyRemoval: Bool = false) throws {
        guard let route = managedIPv4Route(from: entry),
              let arguments = ipv4RouteArguments(.delete, route),
              try ipv4RoutingTableEntries().contains(where: { ipv4RouteEntryMatches($0, ownershipOf: entry) }) else {
            return
        }
        _ = try commandRunner.run("/sbin/route", arguments: arguments, allowNonZero: true)
        if verifyRemoval,
           try ipv4RoutingTableEntries().contains(where: { ipv4RouteEntryMatches($0, ownershipOf: entry) }) {
            throw RouteManagerError.failedToDeleteManagedRoute(route.destination)
        }
    }

    func restoreManagedIPv4RouteIfMissing(_ route: ManagedIPv4Route) throws {
        let entries = try ipv4RoutingTableEntries()
        guard !ownedManagedIPv4RouteExists(route, in: entries, requiresHostFlag: true),
              let canonical = IPRoute.canonicalIPv4(route.destination) else {
            return
        }
        guard try replacedRemoteHostRouteIsRestorable(route) else {
            return
        }
        guard !entries.contains(where: {
            IPRoute.canonicalIPv4($0.destination) == canonical
                && $0.interfaceName == route.interfaceName
                && $0.isInterfaceScoped == route.isInterfaceScoped
        }) else {
            throw RouteManagerError.refusingToReplaceExistingRoute(route.destination)
        }
        try addIPv4Route(route, allowNonZero: true)
    }

    func managedIPv4RouteNeedsInstallation(_ route: ManagedIPv4Route, in entries: [RouteEntry]) throws -> Bool {
        guard let destination = IPRoute.canonicalIPv4(route.destination) else {
            throw RouteManagerError.failedToInstallManagedRoute(route.destination)
        }
        let matchingEntries = entries.filter { IPRoute.canonicalIPv4($0.destination) == destination }
        if ipv4RouteExists(route, in: matchingEntries) {
            return false
        }
        guard !matchingEntries.contains(where: {
            $0.interfaceName != route.interfaceName || $0.isInterfaceScoped == route.isInterfaceScoped
        }) else {
            throw RouteManagerError.refusingToReplaceExistingRoute(route.destination)
        }
        return true
    }

    func ipv6RouteExists(_ route: ManagedIPv6Route, in entries: [RouteEntry]) -> Bool {
        guard let destination = IPRoute.canonicalIPv6(route.destination) else {
            return false
        }
        return entries.contains { entry in
            guard IPRoute.canonicalIPv6(entry.destination) == destination,
                  entry.isInterfaceScoped == route.isInterfaceScoped,
                  entry.interfaceName == route.interfaceName else {
                return false
            }
            switch route.nextHopKind {
            case .interface:
                return true
            case .reject:
                return entry.flags.contains("R")
            }
        }
    }

    func deleteManagedIPv6RouteIfPresent(_ route: ManagedIPv6Route, verifyRemoval: Bool = false) throws {
        guard ipv6RouteExists(route, in: try ipv6RoutingTableEntries()),
              let canonical = IPRoute.canonicalIPv6(route.destination) else {
            return
        }
        var arguments = ["-n", "delete", "-net", "-inet6", canonical.addressString, "-prefixlen", String(canonical.prefixLength)]
        switch route.nextHopKind {
        case .interface:
            arguments += ["-interface", route.nextHopValue]
        case .reject:
            arguments += ["-reject", route.nextHopValue]
        }
        _ = try commandRunner.run("/sbin/route", arguments: arguments, allowNonZero: true)
        if verifyRemoval, ipv6RouteExists(route, in: try ipv6RoutingTableEntries()) {
            throw RouteManagerError.failedToDeleteManagedRoute(route.destination)
        }
    }

    func deleteIPv6RouteIfPresent(_ destination: String, interfaceName: String, verifyRemoval: Bool = false) throws {
        try deleteManagedIPv6RouteIfPresent(ManagedIPv6Route(destination: destination, viaInterface: interfaceName),
                                            verifyRemoval: verifyRemoval)
    }

    func managedIPv6RouteNeedsInstallation(_ route: ManagedIPv6Route, in entries: [RouteEntry]) throws -> Bool {
        guard let destination = IPRoute.canonicalIPv6(route.destination) else {
            throw RouteManagerError.failedToInstallManagedRoute(route.destination)
        }
        let matchingEntries = entries.filter { IPRoute.canonicalIPv6($0.destination) == destination }
        if ipv6RouteExists(route, in: matchingEntries) {
            return false
        }
        guard matchingEntries.isEmpty else {
            throw RouteManagerError.refusingToReplaceExistingRoute(route.destination)
        }
        return true
    }

    func addIPv6Route(_ route: ManagedIPv6Route, allowNonZero: Bool) throws -> Bool {
        guard let canonical = IPRoute.canonicalIPv6(route.destination) else {
            throw RouteManagerError.failedToInstallManagedRoute(route.destination)
        }
        let arguments: [String]
        switch route.nextHopKind {
        case .interface:
            arguments = ["-n", "add", "-inet6", canonical.routeString, "-interface", route.nextHopValue]
        case .reject:
            arguments = ["-n", "add", "-net", "-inet6", canonical.addressString, "-prefixlen", String(canonical.prefixLength), "-reject", route.nextHopValue]
        }
        return try commandRunner.run("/sbin/route", arguments: arguments, allowNonZero: allowNonZero).exitCode == 0
    }

    func installManagedBlockedIPv6Route(_ destination: String,
                                        using state: inout SessionState,
                                        persistPreparedState: (SessionState) throws -> Void) throws {
        let route = ManagedIPv6Route(blocking: destination)
        guard try managedIPv6RouteNeedsInstallation(route, in: try ipv6RoutingTableEntries()) else {
            return
        }
        var managedRoutes = state.managedIPv6Routes ?? []
        if !managedRoutes.contains(route) {
            managedRoutes.append(route)
        }
        state.managedIPv6Routes = managedRoutes
        try persistPreparedState(state)
        guard try addIPv6Route(route, allowNonZero: true),
              ipv6RouteExists(route, in: try ipv6RoutingTableEntries()) else {
            throw RouteManagerError.failedToInstallManagedRoute(route.destination)
        }
    }

    func fullTunnelDefaultRoutes(tunnelName: String) -> [ManagedIPv4Route] {
        Self.ipv4DefaultHalfRoutes.map { ManagedIPv4Route(destination: $0.routeString, viaInterface: tunnelName) }
    }

    func validatedTunnelInterfaceName(_ tunnelName: String) throws -> String {
        guard NetworkValidation.isSafeInterfaceName(tunnelName) else {
            throw RouteManagerError.invalidTunnelInterface
        }
        return tunnelName
    }

    func tunnelIPv4DefaultHalfRouteExists(on tunnelName: String,
                                          in entries: [RouteEntry]) -> Bool {
        entries.contains { entry in
            guard entry.interfaceName == tunnelName,
                  let destination = IPRoute.canonicalIPv4(entry.destination) else {
                return false
            }
            return Self.ipv4DefaultHalfRoutes.contains(destination)
        }
    }

    func removeTunnelDefaultRoutes(tunnelName: String) throws {
        var firstError: Error?
        do {
            let tunnelDefaultHalves = try ipv4RoutingTableEntries().compactMap { entry -> ManagedIPv4Route? in
                guard entry.interfaceName == tunnelName,
                      let destination = IPRoute.canonicalIPv4(entry.destination),
                      Self.ipv4DefaultHalfRoutes.contains(destination) else {
                    return nil
                }
                return managedIPv4Route(from: entry)
            }
            for route in tunnelDefaultHalves {
                do {
                    try deleteManagedIPv4RouteIfPresent(route, verifyRemoval: true)
                } catch {
                    firstError = firstError ?? error
                }
            }
        } catch {
            firstError = error
        }

        do {
            try removeTunnelIPv6DefaultRoutes(tunnelName: tunnelName)
        } catch {
            firstError = firstError ?? error
        }

        if let firstError {
            throw firstError
        }
    }

    func removeTunnelIPv6DefaultRoutes(tunnelName: String) throws {
        for route in Self.ipv6DefaultHalfRoutes {
            try deleteManagedIPv6RouteIfPresent(ManagedIPv6Route(destination: route, viaInterface: tunnelName),
                                                verifyRemoval: true)
        }
    }

    func tunnelInterfaceIsPresent(named tunnelName: String) -> Bool {
        guard let result = try? commandRunner.run("/sbin/ifconfig", arguments: [tunnelName], allowNonZero: true) else {
            return false
        }
        return result.exitCode == 0
    }

    func currentDefaultInterface(in entries: [RouteEntry]) -> String? {
        entries.first { $0.destination == "default" }?.interfaceName
    }

    struct RouteLookup {
        let gateway: String?
        let interfaceName: String
        let isRejected: Bool
    }

    func routeLookup(for destination: String, ipv6: Bool = false,
                     interfaceScope: String? = nil) throws -> RouteLookup? {
        let arguments = ["-n", "get"] + (ipv6 ? ["-inet6"] : []) + [destination]
            + (interfaceScope.map { ["-ifscope", $0] } ?? [])
        let probe = try commandRunner.run("/sbin/route", arguments: arguments, allowNonZero: true)
        let diagnostic = probe.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        if probe.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            if diagnostic == "route: writing to routing socket: not in table"
                || diagnostic == "route: writing to routing socket: Network is unreachable" {
                return nil
            }
            if probe.exitCode != 0, let interfaceScope,
               diagnostic == "route: bad interface name",
               try physicalInterfaceConfigurationOutput(interfaceScope) == nil {
                return nil
            }
        }
        guard probe.exitCode == 0, diagnostic.isEmpty else {
            throw CommandError.commandFailed((["/sbin/route"] + arguments).joined(separator: " "), probe.exitCode, probe.stderr)
        }
        let parsed = parseGatewayAndInterface(probe.stdout)
        guard let interfaceName = parsed.interfaceName, NetworkValidation.isSafeInterfaceName(interfaceName) else {
            throw ipv6 ? RouteManagerError.failedToInspectPublicIPv6Routes : RouteManagerError.failedToInspectPublicIPv4Routes
        }
        return RouteLookup(gateway: parsed.gateway, interfaceName: interfaceName, isRejected: probe.stdout.contains("REJECT"))
    }

    func physicalGatewayIsOnLink(_ gateway: String, on interfaceName: String, scoped: Bool = false) throws -> Bool {
        guard NetworkValidation.isValidIPv4Address(gateway) else {
            throw RouteManagerError.couldNotDeterminePhysicalGateway
        }
        guard let parsed = try routeLookup(for: gateway, interfaceScope: scoped ? interfaceName : nil),
              parsed.interfaceName == interfaceName,
              !NetworkValidation.isVirtualInterfaceName(parsed.interfaceName) else {
            return false
        }
        guard let resolvedGateway = parsed.gateway,
              NetworkValidation.isValidIPv4Address(resolvedGateway) else {
            return true
        }
        return resolvedGateway == gateway
    }

    func replacedRemoteHostRouteIsRestorable(_ route: ManagedIPv4Route) throws -> Bool {
        switch route.nextHopKind {
        case .gateway:
            return try physicalGatewayIsOnLink(route.nextHopValue, on: route.interfaceName, scoped: route.isInterfaceScoped)
        case .interface:
            return try !physicalIPv4Addresses(interfaceName: route.nextHopValue).isEmpty
        }
    }

    func parseGatewayAndInterface(_ output: String) -> (gateway: String?, interfaceName: String?) {
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

struct RouteEntry {
    let destination: String
    let gateway: String
    let flags: String
    let interfaceName: String

    var isStatic: Bool {
        flags.contains("S")
    }

    var isHost: Bool {
        if flags.contains("H") {
            return true
        }
        if let ipv4Route = IPRoute.canonicalIPv4(destination) {
            return ipv4Route.prefixLength == 32
        }
        if let ipv6Route = IPRoute.canonicalIPv6(destination) {
            return ipv6Route.prefixLength == 128
        }
        return false
    }

    var hasHostFlag: Bool {
        flags.contains("H")
    }

    var isInterfaceScoped: Bool {
        flags.contains("I")
    }

    var isKernelCacheEntry: Bool {
        !isStatic && (flags.contains("L") || flags.contains("W"))
    }

    var isLinkLayerNeighborEntry: Bool {
        isKernelCacheEntry
            && hasHostFlag
            && flags.contains("L")
            && !gateway.hasPrefix("link#")
            && !NetworkValidation.isValidIPAddress(gateway)
    }

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
        self.flags = String(fields[2])
        self.interfaceName = String(fields[3])
    }
}
