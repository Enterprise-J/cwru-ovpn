import Foundation
import Darwin

extension RouteManager {
    private enum RouteCommand: String {
        case add
        case delete
    }

    func routeExists(_ configuredRoute: String, on interfaceName: String, in entries: [RouteEntry]) -> Bool {
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

    func routingTableEntries() throws -> [RouteEntry] {
        try routeTable(family: "inet")
    }

    func ipv6RoutingTableEntries() throws -> [RouteEntry] {
        try routeTable(family: "inet6")
    }

    private func routeTable(family: String) throws -> [RouteEntry] {
        try shell.run("/usr/sbin/netstat", arguments: ["-nrf", family]).stdout
            .split(separator: "\n")
            .compactMap(RouteEntry.init(line:))
    }

    func fullTunnelRoutesMatch(_ routes: [ManagedIPv4Route]) throws -> Bool {
        let entries = try routingTableEntries()
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
        for destination in Self.fullTunnelIPv6DefaultRoutes {
            try installManagedBlockedIPv6Route(destination, using: &state, persistPreparedState: persistPreparedState)
        }
    }

    func installSplitTunnelRouting(using state: SessionState, tunnelName: String) throws {
        for route in state.managedSplitDefaultRoutes ?? [] where try managedIPv4RouteNeedsInstallation(route) {
            try addIPv4Route(route, allowNonZero: true)
        }
        for route in cleanupSplitIPv4Routes(using: state) {
            let managedRoute = ManagedIPv4Route(destination: route, viaInterface: tunnelName)
            if try managedIPv4RouteNeedsInstallation(managedRoute) {
                try addIPv4Route(managedRoute, allowNonZero: true)
            }
        }
        for route in cleanupSplitIPv6Routes(using: state) {
            let managedRoute = ManagedIPv6Route(destination: route, viaInterface: tunnelName)
            if try managedIPv6RouteNeedsInstallation(managedRoute) {
                _ = try addIPv6Route(managedRoute, allowNonZero: true)
            }
        }
    }

    func managedIPv4Route(from entry: RouteEntry) -> ManagedIPv4Route? {
        guard let destination = IPRoute.canonicalIPv4(entry.destination)?.routeString else {
            return nil
        }
        if SplitTunnelPolicy.isValidIPv4Address(entry.gateway) {
            return ManagedIPv4Route(destination: destination,
                                    nextHopKind: .gateway,
                                    nextHopValue: entry.gateway,
                                    interfaceName: entry.interfaceName,
                                    isInterfaceScoped: entry.isInterfaceScoped)
        }
        guard SplitTunnelPolicy.isSafeInterfaceName(entry.interfaceName) else {
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
            return
        }
        _ = try shell.run("/sbin/route", arguments: arguments, allowNonZero: allowNonZero, requirePrivileges: true)
    }

    func deleteManagedIPv4RouteIfPresent(_ route: ManagedIPv4Route,
                                         verifyRemoval: Bool = false,
                                         requiresHostFlag: Bool = false) throws {
        guard ownedManagedIPv4RouteExists(route, in: try routingTableEntries(), requiresHostFlag: requiresHostFlag),
              let arguments = ipv4RouteArguments(.delete, route) else {
            return
        }
        _ = try shell.run("/sbin/route", arguments: arguments, allowNonZero: true, requirePrivileges: true)
        if verifyRemoval,
           ownedManagedIPv4RouteExists(route, in: try routingTableEntries(), requiresHostFlag: requiresHostFlag) {
            throw RouteManagerError.failedToDeleteManagedRoute(route.destination)
        }
    }

    func deleteIPv4RouteEntryIfPresent(_ entry: RouteEntry, verifyRemoval: Bool = false) throws {
        guard let route = managedIPv4Route(from: entry),
              let arguments = ipv4RouteArguments(.delete, route),
              try routingTableEntries().contains(where: { ipv4RouteEntryMatches($0, ownershipOf: entry) }) else {
            return
        }
        _ = try shell.run("/sbin/route", arguments: arguments, allowNonZero: true, requirePrivileges: true)
        if verifyRemoval,
           try routingTableEntries().contains(where: { ipv4RouteEntryMatches($0, ownershipOf: entry) }) {
            throw RouteManagerError.failedToDeleteManagedRoute(route.destination)
        }
    }

    func restoreManagedIPv4RouteIfMissing(_ route: ManagedIPv4Route) throws {
        let entries = try routingTableEntries()
        guard !ownedManagedIPv4RouteExists(route, in: entries, requiresHostFlag: true),
              let canonical = IPRoute.canonicalIPv4(route.destination) else {
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

    func managedIPv4RouteNeedsInstallation(_ route: ManagedIPv4Route) throws -> Bool {
        guard let destination = IPRoute.canonicalIPv4(route.destination) else {
            return false
        }
        let matchingEntries = try routingTableEntries().filter { IPRoute.canonicalIPv4($0.destination) == destination }
        if ipv4RouteExists(route, in: matchingEntries) {
            return false
        }
        let conflicts: Bool
        switch route.nextHopKind {
        case .gateway:
            conflicts = matchingEntries.contains {
                $0.interfaceName == route.interfaceName && $0.isInterfaceScoped == route.isInterfaceScoped
            }
        case .interface:
            conflicts = matchingEntries.contains {
                $0.interfaceName != route.interfaceName || $0.isInterfaceScoped == route.isInterfaceScoped
            }
        }
        guard !conflicts else {
            throw RouteManagerError.refusingToReplaceExistingRoute(route.destination)
        }
        return true
    }

    func installManagedSplitDefaultRoute(_ destination: String,
                                         gateway: String,
                                         interfaceName: String,
                                         using state: inout SessionState,
                                         persistPreparedState: (SessionState) throws -> Void) throws {
        let route = ManagedIPv4Route(destination: destination,
                                     nextHopKind: .gateway,
                                     nextHopValue: gateway,
                                     interfaceName: interfaceName,
                                     isInterfaceScoped: true)
        guard try managedIPv4RouteNeedsInstallation(route) else {
            return
        }
        var managedRoutes = state.managedSplitDefaultRoutes ?? []
        if !managedRoutes.contains(route) {
            managedRoutes.append(route)
        }
        state.managedSplitDefaultRoutes = managedRoutes
        try persistPreparedState(state)
        try addIPv4Route(route, allowNonZero: false)
    }

    func ipv6RouteExists(_ route: ManagedIPv6Route, in entries: [RouteEntry]) -> Bool {
        guard let destination = IPRoute.canonicalIPv6(route.destination) else {
            return false
        }
        return entries.contains { entry in
            guard IPRoute.canonicalIPv6(entry.destination) == destination, !entry.isInterfaceScoped else {
                return false
            }
            switch route.nextHopKind {
            case .interface:
                return entry.interfaceName == route.nextHopValue
            case .reject:
                return entry.interfaceName == "lo0" && entry.flags.contains("R")
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
        _ = try shell.run("/sbin/route", arguments: arguments, allowNonZero: true, requirePrivileges: true)
        if verifyRemoval, ipv6RouteExists(route, in: try ipv6RoutingTableEntries()) {
            throw RouteManagerError.failedToDeleteManagedRoute(route.destination)
        }
    }

    func deleteIPv6RouteIfPresent(_ destination: String, interfaceName: String, verifyRemoval: Bool = false) throws {
        try deleteManagedIPv6RouteIfPresent(ManagedIPv6Route(destination: destination, viaInterface: interfaceName),
                                            verifyRemoval: verifyRemoval)
    }

    func managedIPv6RouteNeedsInstallation(_ route: ManagedIPv6Route) throws -> Bool {
        guard let destination = IPRoute.canonicalIPv6(route.destination) else {
            return false
        }
        let matchingEntries = try ipv6RoutingTableEntries().filter { IPRoute.canonicalIPv6($0.destination) == destination }
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
            return false
        }
        let arguments: [String]
        switch route.nextHopKind {
        case .interface:
            arguments = ["-n", "add", "-inet6", canonical.routeString, "-interface", route.nextHopValue]
        case .reject:
            arguments = ["-n", "add", "-net", "-inet6", canonical.addressString, "-prefixlen", String(canonical.prefixLength), "-reject", route.nextHopValue]
        }
        return try shell.run("/sbin/route", arguments: arguments, allowNonZero: allowNonZero, requirePrivileges: true).exitCode == 0
    }

    func installManagedBlockedIPv6Route(_ destination: String,
                                        using state: inout SessionState,
                                        persistPreparedState: (SessionState) throws -> Void) throws {
        let route = ManagedIPv6Route(blocking: destination)
        guard try managedIPv6RouteNeedsInstallation(route) else {
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
        Self.fullTunnelIPv4DefaultRoutes.map { ManagedIPv4Route(destination: $0.routeString, viaInterface: tunnelName) }
    }

    func validatedTunnelInterfaceName(_ tunnelName: String) throws -> String {
        guard SplitTunnelPolicy.isSafeInterfaceName(tunnelName) else {
            throw RouteManagerError.invalidTunnelInterface
        }
        return tunnelName
    }

    static func isUnusableRemoteIPv4Address(_ address: String) -> Bool {
        guard let numeric = IPRoute.canonicalIPv4Address(address) else {
            return false
        }
        return numeric == 0 || (numeric >> 24) == 127
    }

    func serviceName(for interfaceName: String) throws -> String? {
        let result = try shell.run("/usr/sbin/networksetup",
                                   arguments: ["-listnetworkserviceorder"],
                                   requirePrivileges: true)
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
