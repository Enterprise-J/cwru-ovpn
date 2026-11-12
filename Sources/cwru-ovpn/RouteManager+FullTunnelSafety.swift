import Foundation
import Darwin

extension RouteManager {
    func fullTunnelIPv4LooksSafe(tunnelName: String, using state: SessionState) throws -> Bool {
        let entries = try ipv4RoutingTableEntries()
        return try ipv4DefaultHalfRoutesAreCovered(tunnelName: tunnelName, in: entries)
            && unexpectedFullTunnelPublicIPv4Routes(tunnelName: tunnelName, using: state, in: entries).isEmpty
    }

    func fullTunnelIPv4SafetyFailureDetail(tunnelName: String, using state: SessionState) -> String {
        let coverage: String
        let unexpectedSummary: String
        do {
            let entries = try ipv4RoutingTableEntries()
            let unexpectedRoutes = try unexpectedFullTunnelPublicIPv4Routes(tunnelName: tunnelName, using: state, in: entries)
            coverage = Self.ipv4DefaultHalfRoutes.map { requiredRoute in
                let interfaces = entries.compactMap { entry -> String? in
                    guard IPRoute.canonicalIPv4(entry.destination) == requiredRoute else {
                        return nil
                    }
                    let scope = entry.isInterfaceScoped ? ", scoped" : ""
                    return "\(entry.interfaceName)(\(entry.gateway)\(scope))"
                }
                return "\(requiredRoute.routeString)=\(interfaces.isEmpty ? "absent" : interfaces.joined(separator: ","))"
            }.joined(separator: ", ")
            unexpectedSummary = unexpectedRoutes.isEmpty ? "none" : unexpectedRoutes.joined(separator: ", ")
        } catch {
            coverage = "unavailable (\(error.localizedDescription))"
            unexpectedSummary = coverage
        }
        let remoteSummary = allowedRemoteServerIPv4Route(using: state)?.routeString ?? "none"
        return "Full-tunnel IPv4 safety failed after repair: default route coverage \(coverage); unexpected routes \(unexpectedSummary); allowed remote endpoints \(remoteSummary)."
    }

    private struct PhysicalRouteContext {
        let gateway: String
        let gatewayAddress: UInt32?
        let interfaceName: String
        let connectedRoute: CanonicalIPv4Route?
        let ownAddresses: Set<UInt32>
        let serverAddress: UInt32?
        let serverRouteIsSafe: Bool
        let safeOnLinkHosts: Set<UInt32>

        func isOnLink(_ address: UInt32) -> Bool {
            ownAddresses.contains(address) || connectedRoute.map { IPRoute.ipv4Address(address, isIn: $0) } == true
        }
    }

    private func unexpectedFullTunnelPublicIPv4Routes(tunnelName: String,
                                                      using state: SessionState,
                                                      in entries: [RouteEntry]) throws -> [String] {
        let gateway = state.physicalGateway
        let interfaceName = state.physicalInterface
        let addresses = try physicalIPv4Addresses(interfaceName: interfaceName)
        let serverAddress = allowedRemoteServerIPv4Route(using: state)?.networkAddress
        let safeOnLinkHosts = Set(entries.compactMap { entry -> UInt32? in
            guard entry.isHost, entry.isStatic, !entry.isInterfaceScoped,
                  entry.interfaceName == interfaceName,
                  entry.gateway.hasPrefix("link#"),
                  let route = IPRoute.canonicalIPv4(entry.destination), route.prefixLength == 32 else {
                return nil
            }
            return route.networkAddress
        })
        let serverRouteIsSafe = entries.filter { entry in
            entry.isHost && entry.isStatic && !entry.isInterfaceScoped
                && entry.interfaceName == interfaceName
                && entry.gateway == gateway
                && IPRoute.canonicalIPv4(entry.destination).map { $0.prefixLength == 32 && $0.networkAddress == serverAddress } == true
        }.count == 1
        let context = PhysicalRouteContext(gateway: gateway,
                                           gatewayAddress: IPRoute.canonicalIPv4Address(gateway),
                                           interfaceName: interfaceName,
                                           connectedRoute: physicalConnectedIPv4Route(addresses: addresses, gateway: gateway),
                                           ownAddresses: Set(addresses.map(\.address)),
                                           serverAddress: serverAddress,
                                           serverRouteIsSafe: serverRouteIsSafe,
                                           safeOnLinkHosts: safeOnLinkHosts)
        return entries.compactMap { entry in
            guard entry.interfaceName != tunnelName,
                  let route = IPRoute.canonicalIPv4(entry.destination),
                  !fullTunnelPublicIPv4RouteIsAllowed(route, entry: entry, context: context) else {
                return nil
            }
            return route.routeString
        }
    }

    private func fullTunnelPublicIPv4RouteIsAllowed(_ route: CanonicalIPv4Route,
                                                    entry: RouteEntry,
                                                    context: PhysicalRouteContext) -> Bool {
        guard Self.ipv4RouteTouchesPublicUnicast(route) else {
            return true
        }
        guard route.prefixLength == 32 else {
            return route == context.connectedRoute
                && entry.interfaceName == context.interfaceName
                && entry.gateway.hasPrefix("link#")
                && entry.flags.contains("C")
                && entry.flags.contains("S")
                && !entry.flags.contains("G")
                && !entry.isInterfaceScoped
        }
        let address = route.networkAddress
        if entry.isLinkLayerNeighborEntry {
            if address == context.gatewayAddress {
                return entry.interfaceName == context.interfaceName && context.safeOnLinkHosts.contains(address)
            }
            return context.isOnLink(address)
                && (entry.interfaceName == context.interfaceName
                    || (entry.interfaceName == "lo0" && context.ownAddresses.contains(address)))
        }
        guard entry.isHost, entry.isStatic, entry.interfaceName == context.interfaceName else {
            return false
        }
        if address == context.serverAddress {
            return entry.gateway == context.gateway && (!entry.isInterfaceScoped || context.serverRouteIsSafe)
        }
        guard entry.gateway.hasPrefix("link#"), address == context.gatewayAddress || context.isOnLink(address) else {
            return false
        }
        return !entry.isInterfaceScoped || context.safeOnLinkHosts.contains(address)
    }

    func physicalIPv4Addresses(interfaceName: String) throws -> [(address: UInt32, prefixLength: Int)] {
        guard let output = try physicalInterfaceConfigurationOutput(interfaceName) else {
            return []
        }
        return output.components(separatedBy: .newlines).compactMap { line in
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.first == "inet",
                  fields.count >= 4,
                  let netmaskIndex = fields.firstIndex(of: "netmask"),
                  fields.indices.contains(netmaskIndex + 1),
                  let address = IPRoute.canonicalIPv4Address(String(fields[1])),
                  let prefixLength = ipv4PrefixLength(fromNetmask: String(fields[netmaskIndex + 1])) else {
                return nil
            }
            return (address, prefixLength)
        }
    }

    private func physicalConnectedIPv4Route(addresses: [(address: UInt32, prefixLength: Int)],
                                            gateway: String) -> CanonicalIPv4Route? {
        guard let gatewayAddress = IPRoute.canonicalIPv4Address(gateway) else {
            return nil
        }
        let routes = addresses.compactMap { address, prefixLength -> CanonicalIPv4Route? in
            guard prefixLength >= 16 else {
                return nil
            }
            let route = CanonicalIPv4Route(networkAddress: address & IPRoute.ipv4Mask(prefixLength: prefixLength),
                                           prefixLength: prefixLength)
            return IPRoute.ipv4Address(gatewayAddress, isIn: route) ? route : nil
        }.uniqued()
        return routes.count == 1 ? routes[0] : nil
    }

    func ipv4PrefixLength(fromNetmask netmask: String) -> Int? {
        let mask: UInt32
        if netmask.lowercased().hasPrefix("0x") {
            guard let parsed = UInt32(netmask.dropFirst(2), radix: 16) else {
                return nil
            }
            mask = parsed
        } else {
            guard let parsed = IPRoute.canonicalIPv4Address(netmask) else {
                return nil
            }
            mask = parsed
        }
        let prefixLength = mask.nonzeroBitCount
        return mask == IPRoute.ipv4Mask(prefixLength: prefixLength) ? prefixLength : nil
    }

    private func ipv4DefaultHalfRoutesAreCovered(tunnelName: String, in entries: [RouteEntry]) -> Bool {
        let coveredRoutes = entries.compactMap { entry -> CanonicalIPv4Route? in
            !entry.isInterfaceScoped && entry.interfaceName == tunnelName
                ? IPRoute.canonicalIPv4(entry.destination) : nil
        }
        return Self.ipv4DefaultHalfRoutes.allSatisfy(coveredRoutes.contains)
    }

    static func ipv4RouteTouchesPublicUnicast(_ route: CanonicalIPv4Route) -> Bool {
        !nonPublicIPv4Routes.contains { IPRoute.ipv4Route($0, contains: route) }
    }

    static func ipv6RouteTouchesPublicGlobalUnicast(_ route: CanonicalIPv6Route) -> Bool {
        ipv6RoutesOverlap(route, publicGlobalIPv6Route) && !IPRoute.ipv6Route(documentationIPv6Route, contains: route)
    }

    static func ipv6RoutesOverlap(_ lhs: CanonicalIPv6Route, _ rhs: CanonicalIPv6Route) -> Bool {
        IPRoute.ipv6Route(lhs, contains: rhs) || IPRoute.ipv6Route(rhs, contains: lhs)
    }

    func unexpectedFullTunnelPublicIPv6Routes(tunnelName: String, entries: [RouteEntry]) -> [String] {
        let publicIPv6Covered = fullTunnelPublicIPv6RangeIsCovered(tunnelName: tunnelName, entries: entries)
        return entries.compactMap { entry in
            guard entry.interfaceName != tunnelName,
                  entry.interfaceName != "lo0",
                  let route = IPRoute.canonicalIPv6(entry.destination),
                  Self.ipv6RouteTouchesPublicGlobalUnicast(route),
                  !(publicIPv6Covered && route.prefixLength == 0) else {
                return nil
            }
            return route.routeString
        }
    }

    func fullTunnelPublicIPv6RangeIsCovered(tunnelName: String,
                                            entries: [RouteEntry]) -> Bool {
        Self.ipv6DefaultHalfRoutes.allSatisfy { destination in
            guard let expectedRoute = IPRoute.canonicalIPv6(destination) else {
                return false
            }
            return entries.contains { entry in
                guard let route = IPRoute.canonicalIPv6(entry.destination),
                      route == expectedRoute,
                      !entry.isInterfaceScoped else {
                    return false
                }
                return entry.interfaceName == tunnelName || entry.interfaceName == "lo0"
            }
        }
    }

    func assessFullTunnelIPv6Safety(tunnelName: String) -> FullTunnelIPv6SafetyAssessment {
        var inspectionError: Error?
        let probes = Self.fullTunnelIPv6ProbeDestinations.map { destination in
            do {
                return FullTunnelIPv6ProbeAssessment(destination: destination,
                                                     state: try publicIPv6RouteState(for: destination, tunnelName: tunnelName))
            } catch {
                inspectionError = inspectionError ?? error
                return FullTunnelIPv6ProbeAssessment(destination: destination, state: nil)
            }
        }

        let entries: [RouteEntry]?
        do {
            entries = try ipv6RoutingTableEntries()
        } catch {
            inspectionError = inspectionError ?? error
            entries = nil
        }

        let coverage: [String]
        let unexpectedRoutes: [String]?
        if let entries {
            coverage = (Self.ipv6DefaultHalfRoutes + ["2000::/3"]).map { destination in
                let routes = entries.compactMap { entry -> String? in
                    guard let route = IPRoute.canonicalIPv6(entry.destination),
                          route == IPRoute.canonicalIPv6(destination) else {
                        return nil
                    }
                    return "\(entry.interfaceName)(\(entry.gateway))"
                }
                return "\(destination)=\(routes.isEmpty ? "absent" : routes.joined(separator: ","))"
            }
            unexpectedRoutes = unexpectedFullTunnelPublicIPv6Routes(tunnelName: tunnelName, entries: entries)
        } else {
            coverage = ["routing-table=error"]
            unexpectedRoutes = nil
        }

        return FullTunnelIPv6SafetyAssessment(probes: probes,
                                              coverage: coverage,
                                              unexpectedRoutes: unexpectedRoutes,
                                              inspectionError: inspectionError)
    }

    func stabilizedFullTunnelIPv6Safety(tunnelName: String) -> FullTunnelIPv6SafetyOutcome {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: fullTunnelIPv6SafetyTimeout)
        var consecutiveSafeAssessments = 0

        while true {
            let assessment = assessFullTunnelIPv6Safety(tunnelName: tunnelName)
            consecutiveSafeAssessments = assessment.isSafe ? consecutiveSafeAssessments + 1 : 0
            let isStable = consecutiveSafeAssessments >= Self.requiredConsecutiveFullTunnelIPv6SafetyAssessments
            if isStable || clock.now >= deadline {
                return FullTunnelIPv6SafetyOutcome(assessment: assessment,
                                                   consecutiveSafeAssessments: consecutiveSafeAssessments,
                                                   isStable: isStable)
            }
            usleep(Self.fullTunnelIPv6SafetyRetryIntervalMicroseconds)
        }
    }

    func fullTunnelIPv6SafetyFailureDetail(_ outcome: FullTunnelIPv6SafetyOutcome) -> String {
        let probes = outcome.assessment.probes.map { "\($0.destination)=\($0.state?.rawValue ?? "error")" }
        let unexpectedSummary = outcome.assessment.unexpectedRoutes.map { $0.isEmpty ? "none" : $0.joined(separator: ", ") }
            ?? "inspection error"
        return "Full-tunnel IPv6 safety did not stabilize before the deadline: probes \(probes.joined(separator: ", ")); coverage \(outcome.assessment.coverage.joined(separator: ", ")); unexpected routes \(unexpectedSummary); consecutive safe assessments \(outcome.consecutiveSafeAssessments)/\(Self.requiredConsecutiveFullTunnelIPv6SafetyAssessments)."
    }

    func publicIPv4RouteState(for destination: String, tunnelName: String) throws -> PublicRouteState {
        guard let route = try routeLookup(for: destination) else {
            throw RouteManagerError.failedToInspectPublicIPv4Routes
        }
        return publicRouteState(route: route, tunnelName: tunnelName, loopbackGateway: "127.0.0.1")
    }

    func publicIPv6RouteState(for destination: String, tunnelName: String) throws -> PublicRouteState {
        let route = try routeLookup(for: destination, ipv6: true)
        return publicRouteState(route: route, tunnelName: tunnelName, loopbackGateway: "::1")
    }

    func publicRouteState(route: RouteLookup?, tunnelName: String, loopbackGateway: String) -> PublicRouteState {
        guard let route else {
            return .blocked
        }
        if route.isRejected || (route.interfaceName == "lo0" && route.gateway == loopbackGateway) {
            return .blocked
        }
        if route.interfaceName == tunnelName {
            return .tunnel
        }
        return NetworkValidation.isVirtualInterfaceName(route.interfaceName) ? .other : .physical
    }
}
