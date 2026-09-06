import Foundation

extension SessionState {
    func validateForPrivilegedCleanup() throws {
        if let tunName = tunName,
           !tunName.isEmpty,
           !SplitTunnelPolicy.isSafeInterfaceName(tunName) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an unexpected tunnel interface name in session state."
            )
        }

        if physicalInterface.isEmpty
            || !SplitTunnelPolicy.isSafeInterfaceName(physicalInterface) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an unexpected physical interface name in session state."
            )
        }

        if let physicalServiceName = physicalServiceName,
           !physicalServiceName.isEmpty,
           !SplitTunnelPolicy.isSafeNetworkServiceName(physicalServiceName) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an unexpected network service name in session state."
            )
        }

        if let serverIP = serverIP,
           !serverIP.isEmpty,
           !SplitTunnelPolicy.isValidIPAddress(serverIP) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an invalid server IP in session state."
            )
        }

        if physicalGateway.isEmpty
            || !SplitTunnelPolicy.isValidIPAddress(physicalGateway) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an invalid gateway in session state."
            )
        }

        try Self.validateIPAddresses(originalDNSServers, label: "original DNS servers")
        try Self.validateIPAddresses(pushedDNSServers, label: "pushed DNS servers")
        try Self.validateIPAddresses(fullTunnelDNSServers, label: "full-tunnel DNS servers")
        if let vpnIPv4 = vpnIPv4,
           !vpnIPv4.isEmpty,
           !SplitTunnelPolicy.isValidIPv4Address(vpnIPv4) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an invalid VPN IPv4 address in session state."
            )
        }
        if let vpnGatewayIPv4 = vpnGatewayIPv4,
           !vpnGatewayIPv4.isEmpty,
           !SplitTunnelPolicy.isValidIPv4Address(vpnGatewayIPv4) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an invalid VPN gateway IPv4 address in session state."
            )
        }
        if let vpnIPv6 = vpnIPv6,
           !vpnIPv6.isEmpty,
           !SplitTunnelPolicy.isValidIPv6Address(vpnIPv6) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an invalid VPN IPv6 address in session state."
            )
        }
        try Self.validateSearchDomains(originalSearchDomains, label: "original search domains")
        try Self.validateSearchDomains(originalDefaultSearchDomains, label: "original default search domains")
        try Self.validateSearchDomains(pushedSearchDomains, label: "pushed search domains")
        try Self.validateSearchDomains(fullTunnelSearchDomains, label: "full-tunnel search domains")

        if let originalIPv6Mode = originalIPv6Mode,
           !originalIPv6Mode.isEmpty,
           !Self.isSafeIPv6Mode(originalIPv6Mode) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an invalid IPv6 mode in session state."
            )
        }

        if let fullTunnelDefaultRoutes = fullTunnelDefaultRoutes,
           (fullTunnelDefaultRoutes.count > 2
               || !fullTunnelDefaultRoutes.allSatisfy({ route in
                   Self.isSafeManagedIPv4Route(route)
                       && ["0.0.0.0/1", "128.0.0.0/1"].contains(route.destination)
               })) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to invalid full-tunnel routes in session state."
            )
        }
        let managedRemoteIPv4Routes = managedRemoteIPv4Routes ?? []
        let replacedRemoteIPv4Routes = replacedRemoteIPv4Routes ?? []
        if !RouteManager.remoteIPv4RouteLedgerIsValid(managed: managedRemoteIPv4Routes,
                                         replaced: replacedRemoteIPv4Routes) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to invalid remote IPv4 routes in session state."
            )
        }
        if let managedSplitDefaultRoutes = managedSplitDefaultRoutes,
           (managedSplitDefaultRoutes.count > 2
               || !managedSplitDefaultRoutes.allSatisfy({ route in
                   Self.isSafeManagedIPv4Route(route)
                       && route.nextHopKind == .gateway
                       && route.isInterfaceScoped
                       && ["0.0.0.0/1", "128.0.0.0/1"].contains(route.destination)
               })) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to invalid managed split default routes in session state."
            )
        }
        if let managedIPv6Routes = managedIPv6Routes,
           (managedIPv6Routes.count > Self.maximumManagedIPv6RouteCount
               || !managedIPv6Routes.allSatisfy(Self.isSafeManagedIPv6Route)) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to invalid managed IPv6 routes in session state."
            )
        }
        if let sessionOwnedBlockedIPv6Routes = sessionOwnedBlockedIPv6Routes {
            let allowedDestinations = Set(RouteManager.openVPNBlockedIPv6Routes.map(\.routeString))
            if sessionOwnedBlockedIPv6Routes.count > allowedDestinations.count
                || !sessionOwnedBlockedIPv6Routes.allSatisfy({ allowedDestinations.contains($0) }) {
                throw SessionStateError.unsafeRecoveryState(
                    "Refusing cleanup due to invalid session-owned block-ipv6 routes in session state."
                )
            }
        }
        if let appliedSplitIPv4Routes = appliedSplitIPv4Routes,
           !appliedSplitIPv4Routes.allSatisfy(SplitTunnelPolicy.isValidIPv4CIDR) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to invalid split-tunnel IPv4 routes in session state."
            )
        }
        if let appliedSplitIPv6Routes = appliedSplitIPv6Routes,
           !appliedSplitIPv6Routes.allSatisfy(SplitTunnelPolicy.isValidIPv6CIDR) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to invalid split-tunnel IPv6 routes in session state."
            )
        }

        if let appliedDNSDomains = appliedDNSDomains,
           !appliedDNSDomains.allSatisfy({
               SplitTunnelPolicy.isValidDomainName($0)
               && ResolverPaths.isSafeDomainFileName($0)
           }) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to invalid DNS domains in session state."
            )
        }

        if !Self.isSafeUserControlledPath(profilePath) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an unexpected profile path in session state."
            )
        }
    }

    private static func validateIPAddresses(_ values: [String]?, label: String) throws {
        guard let values,
              !values.allSatisfy(SplitTunnelPolicy.isValidIPAddress) else {
            return
        }
        throw SessionStateError.unsafeRecoveryState(
            "Refusing cleanup due to invalid \(label) in session state."
        )
    }

    private static func validateSearchDomains(_ values: [String]?, label: String) throws {
        guard let values,
              !values.allSatisfy(SplitTunnelPolicy.isValidDomainName) else {
            return
        }
        throw SessionStateError.unsafeRecoveryState(
            "Refusing cleanup due to invalid \(label) in session state."
        )
    }

    private static func isSafeIPv6Mode(_ value: String) -> Bool {
        guard value.utf8.count <= 64 else {
            return false
        }
        return value.unicodeScalars.allSatisfy { scalar in
            scalar.value >= 0x20 && scalar.value != 0x7F && !(0x80...0x9F).contains(scalar.value)
        }
    }

    private static func isSafeManagedIPv4Route(_ route: ManagedIPv4Route) -> Bool {
        guard SplitTunnelPolicy.isValidIPv4CIDR(route.destination),
              SplitTunnelPolicy.isSafeInterfaceName(route.interfaceName) else {
            return false
        }

        switch route.nextHopKind {
        case .gateway:
            return SplitTunnelPolicy.isValidIPv4Address(route.nextHopValue)
        case .interface:
            return route.nextHopValue == route.interfaceName
        }
    }

    private static func isSafeManagedIPv6Route(_ route: ManagedIPv6Route) -> Bool {
        guard SplitTunnelPolicy.isValidIPv6CIDR(route.destination),
              SplitTunnelPolicy.isSafeInterfaceName(route.interfaceName) else {
            return false
        }

        switch route.nextHopKind {
        case .interface:
            return route.nextHopValue == route.interfaceName && !route.isInterfaceScoped
        case .reject:
            return route.nextHopValue == "::1%lo0"
                && route.interfaceName == "lo0"
                && !route.isInterfaceScoped
        }
    }

    private static let maxUserControlledPathLength = 1024
    private static let maximumManagedIPv6RouteCount = 2

    private static func isSafeUserControlledPath(_ value: String) -> Bool {
        guard !value.isEmpty,
              value.utf8.count <= maxUserControlledPathLength,
              value.hasPrefix("/"),
              !value.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F || (0x80...0x9F).contains($0.value) }) else {
            return false
        }

        let standardizedPath = URL(fileURLWithPath: value).standardized.path
        let allowedRoots = [
            "/Users/",
            "/var/root/",
            "/private/",
            "/tmp/",
        ]
        return allowedRoots.contains(where: { standardizedPath.hasPrefix($0) })
    }
}
