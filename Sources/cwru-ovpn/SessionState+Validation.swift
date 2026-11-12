import Foundation

extension SessionState {
    func validateForPrivilegedCleanup() throws {
        if let tunnelName = tunnelName,
           !tunnelName.isEmpty,
           !NetworkValidation.isSafeInterfaceName(tunnelName) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an unexpected tunnel interface name in session state."
            )
        }

        if physicalInterface.isEmpty
            || !NetworkValidation.isSafeInterfaceName(physicalInterface) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an unexpected physical interface name in session state."
            )
        }

        if let physicalServiceName = physicalServiceName,
           !physicalServiceName.isEmpty,
           !NetworkValidation.isSafeNetworkServiceName(physicalServiceName) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an unexpected network service name in session state."
            )
        }

        if let serverIP = serverIP,
           !serverIP.isEmpty,
           !NetworkValidation.isValidIPAddress(serverIP) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an invalid server IP in session state."
            )
        }

        if let transportServerIP, !NetworkValidation.isValidIPv4Address(transportServerIP) {
            throw SessionStateError.unsafeRecoveryState("Refusing cleanup due to an invalid transport endpoint in session state.")
        }

        if physicalGateway.isEmpty
            || !NetworkValidation.isValidIPAddress(physicalGateway) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an invalid gateway in session state."
            )
        }

        try Self.validateIPAddresses(originalDNSServers, label: "original DNS servers")
        try Self.validateIPAddresses(pushedDNSServers, label: "pushed DNS servers")
        try Self.validateIPAddresses(fullTunnelDNSServers, label: "full-tunnel DNS servers")
        if let vpnIPv4 = vpnIPv4,
           !vpnIPv4.isEmpty,
           !NetworkValidation.isValidIPv4Address(vpnIPv4) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to an invalid VPN IPv4 address in session state."
            )
        }
        if let vpnIPv6 = vpnIPv6,
           !vpnIPv6.isEmpty,
           !NetworkValidation.isValidIPv6Address(vpnIPv6) {
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

        let managedRemoteIPv4Routes = managedRemoteIPv4Routes ?? []
        let replacedRemoteIPv4Routes = replacedRemoteIPv4Routes ?? []
        if !RouteManager.remoteIPv4RouteLedgerIsValid(managed: managedRemoteIPv4Routes,
                                                      replaced: replacedRemoteIPv4Routes) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to invalid remote IPv4 routes in session state."
            )
        }
        if let managedIPv6Routes = managedIPv6Routes,
           (Set(managedIPv6Routes).count != managedIPv6Routes.count
               || !Set(managedIPv6Routes).isSubset(of: Self.managedIPv6RejectRoutes)) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to invalid managed IPv6 routes in session state."
            )
        }
        if let appliedSplitIPv4Routes = appliedSplitIPv4Routes,
           !appliedSplitIPv4Routes.allSatisfy(NetworkValidation.isValidIPv4CIDR) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to invalid split-tunnel IPv4 routes in session state."
            )
        }
        if let appliedSplitIPv6Routes = appliedSplitIPv6Routes,
           !appliedSplitIPv6Routes.allSatisfy(NetworkValidation.isValidIPv6CIDR) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to invalid split-tunnel IPv6 routes in session state."
            )
        }

        if let appliedDNSDomains = appliedDNSDomains,
           !appliedDNSDomains.allSatisfy({
               NetworkValidation.isValidDomainName($0)
               && ResolverPaths.isSafeDomainFileName($0)
           }) {
            throw SessionStateError.unsafeRecoveryState(
                "Refusing cleanup due to invalid DNS domains in session state."
            )
        }
    }

    private static func validateIPAddresses(_ values: [String]?, label: String) throws {
        guard let values,
              !values.allSatisfy(NetworkValidation.isValidIPAddress) else {
            return
        }
        throw SessionStateError.unsafeRecoveryState(
            "Refusing cleanup due to invalid \(label) in session state."
        )
    }

    private static func validateSearchDomains(_ values: [String]?, label: String) throws {
        guard let values,
              !values.allSatisfy(NetworkValidation.isValidDomainName) else {
            return
        }
        throw SessionStateError.unsafeRecoveryState(
            "Refusing cleanup due to invalid \(label) in session state."
        )
    }

    private static func isSafeIPv6Mode(_ value: String) -> Bool {
        value.utf8.count <= 64 && NetworkValidation.isPrintable(value)
    }

    private static let managedIPv6RejectRoutes = Set(RouteManager.ipv6DefaultHalfRoutes.map(ManagedIPv6Route.init(blocking:)))
}
