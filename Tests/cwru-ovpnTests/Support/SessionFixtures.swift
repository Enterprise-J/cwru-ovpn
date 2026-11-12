import Foundation

@testable import cwru_ovpn

func makeSessionState(
    pid: Int32,
    profilePath: String,
    configFilePath: String?,
    physicalGateway: String,
    physicalInterface: String,
    physicalServiceName: String,
    originalDNSServers: [String],
    originalSearchDomains: [String],
    originalDefaultSearchDomains: [String]? = nil,
    originalIPv6Mode: String,
    tunnelName: String,
    tunnelMode: AppTunnelMode,
    cleanupNeeded: Bool,
    vpnIPv4: String? = "10.8.0.10",
    vpnIPv6: String? = "2606:ea00::100"
) -> SessionState {
    SessionState(
        pid: pid,
        executablePath: "/tmp/cwru-ovpn",
        processStartTime: ProcessStartTime(seconds: 1, microseconds: 0),
        phase: .connected,
        profilePath: profilePath,
        configFilePath: configFilePath,
        startedAt: Date(timeIntervalSince1970: 0),
        lastEvent: nil,
        lastInfo: nil,
        physicalGateway: physicalGateway,
        physicalInterface: physicalInterface,
        physicalServiceName: physicalServiceName,
        originalDNSServers: originalDNSServers,
        originalSearchDomains: originalSearchDomains,
        originalDefaultSearchDomains: originalDefaultSearchDomains,
        originalIPv6Mode: originalIPv6Mode,
        pushedDNSServers: nil,
        pushedSearchDomains: nil,
        tunnelName: tunnelName,
        vpnIPv4: vpnIPv4,
        vpnIPv6: vpnIPv6,
        serverHost: "cwru.openvpn.com",
        serverIP: "203.0.113.10",
        tunnelMode: tunnelMode,
        requestedTunnelMode: nil,
        fullTunnelDNSServers: nil,
        fullTunnelSearchDomains: nil,
        appliedSplitIPv4Routes: nil,
        appliedDNSDomains: nil,
        cleanupNeeded: cleanupNeeded
    )
}
