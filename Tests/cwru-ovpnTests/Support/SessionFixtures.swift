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
        lastEventName: nil,
        diagnosticDetail: nil,
        physicalGateway: physicalGateway,
        physicalInterface: physicalInterface,
        physicalServiceID: "service-" + physicalInterface,
        physicalServiceName: physicalServiceName,
        originalDNSServers: originalDNSServers,
        originalSearchDomains: originalSearchDomains,
        originalDefaultSearchDomains: originalDefaultSearchDomains,
        originalIPv6Mode: originalIPv6Mode,
        tunnelName: tunnelName,
        vpnIPv4: vpnIPv4,
        vpnIPv6: vpnIPv6,
        serverHost: "cwru.openvpn.com",
        connectedServerAddress: "203.0.113.10",
        tunnelMode: tunnelMode,

        appliedSplitIPv4Routes: nil,
        appliedScopedDNSDomains: nil,
        cleanupNeeded: cleanupNeeded
    )
}

extension SessionState {
    mutating func recordDNSOverride(servers: [String], domains: [String] = []) {
        var fields: [String: Any] = [:]
        if let originalDNSServers, !originalDNSServers.isEmpty { fields["ServerAddresses"] = originalDNSServers }
        if let originalSearchDomains, !originalSearchDomains.isEmpty { fields["SearchDomains"] = originalSearchDomains }
        let original = try! ProtocolConfiguration(enabled: true, fields: fields)
        let desired = try! original.replacingDNS(servers: servers, domains: domains)
        serviceMutations.append(ServiceMutation(serviceID: physicalServiceID, kind: .dns, original: original,
                                                previous: original, desired: desired))
    }

    mutating func recordIPv6Override() {
        let original = try! ProtocolConfiguration(enabled: true, fields: ["ConfigMethod": originalIPv6Mode ?? "Automatic"])
        var desired = original
        desired.enabled = false
        serviceMutations.append(ServiceMutation(serviceID: physicalServiceID, kind: .ipv6, original: original,
                                                previous: original, desired: desired))
    }
}

func makeTunnelDNS(servers: [String] = [], searchDomains: [String] = []) -> TunnelDNSConfiguration {
    let addresses = servers.map { TunnelDNSConfiguration.Address(address: $0, port: 0) }
    let upstreams = addresses.isEmpty ? [] : [TunnelDNSConfiguration.Server(
        priority: 0, addresses: addresses, domains: [], security: "Unset", transport: "Unset", sni: "")]
    return TunnelDNSConfiguration(servers: upstreams, searchDomains: searchDomains)
}
