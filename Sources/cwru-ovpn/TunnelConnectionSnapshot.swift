import Foundation

struct TunnelConnectionSnapshot: Decodable {
    let tunnelName: String
    let vpnIPv4: String
    let vpnIPv6: String
    let serverHost: String
    let serverIP: String
    let dns: TunnelDNSConfiguration
}

struct TunnelDNSConfiguration: Codable, Equatable {
    struct Address: Codable, Equatable {
        let address: String
        let port: UInt16
    }

    struct Server: Codable, Equatable {
        let priority: Int
        let addresses: [Address]
        let domains: [String]
        let security: String
        let transport: String
        let sni: String
    }

    let servers: [Server]
    let searchDomains: [String]

    var addresses: [String] {
        servers.sorted { $0.priority < $1.priority }.flatMap { $0.addresses.map(\.address) }.uniqued()
    }

    func validateForSystemDNS() throws {
        guard searchDomains.allSatisfy(NetworkValidation.isValidDomainName) else {
            throw RouteManagerError.failedToInspectPhysicalDNS("The pushed search domain is invalid.")
        }
        for server in servers {
            guard server.domains.isEmpty else {
                throw RouteManagerError.failedToInspectPhysicalDNS("A domain-specific upstream cannot serve as a default resolver.")
            }
            guard ["Plain", "Unset"].contains(server.transport), server.sni.isEmpty,
                  ["Unset", "No", "Optional"].contains(server.security) else {
                throw RouteManagerError.failedToInspectPhysicalDNS("The pushed DNS transport or security requirement is unsupported.")
            }
            guard !server.addresses.isEmpty, server.addresses.allSatisfy({
                ($0.port == 0 || $0.port == 53) && NetworkValidation.isValidIPAddress($0.address)
            }) else {
                throw RouteManagerError.failedToInspectPhysicalDNS("The pushed DNS endpoint requires an unsupported address or port.")
            }
        }
    }
}
