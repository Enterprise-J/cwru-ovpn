import Foundation
import SystemConfiguration
import SystemConfiguration.SCDynamicStoreCopyDHCPInfo

enum ServiceProtocol: String, Codable {
    case dns = "DNS"
    case ipv6 = "IPv6"

    var keys: [String] {
        switch self {
        case .dns: [kSCPropNetDNSServerAddresses as String, kSCPropNetDNSSearchDomains as String]
        case .ipv6: []
        }
    }
}

struct ProtocolConfiguration: Codable, Equatable {
    var enabled: Bool?
    var propertyList: Data?

    init(enabled: Bool?, fields: [String: Any]?) throws {
        self.enabled = enabled
        propertyList = try fields.map { fields in
            var settings = fields
            settings.removeValue(forKey: kSCResvInactive as String)
            return try PropertyListSerialization.data(fromPropertyList: settings, format: .binary, options: 0)
        }
    }

    func fields() throws -> [String: Any]? {
        guard let propertyList else { return nil }
        guard var result = try PropertyListSerialization.propertyList(from: propertyList, format: nil) as? [String: Any],
              enabled != nil else { throw POSIXError(.EINVAL) }
        result.removeValue(forKey: kSCResvInactive as String)
        return result
    }

    func matches(_ other: Self, for kind: ServiceProtocol) throws -> Bool {
        let left = try fields()
        let right = try other.fields()
        return enabled == other.enabled && kind.keys.allSatisfy { (left?[$0] as? NSObject) == (right?[$0] as? NSObject) }
    }

    func replacingDNS(servers: [String], domains: [String]) throws -> Self {
        var settings = try fields() ?? [:]
        settings[kSCPropNetDNSServerAddresses as String] = servers
        settings[kSCPropNetDNSSearchDomains as String] = domains.isEmpty ? nil : domains
        return try Self(enabled: true, fields: settings)
    }

    func merging(_ target: Self, from expected: Self, for kind: ServiceProtocol) throws -> Self {
        let currentFields = try fields()
        let expectedFields = try expected.fields()
        let targetFields = try target.fields()
        let conflict = RouteManagerError.failedToInspectPhysicalDNS("The \(kind.rawValue) configuration was changed externally.")
        var result = currentFields ?? [:]
        guard enabled == target.enabled || enabled == expected.enabled else { throw conflict }
        for key in kind.keys {
            let current = result[key] as? NSObject
            let prior = expectedFields?[key] as? NSObject
            let desired = targetFields?[key] as? NSObject
            guard current == prior || current == desired else { throw conflict }
            result[key] = desired
        }
        if target.enabled == nil, !result.isEmpty { throw conflict }
        return try Self(enabled: target.enabled, fields: result.isEmpty && targetFields == nil ? nil : result)
    }
}

struct ServiceMutation: Codable {
    let serviceID: String
    let kind: ServiceProtocol
    let original: ProtocolConfiguration
    var previous: ProtocolConfiguration
    var desired: ProtocolConfiguration
}

protocol NetworkServiceStore {
    func activeService(for interface: String) throws -> PhysicalServiceConfiguration?
    func configuration(serviceID: String, kind: ServiceProtocol) throws -> ProtocolConfiguration
    func replace(serviceID: String, kind: ServiceProtocol, expected: ProtocolConfiguration,
                 desired: ProtocolConfiguration) throws
    func dynamicDNS(serviceID: String, dhcpOnly: Bool) throws -> (servers: [String], domains: [String])
}

struct SystemNetworkServiceStore: NetworkServiceStore {
    private func preferences() throws -> SCPreferences {
        guard let preferences = SCPreferencesCreate(nil, AppIdentity.executableName as CFString, nil) else { throw failure("Open network preferences") }
        return preferences
    }

    private func failure(_ operation: String) -> RouteManagerError {
        let code = SCError()
        let detail = code == kSCStatusOK ? "the system returned no usable result" : String(cString: SCErrorString(code))
        return .failedToInspectPhysicalDNS("\(operation): \(detail)")
    }

    private func store() throws -> SCDynamicStore {
        guard let store = SCDynamicStoreCreate(nil, AppIdentity.executableName as CFString, nil, nil) else { throw failure("Open network dynamic store") }
        return store
    }

    func activeService(for interface: String) throws -> PhysicalServiceConfiguration? {
        let prefs = try preferences()
        let store = try store()
        guard let set = SCNetworkSetCopyCurrent(prefs),
              let services = SCNetworkSetCopyServices(set) as? [SCNetworkService] else { throw failure("Read the current network services") }
        let global = SCDynamicStoreKeyCreateNetworkGlobalEntity(nil, kSCDynamicStoreDomainState, kSCEntNetIPv4) as String
        let pattern = "State:/Network/Service/[^/]+/IPv4"
        guard let values = SCDynamicStoreCopyMultiple(store, [global] as CFArray, [pattern] as CFArray) as? [String: [String: Any]] else { throw failure("Read active IPv4 service identities") }
        let primary = values[global]?[kSCDynamicStorePropNetPrimaryService as String] as? String
        let candidates = services.filter { service in
            guard SCNetworkServiceGetEnabled(service), let id = SCNetworkServiceGetServiceID(service) as String?,
                  let link = SCNetworkServiceGetInterface(service),
                  let active = values["State:/Network/Service/\(id)/IPv4"],
                  let addresses = active[kSCPropNetIPv4Addresses as String] as? [String], !addresses.isEmpty else { return false }
            if let name = active[kSCPropInterfaceName as String] as? String { return name == interface }
            return SCNetworkInterfaceGetBSDName(link) as String? == interface
        }
        let preferred = candidates.first { SCNetworkServiceGetServiceID($0) as String? == primary }
        guard let service = preferred ?? (candidates.count == 1 ? candidates[0] : nil),
              let id = SCNetworkServiceGetServiceID(service) as String?,
              let name = SCNetworkServiceGetName(service) as String? else { return nil }
        let dns = try read(service, .dns)
        let fields = try dns.fields()
        let ipv6 = try read(service, .ipv6)
        let mode = try ipv6.enabled == true ? ipv6.fields()?[kSCPropNetIPv6ConfigMethod as String] as? String : "Off"
        return PhysicalServiceConfiguration(serviceID: id, serviceName: name,
                                            dnsServers: fields?[kSCPropNetDNSServerAddresses as String] as? [String] ?? [],
                                            searchDomains: fields?[kSCPropNetDNSSearchDomains as String] as? [String] ?? [],
                                            ipv6Mode: mode)
    }

    func dynamicDNS(serviceID: String, dhcpOnly: Bool) throws -> (servers: [String], domains: [String]) {
        let store = try store()
        if dhcpOnly {
            guard let lease = SCDynamicStoreCopyDHCPInfo(store, serviceID as CFString) else { return ([], []) }
            let bytes = DHCPInfoGetOptionData(lease, 6) as Data? ?? Data()
            guard bytes.count.isMultiple(of: 4) else { throw POSIXError(.EINVAL) }
            let servers = stride(from: 0, to: bytes.count, by: 4).map { offset in
                bytes[offset..<offset + 4].map(String.init).joined(separator: ".")
            }
            var domains: [String] = []
            if let data = DHCPInfoGetOptionData(lease, 119) as Data? { domains = try Self.searchList(in: data) }
            if let data = DHCPInfoGetOptionData(lease, 15) as Data?, let domain = String(data: data, encoding: .utf8), !domain.isEmpty {
                domains.append(domain)
            }
            return (servers, domains)
        }
        let key = SCDynamicStoreKeyCreateNetworkServiceEntity(nil, kSCDynamicStoreDomainState, serviceID as CFString, kSCEntNetDNS) as String
        guard let values = SCDynamicStoreCopyMultiple(store, [key] as CFArray, nil) as? [String: [String: Any]] else { throw failure("Read service-specific DNS publication") }
        let fields = values[key] ?? [:]
        func list(_ key: CFString) throws -> [String] {
            guard let value = fields[key as String] else { return [] }
            guard let list = value as? [String] else { throw POSIXError(.EINVAL) }
            return list
        }
        return try (list(kSCPropNetDNSServerAddresses), list(kSCPropNetDNSSearchDomains))
    }

    static func searchList(in data: Data) throws -> [String] {
        let bytes = Array(data)
        var names: [String] = []
        var offset = 0
        while offset < bytes.count {
            var cursor = offset
            var end: Int?
            var seen = Set<Int>()
            var labels: [String] = []
            var length = 0
            while true {
                guard cursor < bytes.count, seen.insert(cursor).inserted else { throw POSIXError(.EINVAL) }
                let size = Int(bytes[cursor])
                cursor += 1
                if size == 0 { break }
                if size & 0xc0 == 0xc0 {
                    guard cursor < bytes.count else { throw POSIXError(.EINVAL) }
                    end = end ?? cursor + 1
                    cursor = ((size & 0x3f) << 8) | Int(bytes[cursor])
                    continue
                }
                length += size + 1
                guard size <= 63, length <= 254, cursor + size <= bytes.count,
                      let label = String(bytes: bytes[cursor..<cursor + size], encoding: .ascii),
                      !label.contains("."), NetworkValidation.isPrintable(label) else { throw POSIXError(.EINVAL) }
                labels.append(label)
                cursor += size
            }
            if !labels.isEmpty { names.append(labels.joined(separator: ".")) }
            offset = end ?? cursor
        }
        return names
    }

    private func service(in prefs: SCPreferences, id: String) throws -> SCNetworkService {
        guard let service = SCNetworkServiceCopy(prefs, id as CFString) else {
            throw RouteManagerError.failedToInspectPhysicalDNS("Network service \(id) is unavailable.")
        }
        return service
    }

    private func read(_ service: SCNetworkService, _ kind: ServiceProtocol) throws -> ProtocolConfiguration {
        guard let item = SCNetworkServiceCopyProtocol(service, kind.rawValue as CFString) else {
            guard SCError() == kSCStatusNoKey else { throw failure("Read the \(kind.rawValue) service protocol") }
            return try ProtocolConfiguration(enabled: nil, fields: nil)
        }
        return try ProtocolConfiguration(enabled: SCNetworkProtocolGetEnabled(item),
                                         fields: SCNetworkProtocolGetConfiguration(item) as? [String: Any])
    }

    func configuration(serviceID: String, kind: ServiceProtocol) throws -> ProtocolConfiguration {
        try read(service(in: preferences(), id: serviceID), kind)
    }

    func replace(serviceID: String, kind: ServiceProtocol, expected: ProtocolConfiguration,
                 desired: ProtocolConfiguration) throws {
        let prefs = try preferences()
        guard SCPreferencesLock(prefs, false) else { throw failure("Lock network preferences") }
        defer { SCPreferencesUnlock(prefs) }
        SCPreferencesSynchronize(prefs)
        let service = try service(in: prefs, id: serviceID)
        let current = try read(service, kind)
        let next = try current.merging(desired, from: expected, for: kind)
        let before = try current.fields() as NSDictionary?
        let after = try next.fields() as NSDictionary?
        if before != after || current.enabled != next.enabled {
            let key = kind.rawValue as CFString
            if let enabled = next.enabled {
                if current.enabled == nil, !SCNetworkServiceAddProtocolType(service, key) { throw failure("Create the \(kind.rawValue) protocol") }
                guard let item = SCNetworkServiceCopyProtocol(service, key) else { throw failure("Open the \(kind.rawValue) protocol for writing") }
                if before != after, !SCNetworkProtocolSetConfiguration(item, after as CFDictionary?) { throw failure("Set \(kind.rawValue) configuration") }
                if SCNetworkProtocolGetEnabled(item) != enabled, !SCNetworkProtocolSetEnabled(item, enabled) { throw failure("Set \(kind.rawValue) enabled state") }
            } else if !SCNetworkServiceRemoveProtocolType(service, key) { throw failure("Remove the \(kind.rawValue) protocol") }
            guard SCPreferencesCommitChanges(prefs) else { throw failure("Commit \(kind.rawValue) preferences") }
        }
        do {
            guard SCPreferencesApplyChanges(prefs) else { throw failure("Apply \(kind.rawValue) preferences") }
            let saved = try configuration(serviceID: serviceID, kind: kind)
            guard saved.enabled == next.enabled, try saved.fields() as NSDictionary? == after else {
                throw RouteManagerError.failedToInspectPhysicalDNS("Read-back of \(kind.rawValue) differs from the committed configuration on \(serviceID).")
            }
        } catch {
            if kind == .dns { throw RouteManagerError.dnsMutationMayHaveOccurred(error.localizedDescription) }
            throw error
        }
    }
}
