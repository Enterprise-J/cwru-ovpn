import Darwin
import Foundation

enum AppVerbosity: String {
    case silent
    case daily
    case debug

    func includes(_ messageLevel: ConsoleMessageLevel) -> Bool {
        switch self {
        case .silent:
            return messageLevel == .error
        case .daily:
            return messageLevel != .debug
        case .debug:
            return true
        }
    }
}

enum AppTunnelMode: String, Codable {
    case split
    case full

    var displayName: String {
        switch self {
        case .split:
            return "Split Tunnel"
        case .full:
            return "Full Tunnel"
        }
    }

    var modeDescription: String {
        switch self {
        case .split:
            return "split-tunnel"
        case .full:
            return "full-tunnel"
        }
    }
}

enum WebAuthSessionMode: String, Decodable {
    case browser
    case system
    case systemShared

    func usesSystemSession(isPrivileged: Bool) -> Bool {
        self != .browser || isPrivileged
    }
}

enum ConsoleMessageLevel {
    case info
    case debug
    case error
}

enum AppConfigError: LocalizedError {
    case invalidConfiguration(String)

    var errorDescription: String? {
        switch self {
        case .invalidConfiguration(let message):
            return "Invalid configuration: \(message)"
        }
    }
}

struct StrictJSONKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = "\(intValue)"
        self.intValue = intValue
    }
}

func rejectUnknownJSONKeys<K: CodingKey & CaseIterable>(
    in decoder: Decoder,
    allowedBy _: K.Type,
    context: String
) throws where K.AllCases.Element == K {
    let allowed = Set(K.allCases.map(\.stringValue))
    let container = try decoder.container(keyedBy: StrictJSONKey.self)
    let unknown = container.allKeys
        .map(\.stringValue)
        .filter { !allowed.contains($0) }
        .sorted()

    guard unknown.isEmpty else {
        let suffix = unknown.count == 1 ? "" : "s"
        throw DecodingError.dataCorrupted(
            DecodingError.Context(codingPath: decoder.codingPath,
                                  debugDescription: "\(context) contains unsupported key\(suffix): \(unknown.joined(separator: ", "))")
        )
    }
}

struct SplitTunnelPolicy {
    static let maxIPv4CIDRLength = 18
    static let maxIPv6CIDRLength = 49
    static let maxIPAddressLength = 45
    static let maxDomainNameLength = 253
    static let maxDomainLabelLength = 63

    static let fixedIPv4Routes = [
        "129.22.0.0/16",
        "192.5.109.0/24",
        "192.5.110.0/24",
        "192.5.111.0/24",
        "192.5.112.0/24",
        "192.5.113.0/24",
    ]
    static let fixedIPv6Routes = ["2606:ea00::/32"]
    static let fixedDNSDomains = ["case.edu", "cwru.edu"]
    static let fixedDNSServers = [
        "129.22.4.32",
        "129.22.104.132",
        "129.22.4.31",
        "129.22.104.25",
    ]
    static let fixedHealthCheckHosts = ["129.22.4.32", "129.22.104.132"]
    static let fixed = SplitTunnelPolicy(
        ipv4Routes: fixedIPv4Routes,
        ipv6Routes: fixedIPv6Routes,
        dnsDomains: fixedDNSDomains,
        dnsServers: fixedDNSServers
    )

    let ipv4Routes: [String]
    let ipv6Routes: [String]
    let dnsDomains: [String]
    let dnsServers: [String]

    static let fixedResolverDomains: [String] = {
        fixed.resolverDomains(forIPv4Routes: fixed.ipv4Routes, ipv6Routes: fixed.ipv6Routes)
    }()

    init(ipv4Routes: [String],
         ipv6Routes: [String] = [],
         dnsDomains: [String],
         dnsServers: [String]) {
        self.ipv4Routes = ipv4Routes
        self.ipv6Routes = ipv6Routes
        self.dnsDomains = dnsDomains
        self.dnsServers = dnsServers
    }

    func resolverDomains(forIPv4Routes routes: [String],
                         ipv6Routes: [String]) -> [String] {
        (dnsDomains
            + Self.reverseResolverZones(forIPv4Routes: routes)
            + Self.reverseResolverZones(forIPv6Routes: ipv6Routes)).uniqued()
    }

    static func reverseResolverZones(forIPv4Routes routes: [String]) -> [String] {
        var zones = Set<String>()
        for cidr in routes {
            guard let canonical = IPRoute.canonicalIPv4(cidr),
                  let zone = IPRoute.reverseResolverZone(forIPv4Address: canonical.networkAddress,
                                                         prefixLength: canonical.prefixLength) else {
                continue
            }
            zones.insert(zone)
        }
        return zones.sorted()
    }

    static func reverseResolverZones(forIPv6Routes routes: [String]) -> [String] {
        var zones = Set<String>()
        for cidr in routes {
            guard let canonical = IPRoute.canonicalIPv6(cidr),
                  let zone = IPRoute.reverseResolverZone(forIPv6AddressBytes: canonical.networkBytes,
                                                         prefixLength: canonical.prefixLength) else {
                continue
            }
            zones.insert(zone)
        }
        return zones.sorted()
    }

    static func isValidIPv4CIDR(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= maxIPv4CIDRLength else {
            return false
        }

        let parts = value.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              let prefixLength = Int(parts[1]),
              (0...32).contains(prefixLength) else {
            return false
        }
        return isValidIPv4Address(String(parts[0]))
    }

    static func isValidIPv6CIDR(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= maxIPv6CIDRLength else {
            return false
        }

        let parts = value.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              let prefixLength = Int(parts[1]),
              (0...128).contains(prefixLength) else {
            return false
        }
        return isValidIPv6Address(String(parts[0]))
    }

    static func isValidIPv4Address(_ value: String) -> Bool {
        IPRoute.canonicalIPv4Address(value) != nil
    }

    static func isValidIPv6Address(_ value: String) -> Bool {
        guard !value.isEmpty,
              value.count <= maxIPAddressLength,
              !value.utf8.contains(0) else {
            return false
        }
        var addr = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &addr) == 1 }
    }

    static func isValidDomainName(_ value: String) -> Bool {
        guard !value.isEmpty,
              value.utf8.count <= maxDomainNameLength,
              !value.hasPrefix("."),
              !value.hasSuffix(".") else {
            return false
        }
        return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            let s = String(label)
            return !s.isEmpty
                && s.utf8.count <= maxDomainLabelLength
                && s.unicodeScalars.allSatisfy(Self.isASCIIDomainLabelScalar)
                && !s.hasPrefix("-")
                && !s.hasSuffix("-")
        }
    }

    private static func isASCIIDomainLabelScalar(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x30...0x39, 0x41...0x5A, 0x61...0x7A, 0x2D:
            return true
        default:
            return false
        }
    }

    static func isValidIPAddress(_ value: String) -> Bool {
        isValidIPv4Address(value) || isValidIPv6Address(value)
    }

    static func isSafeInterfaceName(_ value: String) -> Bool {
        !value.isEmpty
            && !value.hasPrefix("-")
            && value.count <= 32
            && value.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "." || $0 == "-" }
    }

    static func isVirtualInterfaceName(_ value: String) -> Bool {
        value.hasPrefix("utun") || value.hasPrefix("ppp")
    }

    private static let networkServiceNameCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -./()_+'&")

    static func isSafeNetworkServiceName(_ value: String) -> Bool {
        !value.isEmpty
            && !value.hasPrefix("-")
            && value.count <= 128
            && value.unicodeScalars.allSatisfy(networkServiceNameCharacters.contains)
    }

    static func isCWRUDomain(_ value: String) -> Bool {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return fixedDNSDomains.contains { domain in
            normalized == domain || normalized.hasSuffix(".\(domain)")
        }
    }
}

struct AppConfig: Decodable {
    private static let maxDNSBootstrapServerCount = 16
    private static let maxConfigFileBytes = 64 * 1024

    let tunnelMode: AppTunnelMode
    let preventSleep: Bool
    let privacyMode: Bool
    let webAuthSession: WebAuthSessionMode
    let dnsBootstrapServers: [String]?

    static let supportedSSOMethods = ["webauth"]

    static let defaults = AppConfig(
        tunnelMode: .split,
        preventSleep: true,
        privacyMode: true,
        webAuthSession: .systemShared,
        dnsBootstrapServers: nil
    )

    var effectiveDNSBootstrapServers: [String] {
        (dnsBootstrapServers ?? []).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.uniqued()
    }

    static func load(explicitConfigPath: String?,
                     allowEnvironmentConfigPath: Bool = true,
                     homeConfigFile: URL = RuntimePaths.homeConfigFile) throws -> AppConfig {
        try load(at: resolvedConfigURL(explicitConfigPath: explicitConfigPath,
                                       allowEnvironmentConfigPath: allowEnvironmentConfigPath,
                                       homeConfigFile: homeConfigFile))
    }

    static func load(at configURL: URL?) throws -> AppConfig {
        try configURL.map(decode(from:)) ?? defaults
    }

    static func resolvedConfigURL(explicitConfigPath: String?,
                                  allowEnvironmentConfigPath: Bool = true,
                                  homeConfigFile: URL = RuntimePaths.homeConfigFile) -> URL? {
        if let explicitConfigPath {
            return URL(fileURLWithPath: expandUserPath(explicitConfigPath)).standardized
        }

        if allowEnvironmentConfigPath,
           let environmentConfigPath = configPathFromEnvironment() {
            return URL(fileURLWithPath: expandUserPath(environmentConfigPath)).standardized
        }

        return FileManager.default.fileExists(atPath: homeConfigFile.path)
            ? homeConfigFile.standardized
            : nil
    }

    static func approvedProfilePath(homeProfileFile: URL = RuntimePaths.homeProfileFile) throws -> String {
        let profilePath = homeProfileFile.standardized.path
        guard FileManager.default.fileExists(atPath: profilePath) else {
            throw CLIError.missingProfile
        }
        return profilePath
    }

    static func expandUserPath(_ path: String) -> String {
        if getuid() == 0,
           path == "~" || path.hasPrefix("~/"),
           let sudoIdentity = try? ExecutionIdentity.validatedSudoUserIfAvailable() {
            let suffix = String(path.dropFirst())
            return sudoIdentity.homeDirectory.path + suffix
        }
        return NSString(string: path).expandingTildeInPath
    }

    private static func configPathFromEnvironment() -> String? {
        ProcessInfo.processInfo.environment["CWRU_OVPN_CONFIG"].flatMap { $0.isEmpty ? nil : $0 }
    }

    private static func decode(from url: URL) throws -> AppConfig {
        let data = try SecureFile.readRegularFile(at: url,
                                                        maximumBytes: maxConfigFileBytes,
                                                        context: "configuration file \(url.path)")
        return try JSONDecoder().decode(AppConfig.self, from: data)
    }

    private func validationError() -> String? {
        if let dnsBootstrapServers {
            if dnsBootstrapServers.count > Self.maxDNSBootstrapServerCount {
                return "dnsBootstrapServers contains \(dnsBootstrapServers.count) entries; the maximum is \(Self.maxDNSBootstrapServerCount)."
            }
            for server in dnsBootstrapServers {
                let trimmed = server.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.isEmpty || !SplitTunnelPolicy.isValidIPAddress(trimmed) {
                    return "Invalid dnsBootstrapServer '\(server)'. Expected an IP address."
                }
            }
        }

        return nil
    }

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case tunnelMode
        case privacyMode
        case preventSleep
        case webAuthSession
        case dnsBootstrapServers
    }

    private init(tunnelMode: AppTunnelMode,
                 preventSleep: Bool,
                 privacyMode: Bool,
                 webAuthSession: WebAuthSessionMode,
                 dnsBootstrapServers: [String]?) {
        self.tunnelMode = tunnelMode
        self.preventSleep = preventSleep
        self.privacyMode = privacyMode
        self.webAuthSession = webAuthSession
        self.dnsBootstrapServers = dnsBootstrapServers
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownJSONKeys(in: decoder,
                                  allowedBy: CodingKeys.self,
                                  context: "config")
        let container = try decoder.container(keyedBy: CodingKeys.self)

        tunnelMode = try container.decodeIfPresent(AppTunnelMode.self, forKey: .tunnelMode) ?? Self.defaults.tunnelMode
        privacyMode = try container.decodeIfPresent(Bool.self, forKey: .privacyMode) ?? Self.defaults.privacyMode
        preventSleep = try container.decodeIfPresent(Bool.self, forKey: .preventSleep) ?? Self.defaults.preventSleep
        webAuthSession = try container.decodeIfPresent(WebAuthSessionMode.self,
                                                       forKey: .webAuthSession) ?? Self.defaults.webAuthSession
        dnsBootstrapServers = try container.decodeIfPresent([String].self, forKey: .dnsBootstrapServers)
        if let problem = validationError() {
            throw AppConfigError.invalidConfiguration(problem)
        }
    }
}
