import Darwin
import Foundation

enum AppVerbosity: String, Codable {
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

struct AppConfig: Codable {
    struct SplitTunnelConfiguration: Codable {
        static let defaultReachabilityProbeHosts = [
            "1.1.1.1",
            "8.8.8.8",
            "223.5.5.5",
        ]

        var includedRoutes: [String]
        var resolverDomains: [String]
        var resolverNameServers: [String]
        var reachabilityProbeHosts: [String]?

        init(includedRoutes: [String],
             resolverDomains: [String],
             resolverNameServers: [String],
             reachabilityProbeHosts: [String]?) {
            self.includedRoutes = includedRoutes
            self.resolverDomains = resolverDomains
            self.resolverNameServers = resolverNameServers
            self.reachabilityProbeHosts = reachabilityProbeHosts
        }

        var effectiveReachabilityProbeHosts: [String] {
            guard let reachabilityProbeHosts else {
                return Self.defaultReachabilityProbeHosts
            }

            return reachabilityProbeHosts.compactMap { host in
                let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
                return trimmed.isEmpty ? nil : trimmed
            }
        }

        var effectiveResolverDomains: [String] {
            var seen = Set<String>()
            var result: [String] = []
            for domain in resolverDomains + Self.reverseResolverZones(forIncludedRoutes: includedRoutes) {
                if seen.insert(domain).inserted {
                    result.append(domain)
                }
            }
            return result
        }

        static func reverseResolverZones(forIncludedRoutes routes: [String]) -> [String] {
            var zones = Set<String>()
            for cidr in routes {
                guard let canonical = RouteManager.canonicalIPv4Route(cidr) else { continue }
                let octetPrefix = canonical.prefixLength / 8
                guard octetPrefix > 0 else { continue }
                var labels: [String] = []
                for i in 0..<octetPrefix {
                    let shift = 24 - (i * 8)
                    let octet = (canonical.networkAddress >> UInt32(shift)) & 0xFF
                    labels.append(String(octet))
                }
                zones.insert(labels.reversed().joined(separator: ".") + ".in-addr.arpa")
            }
            return zones.sorted()
        }

        func validationError() -> String? {
            for route in includedRoutes {
                if !Self.isValidCIDR(route) {
                    return "Invalid includedRoute '\(route)'. Expected an IPv4 CIDR block such as '129.22.0.0/16'."
                }
            }
            for domain in resolverDomains {
                if !Self.isValidDomainName(domain) {
                    return "Invalid resolverDomain '\(domain)'. Expected a hostname such as 'case.edu'."
                }
            }
            for ns in resolverNameServers {
                if !Self.isValidIPAddress(ns) {
                    return "Invalid resolverNameServer '\(ns)'. Expected an IPv4 or IPv6 address."
                }
            }
            if let reachabilityProbeHosts {
                for host in reachabilityProbeHosts {
                    let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
                    if trimmed.isEmpty || !Self.isValidReachabilityProbeHost(trimmed) {
                        return "Invalid reachabilityProbeHost '\(host)'. Expected an IP address or hostname such as '1.1.1.1' or 'cloudflare.com'."
                    }
                }
            }
            return nil
        }
        static func isValidCIDR(_ value: String) -> Bool {
            let parts = value.split(separator: "/", maxSplits: 1)
            guard parts.count == 2,
                  let prefixLength = Int(parts[1]),
                  (0...32).contains(prefixLength) else {
                return false
            }
            var addr = in_addr()
            return String(parts[0]).withCString { inet_pton(AF_INET, $0, &addr) == 1 }
        }

        static func isValidDomainName(_ value: String) -> Bool {
            guard !value.isEmpty, !value.hasPrefix("."), !value.hasSuffix(".") else {
                return false
            }
            return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
                let s = String(label)
                return !s.isEmpty
                    && s.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" }
                    && !s.hasPrefix("-")
                    && !s.hasSuffix("-")
            }
        }

        static func isValidIPAddress(_ value: String) -> Bool {
            var addr4 = in_addr()
            var addr6 = in6_addr()
            return value.withCString { ptr in
                inet_pton(AF_INET, ptr, &addr4) == 1 || inet_pton(AF_INET6, ptr, &addr6) == 1
            }
        }

        static func isValidReachabilityProbeHost(_ value: String) -> Bool {
            isValidIPAddress(value) || isValidDomainName(value)
        }

        private enum CodingKeys: String, CodingKey {
            case includedRoutes
            case resolverDomains
            case resolverNameServers
            case reachabilityProbeHosts
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            includedRoutes = try container.decodeIfPresent([String].self, forKey: .includedRoutes) ?? []
            resolverDomains = try container.decodeIfPresent([String].self, forKey: .resolverDomains) ?? []
            resolverNameServers = try container.decodeIfPresent([String].self, forKey: .resolverNameServers) ?? []
            reachabilityProbeHosts = try container.decodeIfPresent([String].self, forKey: .reachabilityProbeHosts)
        }
    }

    var profilePath: String?
    var tunnelMode: AppTunnelMode
    var preventSleep: Bool
    var splitTunnel: SplitTunnelConfiguration
    var verbosity: AppVerbosity

    static let hardcodedSSOMethods = ["webauth", "openurl", "crtext"]

    static let defaultConfigFileNames = [
        AppIdentity.defaultConfigFileName,
        "cwru-ovpn.json",
    ]

    static let fallback = AppConfig(
        profilePath: nil,
        tunnelMode: .split,
        preventSleep: true,
        splitTunnel: SplitTunnelConfiguration(
            includedRoutes: [],
            resolverDomains: [],
            resolverNameServers: [],
            reachabilityProbeHosts: nil
        ),
        verbosity: .daily
    )

    static func load(explicitConfigPath: String?) throws -> AppConfig {
        guard let configURL = resolvedConfigURL(explicitConfigPath: explicitConfigPath) else {
            return fallback
        }

        return try decode(from: configURL)
    }

    static func resolvedConfigURL(explicitConfigPath: String?) -> URL? {
        if let explicitConfigPath {
            return URL(fileURLWithPath: expandUserPath(explicitConfigPath)).standardized
        }

        if let environmentConfigPath = configPathFromEnvironment() {
            return URL(fileURLWithPath: expandUserPath(environmentConfigPath)).standardized
        }

        return candidateURLs().first {
            FileManager.default.fileExists(atPath: $0.path)
        }?.standardized
    }

    func resolvedProfilePath(explicitConfigPath: String?) throws -> String {
        if let profilePath, !profilePath.isEmpty {
            return URL(fileURLWithPath: Self.expandUserPath(profilePath)).standardized.path
        }
        if Self.resolvedConfigURL(explicitConfigPath: explicitConfigPath) == nil {
            throw CLIError.missingConfigFile
        }
        throw CLIError.missingConfig
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

    private static func candidateURLs() -> [URL] {
        let currentDirectory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
        var candidates = defaultConfigFileNames.map { currentDirectory.appendingPathComponent($0) }
        candidates.append(RuntimePaths.homeConfigFile)
        return candidates
    }

    private static func configPathFromEnvironment() -> String? {
        ProcessInfo.processInfo.environment["CWRU_OVPN_CONFIG"].flatMap { $0.isEmpty ? nil : $0 }
    }

    private static func decode(from url: URL) throws -> AppConfig {
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        let config = try decoder.decode(AppConfig.self, from: data)
        if let problem = config.splitTunnel.validationError() {
            throw AppConfigError.invalidConfiguration(problem)
        }
        return config
    }

    enum CodingKeys: String, CodingKey {
        case profilePath
        case tunnelMode
        case preventSleep
        case splitTunnel
        case verbosity
    }

    private enum LegacyCodingKeys: String, CodingKey {
        case defaultProfilePath
    }

    init(profilePath: String?,
         tunnelMode: AppTunnelMode,
         preventSleep: Bool,
         splitTunnel: SplitTunnelConfiguration,
         verbosity: AppVerbosity) {
        self.profilePath = profilePath
        self.tunnelMode = tunnelMode
        self.preventSleep = preventSleep
        self.splitTunnel = splitTunnel
        self.verbosity = verbosity
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(profilePath, forKey: .profilePath)
        try container.encode(tunnelMode, forKey: .tunnelMode)
        try container.encode(preventSleep, forKey: .preventSleep)
        try container.encode(splitTunnel, forKey: .splitTunnel)
        try container.encode(verbosity, forKey: .verbosity)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let legacyContainer = try decoder.container(keyedBy: LegacyCodingKeys.self)

        profilePath = try container.decodeIfPresent(String.self, forKey: .profilePath)
            ?? legacyContainer.decodeIfPresent(String.self, forKey: .defaultProfilePath)
        tunnelMode = try container.decodeIfPresent(AppTunnelMode.self, forKey: .tunnelMode) ?? Self.fallback.tunnelMode
        preventSleep = try container.decodeIfPresent(Bool.self, forKey: .preventSleep) ?? Self.fallback.preventSleep
        splitTunnel = try container.decodeIfPresent(SplitTunnelConfiguration.self, forKey: .splitTunnel) ?? Self.fallback.splitTunnel
        verbosity = try container.decodeIfPresent(AppVerbosity.self, forKey: .verbosity) ?? .daily
    }
}
