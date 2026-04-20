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

        var effectiveReachabilityProbeHosts: [String] {
            guard let reachabilityProbeHosts else {
                return Self.defaultReachabilityProbeHosts
            }

            return reachabilityProbeHosts.compactMap { host in
                let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
                return trimmed.isEmpty ? nil : trimmed
            }
        }

        /// Resolver domains used at runtime: the user's `resolverDomains` plus
        /// in-addr.arpa zones derived from `includedRoutes`. Auto-deriving the
        /// reverse zones ensures PTR lookups for campus IPs cannot leak even if
        /// the user edits resolverDomains.
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

        /// Returns a human-readable error message if any values fail validation,
        /// or nil when the configuration is valid.
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

        // MARK: - Validators

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
    }

    var profilePath: String?
    var tunnelMode: AppTunnelMode
    var allowSleep: Bool
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
        allowSleep: false,
        splitTunnel: SplitTunnelConfiguration(
            includedRoutes: [],
            resolverDomains: [],
            resolverNameServers: [],
            reachabilityProbeHosts: nil
        ),
        verbosity: .daily
    )

    static func load(explicitConfigPath: String?) throws -> AppConfig {
        if let explicitConfigPath {
            return try decode(from: URL(fileURLWithPath: expandUserPath(explicitConfigPath)))
        }

        if let environmentConfigPath = configPathFromEnvironment() {
            return try decode(from: URL(fileURLWithPath: expandUserPath(environmentConfigPath)))
        }

        for candidate in candidateURLs() {
            if FileManager.default.fileExists(atPath: candidate.path) {
                return try decode(from: candidate)
            }
        }

        return fallback
    }

    static func resolvedConfigURL(explicitConfigPath: String?) -> URL? {
        if let explicitConfigPath {
            return URL(fileURLWithPath: expandUserPath(explicitConfigPath)).standardized
        }

        if let environmentConfigPath = configPathFromEnvironment() {
            return URL(fileURLWithPath: expandUserPath(environmentConfigPath)).standardized
        }

        for candidate in candidateURLs() {
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate.standardized
            }
        }

        return nil
    }

    func resolvedProfilePath() throws -> String {
        if let profilePath, !profilePath.isEmpty {
            return URL(fileURLWithPath: Self.expandUserPath(profilePath)).standardized.path
        }
        throw CLIError.missingConfig
    }

    static func expandUserPath(_ path: String) -> String {
        if path == "~" || path.hasPrefix("~/") {
            let environment = ProcessInfo.processInfo.environment
            if let sudoUser = environment["SUDO_USER"],
               !sudoUser.isEmpty,
               sudoUser != "root" {
                let userHome = NSString(string: "~\(sudoUser)").expandingTildeInPath
                let suffix = String(path.dropFirst())
                return userHome + suffix
            }
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
        let environment = ProcessInfo.processInfo.environment
        for key in ["CWRU_OVPN_CONFIG"] {
            if let value = environment[key], !value.isEmpty {
                return value
            }
        }
        return nil
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
        case allowSleep
        case splitTunnel
        case verbosity
    }

    private enum LegacyCodingKeys: String, CodingKey {
        case defaultProfilePath
        case allowIdleSleep
    }

    init(profilePath: String?,
         tunnelMode: AppTunnelMode,
         allowSleep: Bool,
         splitTunnel: SplitTunnelConfiguration,
         verbosity: AppVerbosity) {
        self.profilePath = profilePath
        self.tunnelMode = tunnelMode
        self.allowSleep = allowSleep
        self.splitTunnel = splitTunnel
        self.verbosity = verbosity
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(profilePath, forKey: .profilePath)
        try container.encode(tunnelMode, forKey: .tunnelMode)
        try container.encode(allowSleep, forKey: .allowSleep)
        try container.encode(splitTunnel, forKey: .splitTunnel)
        try container.encode(verbosity, forKey: .verbosity)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let legacyContainer = try decoder.container(keyedBy: LegacyCodingKeys.self)

        // Keep loading the legacy field names so older installs continue to
        // work after the config schema was simplified.
        profilePath = try container.decodeIfPresent(String.self, forKey: .profilePath)
            ?? legacyContainer.decodeIfPresent(String.self, forKey: .defaultProfilePath)
        tunnelMode = try container.decodeIfPresent(AppTunnelMode.self, forKey: .tunnelMode) ?? Self.fallback.tunnelMode
        allowSleep = try container.decodeIfPresent(Bool.self, forKey: .allowSleep)
            ?? legacyContainer.decodeIfPresent(Bool.self, forKey: .allowIdleSleep)
            ?? Self.fallback.allowSleep
        splitTunnel = try container.decodeIfPresent(SplitTunnelConfiguration.self, forKey: .splitTunnel) ?? Self.fallback.splitTunnel
        verbosity = try container.decodeIfPresent(AppVerbosity.self, forKey: .verbosity) ?? .daily
    }
}
