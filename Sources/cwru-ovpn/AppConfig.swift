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

enum AppTunnelMode: String, Codable, CaseIterable {
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
    case system
    case systemShared
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

struct AppConfig: Decodable {
    private static let maxDNSBootstrapServerCount = 16
    private static let maxConfigFileBytes = 64 * 1024

    let tunnelMode: AppTunnelMode
    let preventSleep: Bool
    let privacyMode: Bool
    let webAuthSession: WebAuthSessionMode
    let dnsBootstrapServers: [String]?

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
                     homeConfigFile: URL = RuntimePaths.homeConfigFile) throws -> AppConfig {
        try load(at: resolvedConfigURL(explicitConfigPath: explicitConfigPath,
                                       homeConfigFile: homeConfigFile))
    }

    static func load(at configURL: URL?) throws -> AppConfig {
        try configURL.map(decode(from:)) ?? defaults
    }

    static func resolvedConfigURL(explicitConfigPath: String?,
                                  homeConfigFile: URL = RuntimePaths.homeConfigFile) -> URL? {
        if let explicitConfigPath {
            return URL(fileURLWithPath: expandUserPath(explicitConfigPath)).standardized
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
                if trimmed.isEmpty || !NetworkValidation.isValidIPAddress(trimmed) {
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
