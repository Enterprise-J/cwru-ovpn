import Foundation

struct SessionState: Codable {
    enum Phase: String, Codable {
        case connecting
        case authPending = "auth-pending"
        case connected
        case disconnecting
        case disconnected
        case failed
    }

    var pid: Int32
    var executablePath: String?
    var phase: Phase
    var profilePath: String
    var configFilePath: String?
    var startedAt: Date
    var lastEvent: String?
    var lastInfo: String?
    var physicalGateway: String?
    var physicalInterface: String?
    var physicalServiceName: String?
    var originalDNSServers: [String]?
    var originalSearchDomains: [String]?
    var originalIPv6Mode: String?
    var pushedDNSServers: [String]?
    var pushedSearchDomains: [String]?
    var tunName: String?
    var vpnIPv4: String?
    var serverHost: String?
    var serverIP: String?
    var tunnelMode: AppTunnelMode?
    var requestedTunnelMode: AppTunnelMode?
    var fullTunnelDefaultRoutes: [ManagedIPv4Route]?
    var fullTunnelDNSServers: [String]?
    var fullTunnelSearchDomains: [String]?
    var appliedIncludedRoutes: [String]?
    var appliedResolverDomains: [String]?
    var routesApplied: Bool
    var cleanupNeeded: Bool

    static func load() -> SessionState? {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        for candidate in candidateFilesForLoad() {
            guard let data = try? Data(contentsOf: candidate),
                  let decoded = try? decoder.decode(SessionState.self, from: data) else {
                continue
            }
            return decoded
        }

        return nil
    }

    func save() throws {
        try RuntimePaths.ensureSessionStateDirectory()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(self)
        try data.write(to: RuntimePaths.sessionStateFile, options: .atomic)
        try RuntimePaths.secureSessionStateFile(at: RuntimePaths.sessionStateFile)
    }

    mutating func markRecoveryRequired(message: String) {
        phase = .failed
        cleanupNeeded = true
        lastEvent = "RECOVERY_REQUIRED"
        lastInfo = message.isEmpty ? nil : message
    }

    static func remove() {
        try? FileManager.default.removeItem(at: RuntimePaths.sessionStateFile)
        if RuntimePaths.legacySessionStateFile.path != RuntimePaths.sessionStateFile.path {
            try? FileManager.default.removeItem(at: RuntimePaths.legacySessionStateFile)
        }
    }

    private static func candidateFilesForLoad() -> [URL] {
        if getuid() != 0 {
            return [RuntimePaths.sessionStateFile]
        }

        let primary = RuntimePaths.sessionStateFile
        guard primary.path != RuntimePaths.legacySessionStateFile.path,
              isSecureRootOwnedFile(RuntimePaths.legacySessionStateFile) else {
            return [primary]
        }

        return [primary, RuntimePaths.legacySessionStateFile]
    }

    private static func isSecureRootOwnedFile(_ fileURL: URL) -> Bool {
        guard let fileAttributes = try? FileManager.default.attributesOfItem(atPath: fileURL.path),
              let owner = fileAttributes[.ownerAccountID] as? NSNumber,
              owner.intValue == 0,
              let permissions = fileAttributes[.posixPermissions] as? NSNumber,
              permissions.intValue & 0o077 == 0 else {
            return false
        }

        let directoryURL = fileURL.deletingLastPathComponent()
        guard let directoryAttributes = try? FileManager.default.attributesOfItem(atPath: directoryURL.path),
              let directoryOwner = directoryAttributes[.ownerAccountID] as? NSNumber,
              directoryOwner.intValue == 0,
              let directoryPermissions = directoryAttributes[.posixPermissions] as? NSNumber,
              directoryPermissions.intValue & 0o022 == 0 else {
            return false
        }

        return true
    }
}
