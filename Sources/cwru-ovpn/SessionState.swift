import Darwin
import Foundation

enum SessionStateError: LocalizedError {
    case encodedStateTooLarge(actualBytes: Int, maximumBytes: Int)
    case invalidPersistedState(String)
    case sessionAlreadyExists
    case unsafeRecoveryState(String)
    case couldNotRemove(String)

    var errorDescription: String? {
        switch self {
        case .encodedStateTooLarge(let actualBytes, let maximumBytes):
            return "Session recovery state is \(actualBytes) bytes; the maximum is \(maximumBytes) bytes. Refusing to modify the network without a readable recovery ledger."
        case .invalidPersistedState(let message):
            return "Session recovery state is invalid: \(message)"
        case .sessionAlreadyExists:
            return "A VPN session or recovery ledger already exists. Disconnect before starting a new session."
        case .unsafeRecoveryState(let message):
            return message
        case .couldNotRemove(let message):
            return "Could not remove the session recovery state: \(message)"
        }
    }
}

struct SessionState: Codable {
    private static let maxSessionStateBytes = 64 * 1024
    private static let currentSchemaVersion = 4
    private static let fileName = "session.json"
    private static let lockName = "session-state.lock"

    enum LoadResult {
        case missing
        case loaded(SessionState)
        case invalid(String)

        var loadedSession: SessionState? {
            if case .loaded(let session) = self {
                return session
            }
            return nil
        }
    }

    enum Phase: String, Codable {
        case connecting
        case authPending = "auth-pending"
        case connected
        case disconnecting
        case disconnected
        case failed
    }

    let schemaVersion: Int
    var pid: Int32
    var executablePath: String
    var processStartTime: ProcessStartTime
    var phase: Phase
    var profilePath: String
    var configFilePath: String?
    var startedAt: Date
    var connectedAt: Date?
    var lastEvent: String?
    var lastInfo: String?
    var physicalGateway: String
    var physicalInterface: String
    var physicalServiceName: String?
    var originalDNSServers: [String]?
    var originalSearchDomains: [String]?
    var originalDefaultSearchDomains: [String]?
    var originalIPv6Mode: String?
    var pushedDNSServers: [String]?
    var pushedSearchDomains: [String]?
    var tunName: String?
    var vpnIPv4: String?
    var vpnGatewayIPv4: String?
    var vpnIPv6: String?
    var serverHost: String?
    var serverIP: String?
    var tunnelMode: AppTunnelMode
    var requestedTunnelMode: AppTunnelMode?
    var fullTunnelDefaultRoutes: [ManagedIPv4Route]?
    var fullTunnelDNSServers: [String]?
    var fullTunnelSearchDomains: [String]?
    var managedRemoteIPv4Routes: [ManagedIPv4Route]?
    var replacedRemoteIPv4Routes: [ManagedIPv4Route]?
    var managedSplitDefaultRoutes: [ManagedIPv4Route]?
    var managedIPv6Routes: [ManagedIPv6Route]?
    var sessionOwnedBlockedIPv6Routes: [String]?
    var appliedSplitIPv4Routes: [String]?
    var appliedSplitIPv6Routes: [String]?
    var appliedDNSDomains: [String]?
    var cleanupNeeded: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion
        case pid
        case executablePath
        case processStartTime
        case phase
        case profilePath
        case configFilePath
        case startedAt
        case connectedAt
        case lastEvent
        case lastInfo
        case physicalGateway
        case physicalInterface
        case physicalServiceName
        case originalDNSServers
        case originalSearchDomains
        case originalDefaultSearchDomains
        case originalIPv6Mode
        case pushedDNSServers
        case pushedSearchDomains
        case tunName
        case vpnIPv4
        case vpnGatewayIPv4
        case vpnIPv6
        case serverHost
        case serverIP
        case tunnelMode
        case requestedTunnelMode
        case fullTunnelDefaultRoutes
        case fullTunnelDNSServers
        case fullTunnelSearchDomains
        case managedRemoteIPv4Routes
        case replacedRemoteIPv4Routes
        case managedSplitDefaultRoutes
        case managedIPv6Routes
        case sessionOwnedBlockedIPv6Routes
        case appliedSplitIPv4Routes
        case appliedSplitIPv6Routes
        case appliedDNSDomains
        case cleanupNeeded
    }

    init(pid: Int32,
         executablePath: String,
         processStartTime: ProcessStartTime,
         phase: Phase,
         profilePath: String,
         configFilePath: String? = nil,
         startedAt: Date,
         connectedAt: Date? = nil,
         lastEvent: String? = nil,
         lastInfo: String? = nil,
         physicalGateway: String,
         physicalInterface: String,
         physicalServiceName: String? = nil,
         originalDNSServers: [String]? = nil,
         originalSearchDomains: [String]? = nil,
         originalDefaultSearchDomains: [String]? = nil,
         originalIPv6Mode: String? = nil,
         pushedDNSServers: [String]? = nil,
         pushedSearchDomains: [String]? = nil,
         tunName: String? = nil,
         vpnIPv4: String? = nil,
         vpnGatewayIPv4: String? = nil,
         vpnIPv6: String? = nil,
         serverHost: String? = nil,
         serverIP: String? = nil,
         tunnelMode: AppTunnelMode,
         requestedTunnelMode: AppTunnelMode? = nil,
         fullTunnelDefaultRoutes: [ManagedIPv4Route]? = nil,
         fullTunnelDNSServers: [String]? = nil,
         fullTunnelSearchDomains: [String]? = nil,
         managedRemoteIPv4Routes: [ManagedIPv4Route]? = nil,
         replacedRemoteIPv4Routes: [ManagedIPv4Route]? = nil,
         managedSplitDefaultRoutes: [ManagedIPv4Route]? = nil,
         managedIPv6Routes: [ManagedIPv6Route]? = nil,
         appliedSplitIPv4Routes: [String]? = nil,
         appliedSplitIPv6Routes: [String]? = nil,
         appliedDNSDomains: [String]? = nil,
         cleanupNeeded: Bool) {
        self.schemaVersion = Self.currentSchemaVersion
        self.pid = pid
        self.executablePath = executablePath
        self.processStartTime = processStartTime
        self.phase = phase
        self.profilePath = profilePath
        self.configFilePath = configFilePath
        self.startedAt = startedAt
        self.connectedAt = connectedAt
        self.lastEvent = lastEvent
        self.lastInfo = lastInfo
        self.physicalGateway = physicalGateway
        self.physicalInterface = physicalInterface
        self.physicalServiceName = physicalServiceName
        self.originalDNSServers = originalDNSServers
        self.originalSearchDomains = originalSearchDomains
        self.originalDefaultSearchDomains = originalDefaultSearchDomains
        self.originalIPv6Mode = originalIPv6Mode
        self.pushedDNSServers = pushedDNSServers
        self.pushedSearchDomains = pushedSearchDomains
        self.tunName = tunName
        self.vpnIPv4 = vpnIPv4
        self.vpnGatewayIPv4 = vpnGatewayIPv4
        self.vpnIPv6 = vpnIPv6
        self.serverHost = serverHost
        self.serverIP = serverIP
        self.tunnelMode = tunnelMode
        self.requestedTunnelMode = requestedTunnelMode
        self.fullTunnelDefaultRoutes = fullTunnelDefaultRoutes
        self.fullTunnelDNSServers = fullTunnelDNSServers
        self.fullTunnelSearchDomains = fullTunnelSearchDomains
        self.managedRemoteIPv4Routes = managedRemoteIPv4Routes
        self.replacedRemoteIPv4Routes = replacedRemoteIPv4Routes
        self.managedSplitDefaultRoutes = managedSplitDefaultRoutes
        self.managedIPv6Routes = managedIPv6Routes
        self.sessionOwnedBlockedIPv6Routes = nil
        self.appliedSplitIPv4Routes = appliedSplitIPv4Routes
        self.appliedSplitIPv6Routes = appliedSplitIPv6Routes
        self.appliedDNSDomains = appliedDNSDomains
        self.cleanupNeeded = cleanupNeeded
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownJSONKeys(in: decoder,
                                  allowedBy: CodingKeys.self,
                                  context: "session state")
        let container = try decoder.container(keyedBy: CodingKeys.self)

        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        guard schemaVersion == Self.currentSchemaVersion else {
            throw DecodingError.dataCorruptedError(forKey: .schemaVersion,
                                                   in: container,
                                                   debugDescription: "Unsupported session state schema version.")
        }
        pid = try container.decode(Int32.self, forKey: .pid)
        executablePath = try container.decode(String.self, forKey: .executablePath)
        processStartTime = try container.decode(ProcessStartTime.self, forKey: .processStartTime)
        phase = try container.decode(Phase.self, forKey: .phase)
        profilePath = try container.decode(String.self, forKey: .profilePath)
        configFilePath = try container.decodeIfPresent(String.self, forKey: .configFilePath)
        startedAt = try container.decode(Date.self, forKey: .startedAt)
        connectedAt = try container.decodeIfPresent(Date.self, forKey: .connectedAt)
        lastEvent = try container.decodeIfPresent(String.self, forKey: .lastEvent)
        lastInfo = try container.decodeIfPresent(String.self, forKey: .lastInfo)
        physicalGateway = try container.decode(String.self, forKey: .physicalGateway)
        physicalInterface = try container.decode(String.self, forKey: .physicalInterface)
        physicalServiceName = try container.decodeIfPresent(String.self, forKey: .physicalServiceName)
        originalDNSServers = try container.decodeIfPresent([String].self, forKey: .originalDNSServers)
        originalSearchDomains = try container.decodeIfPresent([String].self, forKey: .originalSearchDomains)
        originalDefaultSearchDomains = try container.decodeIfPresent([String].self, forKey: .originalDefaultSearchDomains)
        originalIPv6Mode = try container.decodeIfPresent(String.self, forKey: .originalIPv6Mode)
        pushedDNSServers = try container.decodeIfPresent([String].self, forKey: .pushedDNSServers)
        pushedSearchDomains = try container.decodeIfPresent([String].self, forKey: .pushedSearchDomains)
        tunName = try container.decodeIfPresent(String.self, forKey: .tunName)
        vpnIPv4 = try container.decodeIfPresent(String.self, forKey: .vpnIPv4)
        vpnGatewayIPv4 = try container.decodeIfPresent(String.self, forKey: .vpnGatewayIPv4)
        vpnIPv6 = try container.decodeIfPresent(String.self, forKey: .vpnIPv6)
        serverHost = try container.decodeIfPresent(String.self, forKey: .serverHost)
        serverIP = try container.decodeIfPresent(String.self, forKey: .serverIP)
        tunnelMode = try container.decode(AppTunnelMode.self, forKey: .tunnelMode)
        requestedTunnelMode = try container.decodeIfPresent(AppTunnelMode.self, forKey: .requestedTunnelMode)
        fullTunnelDefaultRoutes = try container.decodeIfPresent([ManagedIPv4Route].self, forKey: .fullTunnelDefaultRoutes)
        fullTunnelDNSServers = try container.decodeIfPresent([String].self, forKey: .fullTunnelDNSServers)
        fullTunnelSearchDomains = try container.decodeIfPresent([String].self, forKey: .fullTunnelSearchDomains)
        managedRemoteIPv4Routes = try container.decodeIfPresent([ManagedIPv4Route].self, forKey: .managedRemoteIPv4Routes)
        replacedRemoteIPv4Routes = try container.decodeIfPresent([ManagedIPv4Route].self, forKey: .replacedRemoteIPv4Routes)
        managedSplitDefaultRoutes = try container.decodeIfPresent([ManagedIPv4Route].self, forKey: .managedSplitDefaultRoutes)
        managedIPv6Routes = try container.decodeIfPresent([ManagedIPv6Route].self, forKey: .managedIPv6Routes)
        sessionOwnedBlockedIPv6Routes = try container.decodeIfPresent([String].self, forKey: .sessionOwnedBlockedIPv6Routes)
        appliedSplitIPv4Routes = try container.decodeIfPresent([String].self, forKey: .appliedSplitIPv4Routes)
        appliedSplitIPv6Routes = try container.decodeIfPresent([String].self, forKey: .appliedSplitIPv6Routes)
        appliedDNSDomains = try container.decodeIfPresent([String].self, forKey: .appliedDNSDomains)
        cleanupNeeded = try container.decode(Bool.self, forKey: .cleanupNeeded)
    }

    static func load(from store: StateDirectory = StateDirectory()) -> SessionState? {
        guard case .loaded(let session) = loadResult(from: store) else {
            return nil
        }
        return session
    }

    static func loadResult(from store: StateDirectory = StateDirectory()) -> LoadResult {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var failures: [String] = []

        let primary = store.url.appendingPathComponent(fileName)
        if !store.usesRuntimePaths || FileManager.default.fileExists(atPath: primary.path) {
            do {
                let data = try store.withAnchor { directoryFD, userID, groupID in
                    try AnchoredFileIO.readOwnedRegularFile(in: directoryFD,
                                                            name: fileName,
                                                            userID: userID,
                                                            groupID: groupID,
                                                            maximumBytes: maxSessionStateBytes)
                }
                if let data {
                    return .loaded(try decoder.decode(SessionState.self, from: data))
                }
                if !store.usesRuntimePaths {
                    return .missing
                }
            } catch {
                failures.append("\(primary.path): \(error.localizedDescription)")
            }
        }

        if store.usesRuntimePaths,
           getuid() != 0,
           primary.path != RuntimePaths.homeSessionStateFile.path {
            do {
                if let data = try RuntimePaths.readHomeStateFile(name: fileName,
                                                                 maximumBytes: maxSessionStateBytes) {
                    return .loaded(try decoder.decode(SessionState.self, from: data))
                }
            } catch {
                failures.append("\(RuntimePaths.homeSessionStateFile.path): \(error.localizedDescription)")
            }
        }

        return failures.isEmpty ? .missing : .invalid(failures.joined(separator: "; "))
    }

    func create(to store: StateDirectory = StateDirectory()) throws {
        _ = try Self.saveAtomically(in: store) { persistedState in
            guard persistedState == nil else {
                throw SessionStateError.sessionAlreadyExists
            }
            return self
        }
    }

    func save(to store: StateDirectory = StateDirectory()) throws {
        _ = try Self.saveAtomically(in: store) { _ in self }
    }

    @discardableResult
    static func saveAtomically(in store: StateDirectory = StateDirectory(),
                               _ transform: (SessionState?) throws -> SessionState) throws -> SessionState {
        try store.withExclusiveLock(named: lockName) { _, _, _ in
            let persistedState: SessionState?
            switch loadResult(from: store) {
            case .missing:
                persistedState = nil
            case .loaded(let session):
                persistedState = session
            case .invalid(let message):
                throw SessionStateError.invalidPersistedState(message)
            }

            let updatedState = try transform(persistedState)
            try updatedState.saveUnlocked(to: store)
            return updatedState
        }
    }

    private func saveUnlocked(to store: StateDirectory) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(self)
        guard data.count <= Self.maxSessionStateBytes else {
            throw SessionStateError.encodedStateTooLarge(actualBytes: data.count,
                                                         maximumBytes: Self.maxSessionStateBytes)
        }
        try store.withAnchor { directoryFD, userID, groupID in
            try AnchoredFileIO.writeOwnedRegularFileAtomically(data,
                                                               in: directoryFD,
                                                               name: Self.fileName,
                                                               userID: userID,
                                                               groupID: groupID)
        }
        if store.usesRuntimePaths, RuntimePaths.homeSessionStateFile.path != RuntimePaths.sessionStateFile.path {
            do {
                try RuntimePaths.writeHomeStateFileAtomically(data, name: Self.fileName)
            } catch {
                fputs("\(AppIdentity.executableName): failed to update the non-authoritative session state mirror: \(error.localizedDescription)\n", stderr)
            }
        }
    }

    func requestingModeSwitch(to mode: AppTunnelMode) -> SessionState {
        var updated = self
        updated.requestedTunnelMode = mode
        if updated.lastEvent == "MODE_SWITCH_DEFERRED" {
            updated.lastEvent = nil
            updated.lastInfo = nil
        }
        return updated
    }

    mutating func markRecoveryRequired(message: String) {
        phase = .failed
        cleanupNeeded = true
        lastEvent = "RECOVERY_REQUIRED"
        lastInfo = message.isEmpty ? nil : message
    }

    static func remove() {
        do {
            try remove(from: StateDirectory())
        } catch {
            reportRemovalFailure(error, writeToStandardError: true)
        }
    }

    static func remove(from store: StateDirectory) throws {
        try store.withExclusiveLock(named: lockName) { directoryFD, _, _ in
            var failures: [String] = []
            do {
                try AnchoredFileIO.removeFileAndSync(in: directoryFD, name: fileName)
            } catch {
                failures.append(error.localizedDescription)
            }
            if store.usesRuntimePaths, RuntimePaths.homeSessionStateFile.path != RuntimePaths.sessionStateFile.path {
                do {
                    try RuntimePaths.removeHomeStateFile(name: fileName)
                } catch {
                    failures.append(error.localizedDescription)
                }
            }
            guard failures.isEmpty else {
                throw SessionStateError.couldNotRemove(failures.joined(separator: "; "))
            }
        }
    }

    static func reportRemovalFailure(_ error: Error,
                                     writeToStandardError: Bool,
                                     eventLogDirectory: URL? = nil) {
        let message = "Failed to remove session recovery state: \(error.localizedDescription)"
        EventLog.append(eventName: "SESSION_STATE_REMOVE_FAILED",
                        info: message,
                        isError: true,
                        isFatal: false,
                        phase: .failed,
                        in: eventLogDirectory)
        if writeToStandardError {
            fputs("\(AppIdentity.executableName): failed to remove session recovery state: \(error.localizedDescription)\n", stderr)
        }
    }
}
