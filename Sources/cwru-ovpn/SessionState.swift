import Darwin
import Foundation

enum SessionStateError: LocalizedError {
    case encodedStateTooLarge(actualBytes: Int, maximumBytes: Int)
    case invalidPersistedState(String)
    case sessionAlreadyExists
    case unsafeRecoveryState(String)

    var errorDescription: String? {
        switch self {
        case .encodedStateTooLarge(let actualBytes, let maximumBytes):
            return "The saved session is \(actualBytes) bytes. The limit is \(maximumBytes) bytes. Network changes require a readable session file."
        case .invalidPersistedState(let message):
            return "Session recovery state is invalid: \(message)"
        case .sessionAlreadyExists:
            return "A VPN session is already recorded. Run ovpnd before starting another session."
        case .unsafeRecoveryState(let message):
            return message
        }
    }
}

struct PendingTransportEndpoint: Codable, Equatable {
    let address: String
    let clientGeneration: Int
    let requestID: UInt64
}

struct ModeRequest: Codable, Equatable {
    let id: UUID
    let mode: AppTunnelMode
    var deferral: String?
}

struct ModeReceipt: Codable, Equatable {
    enum Outcome: String, Codable { case applied, rolledBack, recoveryRequired, superseded }
    let id: UUID
    let outcome: Outcome
    let detail: String?
}

struct DNSWithdrawal: Codable {
    var servers: [String] = []
    var searchDomains: [String] = []
}

struct SessionState: Codable {
    private static let maxSessionStateBytes = 64 * 1024
    static let fileName = "session.json"
    static let lockName = "session-state.lock"

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

    var pid: Int32
    var executablePath: String
    var processStartTime: ProcessStartTime
    var phase: Phase
    var profilePath: String
    var configFilePath: String?
    var startedAt: Date
    var connectedAt: Date?
    var lastEventName: String? {
        didSet { lastEventName = lastEventName.map(redactSensitiveText) }
    }
    var diagnosticDetail: String? {
        didSet { diagnosticDetail = diagnosticDetail.map(redactSensitiveText) }
    }
    var physicalGateway: String
    var physicalInterface: String
    var physicalServiceID: String
    var serviceMutations: [ServiceMutation] = []
    var physicalServiceName: String?
    var originalDNSServers: [String]?
    var originalSearchDomains: [String]?
    var originalDefaultSearchDomains: [String]?
    var originalIPv6Mode: String?
    var pushedDNS: TunnelDNSConfiguration?
    var tunnelName: String?
    var vpnIPv4: String?
    var vpnIPv6: String?
    var serverHost: String?
    var connectedServerAddress: String?
    var pendingTransportEndpoint: PendingTransportEndpoint?
    var tunnelMode: AppTunnelMode
    var modeRequest: ModeRequest?
    var applyingModeRequest: ModeRequest?
    var modeReceipts: [ModeReceipt] = []
    var stopRequestedByUser = false
    var requestedTunnelMode: AppTunnelMode? { modeRequest?.mode ?? applyingModeRequest?.mode }
    var pendingDNSWithdrawal = DNSWithdrawal()
    var transportHealth: TransportRecoveryState?
    var isRecoveryRequired = false
    var managedRemoteIPv4Routes: [ManagedIPv4Route]?
    var replacedRemoteIPv4Routes: [ManagedIPv4Route]?
    var managedIPv6Routes: [ManagedIPv6Route]?
    var appliedSplitIPv4Routes: [String]?
    var appliedSplitIPv6Routes: [String]?
    var appliedScopedDNSDomains: [String]?
    var cleanupNeeded: Bool

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case pid
        case executablePath
        case processStartTime
        case phase
        case profilePath
        case configFilePath
        case startedAt
        case connectedAt
        case lastEventName
        case diagnosticDetail
        case physicalGateway
        case physicalInterface
        case physicalServiceID
        case serviceMutations
        case physicalServiceName
        case originalDNSServers
        case originalSearchDomains
        case originalDefaultSearchDomains
        case originalIPv6Mode
        case pushedDNS
        case tunnelName
        case vpnIPv4
        case vpnIPv6
        case serverHost
        case connectedServerAddress
        case pendingTransportEndpoint
        case tunnelMode
        case modeRequest
        case applyingModeRequest
        case modeReceipts
        case stopRequestedByUser
        case pendingDNSWithdrawal
        case transportHealth
        case isRecoveryRequired
        case managedRemoteIPv4Routes
        case replacedRemoteIPv4Routes
        case managedIPv6Routes
        case appliedSplitIPv4Routes
        case appliedSplitIPv6Routes
        case appliedScopedDNSDomains
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
         lastEventName: String? = nil,
         diagnosticDetail: String? = nil,
         physicalGateway: String,
         physicalInterface: String,
         physicalServiceID: String,
         physicalServiceName: String? = nil,
         originalDNSServers: [String]? = nil,
         originalSearchDomains: [String]? = nil,
         originalDefaultSearchDomains: [String]? = nil,
         originalIPv6Mode: String? = nil,
         pushedDNS: TunnelDNSConfiguration? = nil,
         tunnelName: String? = nil,
         vpnIPv4: String? = nil,
         vpnIPv6: String? = nil,
         serverHost: String? = nil,
         connectedServerAddress: String? = nil,
         pendingTransportEndpoint: PendingTransportEndpoint? = nil,
         tunnelMode: AppTunnelMode,
         managedRemoteIPv4Routes: [ManagedIPv4Route]? = nil,
         replacedRemoteIPv4Routes: [ManagedIPv4Route]? = nil,
         managedIPv6Routes: [ManagedIPv6Route]? = nil,
         appliedSplitIPv4Routes: [String]? = nil,
         appliedSplitIPv6Routes: [String]? = nil,
         appliedScopedDNSDomains: [String]? = nil,
         cleanupNeeded: Bool) {
        self.pid = pid
        self.executablePath = executablePath
        self.processStartTime = processStartTime
        self.phase = phase
        self.profilePath = profilePath
        self.configFilePath = configFilePath
        self.startedAt = startedAt
        self.connectedAt = connectedAt
        self.lastEventName = lastEventName.map(redactSensitiveText)
        self.diagnosticDetail = diagnosticDetail.map(redactSensitiveText)
        self.physicalGateway = physicalGateway
        self.physicalInterface = physicalInterface
        self.physicalServiceID = physicalServiceID
        self.physicalServiceName = physicalServiceName
        self.originalDNSServers = originalDNSServers
        self.originalSearchDomains = originalSearchDomains
        self.originalDefaultSearchDomains = originalDefaultSearchDomains
        self.originalIPv6Mode = originalIPv6Mode
        self.pushedDNS = pushedDNS
        self.tunnelName = tunnelName
        self.vpnIPv4 = vpnIPv4
        self.vpnIPv6 = vpnIPv6
        self.serverHost = serverHost
        self.connectedServerAddress = connectedServerAddress
        self.pendingTransportEndpoint = pendingTransportEndpoint
        self.tunnelMode = tunnelMode
        self.managedRemoteIPv4Routes = managedRemoteIPv4Routes
        self.replacedRemoteIPv4Routes = replacedRemoteIPv4Routes
        self.managedIPv6Routes = managedIPv6Routes
        self.appliedSplitIPv4Routes = appliedSplitIPv4Routes
        self.appliedSplitIPv6Routes = appliedSplitIPv6Routes
        self.appliedScopedDNSDomains = appliedScopedDNSDomains
        self.cleanupNeeded = cleanupNeeded
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        try rejectUnknownJSONKeys(in: decoder,
                                  allowedBy: CodingKeys.self,
                                  context: "session state")
        pid = try container.decode(Int32.self, forKey: .pid)
        executablePath = try container.decode(String.self, forKey: .executablePath)
        processStartTime = try container.decode(ProcessStartTime.self, forKey: .processStartTime)
        phase = try container.decode(Phase.self, forKey: .phase)
        profilePath = try container.decode(String.self, forKey: .profilePath)
        configFilePath = try container.decodeIfPresent(String.self, forKey: .configFilePath)
        startedAt = try container.decode(Date.self, forKey: .startedAt)
        connectedAt = try container.decodeIfPresent(Date.self, forKey: .connectedAt)
        lastEventName = try container.decodeIfPresent(String.self, forKey: .lastEventName).map(redactSensitiveText)
        diagnosticDetail = try container.decodeIfPresent(String.self, forKey: .diagnosticDetail).map(redactSensitiveText)
        physicalGateway = try container.decode(String.self, forKey: .physicalGateway)
        physicalInterface = try container.decode(String.self, forKey: .physicalInterface)
        physicalServiceID = try container.decode(String.self, forKey: .physicalServiceID)
        serviceMutations = try container.decode([ServiceMutation].self, forKey: .serviceMutations)
        physicalServiceName = try container.decodeIfPresent(String.self, forKey: .physicalServiceName)
        originalDNSServers = try container.decodeIfPresent([String].self, forKey: .originalDNSServers)
        originalSearchDomains = try container.decodeIfPresent([String].self, forKey: .originalSearchDomains)
        originalDefaultSearchDomains = try container.decodeIfPresent([String].self, forKey: .originalDefaultSearchDomains)
        originalIPv6Mode = try container.decodeIfPresent(String.self, forKey: .originalIPv6Mode)
        pushedDNS = try container.decodeIfPresent(TunnelDNSConfiguration.self, forKey: .pushedDNS)
        tunnelName = try container.decodeIfPresent(String.self, forKey: .tunnelName)
        vpnIPv4 = try container.decodeIfPresent(String.self, forKey: .vpnIPv4)
        vpnIPv6 = try container.decodeIfPresent(String.self, forKey: .vpnIPv6)
        serverHost = try container.decodeIfPresent(String.self, forKey: .serverHost)
        connectedServerAddress = try container.decodeIfPresent(String.self, forKey: .connectedServerAddress)
        pendingTransportEndpoint = try container.decodeIfPresent(PendingTransportEndpoint.self, forKey: .pendingTransportEndpoint)
        tunnelMode = try container.decode(AppTunnelMode.self, forKey: .tunnelMode)
        modeRequest = try container.decodeIfPresent(ModeRequest.self, forKey: .modeRequest)
        applyingModeRequest = try container.decodeIfPresent(ModeRequest.self, forKey: .applyingModeRequest)
        modeReceipts = try container.decode([ModeReceipt].self, forKey: .modeReceipts)
        stopRequestedByUser = try container.decode(Bool.self, forKey: .stopRequestedByUser)
        pendingDNSWithdrawal = try container.decode(DNSWithdrawal.self, forKey: .pendingDNSWithdrawal)
        transportHealth = try container.decodeIfPresent(TransportRecoveryState.self, forKey: .transportHealth)
        isRecoveryRequired = try container.decode(Bool.self, forKey: .isRecoveryRequired)
        managedRemoteIPv4Routes = try container.decodeIfPresent([ManagedIPv4Route].self, forKey: .managedRemoteIPv4Routes)
        replacedRemoteIPv4Routes = try container.decodeIfPresent([ManagedIPv4Route].self, forKey: .replacedRemoteIPv4Routes)
        managedIPv6Routes = try container.decodeIfPresent([ManagedIPv6Route].self, forKey: .managedIPv6Routes)
        appliedSplitIPv4Routes = try container.decodeIfPresent([String].self, forKey: .appliedSplitIPv4Routes)
        appliedSplitIPv6Routes = try container.decodeIfPresent([String].self, forKey: .appliedSplitIPv6Routes)
        appliedScopedDNSDomains = try container.decodeIfPresent([String].self, forKey: .appliedScopedDNSDomains)
        cleanupNeeded = try container.decode(Bool.self, forKey: .cleanupNeeded)
    }

    static func load(from store: StateDirectory = StateDirectory()) -> SessionState? {
        guard case .loaded(let session) = loadResult(from: store) else {
            return nil
        }
        return session
    }

    static func loadResult(from store: StateDirectory = StateDirectory()) -> LoadResult {
        let file = store.url.appendingPathComponent(fileName)
        do {
            let record = try store.withAnchor(createIfMissing: false) { directory, uid, gid in
                try AnchoredFileIO.readOwnedRegularFile(in: directory, name: fileName, userID: uid, groupID: gid,
                                                        maximumBytes: maxSessionStateBytes)
            }
            guard let data = record else {
                return .missing
            }
            return .loaded(try decode(data))
        } catch let error as POSIXError where error.code == .ENOENT {
            return .missing
        } catch {
            return .invalid("\(file.path): \(error.localizedDescription)")
        }
    }

    private static func decode(_ data: Data) throws -> SessionState {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(Self.self, from: data)
    }

    static func statusResult() -> LoadResult {
        if ExecutionIdentity.isPrivileged { return loadResult() }
        do {
            guard let data = try RuntimePaths.readHomeStateFile(name: fileName, maximumBytes: maxSessionStateBytes) else { return .missing }
            return .loaded(try decode(data))
        } catch let error as POSIXError where error.code == .ENOENT {
            return .missing
        } catch { return .invalid(error.localizedDescription) }
    }

    func create(in store: StateDirectory = StateDirectory()) throws {
        _ = try Self.saveAtomically(in: store) { persistedState in
            guard persistedState == nil else {
                throw SessionStateError.sessionAlreadyExists
            }
            return self
        }
    }

    func save(in store: StateDirectory = StateDirectory()) throws {
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
            try updatedState.saveUnlocked(in: store)
            return updatedState
        }
    }

    private func saveUnlocked(in store: StateDirectory) throws {
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
        if store.usesRuntimePaths, ExecutionIdentity.isPrivileged {
            do {
                var mirror = self
                mirror.serviceMutations = []
                try RuntimePaths.writeHomeStateFileAtomically(try encoder.encode(mirror), name: Self.fileName)
            } catch {
                fputs("\(AppIdentity.executableName): failed to update the non-authoritative session state mirror: \(error.localizedDescription)\n", stderr)
            }
        }
    }

    mutating func retire(_ change: ServiceMutation) {
        serviceMutations.removeAll { $0.serviceID == change.serviceID && $0.kind == change.kind }
    }

    func requestingModeSwitch(to mode: AppTunnelMode) -> SessionState {
        var updated = self
        if let previous = modeRequest { updated.finish(previous, outcome: .superseded) }
        updated.modeRequest = ModeRequest(id: UUID(), mode: mode)
        if updated.lastEventName == "MODE_SWITCH_DEFERRED" {
            updated.lastEventName = nil
            updated.diagnosticDetail = nil
        }
        return updated
    }

    mutating func claim(_ request: ModeRequest) -> Bool {
        guard !stopRequestedByUser, applyingModeRequest == nil, modeRequest?.id == request.id else { return false }
        applyingModeRequest = request
        modeRequest = nil
        return true
    }

    mutating func finish(_ request: ModeRequest, outcome: ModeReceipt.Outcome, detail: String? = nil) {
        modeReceipts.removeAll { $0.id == request.id }
        modeReceipts.append(ModeReceipt(id: request.id, outcome: outcome, detail: detail.map(redactSensitiveText)))
        if modeReceipts.count > 32 { modeReceipts.removeFirst(modeReceipts.count - 32) }
        if modeRequest?.id == request.id { modeRequest = nil }
        if applyingModeRequest?.id == request.id { applyingModeRequest = nil }
    }

    mutating func markRecoveryRequired(message: String) {
        phase = .failed
        cleanupNeeded = true
        isRecoveryRequired = true
        lastEventName = "RECOVERY_REQUIRED"
        diagnosticDetail = message.isEmpty ? nil : message
    }

    static func remove(from store: StateDirectory = StateDirectory()) throws {
        try store.withExclusiveLock(named: lockName) { directoryFD, _, _ in
            try AnchoredFileIO.removeFileAndSync(in: directoryFD, name: fileName)
            if store.usesRuntimePaths, ExecutionIdentity.isPrivileged {
                do {
                    try RuntimePaths.removeHomeStateFile(name: fileName)
                } catch {
                    fputs("Failed to remove the session status mirror: \(error.localizedDescription)\n", stderr)
                }
            }
        }
    }
}
