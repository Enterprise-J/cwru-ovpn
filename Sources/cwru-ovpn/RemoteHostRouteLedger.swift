import Darwin
import Foundation

struct RemoteHostRouteLedgerEntry: Codable, Equatable {
    let route: ManagedIPv4Route
    let pid: Int32
    let processStartTime: ProcessStartTime
    let executablePath: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case route
        case pid
        case processStartTime
        case executablePath
    }

    init(route: ManagedIPv4Route,
         pid: Int32,
         processStartTime: ProcessStartTime,
         executablePath: String) {
        self.route = route
        self.pid = pid
        self.processStartTime = processStartTime
        self.executablePath = executablePath
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownJSONKeys(in: decoder,
                                  allowedBy: CodingKeys.self,
                                  context: "remote-host route ledger entry")
        let container = try decoder.container(keyedBy: CodingKeys.self)
        route = try container.decode(ManagedIPv4Route.self, forKey: .route)
        pid = try container.decode(Int32.self, forKey: .pid)
        processStartTime = try container.decode(ProcessStartTime.self, forKey: .processStartTime)
        executablePath = try container.decode(String.self, forKey: .executablePath)
    }
}

struct RemoteHostRouteLedger: Sendable {
    private static let maxLedgerBytes = 64 * 1024
    private static let fileName = "remote-host-routes.json"
    private static let lockName = "remote-host-routes.lock"

    private let store: StateDirectory

    init(store: StateDirectory = StateDirectory()) {
        self.store = store
    }

    init(directory: URL) {
        self.init(store: StateDirectory(directory: directory))
    }

    func recordOwnedRoutes(_ routes: [ManagedIPv4Route],
                           pid: Int32,
                           processStartTime: ProcessStartTime,
                           executablePath: String) throws {
        guard !routes.isEmpty else {
            return
        }
        try mutate { entries in
            entries.filter { !routes.contains($0.route) }
                + routes.map {
                    RemoteHostRouteLedgerEntry(route: $0,
                                               pid: pid,
                                               processStartTime: processStartTime,
                                               executablePath: executablePath)
                }
        }
    }

    func removeRoutes(_ routes: [ManagedIPv4Route]) throws {
        guard !routes.isEmpty else {
            return
        }
        try mutate { entries in
            entries.filter { !routes.contains($0.route) }
        }
    }

    func remove(entries staleEntries: [RemoteHostRouteLedgerEntry]) throws {
        guard !staleEntries.isEmpty else {
            return
        }
        try mutate { entries in
            entries.filter { !staleEntries.contains($0) }
        }
    }

    func entries() throws -> [RemoteHostRouteLedgerEntry] {
        try store.withExclusiveLock(named: Self.lockName, Self.load)
    }

    private func mutate(_ transform: ([RemoteHostRouteLedgerEntry]) -> [RemoteHostRouteLedgerEntry]) throws {
        try store.withExclusiveLock(named: Self.lockName) { directoryFD, userID, groupID in
            let entries = transform(try Self.load(in: directoryFD, userID: userID, groupID: groupID))
            guard !entries.isEmpty else {
                try AnchoredFileIO.removeFileAndSync(in: directoryFD, name: Self.fileName)
                return
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(entries)
            guard data.count <= Self.maxLedgerBytes else {
                throw FileIO.posixError(E2BIG)
            }
            try AnchoredFileIO.writeOwnedRegularFileAtomically(data,
                                                               in: directoryFD,
                                                               name: Self.fileName,
                                                               userID: userID,
                                                               groupID: groupID)
        }
    }

    private static func load(in directoryFD: Int32, userID: uid_t, groupID: gid_t) throws -> [RemoteHostRouteLedgerEntry] {
        guard let data = try AnchoredFileIO.readOwnedRegularFile(in: directoryFD,
                                                                 name: fileName,
                                                                 userID: userID,
                                                                 groupID: groupID,
                                                                 maximumBytes: maxLedgerBytes) else {
            return []
        }
        return try JSONDecoder().decode([RemoteHostRouteLedgerEntry].self, from: data)
    }
}
