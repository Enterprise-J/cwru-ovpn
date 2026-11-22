import Darwin
import Foundation

struct ManagedReconnectBudgetState: Codable, Equatable {
    let windowStartedAt: Date
    let attempts: Int

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case windowStartedAt
        case attempts
    }

    init(windowStartedAt: Date, attempts: Int) {
        self.windowStartedAt = windowStartedAt
        self.attempts = attempts
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownJSONKeys(in: decoder,
                                  allowedBy: CodingKeys.self,
                                  context: "managed reconnect budget")
        let container = try decoder.container(keyedBy: CodingKeys.self)
        windowStartedAt = try container.decode(Date.self, forKey: .windowStartedAt)
        attempts = try container.decode(Int.self, forKey: .attempts)
    }
}

enum ManagedReconnectBudget {
    static let maximumAttempts = 2
    static let windowSeconds: TimeInterval = 15 * 60
    private static let maximumFileBytes = 4 * 1024
    static let fileName = "managed-reconnect-budget.json"
    static let lockName = "managed-reconnect-budget.lock"

    static func decision(state: ManagedReconnectBudgetState?,
                         now: Date) -> (allowed: Bool, state: ManagedReconnectBudgetState) {
        guard let state,
              now.timeIntervalSince(state.windowStartedAt) < windowSeconds else {
            return (true, ManagedReconnectBudgetState(windowStartedAt: now, attempts: 1))
        }

        let start = min(now, state.windowStartedAt)
        guard state.attempts < maximumAttempts else {
            return (false, ManagedReconnectBudgetState(windowStartedAt: start, attempts: state.attempts))
        }
        return (true, ManagedReconnectBudgetState(windowStartedAt: start,
                                                  attempts: state.attempts + 1))
    }

    static func reserveAttempt() throws -> Bool {
        let now = Date()
        return try StateDirectory().withExclusiveLock(named: lockName) { directoryFD, userID, groupID in
            let current = try AnchoredFileIO.readOwnedRegularFile(in: directoryFD,
                                                                  name: fileName,
                                                                  userID: userID,
                                                                  groupID: groupID,
                                                                  maximumBytes: maximumFileBytes)
                .map { try JSONDecoder().decode(ManagedReconnectBudgetState.self, from: $0) }
            if let current,
               !(0...maximumAttempts).contains(current.attempts) {
                throw FileIO.posixError(EINVAL, "The automatic reconnect history file is corrupt.")
            }
            let result = decision(state: current, now: now)
            guard result.state != current else {
                return false
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            try AnchoredFileIO.writeOwnedRegularFileAtomically(try encoder.encode(result.state),
                                                               in: directoryFD,
                                                               name: fileName,
                                                               userID: userID,
                                                               groupID: groupID)
            return result.allowed
        }
    }

    static func reset() throws {
        try StateDirectory().withExclusiveLock(named: lockName) { directoryFD, _, _ in
            try AnchoredFileIO.removeFileAndSync(in: directoryFD, name: fileName)
        }
    }
}
