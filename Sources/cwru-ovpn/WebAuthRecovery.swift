import Foundation

struct WebAuthRecovery {
    static let defaultTimeoutSeconds: TimeInterval = 300
    static let maximumTimeoutSeconds: TimeInterval = 900
    static let maximumWaitSeconds = 2 * maximumTimeoutSeconds

    private(set) var deadline: Date?
    private(set) var retryUsed = false

    var canRetry: Bool {
        deadline != nil && !retryUsed
    }

    mutating func begin(info: String, now: Date) -> Date? {
        guard deadline == nil else {
            return nil
        }
        let timeoutOptions = info.split(separator: ",")
            .map { $0.split(whereSeparator: \.isWhitespace) }
            .filter { $0.first == "timeout" }
        let timeout: TimeInterval
        if timeoutOptions.count == 1, let fields = timeoutOptions.first, fields.count == 2,
           let seconds = UInt(fields[1]), seconds > 0 {
            timeout = min(TimeInterval(seconds), Self.maximumTimeoutSeconds)
        } else {
            timeout = Self.defaultTimeoutSeconds
        }
        let deadline = now.addingTimeInterval(timeout)
        self.deadline = deadline
        return deadline
    }

    mutating func retry() -> Bool {
        guard canRetry else {
            return false
        }
        retryUsed = true
        self.deadline = nil
        return true
    }

    mutating func finish() {
        deadline = nil
    }
}
