import Foundation

private struct EventLogSessionRecord: Encodable {
    let kind = "session_start"
    let timestamp: String
    let pid: Int32
    let profilePath: String
    let stateDirectory: String
}

private struct EventLogVPNRecord: Encodable {
    let kind = "vpn_event"
    let timestamp: String
    let pid: Int32
    let phase: String
    let name: String
    let info: String
    let isError: Bool
    let isFatal: Bool
}

private struct EventLogNoteRecord: Encodable {
    let kind = "note"
    let timestamp: String
    let pid: Int32
    let phase: String?
    let message: String
}

enum EventLog {
    static func startSession(profilePath: String) {
        resetForNewSession()
        appendRecord(EventLogSessionRecord(
            timestamp: timestampString(),
            pid: getpid(),
            profilePath: profilePath,
            stateDirectory: RuntimePaths.stateDirectory.path
        ))
    }

    private static func resetForNewSession() {
        do {
            try RuntimePaths.ensureStateDirectory()
            if FileManager.default.fileExists(atPath: RuntimePaths.eventLogFile.path) {
                try FileManager.default.removeItem(at: RuntimePaths.eventLogFile)
            }
            FileManager.default.createFile(atPath: RuntimePaths.eventLogFile.path, contents: nil)
            try RuntimePaths.secureFile(at: RuntimePaths.eventLogFile)
        } catch {
            fputs("\(AppIdentity.executableName): failed to reset event log: \(error.localizedDescription)\n", stderr)
        }
    }

    static func append(eventName: String,
                       info: String,
                       isError: Bool,
                       isFatal: Bool,
                       phase: SessionState.Phase) {
        appendRecord(EventLogVPNRecord(
            timestamp: timestampString(),
            pid: getpid(),
            phase: phase.rawValue,
            name: eventName,
            info: sanitize(info),
            isError: isError,
            isFatal: isFatal
        ))
    }

    static func append(note: String, phase: SessionState.Phase? = nil) {
        appendRecord(EventLogNoteRecord(
            timestamp: timestampString(),
            pid: getpid(),
            phase: phase?.rawValue,
            message: sanitize(note)
        ))
    }

    private static func appendRecord<T: Encodable>(_ record: T) {
        do {
            try RuntimePaths.ensureStateDirectory()
            let encoder = JSONEncoder()
            let data = try encoder.encode(record)
            var line = data
            line.append(0x0a)

            if !FileManager.default.fileExists(atPath: RuntimePaths.eventLogFile.path) {
                FileManager.default.createFile(atPath: RuntimePaths.eventLogFile.path, contents: nil)
                try RuntimePaths.secureFile(at: RuntimePaths.eventLogFile)
            }

            let handle = try FileHandle(forWritingTo: RuntimePaths.eventLogFile)
            defer { handle.closeFile() }
            handle.seekToEndOfFile()
            handle.write(line)
            try RuntimePaths.secureFile(at: RuntimePaths.eventLogFile)
        } catch {
            fputs("\(AppIdentity.executableName): failed to append event log: \(error.localizedDescription)\n", stderr)
        }
    }

    private static func sanitize(_ value: String) -> String {
        var sanitized = value

        let fullLinePatterns: [(String, String)] = [
            (#"(?m)^Session token:\s+.*$"#, "Session token: [redacted]"),
            (#"(?m)^WEB_AUTH:[^\n]*$"#, "WEB_AUTH:[redacted]"),
            (#"(?m)^OPEN_URL:[^\n]*$"#, "OPEN_URL:[redacted]")
        ]

        for (pattern, replacement) in fullLinePatterns {
            sanitized = sanitized.replacingOccurrences(of: pattern,
                                                       with: replacement,
                                                       options: .regularExpression)
        }

        let inlinePatterns: [(String, String)] = [
            (#"\[auth-token\]\s+[^\s\n]+"#, "[auth-token] [redacted]"),
            (#"https?://cwru\.openvpn\.com/connect[^\s\n]*"#, "https://cwru.openvpn.com/connect?[redacted]")
        ]

        for (pattern, replacement) in inlinePatterns {
            sanitized = sanitized.replacingOccurrences(of: pattern,
                                                       with: replacement,
                                                       options: .regularExpression)
        }

        return sanitized
    }

    // ISO8601DateFormatter is documented as thread-safe on macOS 10.9+, so a
    // shared instance avoids rebuilding the formatter on every log entry.
    nonisolated(unsafe) private static let timestampFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    private static func timestampString() -> String {
        timestampFormatter.string(from: Date())
    }
}
