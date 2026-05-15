import Darwin
import Foundation

func redactSensitiveText(_ value: String) -> String {
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
        (#"(?im)^Authorization:\s*Bearer\s+[^\s\n]+$"#, "Authorization: Bearer [redacted]"),
        (#"(?i)\bbearer\s+[^\s\n]+"#, "Bearer [redacted]"),
        (#"(?i)\b(auth[-_]?token|token|assertion|session)\s*[:=]\s*[^\s&]+"#, "$1=[redacted]")
    ]

    for (pattern, replacement) in inlinePatterns {
        sanitized = sanitized.replacingOccurrences(of: pattern,
                                                   with: replacement,
                                                   options: .regularExpression)
    }

    return redactHTTPURLQueryStrings(in: sanitized)
}

private func redactHTTPURLQueryStrings(in value: String) -> String {
    guard let detector = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue) else {
        return value
    }

    var redacted = value
    let matches = detector.matches(in: redacted,
                                   options: [],
                                   range: NSRange(redacted.startIndex..., in: redacted)).reversed()
    for match in matches {
        guard let range = Range(match.range, in: redacted) else {
            continue
        }

        let matchedURL = String(redacted[range])
        let normalizedURL = matchedURL.lowercased()
        guard normalizedURL.hasPrefix("https://") || normalizedURL.hasPrefix("http://") else {
            continue
        }

        let queryStart = matchedURL.firstIndex(of: "?")
        let fragmentStart = matchedURL.firstIndex(of: "#")
        guard queryStart != nil || fragmentStart != nil else {
            continue
        }

        let cutoff: String.Index
        switch (queryStart, fragmentStart) {
        case let (query?, fragment?):
            cutoff = min(query, fragment)
        case let (query?, nil):
            cutoff = query
        case let (nil, fragment?):
            cutoff = fragment
        case (nil, nil):
            continue
        }

        let replacement = String(matchedURL[..<cutoff])
            + (queryStart == cutoff ? "?[redacted]" : "")
            + (fragmentStart == cutoff || (fragmentStart != nil && queryStart == cutoff) ? "#[redacted]" : "")
        redacted.replaceSubrange(range, with: replacement)
    }

    return redacted
}

private struct EventLogSessionRecord: Encodable {
    let kind = "session_start"
    let timestamp: String
    let pid: Int32
    let profilePath: String
    let stateDirectory: String
    let privacyMode: Bool
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
    private static let privacyLock = NSLock()
    nonisolated(unsafe) private static var privacyMode = true

    static func configure(privacyMode enabled: Bool) {
        privacyLock.lock()
        privacyMode = enabled
        privacyLock.unlock()
    }

    static func startSession(profilePath: String) {
        resetForNewSession()
        let privacyMode = isPrivacyModeEnabled()
        appendRecord(EventLogSessionRecord(
            timestamp: timestampString(),
            pid: getpid(),
            profilePath: privacyMode ? "[redacted]" : profilePath,
            stateDirectory: privacyMode ? "[redacted]" : RuntimePaths.stateDirectory.path,
            privacyMode: privacyMode
        ))
    }

    private static func resetForNewSession() {
        do {
            try RuntimePaths.ensureStateDirectory()
            if FileManager.default.fileExists(atPath: RuntimePaths.eventLogFile.path) {
                try FileManager.default.removeItem(at: RuntimePaths.eventLogFile)
            }
            let handle = try openEventLogForAppend()
            try? handle.close()
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
            info: eventInfoForStorage(info),
            isError: isError,
            isFatal: isFatal
        ))
    }

    static func append(note: String, phase: SessionState.Phase? = nil) {
        appendRecord(EventLogNoteRecord(
            timestamp: timestampString(),
            pid: getpid(),
            phase: phase?.rawValue,
            message: noteForStorage(note)
        ))
    }

    private static func appendRecord<T: Encodable>(_ record: T) {
        do {
            try RuntimePaths.ensureStateDirectory()
            let encoder = JSONEncoder()
            let data = try encoder.encode(record)
            var line = data
            line.append(0x0a)

            let handle = try openEventLogForAppend()
            defer { try? handle.close() }
            handle.write(line)
        } catch {
            fputs("\(AppIdentity.executableName): failed to append event log: \(error.localizedDescription)\n", stderr)
        }
    }

#if CWRU_OVPN_INCLUDE_SELF_TEST
    static func openEventLogForAppendForSelfTest() throws -> FileHandle {
        try openEventLogForAppend()
    }
#endif

    private static func openEventLogForAppend() throws -> FileHandle {
        let path = RuntimePaths.eventLogFile.path
        let fd = open(path,
                      O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_NONBLOCK,
                      mode_t(S_IRUSR | S_IWUSR))
        let openError = errno
        guard fd >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: openError) ?? .EIO)
        }

        var fileInfo = stat()
        let statResult = fstat(fd, &fileInfo)
        let statError = errno
        guard statResult == 0 else {
            close(fd)
            throw POSIXError(POSIXErrorCode(rawValue: statError) ?? .EIO)
        }

        guard (fileInfo.st_mode & S_IFMT) == S_IFREG else {
            close(fd)
            throw NSError(domain: NSPOSIXErrorDomain,
                          code: Int(EFTYPE),
                          userInfo: [NSLocalizedDescriptionKey: "Refusing to append to a non-regular event log file."])
        }

        guard fileInfo.st_nlink == 1 else {
            close(fd)
            throw NSError(domain: NSPOSIXErrorDomain,
                          code: Int(EMLINK),
                          userInfo: [NSLocalizedDescriptionKey: "Refusing to append to a hardlinked event log file."])
        }

        guard fchmod(fd, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            let chmodError = errno
            close(fd)
            throw POSIXError(POSIXErrorCode(rawValue: chmodError) ?? .EIO)
        }

        if let sudoIdentity = try? ExecutionIdentity.validatedSudoUserIfAvailable(),
           fchown(fd, sudoIdentity.userID, sudoIdentity.groupID) != 0 {
            let chownError = errno
            close(fd)
            throw POSIXError(POSIXErrorCode(rawValue: chownError) ?? .EIO)
        }

        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }

    private static func sanitize(_ value: String) -> String {
        redactSensitiveText(value)
    }

    private static func eventInfoForStorage(_ value: String) -> String {
        isPrivacyModeEnabled() ? "[suppressed]" : sanitize(value)
    }

    private static func noteForStorage(_ value: String) -> String {
        isPrivacyModeEnabled() ? "Detail suppressed by privacy mode." : sanitize(value)
    }

    private static func isPrivacyModeEnabled() -> Bool {
        privacyLock.lock()
        let enabled = privacyMode
        privacyLock.unlock()
        return enabled
    }

    nonisolated(unsafe) private static let timestampFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()

    private static func timestampString() -> String {
        timestampFormatter.string(from: Date())
    }
}
