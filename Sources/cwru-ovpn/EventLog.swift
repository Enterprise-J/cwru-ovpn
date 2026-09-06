import Darwin
import Foundation

private let sensitiveTextRedactionPatterns: [(regex: NSRegularExpression, template: String)] = {
    let fullLinePatterns: [(String, String)] = [
        (#"(?m)^Session token:\s+.*$"#, "Session token: [redacted]"),
        (#"(?im)\b(WEB_AUTH|OPEN_URL|CR_TEXT):[^\n]*$"#, "$1:[redacted]")
    ]

    let inlinePatterns: [(String, String)] = [
        (#"\[auth-token\]\s+[^\s\n]+"#, "[auth-token] [redacted]"),
        (#"(?im)^Authorization:\s*Bearer\s+[^\s\n]+$"#, "Authorization: Bearer [redacted]"),
        (#"(?im)^Authorization:\s*Basic\s+[^\s\n]+$"#, "Authorization: Basic [redacted]"),
        (#"(?i)\bbearer\s+[^\s\n]+"#, "Bearer [redacted]"),
        (#"(?i)\"(access[-_]?token|auth[-_]?token|id[-_]?token|refresh[-_]?token|samlresponse|assertion|session|token|password|passwd|pass|otp|secret|client[-_]?secret|refresh[-_]?secret)\"\s*:\s*\"(?:\\.|[^\"\\])*\""#, #""$1":"[redacted]""#),
        (#"(?i)\b(access[-_]?token|auth[-_]?token|id[-_]?token|refresh[-_]?token|samlresponse|assertion|session|token|password|passwd|pass|otp|secret|client[-_]?secret|refresh[-_]?secret)\s*([:=])\s*\"(?:\\.|[^\"\\])*\""#, #"$1$2"[redacted]""#),
        (#"(?i)\b(access[-_]?token|auth[-_]?token|id[-_]?token|refresh[-_]?token|samlresponse|assertion|session|token|password|passwd|pass|otp|secret|client[-_]?secret|refresh[-_]?secret)\s*([:=])\s*[^\s&,"]+"#, "$1$2[redacted]")
    ]

    return (fullLinePatterns + inlinePatterns).compactMap { pattern, template in
        (try? NSRegularExpression(pattern: pattern)).map { ($0, template) }
    }
}()

private let httpURLDetector = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue)
private let httpURLUserInfoRegex = try? NSRegularExpression(pattern: #"(?i)\b(https?://)([^/\s@]+@)([^\s/?#]+)"#)

func redactSensitiveText(_ value: String) -> String {
    var sanitized = value

    for (regex, template) in sensitiveTextRedactionPatterns {
        sanitized = regex.stringByReplacingMatches(in: sanitized,
                                                   range: NSRange(sanitized.startIndex..., in: sanitized),
                                                   withTemplate: template)
    }

    return redactHTTPURLQueryStrings(in: redactHTTPURLUserInfo(in: sanitized))
}

private func redactHTTPURLUserInfo(in value: String) -> String {
    guard let httpURLUserInfoRegex else {
        return value
    }

    return httpURLUserInfoRegex.stringByReplacingMatches(in: value,
                                                         range: NSRange(value.startIndex..., in: value),
                                                         withTemplate: "$1[redacted]@$3")
}

private func redactHTTPURLQueryStrings(in value: String) -> String {
    guard let detector = httpURLDetector else {
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
    private static let writeLock = NSLock()
    static let maximumBytes = 5 * 1024 * 1024
    private static let maxEventRecordBytes = 64 * 1024
    nonisolated(unsafe) private static var privacyMode = true

    static func configure(privacyMode enabled: Bool) {
        privacyLock.lock()
        privacyMode = enabled
        privacyLock.unlock()
    }

    static func startSession(profilePath: String, in stateDirectory: URL? = nil) {
        let privacyMode = isPrivacyModeEnabled()
        appendRecord(EventLogSessionRecord(
            timestamp: timestampString(),
            pid: getpid(),
            profilePath: privacyMode ? "[redacted]" : profilePath,
            stateDirectory: privacyMode ? "[redacted]" : (stateDirectory ?? RuntimePaths.stateDirectory).path,
            privacyMode: privacyMode
        ), in: stateDirectory)
    }

    static func append(eventName: String,
                       info: String,
                       isError: Bool,
                       isFatal: Bool,
                       phase: SessionState.Phase,
                       in stateDirectory: URL? = nil) {
        appendRecord(EventLogVPNRecord(
            timestamp: timestampString(),
            pid: getpid(),
            phase: phase.rawValue,
            name: eventName,
            info: eventInfoForStorage(info),
            isError: isError,
            isFatal: isFatal
        ), in: stateDirectory)
    }

    static func append(note: String,
                       phase: SessionState.Phase? = nil,
                       in stateDirectory: URL? = nil) {
        appendRecord(EventLogNoteRecord(
            timestamp: timestampString(),
            pid: getpid(),
            phase: phase?.rawValue,
            message: noteForStorage(note)
        ), in: stateDirectory)
    }

    private static func appendRecord<T: Encodable>(_ record: T, in stateDirectory: URL?) {
        writeLock.lock()
        defer { writeLock.unlock() }
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            var data = try encoder.encode(record)
            if data.count > maxEventRecordBytes {
                data = try encoder.encode(EventLogNoteRecord(
                    timestamp: timestampString(),
                    pid: getpid(),
                    phase: nil,
                    message: "Oversized event record omitted."
                ))
            }
            var line = data
            line.append(0x0a)

            let handle = try openEventLogForAppend(in: stateDirectory)
            defer { try? handle.close() }
            guard flock(handle.fileDescriptor, LOCK_EX | LOCK_NB) == 0 else {
                throw FileIO.posixError(errno)
            }
            defer { _ = flock(handle.fileDescriptor, LOCK_UN) }
            var fileInfo = Darwin.stat()
            guard Darwin.fstat(handle.fileDescriptor, &fileInfo) == 0 else {
                throw FileIO.posixError(errno)
            }
            if Int(fileInfo.st_size) + line.count > maximumBytes {
                let existing = try readExistingLog(fileDescriptor: handle.fileDescriptor)
                var marker = try encoder.encode(EventLogNoteRecord(
                    timestamp: timestampString(),
                    pid: getpid(),
                    phase: nil,
                    message: "Event log reached its size limit and was compacted while retaining failure evidence."
                ))
                marker.append(0x0a)
                let retained = compactedLog(existing: existing, marker: marker)
                guard ftruncate(handle.fileDescriptor, 0) == 0 else {
                    throw FileIO.posixError(errno)
                }
                try FileIO.writeAll(retained, to: handle.fileDescriptor)
            }
            try FileIO.writeAll(line, to: handle.fileDescriptor)
        } catch {
            fputs("\(AppIdentity.executableName): failed to append event log: \(error.localizedDescription)\n", stderr)
        }
    }

    private static func openEventLogForAppend(in stateDirectory: URL? = nil) throws -> FileHandle {
        if let stateDirectory {
            return try AnchoredFileIO.withDirectory(at: stateDirectory,
                                                    parentUserID: getuid(),
                                                    parentGroupID: getgid(),
                                                    userID: getuid(),
                                                    groupID: getgid()) { directoryFD in
                let fileFD = try AnchoredFileIO.openOwnedRegularFileForAppend(in: directoryFD,
                                                                              name: "events.ndjson",
                                                                              userID: getuid(),
                                                                              groupID: getgid())
                return FileHandle(fileDescriptor: fileFD, closeOnDealloc: true)
            }
        }
        return try RuntimePaths.withStateDirectoryAnchor { directoryFD, userID, groupID in
            let fileFD = try AnchoredFileIO.openOwnedRegularFileForAppend(in: directoryFD,
                                                                          name: "events.ndjson",
                                                                          userID: userID,
                                                                          groupID: groupID)
            return FileHandle(fileDescriptor: fileFD, closeOnDealloc: true)
        }
    }

    private static func readExistingLog(fileDescriptor: Int32) throws -> Data {
        guard lseek(fileDescriptor, 0, SEEK_SET) == 0 else {
            throw FileIO.posixError(errno)
        }
        return try FileIO.readAll(from: fileDescriptor, maximumBytes: maximumBytes + maxEventRecordBytes)
    }

    private static func compactedLog(existing: Data, marker: Data) -> Data {
        guard !existing.isEmpty else {
            return marker
        }

        let headBudget = maximumBytes / 5
        let failureBudget = maximumBytes / 10
        let tailBudget = maximumBytes / 2
        let sessionPattern = Data(#""kind":"session_start""#.utf8)
        let failurePatterns = [
            Data(#""name":"RECONNECTING""#.utf8),
            Data(#""name":"CORE_EXIT""#.utf8),
            Data(#""isFatal":true"#.utf8),
            Data(#""isError":true"#.utf8),
            Data("Network is unreachable".utf8),
            Data("DATA_PATH_DEGRADED".utf8),
        ]

        let sessionMatch = existing.range(of: sessionPattern, options: .backwards)
        let sessionStart = sessionMatch.map { lineBoundary(in: existing, atOrBefore: $0.lowerBound) } ?? 0
        var ranges: [Range<Int>] = []

        let headEnd = lineBoundary(in: existing, atOrBefore: min(existing.count, sessionStart + headBudget))
        if headEnd > sessionStart {
            ranges.append(sessionStart..<headEnd)
        }

        let searchRange = sessionStart..<existing.count
        let firstFailure = failurePatterns.compactMap {
            existing.range(of: $0, options: [], in: searchRange)?.lowerBound
        }.min()
        if let firstFailure {
            let failureStart = lineBoundary(in: existing, atOrBefore: firstFailure)
            let failureEnd = lineBoundary(in: existing, atOrBefore: min(existing.count, failureStart + failureBudget))
            if failureEnd > failureStart {
                ranges.append(failureStart..<failureEnd)
            }
        }

        let proposedTailStart = max(sessionStart, existing.count - tailBudget)
        let tailStart = lineStartAfter(in: existing, atOrAfter: proposedTailStart)
        if tailStart < existing.count {
            ranges.append(tailStart..<existing.count)
        }

        let merged = mergeRanges(ranges)
        var retained = Data()
        for range in merged {
            retained.append(existing.subdata(in: range))
        }
        retained.append(marker)
        return retained
    }

    private static func lineBoundary(in data: Data, atOrBefore index: Int) -> Int {
        guard index > 0,
              let newline = data.range(of: Data([0x0a]), options: .backwards, in: 0..<min(index, data.count)) else {
            return 0
        }
        return newline.upperBound
    }

    private static func lineStartAfter(in data: Data, atOrAfter index: Int) -> Int {
        guard index > 0 else {
            return 0
        }
        guard index < data.count,
              let newline = data.range(of: Data([0x0a]),
                                       options: [],
                                       in: index..<data.count) else {
            return data.count
        }
        return newline.upperBound
    }

    private static func mergeRanges(_ ranges: [Range<Int>]) -> [Range<Int>] {
        let sorted = ranges.sorted { lhs, rhs in
            lhs.lowerBound == rhs.lowerBound
                ? lhs.upperBound < rhs.upperBound
                : lhs.lowerBound < rhs.lowerBound
        }
        var merged: [Range<Int>] = []
        for range in sorted where !range.isEmpty {
            guard let last = merged.last,
                  range.lowerBound <= last.upperBound else {
                merged.append(range)
                continue
            }
            merged[merged.count - 1] = last.lowerBound..<max(last.upperBound, range.upperBound)
        }
        return merged
    }

    private static func eventInfoForStorage(_ value: String) -> String {
        isPrivacyModeEnabled() ? "[suppressed]" : redactSensitiveText(value)
    }

    private static func noteForStorage(_ value: String) -> String {
        isPrivacyModeEnabled() ? "Detail suppressed by privacy mode." : redactSensitiveText(value)
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
