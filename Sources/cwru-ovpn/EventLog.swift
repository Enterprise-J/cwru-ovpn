import Darwin
import Foundation

private let sensitiveTextRedactionPatterns: [(NSRegularExpression, String)] = {
    let key = #"(?:[a-z0-9]+[-_])*(?:access[-_]?token|auth[-_]?token|id[-_]?token|refresh[-_]?token|samlresponse|assertion|session|token|password|passwd|pass|otp|secret)"#
    let patterns = [
        (#"(?is)-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?(?:-----END \1-----|\z)"#, "[redacted]"),
        (#"(?im)^Session token:[^\n]*"#, "Session token: [redacted]"),
        (#"(?im)\b(WEB_AUTH|OPEN_URL|CR_TEXT):[^\n]*"#, "$1:[redacted]"),
        (#"(?im)^((?:Proxy-)?Authorization|Cookie|Set-Cookie):[^\n]*"#, "$1: [redacted]"),
        (#"(?i)\[auth-token\]\s+[^\s\n]+"#, "[auth-token] [redacted]"),
        (#"(?i)\bbearer\s+[^\s\n]+"#, "Bearer [redacted]"),
        (#"(?i)(?<![\w-])(["']?"# + key + #"["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*(?:"|\z)|'(?:\\.|[^'\\])*(?:'|\z)|[^\s&,"']+)"#, "$1[redacted]"),
    ]
    return patterns.map { (try! NSRegularExpression(pattern: $0.0), $0.1) }
}()

private let absoluteURIPattern = try! NSRegularExpression(pattern: #"(?i)\b([a-z][a-z0-9+.-]*://)([^\s<>"']*)"#)

func redactSensitiveText(_ value: String) -> String {
    let scalars = value.unicodeScalars.filter {
        $0 == "\n" || $0 == "\t" || ($0.value >= 0x20 && !(0x7F...0x9F).contains($0.value))
    }
    var result = String(String.UnicodeScalarView(scalars))
    for match in absoluteURIPattern.matches(in: result, range: NSRange(result.startIndex..., in: result)).reversed() {
        guard let range = Range(match.range(at: 2), in: result) else { continue }
        let body = result[range]
        let path = body.prefix { $0 != "?" && $0 != "#" }
        let authority = path.prefix { $0 != "/" }
        var replacement = String(path)
        if let at = authority.lastIndex(of: "@") {
            replacement = "[redacted]" + String(path[at...])
        }
        if path.endIndex < body.endIndex {
            let suffix = body[path.endIndex...]
            replacement += suffix.first == "?" ? "?[redacted]" : "#[redacted]"
            if suffix.first == "?", suffix.contains("#") { replacement += "#[redacted]" }
        }
        result.replaceSubrange(range, with: replacement)
    }
    for (regex, template) in sensitiveTextRedactionPatterns {
        result = regex.stringByReplacingMatches(in: result, range: NSRange(result.startIndex..., in: result),
                                                withTemplate: template)
    }
    return result
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
    static let fileName = "events.ndjson"
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
            stateDirectory: privacyMode ? "[redacted]" : (stateDirectory ?? RuntimePaths.homeStateDirectory).path,
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
            name: redactSensitiveText(eventName),
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
                throw FileIO.failure("Failed to lock the event log", errno)
            }
            defer { _ = flock(handle.fileDescriptor, LOCK_UN) }
            var fileInfo = Darwin.stat()
            guard Darwin.fstat(handle.fileDescriptor, &fileInfo) == 0 else {
                throw FileIO.failure("Failed to inspect the event log", errno)
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
                    throw FileIO.failure("Failed to compact the event log", errno)
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
                                                                              name: fileName,
                                                                              userID: getuid(),
                                                                              groupID: getgid())
                return FileHandle(fileDescriptor: fileFD, closeOnDealloc: true)
            }
        }
        return try RuntimePaths.withHomeStateDirectoryAnchor { directoryFD, userID, groupID in
            let fileFD = try AnchoredFileIO.openOwnedRegularFileForAppend(in: directoryFD,
                                                                          name: fileName,
                                                                          userID: userID,
                                                                          groupID: groupID)
            return FileHandle(fileDescriptor: fileFD, closeOnDealloc: true)
        }
    }

    private static func readExistingLog(fileDescriptor: Int32) throws -> Data {
        guard lseek(fileDescriptor, 0, SEEK_SET) == 0 else {
            throw FileIO.failure("Failed to rewind the event log", errno)
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
            for line in existing[range].split(separator: 0x0a) where line.count > 2 && line.count <= maxEventRecordBytes {
                guard var record = (try? JSONSerialization.jsonObject(with: Data(line))) as? [String: Any],
                      let kind = record["kind"] as? String, ["session_start", "vpn_event", "note"].contains(kind) else { continue }
                for key in ["profilePath", "stateDirectory", "name", "info", "message"] {
                    if let value = record[key] as? String { record[key] = redactSensitiveText(value) }
                }
                if let safe = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys, .withoutEscapingSlashes]),
                   safe.count <= maxEventRecordBytes, retained.count + safe.count + marker.count + maxEventRecordBytes + 2 <= maximumBytes {
                    retained.append(safe)
                    retained.append(0x0a)
                }
            }
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

    private static let timestampFormat = Date.ISO8601FormatStyle(includingFractionalSeconds: true)

    private static func timestampString() -> String {
        Date().formatted(timestampFormat)
    }
}
