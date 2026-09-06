import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite(.serialized)
struct EventLogTests {
    @Test
    func heldLogLockDoesNotBlockTheController() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-contended-log")
        defer { try? FileManager.default.removeItem(at: directory) }
        EventLog.append(note: "before contention", in: directory)
        let file = directory.appendingPathComponent("events.ndjson")
        let descriptor = open(file.path, O_RDWR | O_CLOEXEC)
        try #require(descriptor >= 0)
        defer {
            _ = flock(descriptor, LOCK_UN)
            close(descriptor)
        }
        try #require(flock(descriptor, LOCK_EX | LOCK_NB) == 0)
        let started = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            started.signal()
            EventLog.append(note: "during contention", in: directory)
            finished.signal()
        }
        try #require(started.wait(timeout: .now() + .seconds(5)) == .success)
        let returnedWhileLocked = finished.wait(timeout: .now() + .seconds(5)) == .success
        try #require(flock(descriptor, LOCK_UN) == 0)
        if !returnedWhileLocked {
            try #require(finished.wait(timeout: .now() + .seconds(5)) == .success)
        }
        #expect(returnedWhileLocked, "Appending a log must return before the existing lock is released.")
        EventLog.append(note: "after contention", in: directory)
        let lines = try Diagnostics.tailLines(from: file, count: 10)
        #expect(lines.count == 2)
    }

    @Test
    func privacyModeEventLog() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-private-log-state")
        defer {
            EventLog.configure(privacyMode: true)
            try? FileManager.default.removeItem(at: homeStateDirectory)
        }

        EventLog.configure(privacyMode: true)
        EventLog.startSession(
            profilePath: "/private/tmp/sensitive-profile.ovpn",
            in: homeStateDirectory)
        EventLog.append(
            eventName: "LOG",
            info: "OPEN_URL:https://login.example/callback?token=secret",
            isError: false,
            isFatal: false,
            phase: .connecting,
            in: homeStateDirectory)
        EventLog.append(
            note: "Learned server-pushed DNS servers: 10.8.0.2",
            phase: .connected,
            in: homeStateDirectory)

        let logText = try String(
            contentsOf: homeStateDirectory.appendingPathComponent("events.ndjson"),
            encoding: .utf8)
        #expect(
            logText.contains(#""privacyMode":true"#),
            "Privacy-mode event logs should mark the session as privacy mode.")
        #expect(
            !logText.contains("sensitive-profile.ovpn"),
            "Privacy-mode event logs should suppress profile paths.")
        #expect(
            !logText.contains("https://login.example"),
            "Privacy-mode event logs should suppress raw event info.")
        #expect(
            !logText.contains("10.8.0.2"),
            "Privacy-mode event logs should suppress note details.")
    }

    @Test
    func eventLogKeepsHistoryAcrossSessions() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-log-history-state")
        defer {
            EventLog.configure(privacyMode: true)
            try? FileManager.default.removeItem(at: homeStateDirectory)
        }

        EventLog.configure(privacyMode: false)
        EventLog.append(
            note: "history-from-previous-session",
            phase: .disconnected,
            in: homeStateDirectory)
        EventLog.startSession(
            profilePath: "/private/tmp/history-profile.ovpn",
            in: homeStateDirectory)
        EventLog.append(
            note: "history-from-current-session",
            phase: .connecting,
            in: homeStateDirectory)

        let logText = try String(
            contentsOf: homeStateDirectory.appendingPathComponent("events.ndjson"),
            encoding: .utf8)
        #expect(
            logText.contains("history-from-previous-session"),
            "Starting a session must preserve prior-session event log history.")
        #expect(
            logText.contains("history-from-current-session"),
            "Starting a session should keep appending new records.")
    }

    @Test
    func eventLogSizeLimit() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-bounded-log-state")
        let maximumBytes = 5 * 1024 * 1024
        defer {
            EventLog.configure(privacyMode: true)
            try? FileManager.default.removeItem(at: homeStateDirectory)
        }

        let eventLogFile = homeStateDirectory.appendingPathComponent("events.ndjson")
        var oversizedPrefix = Data(
            #"{"kind":"session_start","profilePath":"evidence-profile"}"#.utf8)
        oversizedPrefix.append(0x0a)
        let firstFillerCount =
            (maximumBytes * 3 / 10
                - oversizedPrefix.count) / 3
        oversizedPrefix.append(Data(String(repeating: "{}\n", count: firstFillerCount).utf8))
        oversizedPrefix.append(
            Data(
                #"{"kind":"vpn_event","name":"RECONNECTING","isError":false,"isFatal":false}"#.utf8)
        )
        oversizedPrefix.append(0x0a)
        let remainingFillerCount =
            (maximumBytes - 16
                - oversizedPrefix.count) / 3
        oversizedPrefix.append(Data(String(repeating: "{}\n", count: remainingFillerCount).utf8))
        try oversizedPrefix.write(to: eventLogFile, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: eventLogFile.path)

        EventLog.configure(privacyMode: false)
        EventLog.append(
            note: "rotation-trigger",
            phase: .connected,
            in: homeStateDirectory)

        let attributes = try FileManager.default.attributesOfItem(atPath: eventLogFile.path)
        let size = (attributes[.size] as? NSNumber)?.intValue ?? Int.max
        let contents = try String(contentsOf: eventLogFile, encoding: .utf8)
        #expect(
            size < maximumBytes,
            "Event logs should compact safely before exceeding the configured size limit.")
        #expect(
            contents.contains("Event log reached its size limit")
                && contents.contains("rotation-trigger"),
            "Event-log compaction should leave a marker and preserve the triggering record.")
        #expect(
            contents.contains("evidence-profile"),
            "Event-log compaction should retain the current session start.")
        #expect(
            contents.contains(#""name":"RECONNECTING""#),
            "Event-log compaction should retain the first transport-failure evidence.")
    }

    @Test
    func eventLogRejectsHardlink() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-hardlink-log-state")
        defer { try? FileManager.default.removeItem(at: homeStateDirectory) }

        let eventLogFile = homeStateDirectory.appendingPathComponent("events.ndjson")
        let target = homeStateDirectory.appendingPathComponent("linked-events-target")
        try "existing\n".write(to: target, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)

        guard link(target.path, eventLogFile.path) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        EventLog.append(
            note: "must-not-follow-hardlink",
            phase: .failed,
            in: homeStateDirectory)

        let targetText = try String(contentsOf: target, encoding: .utf8)
        #expect(
            targetText == "existing\n",
            "Rejected hardlinked event logs should not be modified.")
    }

    @Test
    func eventLogRejectsSymlink() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-symlink-log-state")
        defer { try? FileManager.default.removeItem(at: homeStateDirectory) }

        let eventLogFile = homeStateDirectory.appendingPathComponent("events.ndjson")
        let target = homeStateDirectory.appendingPathComponent("linked-events-target")
        try "existing\n".write(to: target, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)

        guard symlink(target.path, eventLogFile.path) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        EventLog.append(
            note: "must-not-follow-symlink",
            phase: .failed,
            in: homeStateDirectory)

        let targetText = try String(contentsOf: target, encoding: .utf8)
        #expect(
            targetText == "existing\n",
            "Rejected symlinked event logs should not be modified.")
    }

    @Test
    func eventLogParentSwapIsContained() throws {
        let parent = temporaryDirectory(named: "cwru-ovpn-event-parent-swap")
        defer { try? FileManager.default.removeItem(at: parent) }
        let state = parent.appendingPathComponent("state", isDirectory: true)
        let original = parent.appendingPathComponent("state-original", isDirectory: true)
        let victim = parent.appendingPathComponent("victim", isDirectory: true)
        try FileManager.default.createDirectory(
            at: state,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(
            at: victim,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        let victimLog = victim.appendingPathComponent("events.ndjson")
        try Data("victim\n".utf8).write(to: victimLog)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: victimLog.path)

        let handle = try AnchoredFileIO.withDirectory(
            at: state,
            parentUserID: getuid(),
            parentGroupID: getgid(),
            userID: getuid(),
            groupID: getgid()
        ) { directoryFD in
            try FileManager.default.moveItem(at: state, to: original)
            guard symlink(victim.path, state.path) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            let fileFD = try AnchoredFileIO.openOwnedRegularFileForAppend(
                in: directoryFD,
                name: "events.ndjson",
                userID: getuid(),
                groupID: getgid())
            return FileHandle(fileDescriptor: fileFD, closeOnDealloc: true)
        }
        handle.write(Data("anchored\n".utf8))
        try handle.close()

        let victimLogData = try Data(contentsOf: victimLog)
        let originalLogData = try Data(contentsOf: original.appendingPathComponent("events.ndjson"))
        #expect(
            victimLogData == Data("victim\n".utf8),
            "Event logging should not follow a replacement state-directory symlink.")
        #expect(
            originalLogData == Data("anchored\n".utf8),
            "Event logging should remain bound to the opened state directory.")
    }

    @Test
    func eventLogRejectsWrongModeWithoutRepair() throws {
        let state = temporaryDirectory(named: "cwru-ovpn-event-wrong-mode")
        defer { try? FileManager.default.removeItem(at: state) }
        let eventLog = state.appendingPathComponent("events.ndjson")
        try Data("existing\n".utf8).write(to: eventLog)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: eventLog.path)

        EventLog.append(
            note: "must-not-repair-unsafe-mode",
            phase: .failed,
            in: state)

        let attributes = try FileManager.default.attributesOfItem(atPath: eventLog.path)
        #expect(
            (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o644,
            "Event logging should not chmod an existing unsafe file.")
        let contents = try Data(contentsOf: eventLog)
        #expect(
            contents == Data("existing\n".utf8),
            "Event logging should not modify an existing unsafe file.")
    }

    @Test
    func sessionStateRemoveFailureIsLogged() throws {
        let stateDirectory = temporaryDirectory(named: "cwru-ovpn-session-remove-failure")
        defer {
            EventLog.configure(privacyMode: true)
            try? FileManager.default.removeItem(at: stateDirectory)
        }
        EventLog.configure(privacyMode: true)
        SessionState.reportRemovalFailure(
            POSIXError(.EPERM),
            writeToStandardError: false,
            eventLogDirectory: stateDirectory)
        let eventLog = try Data(contentsOf: stateDirectory.appendingPathComponent("events.ndjson"))
        let eventNames = eventLog.split(separator: 0x0a).compactMap { line -> String? in
            guard let object = try? JSONSerialization.jsonObject(with: Data(line)) as? [String: Any]
            else {
                return nil
            }
            return object["name"] as? String
        }
        #expect(
            eventNames.contains("SESSION_STATE_REMOVE_FAILED"),
            "A session-state removal failure should remain visible in the persistent event log.")
    }

    @Test
    func logTailsAreBoundedAndRejectLinkedFiles() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-log-tail")
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("events.ndjson")
        #expect(try Diagnostics.tailLines(from: file, count: 2).isEmpty)
        try Data("first\nsecond\nthird\n".utf8).write(to: file)
        #expect(try Diagnostics.tailLines(from: file, count: 2) == ["second", "third"])
        let alias = directory.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: file)
        #expect(throws: (any Error).self) { _ = try Diagnostics.tailLines(from: alias, count: 2) }
        try Data(repeating: 0x61, count: EventLog.maximumBytes + 1).write(to: file)
        #expect(throws: (any Error).self) { _ = try Diagnostics.tailLines(from: file, count: 2) }
    }
}
