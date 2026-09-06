import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct ShellAndProcessTests {
    @Test
    func reachabilityProbeReturnsOnFirstSuccess() throws {
        let blocker = DispatchSemaphore(value: 0)
        let slowProbeCompletion = DispatchSemaphore(value: 0)
        let result = ReachabilityProbe.run(
            hosts: ["reachable", "slow-a", "slow-b"],
            timeout: 2
        ) { host, _ in
            if host == "reachable" {
                return true
            }
            _ = blocker.wait(timeout: .now() + 30)
            slowProbeCompletion.signal()
            return false
        }
        let waitedForSlowProbe = slowProbeCompletion.wait(timeout: .now()) == .success
        blocker.signal()
        blocker.signal()
        #expect(
            result.reachableHost == "reachable",
            "The reachability race should return the first host that succeeds.")
        #expect(
            !waitedForSlowProbe,
            "A successful reachability probe should not wait for slower hosts to time out.")

        let failed = ReachabilityProbe.run(hosts: ["a", "b"], timeout: 1) { _, _ in false }
        #expect(
            failed.reachableHost == nil && failed.checkedHosts == ["a", "b"],
            "The reachability race should report all configured hosts when every probe fails.")
    }

    @Test
    func openVPNBridgeLivenessSurface() throws {
        let client = try #require(
            cwru_ovpn_client_create(),
            "The OpenVPN bridge client could not be created.")
        defer { cwru_ovpn_client_destroy(client) }
        #expect(
            !cwru_ovpn_client_is_running(client),
            "A newly created OpenVPN bridge must not report a running worker before start.")
    }

    @Test
    func privilegedShellEnvironment() throws {
        var privilegedInvocation: ShellInvocation?
        let privilegedShell = Shell(handler: { invocation in
            privilegedInvocation = invocation
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        })
        _ = try privilegedShell.run("/bin/echo", arguments: ["ok"], requirePrivileges: true)

        #expect(
            privilegedInvocation?.environment == [
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
                "LC_ALL": "C",
            ], "Privileged subprocesses should use a deterministic minimal environment.")

        #expect(
            Shell.subprocessEnvironment(
                requirePrivileges: false,
                effectiveUserID: 0) == [
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "LANG": "C",
                    "LC_ALL": "C",
                ], "Already-root subprocesses should also use a deterministic minimal environment.")

        var unprivilegedInvocation: ShellInvocation?
        let unprivilegedShell = Shell(handler: { invocation in
            unprivilegedInvocation = invocation
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        })
        _ = try unprivilegedShell.run("/bin/echo", arguments: ["ok"])

        #expect(
            unprivilegedInvocation?.environment == nil,
            "Unprivileged subprocesses should keep the default inherited environment.")
    }

    @Test
    func shellTimeout() throws {
        #expect(
            !Shell.shouldReportTimeout(waitTimedOut: true, processExitedAtBoundary: true),
            "A command that exited at the timeout boundary should retain its completed result.")
        #expect(
            Shell.shouldReportTimeout(waitTimedOut: true, processExitedAtBoundary: false),
            "A command still running after its deadline should be reported as timed out.")

        for index in 0..<40 {
            let result = try Shell().run("/bin/echo", arguments: [String(index)])
            #expect(
                result.stdout == "\(index)\n" && result.stderr.isEmpty,
                "Rapid pipe cancellation and descriptor reuse must preserve command output.")
        }

        for _ in 0..<20 {
            do {
                _ = try Shell().run("/nonexistent/cwru-ovpn-shell-test", arguments: [])
                try #require(Bool(false), "Shell.run should reject a missing executable.")
            } catch let error as POSIXError {
                #expect(
                    error.code == .ENOENT,
                    "A spawn failure should preserve the underlying POSIX error.")
            }
        }

        let input = Data(repeating: 0x61, count: 512 * 1024)
        let inputResult = try Shell().run("/bin/cat", arguments: [], input: input)
        #expect(
            inputResult.stdout.utf8.count == input.count
                && inputResult.stdout.utf8.allSatisfy { $0 == 0x61 },
            "Shell.run should preserve large stdin and stdout payloads.")
        let emptyInputResult = try Shell().run("/bin/cat", arguments: [], input: Data())
        #expect(
            emptyInputResult.stdout.isEmpty,
            "Shell.run should close an empty stdin payload cleanly.")

        let unreadInput = Data(repeating: 0x62, count: 512 * 1024)
        let earlyExit = try Shell().run("/usr/bin/true", arguments: [], input: unreadInput)
        #expect(
            earlyExit.exitCode == 0,
            "A child that exits without reading stdin must not terminate the controller.")
        let earlyFailure = try Shell().run(
            "/bin/sh",
            arguments: ["-c", "exit 23"],
            input: unreadInput,
            allowNonZero: true)
        #expect(
            earlyFailure.exitCode == 23,
            "An early child failure should preserve its exit status when stdin is unread.")

        do {
            _ = try Shell().run(
                "/bin/sleep",
                arguments: ["60"],
                input: unreadInput,
                timeout: 0.1)
            try #require(
                Bool(false), "Shell.run should time out while its stdin writer is blocked.")
        } catch ShellError.timedOut(let command, let timeout, _) {
            #expect(
                command == "/bin/sleep 60" && timeout == 0.1,
                "A blocked stdin writer should preserve timeout error details.")
        }

        let largeOutput = try Shell().run(
            "/bin/sh",
            arguments: ["-c", "/usr/bin/yes x | /usr/bin/head -c 2097152"])
        #expect(
            largeOutput.stdout.utf8.count == 2 * 1024 * 1024,
            "Shell.run should continuously drain output larger than the pipe buffer.")

        let overriddenEnvironment = try Shell().run(
            "/bin/sh",
            arguments: ["-c", "printf %s \"$CWRU_OVPN_SHELL_TEST\""],
            environmentOverrides: ["CWRU_OVPN_SHELL_TEST": "preserved"])
        #expect(
            overriddenEnvironment.stdout == "preserved",
            "The process-group spawn path should preserve explicit environment overrides.")

        let nonzero = try Shell().run("/bin/sh", arguments: ["-c", "exit 7"], allowNonZero: true)
        #expect(
            nonzero.exitCode == 7,
            "The process-group spawn path should preserve normal nonzero exit status.")
        let signaled = try Shell().run(
            "/bin/sh", arguments: ["-c", "kill -TERM $$"], allowNonZero: true)
        #expect(
            signaled.exitCode == SIGTERM,
            "The process-group spawn path should restore child signal defaults and report termination signals."
        )

        let startedAt = Date()
        do {
            _ = try Shell().run("/bin/sleep", arguments: ["1"], timeout: 0.1)
            try #require(
                Bool(false), "Shell.run should time out a command that exceeds its deadline.")
        } catch ShellError.timedOut(let command, let timeout, _) {
            #expect(
                command == "/bin/sleep 1" && timeout == 0.1,
                "Shell timeout errors should identify the command and effective deadline.")
            #expect(
                Date().timeIntervalSince(startedAt) < 2,
                "Shell.run should terminate a timed-out command promptly.")
        }

        let directory = temporaryDirectory(named: "cwru-ovpn-shell-timeout-descendant")
        let pidFile = directory.appendingPathComponent("descendant.pid")
        defer {
            if let value = try? String(contentsOf: pidFile, encoding: .utf8) {
                let pids = value.split(whereSeparator: { $0.isWhitespace }).compactMap { Int32($0) }
                for pid in pids {
                    _ = kill(pid, SIGKILL)
                }
                if let processGroupID = pids.first {
                    _ = kill(-processGroupID, SIGKILL)
                }
            }
            try? FileManager.default.removeItem(at: directory)
        }
        let descendantStartedAt = Date()
        let descendantScript =
            "trap '/bin/sleep 60 & echo $! >> \"$1\"; trap \"\" TERM; wait' TERM; "
            + "/bin/sleep 60 & echo $$ $! > \"$1\"; wait"
        do {
            _ = try Shell().run(
                "/bin/sh",
                arguments: [
                    "-c",
                    descendantScript,
                    "sh",
                    pidFile.path,
                ],
                timeout: 0.1)
            try #require(
                Bool(false),
                "Shell.run should time out a command whose descendant keeps its pipes open.")
        } catch ShellError.timedOut {
            #expect(
                Date().timeIntervalSince(descendantStartedAt) < 3,
                "A descendant that inherits stdout and stderr must not keep Shell.run blocked after the direct child is reaped."
            )
            let processIDs = try String(contentsOf: pidFile, encoding: .utf8)
                .split(whereSeparator: { $0.isWhitespace })
                .compactMap { Int32($0) }
            try #require(
                processIDs.count >= 3,
                "The shell timeout fixture did not record the process group and its TERM-handler descendant."
            )
            let processGroupID = processIDs[0]
            let descendantPIDs = Array(processIDs.dropFirst())
            let descendantDeadline = Date().addingTimeInterval(1)
            while Date() < descendantDeadline {
                let groupExists = kill(-processGroupID, 0) == 0 || errno == EPERM
                if descendantPIDs.allSatisfy({ !processExists($0) }), !groupExists {
                    break
                }
                usleep(10_000)
            }
            let groupExists = kill(-processGroupID, 0) == 0 || errno == EPERM
            #expect(
                descendantPIDs.allSatisfy { !processExists($0) },
                "Shell.run should reap descendants created before and after TERM delivery.")
            #expect(
                !groupExists,
                "Shell.run should leave no surviving member in a timed-out command's process group."
            )
        }
    }

    @Test
    func privilegedChildProcessEnvironment() throws {
        let identity = ResolvedUserIdentity(
            username: "alice",
            userID: 501,
            groupID: 20,
            homeDirectory: URL(fileURLWithPath: "/Users/alice", isDirectory: true))
        let environment = ChildProcess.sanitizedPrivilegedEnvironment(
            sudoIdentity: identity)

        #expect(
            environment["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin",
            "Privileged child processes should use a deterministic PATH.")
        #expect(
            environment["SUDO_USER"] == "alice",
            "Privileged child processes should preserve the validated sudo username.")
        #expect(
            environment["SUDO_UID"] == "501",
            "Privileged child processes should preserve the validated sudo uid.")
        #expect(
            environment["SUDO_GID"] == "20",
            "Privileged child processes should preserve the validated sudo gid.")
        #expect(
            environment["HOME"] == "/Users/alice",
            "Privileged child processes should keep user-state resolution pointed at the invoking user."
        )
        #expect(
            environment["CWRU_OVPN_CONFIG"] == nil,
            "Privileged child processes should not inherit config override environment variables.")
        #expect(
            environment["DYLD_INSERT_LIBRARIES"] == nil,
            "Privileged child processes should not inherit dynamic loader injection variables.")
    }

    @Test
    func detachedStartupStatus() throws {
        let tempURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("cwru-ovpn-startup-status-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: tempURL) }

        DetachedStartupStatus.writeFailure(message: "Profile missing.", to: tempURL.path)
        let loaded = DetachedStartupStatus.load(from: tempURL.path)

        #expect(
            loaded?.state == .failed,
            "Detached startup status should decode the failure state.")
        #expect(
            loaded?.message == "Profile missing.",
            "Detached startup status should preserve the failure message.")
        let permissions =
            (try FileManager.default.attributesOfItem(atPath: tempURL.path)[.posixPermissions]
            as? NSNumber)?.intValue ?? -1
        #expect(
            permissions & 0o077 == 0,
            "Detached startup status should stay owner-only after atomic writes.")

        let data = try Data(contentsOf: tempURL)
        var object = try #require(
            try JSONSerialization.jsonObject(with: data) as? [String: Any],
            "Encoded detached startup status should be a JSON object.")
        object["legacyDetail"] = "unsupported"
        let unknownFieldData = try JSONSerialization.data(withJSONObject: object)
        #expect(throws: (any Error).self, "Detached startup status should reject unknown fields.") {
            _ = try JSONDecoder().decode(DetachedStartupStatus.self, from: unknownFieldData)
        }
    }

    @Test
    func processStartTimeMatching() throws {
        let expectedStartTime = ProcessStartTime(seconds: 123, microseconds: 456)
        let executablePath = "/opt/tools/bin/cwru-ovpn"

        #expect(
            processStartTimeMatches(
                actualStartTime: nil,
                expectedStartTime: expectedStartTime),
            "Process liveness checks should treat an unreadable start time as inconclusive instead of assuming the process exited."
        )

        #expect(
            processStartTimeMatches(
                actualStartTime: expectedStartTime,
                expectedStartTime: expectedStartTime),
            "Matching start times should validate the same process instance.")

        #expect(
            !processStartTimeMatches(
                actualStartTime: ProcessStartTime(seconds: 123, microseconds: 789),
                expectedStartTime: expectedStartTime),
            "Mismatched start times should still detect PID reuse.")

        #expect(
            processIdentityAssessment(
                processExists: false,
                actualExecutablePath: executablePath,
                expectedExecutablePath: executablePath,
                actualStartTime: expectedStartTime,
                expectedStartTime: expectedStartTime) == .notRunning,
            "Missing processes should remain distinguishable from unreadable process identities.")

        let inaccessiblePath = processIdentityAssessment(
            processExists: true,
            actualExecutablePath: nil,
            expectedExecutablePath: executablePath,
            actualStartTime: nil,
            expectedStartTime: expectedStartTime)
        #expect(
            inaccessiblePath == .unavailable && inaccessiblePath.permitsReadOnlyStatus,
            "Read-only status should keep a live privileged process active when its identity is inaccessible."
        )

        let inaccessibleStartTime = processIdentityAssessment(
            processExists: true,
            actualExecutablePath: executablePath,
            expectedExecutablePath: executablePath,
            actualStartTime: nil,
            expectedStartTime: expectedStartTime)
        #expect(
            inaccessibleStartTime == .unavailable && inaccessibleStartTime.permitsReadOnlyStatus,
            "Read-only status should treat an unreadable start time as inconclusive.")

        #expect(
            processIdentityAssessment(
                processExists: true,
                actualExecutablePath: "/opt/tools/bin/other",
                expectedExecutablePath: executablePath,
                actualStartTime: expectedStartTime,
                expectedStartTime: expectedStartTime) == .mismatched,
            "Executable mismatches should still detect PID reuse.")

        #expect(
            processIdentityAssessment(
                processExists: true,
                actualExecutablePath: executablePath,
                expectedExecutablePath: executablePath,
                actualStartTime: ProcessStartTime(seconds: 123, microseconds: 789),
                expectedStartTime: expectedStartTime) == .mismatched,
            "Start-time mismatches should still detect PID reuse.")

        #expect(
            processIdentityAssessment(
                processExists: true,
                actualExecutablePath: executablePath,
                expectedExecutablePath: executablePath,
                actualStartTime: expectedStartTime,
                expectedStartTime: expectedStartTime) == .matched,
            "Matching process identities should remain verified.")

        let strictCases: [(ProcessIdentityAssessment, Bool, Bool, Bool)] = [
            (.notRunning, false, false, true),
            (.matched, true, true, false),
            (.mismatched, false, false, true),
            (.unavailable, false, true, false),
        ]
        for (assessment, isVerifiedMatch, permitsReadOnlyStatus, indicatesStaleOwner) in strictCases
        {
            #expect(
                assessment.isVerifiedMatch == isVerifiedMatch,
                "Only a verified identity match should pass strict process validation.")
            #expect(
                assessment.permitsReadOnlyStatus == permitsReadOnlyStatus,
                "Read-only status should accept only matched or inaccessible live process identities."
            )
            #expect(
                assessment.indicatesStaleOwner == indicatesStaleOwner,
                "Stale route cleanup should mutate only for a missing process or a verified identity mismatch."
            )
        }

        let exitedProcess = Process()
        exitedProcess.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try exitedProcess.run()
        let exitedPID = Int32(exitedProcess.processIdentifier)
        exitedProcess.waitUntilExit()
        #expect(
            !processExists(exitedPID),
            "The reaped process fixture should no longer exist.")
        #expect(
            processIdentityAssessment(
                exitedPID,
                expectedExecutablePath: "/usr/bin/true",
                expectedStartTime: ProcessStartTime(seconds: 1, microseconds: 0)) == .notRunning,
            "A reaped process should not be classified as an inaccessible live process.")
    }

    @Test
    func existingSessionIdentityDecisions() throws {
        let dispositionCases: [(ProcessIdentityAssessment, SessionControl.ExistingSessionDisposition)] = [
            (.matched, .live),
            (.unavailable, .refuse),
            (.mismatched, .stale),
            (.notRunning, .stale),
        ]
        for (assessment, expectedDisposition) in dispositionCases {
            #expect(
                SessionControl.existingSessionDisposition(identityAssessment: assessment) == expectedDisposition,
                "Existing-session handling should refuse inaccessible identities and only recover verified stale state."
            )
        }

        #expect(
            SessionControl.processIdentityRefusalMessage(
                pid: 4321,
                assessment: .unavailable,
                operation: "disconnect")
                == "Refusing to disconnect PID 4321 because its process identity is unavailable to the current user. Retry the command with sudo.",
            "Unavailable process identities should produce actionable privilege guidance.")
        #expect(
            SessionControl.processIdentityRefusalMessage(
                pid: 4321,
                assessment: .mismatched,
                operation: "signal")
                == "Refusing to signal PID 4321 because it does not match the expected cwru-ovpn controller identity.",
            "Mismatched process identities should report the actual validation failure.")
        #expect(
            SessionControl.processIdentityRefusalMessage(
                pid: 4321,
                assessment: .matched,
                operation: "signal") == nil,
            "Matched process identities should not produce refusal messages.")
        #expect(
            SessionControl.processIdentityRefusalMessage(
                pid: 4321,
                assessment: .notRunning,
                operation: "signal") == nil,
            "Absent processes should not be mislabeled as identity validation failures.")
    }
}
