import Darwin
import Foundation

enum Diagnostics {
    static func printLogs(tailCount: Int) throws {
        print("Event log: \(RuntimePaths.eventLogFile.path)")

        let lines = try tailLines(from: RuntimePaths.eventLogFile, count: tailCount)
        guard !lines.isEmpty else {
            print("No event log entries found.")
            return
        }

        for line in lines {
            print(line)
        }
    }

    static func tailLines(from fileURL: URL, count: Int) throws -> [String] {
        let limit = max(1, count)
        let descriptor = open(fileURL.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        if descriptor < 0, errno == ENOENT {
            return []
        }
        guard descriptor >= 0 else {
            throw FileIO.posixError(errno)
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        try SecureFile.assertRegularFile(fileDescriptor: descriptor, context: "event log")
        let fileSize = try handle.seekToEnd()
        guard fileSize <= EventLog.maximumBytes else {
            throw POSIXError(.EFBIG)
        }
        guard fileSize > 0 else {
            return []
        }

        let chunkSize = 4096
        var remaining = Int(fileSize)
        var newlineCount = 0
        var chunks: [Data] = []

        while remaining > 0 && newlineCount <= limit {
            let readLength = min(chunkSize, remaining)
            remaining -= readLength
            try handle.seek(toOffset: UInt64(remaining))
            let chunk = handle.readData(ofLength: readLength)
            guard !chunk.isEmpty else {
                break
            }

            newlineCount += chunk.reduce(into: 0) { count, byte in
                if byte == 0x0a {
                    count += 1
                }
            }
            chunks.append(chunk)
        }

        let data = chunks.reversed().reduce(into: Data()) { $0.append($1) }
        let lines = String(decoding: data, as: UTF8.self)
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map(String.init)
        return Array(lines.suffix(limit))
    }

    static func printDoctor() {
        let fileManager = FileManager.default
        let sessionLoadResult = SessionState.loadResult()
        let session = sessionLoadResult.loadedSession
        let configURL = AppConfig.resolvedConfigURL(explicitConfigPath: session?.configFilePath)
        let sudoersPath = "/etc/sudoers.d/cwru-ovpn"
        let executablePath = (try? ExecutionIdentity.currentExecutablePath())
            ?? CommandLine.arguments.first
            ?? AppIdentity.executableName

        print("Executable: \(executablePath)")
        print("Version: \(AppIdentity.version)")
        print("Home state directory: \(RuntimePaths.homeStateDirectory.path)")
        print("Runtime state directory: \(RuntimePaths.stateDirectory.path)")
        print("Session state: \(RuntimePaths.sessionStateFile.path)")
        print("Event log: \(RuntimePaths.eventLogFile.path)")
        for line in liveTunnelInterfaceLines() {
            print(line)
        }
        print("Config file: \(configURL?.path ?? "not found")")
        print("Profile file: \(RuntimePaths.homeProfileFile.path)")
        print("Sudoers rule: \(fileManager.fileExists(atPath: sudoersPath) ? sudoersPath : "not installed")")

        if case .invalid(let message) = sessionLoadResult {
            print("Session status: Recovery Needed")
            print("Recovery ledger error: \(message)")
            print("Recovery: Refusing to reconnect or discard state until the persistent recovery ledger is repaired.")
        } else if let session {
            let identityAssessment = processIdentityAssessment(
                session.pid,
                expectedExecutablePath: session.executablePath,
                expectedStartTime: session.processStartTime
            )
            let sessionMayBeActive = identityAssessment.permitsReadOnlyStatus
            let statusTitle = SessionPresentation.readOnlyStatusTitle(
                for: session,
                identityAssessment: identityAssessment
            )
            print("Session status: \(statusTitle)")
            print("Session PID: \(session.pid)")
            print(SessionPresentation.readOnlySessionAliveLine(identityAssessment: identityAssessment))
            print(SessionPresentation.readOnlySessionIdentityLine(identityAssessment: identityAssessment))
            print("Tunnel mode: \(session.tunnelMode.rawValue)")
            print("Started: \(ISO8601DateFormatter().string(from: session.startedAt))")
            if let configPath = session.configFilePath {
                print("Session config: \(configPath)")
            }
            print("Cleanup needed: \(session.cleanupNeeded ? "yes" : "no")")
            if let serverHost = session.serverHost {
                print("VPN gateway: \(serverHost)")
            }
            if let detail = SessionPresentation.recoveryDetail(for: session, stale: !sessionMayBeActive) {
                print("Recovery: \(detail)")
            } else if let lastInfo = session.lastInfo, !lastInfo.isEmpty {
                print("Last info: \(lastInfo)")
            }
            SessionControl.printSplitTunnelHealthIfNeeded(for: session)
        } else {
            print("Session status: Disconnected")
        }

        let dnsDomains = Array(Set(SplitTunnelPolicy.fixedResolverDomains
                                   + (session?.appliedDNSDomains ?? [])))
            .filter {
                SplitTunnelPolicy.isValidDomainName($0)
                    && ResolverPaths.isSafeDomainFileName($0)
            }
            .sorted()
        print("Resolver directory: \(ResolverPaths.directory.path)")
        if dnsDomains.isEmpty {
            print("Resolver files: none configured")
        } else {
            let presentResolvers = dnsDomains.filter {
                fileManager.fileExists(atPath: ResolverPaths.fileURL(for: $0).path)
            }
            print("Resolver files present: \(presentResolvers.isEmpty ? "none" : presentResolvers.joined(separator: ", "))")
        }
    }

    static func liveTunnelInterfaceLines(shell: Shell = Shell()) -> [String] {
        do {
            let interfaces = try shell.run("/sbin/ifconfig", arguments: ["-l"]).stdout
                .split(whereSeparator: \.isWhitespace)
                .filter { $0.hasPrefix("utun") }
            guard !interfaces.isEmpty else {
                return ["Live utun interfaces: none"]
            }
            return [
                "Live utun interfaces: \(interfaces.joined(separator: ", "))",
                "Live utun note: OpenVPN 3 keeps its utun device persistent across reconnects. After an interrupted cleanup, stale entries here can help explain recovery issues.",
            ]
        } catch {
            return ["Live utun interfaces: unavailable (\(error.localizedDescription))"]
        }
    }
}
