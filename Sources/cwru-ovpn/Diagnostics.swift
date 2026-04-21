import Foundation

enum Diagnostics {
    static func printLogs(tailCount: Int) {
        print("Event log: \(RuntimePaths.eventLogFile.path)")

        guard let lines = try? tailLines(from: RuntimePaths.eventLogFile, count: tailCount),
              !lines.isEmpty else {
            print("No event log entries found.")
            return
        }

        for line in lines {
            print(line)
        }
    }

    private static func tailLines(from fileURL: URL, count: Int) throws -> [String] {
        let limit = max(1, count)
        let handle = try FileHandle(forReadingFrom: fileURL)
        defer { try? handle.close() }

        let fileSize = try handle.seekToEnd()
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

        let data = Data(chunks.reversed().flatMap { $0 })
        let lines = String(decoding: data, as: UTF8.self)
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map(String.init)
        return Array(lines.suffix(limit))
    }

    static func printDoctor() {
        let fileManager = FileManager.default
        let session = SessionState.load()
        let configURL = AppConfig.resolvedConfigURL(explicitConfigPath: session?.configFilePath)
        let config = try? AppConfig.load(explicitConfigPath: session?.configFilePath)
        let sudoersPath = "/etc/sudoers.d/cwru-ovpn"
        let executablePath = URL(fileURLWithPath: CommandLine.arguments[0])
            .resolvingSymlinksInPath()
            .standardized.path

        print("Executable: \(executablePath)")
        print("Version: \(AppIdentity.version)")
        print("Home state directory: \(RuntimePaths.homeStateDirectory.path)")
        print("Runtime state directory: \(RuntimePaths.stateDirectory.path)")
        print("Session state: \(RuntimePaths.sessionStateFile.path)")
        print("Event log: \(RuntimePaths.eventLogFile.path)")
        let liveTunnelInterfaces = ((try? Shell.run("/sbin/ifconfig", arguments: ["-l"]).stdout) ?? "")
            .split(whereSeparator: \.isWhitespace)
            .map(String.init)
            .filter { $0.hasPrefix("utun") }
        print("Live utun interfaces: \(liveTunnelInterfaces.isEmpty ? "none" : liveTunnelInterfaces.joined(separator: ", "))")
        if !liveTunnelInterfaces.isEmpty {
            print("Live utun note: OpenVPN 3 keeps its utun device persistent across reconnects. After an interrupted cleanup, stale entries here can help explain recovery issues.")
        }
        print("Config file: \(configURL?.path ?? "not found")")
        print("Profile file: \(config?.profilePath.map(AppConfig.expandUserPath) ?? RuntimePaths.homeProfileFile.path)")
        print("Sudoers rule: \(fileManager.fileExists(atPath: sudoersPath) ? sudoersPath : "not installed")")

        if let session {
            let alive = processExists(session.pid)
            let statusTitle = VPNController.statusTitle(for: session.phase,
                                                        stale: !alive,
                                                        recoveryNeeded: !alive && session.cleanupNeeded)
            print("Session status: \(statusTitle)")
            print("Session PID: \(session.pid)")
            print("Session alive: \(alive ? "yes" : "no")")
            print("Tunnel mode: \(session.tunnelMode?.rawValue ?? "unknown")")
            print("Started: \(ISO8601DateFormatter().string(from: session.startedAt))")
            if let configPath = session.configFilePath {
                print("Session config: \(configPath)")
            }
            print("Cleanup needed: \(session.cleanupNeeded ? "yes" : "no")")
            if let serverHost = session.serverHost {
                print("Gateway: \(serverHost)")
            }
            if let detail = VPNController.recoveryDetail(for: session, stale: !alive) {
                print("Recovery: \(detail)")
            } else if let lastInfo = session.lastInfo, !lastInfo.isEmpty {
                print("Last info: \(lastInfo)")
            }
        } else {
            print("Session status: Disconnected")
        }

        let resolverDomains = Array(Set((config?.splitTunnel.effectiveResolverDomains ?? [])
                                        + (session?.appliedResolverDomains ?? [])))
            .filter {
                AppConfig.SplitTunnelConfiguration.isValidDomainName($0)
                    && ResolverPaths.isSafeDomainFileName($0)
            }
            .sorted()
        print("Resolver directory: \(ResolverPaths.directory.path)")
        if resolverDomains.isEmpty {
            print("Resolver files: none configured")
        } else {
            let presentResolvers = resolverDomains.filter {
                fileManager.fileExists(atPath: ResolverPaths.fileURL(for: $0).path)
            }
            print("Resolver files present: \(presentResolvers.isEmpty ? "none" : presentResolvers.joined(separator: ", "))")
        }
    }
}
