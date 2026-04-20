import Foundation

enum Diagnostics {
    static func printLogs(tailCount: Int) {
        print("Event log: \(RuntimePaths.eventLogFile.path)")

        guard let data = try? Data(contentsOf: RuntimePaths.eventLogFile),
              let content = String(data: data, encoding: .utf8),
              !content.isEmpty else {
            print("No event log entries found.")
            return
        }

        let lines = content
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map(String.init)
        let tail = lines.suffix(max(1, tailCount))

        for line in tail {
            print(line)
        }
    }

    static func printDoctor() {
        let fileManager = FileManager.default
        let session = SessionState.load()
        let configURL = AppConfig.resolvedConfigURL(explicitConfigPath: session?.configFilePath)
        let config = try? AppConfig.load(explicitConfigPath: session?.configFilePath)
        let sudoersPath = "/etc/sudoers.d/cwru-ovpn"

        print("Executable: \(CommandLine.arguments[0])")
        print("Version: \(AppIdentity.version)")
        print("State directory: \(RuntimePaths.homeStateDirectory.path)")
        print("Session state: \(RuntimePaths.sessionStateFile.path)")
        print("Event log: \(RuntimePaths.eventLogFile.path)")
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

        let resolverDomains = config?.splitTunnel.effectiveResolverDomains ?? []
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
