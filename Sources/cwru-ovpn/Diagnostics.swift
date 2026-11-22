import Darwin
import Foundation

enum Diagnostics {
    static func printLogs(tailCount: Int) throws {
        print("Event log: \(RuntimePaths.eventLogFile.path)")

        let owner = try ExecutionIdentity.invokingUser()
        let lines = try tailLines(from: RuntimePaths.eventLogFile, count: tailCount, userID: owner.userID, groupID: owner.groupID)
        guard !lines.isEmpty else {
            print("No event log entries found.")
            return
        }

        for line in lines {
            print(line)
        }
    }

    static func tailLines(from file: URL, count: Int, userID: uid_t = getuid(), groupID: gid_t = getgid()) throws -> [String] {
        do {
            return try AnchoredFileIO.withDirectory(at: file.deletingLastPathComponent(), parentUserID: userID, parentGroupID: groupID,
                                                    userID: userID, groupID: groupID, createIfMissing: false) { directory in
                guard let data = try AnchoredFileIO.readOwnedRegularFile(in: directory, name: file.lastPathComponent, userID: userID,
                                                                         groupID: groupID, maximumBytes: EventLog.maximumBytes) else { return [] }
                return data.split(separator: 10).suffix(max(1, count)).map { String(decoding: $0, as: UTF8.self) }
            }
        } catch let error as NSError where error.domain == NSPOSIXErrorDomain && error.code == Int(ENOENT) { return [] }
    }

    static func printDoctor() {
        let fileManager = FileManager.default
        let sessionLoadResult = SessionState.statusResult()
        let session = sessionLoadResult.loadedSession
        let configURL = (try? AppConfig.resolve(explicitConfigPath: session?.configFilePath))?.url
        let sudoersPath = RuntimePaths.sudoersFile.path
        do {
            print("Executable: \(try ExecutionIdentity.currentExecutablePath())")
        } catch {
            print("Executable: unavailable (\(error.localizedDescription))")
        }
        print("Version: \(AppIdentity.version)")
        print("State directory: \(RuntimePaths.homeStateDirectory.path)")
        print("Session state: \((ExecutionIdentity.isPrivileged ? RuntimePaths.privilegedStateDirectory : RuntimePaths.homeStateDirectory).appendingPathComponent(SessionState.fileName).path)")
        print("Event log: \(RuntimePaths.eventLogFile.path)")
        print(liveTunnelInterfacesLine())
        print("Config file: \(configURL?.path ?? "not found")")
        print("Profile file: \(RuntimePaths.homeProfileFile.path)")
        print("Sudoers rule: \(fileManager.fileExists(atPath: sudoersPath) ? sudoersPath : "not installed")")

        if case .invalid(let message) = sessionLoadResult {
            print("Session status: Recovery Needed")
            print("Saved session error: \(message)")
            print("Reconnect is blocked. The saved network settings have been retained.")
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
            print("Started: \(session.startedAt.formatted(.iso8601))")
            if let configPath = session.configFilePath {
                print("Session config: \(configPath)")
            }
            print("Cleanup needed: \(session.cleanupNeeded ? "yes" : "no")")
            if let serverHost = session.serverHost {
                print("VPN gateway: \(serverHost)")
            }
            if let detail = SessionPresentation.recoveryDetail(for: session, stale: !sessionMayBeActive) {
                print("Recovery: \(detail)")
            } else if let diagnosticDetail = session.diagnosticDetail, !diagnosticDetail.isEmpty {
                print("Last info: \(diagnosticDetail)")
            }
            if sessionMayBeActive {
                SessionControl.printTunnelHealthIfNeeded(for: session)
            }
        } else {
            print("Session status: Disconnected")
        }

        let scan = RouteManager().scanManagedResolverDirectory()
        for domain in scan.managed { print("Managed resolver: \(domain)") }
        for domain in scan.unmanaged.sorted() { print("Independent resolver: \(domain)") }
        for (domain, error) in scan.unreadable.sorted(by: { $0.key < $1.key }) { print("Unreadable resolver \(domain): \(error.localizedDescription)") }
        if let error = scan.directoryError { print("Resolver directory unavailable: \(error.localizedDescription)") }

    }

    static func liveTunnelInterfacesLine(commandRunner: CommandRunner = CommandRunner()) -> String {
        do {
            let interfaces = try commandRunner.run("/sbin/ifconfig", arguments: ["-l"]).stdout
                .split(whereSeparator: \.isWhitespace)
                .filter { $0.hasPrefix("utun") }
            return "Live utun interfaces: \(interfaces.isEmpty ? "none" : interfaces.joined(separator: ", "))"
        } catch {
            return "Live utun interfaces: unavailable (\(error.localizedDescription))"
        }
    }
}
