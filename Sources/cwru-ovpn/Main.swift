import AppKit
import Darwin
import Foundation

func renderUserFacingError(_ error: Error) -> String {
    "\(error.localizedDescription)\n"
}

@MainActor
private enum RuntimeState {
    static var controller: VPNController?
}

private enum DetachedConnectError: LocalizedError {
    case launcherFailed(String)

    var errorDescription: String? {
        switch self {
        case .launcherFailed(let message):
            return message
        }
    }
}

private enum DetachedConnectLauncher {
    static func launch(configFilePath: String?,
                       verbosityOverride: AppVerbosity?,
                       tunnelModeOverride: AppTunnelMode?,
                       allowSleep: Bool) throws {
        let configuration = try AppConfig.load(explicitConfigPath: configFilePath)
        let tunnelMode = tunnelModeOverride ?? configuration.tunnelMode

        if try VPNController.handleConnectRequestForActiveSession(targetMode: tunnelMode,
                                                                  configFilePath: configFilePath) {
            return
        }

        let executablePath = try ExecutionIdentity.currentExecutablePath()
        let startupStatusFile = try RuntimePaths.createTemporaryFile(prefix: "startup-status")
        defer { try? FileManager.default.removeItem(at: startupStatusFile) }

        print("Starting VPN in \(tunnelMode.modeDescription) mode.")
        let effectiveVerbosity = verbosityOverride ?? configuration.verbosity
        if effectiveVerbosity == .debug {
            print("Event log: \(RuntimePaths.eventLogFile.path)")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = childArguments(configFilePath: configFilePath,
                                           verbosityOverride: verbosityOverride,
                                           tunnelModeOverride: tunnelModeOverride,
                                           allowSleep: allowSleep,
                                           startupStatusFilePath: startupStatusFile.path)
        process.environment = ProcessInfo.processInfo.environment
        process.standardInput = FileHandle(forReadingAtPath: "/dev/null")
        process.standardOutput = FileHandle(forWritingAtPath: "/dev/null")
        process.standardError = FileHandle(forWritingAtPath: "/dev/null")

        try process.run()
        let childPID = Int32(process.processIdentifier)
        let childStartTime = processStartTime(childPID)
        try waitForConnection(childPID: childPID,
                              expectedExecutablePath: executablePath,
                              expectedStartTime: childStartTime,
                              startupStatusFilePath: startupStatusFile.path)
    }

    private static func childArguments(configFilePath: String?,
                                       verbosityOverride: AppVerbosity?,
                                       tunnelModeOverride: AppTunnelMode?,
                                       allowSleep: Bool,
                                       startupStatusFilePath: String) -> [String] {
        var arguments = ["connect"]
        if let configFilePath {
            arguments += ["--config", configFilePath]
        }
        if let verbosityOverride {
            arguments += ["--verbosity", verbosityOverride.rawValue]
        }
        if let tunnelModeOverride {
            arguments += ["--mode", tunnelModeOverride.rawValue]
        }
        if allowSleep {
            arguments.append("--allow-sleep")
        }
        arguments += ["--background-child", "--startup-status-file", startupStatusFilePath]
        return arguments
    }

    private static func waitForConnection(childPID: Int32,
                                          expectedExecutablePath: String,
                                          expectedStartTime: ProcessStartTime?,
                                          startupStatusFilePath: String) throws {
        var announcedAuth = false
        try RuntimePaths.ensureSessionStateDirectory()
        let watchedDirectories = [
            RuntimePaths.sessionStateDirectory,
            URL(fileURLWithPath: startupStatusFilePath).standardizedFileURL.deletingLastPathComponent(),
        ]
        let monitor = BlockingEventMonitor(directoryURLs: watchedDirectories, processIDs: [childPID])

        while true {
            if let session = SessionState.load(), session.pid == childPID {
                switch session.phase {
                case .authPending:
                    if !announcedAuth {
                        print("Opening browser for sign-in.")
                        announcedAuth = true
                    }
                case .connected:
                    print("Connected.")
                    return
                case .failed:
                    let detail = VPNController.recoveryDetail(for: session, stale: false)
                        ?? session.lastInfo
                        ?? "The VPN session failed before connecting."
                    throw DetachedConnectError.launcherFailed(detail)
                case .disconnected:
                    let detail = session.lastInfo ?? "The VPN session ended before connecting."
                    throw DetachedConnectError.launcherFailed(detail)
                case .connecting, .disconnecting:
                    break
                }
            }

            if let startupStatus = DetachedStartupStatus.load(from: startupStatusFilePath) {
                throw DetachedConnectError.launcherFailed(startupStatus.message)
            }

            let childStillRunning =
                processMatchesExecutable(childPID,
                                         expectedExecutablePath: expectedExecutablePath,
                                         expectedStartTime: expectedStartTime)
                || (expectedStartTime == nil && processExists(childPID))
            if !childStillRunning {
                if let session = SessionState.load(), session.pid == childPID, session.phase == .connected {
                    print("Connected.")
                    return
                }
                let startupDetail = DetachedStartupStatus.load(from: startupStatusFilePath)?.message
                throw DetachedConnectError.launcherFailed(
                    startupDetail ?? "The background VPN controller exited before reporting a connected session."
                )
            }

            _ = monitor.wait(until: .distantFuture)
        }
    }
}

@main
enum CWRUOVPNMain {
    static func main() {
        do {
            switch try CLI.parse(arguments: Array(CommandLine.arguments.dropFirst())) {
            case .connect(let configFilePath,
                          let verbosityOverride,
                          let tunnelModeOverride,
                          let allowSleep,
                          let foregroundRequested,
                          let backgroundChild,
                          let startupStatusFilePath):
                do {
                    if foregroundRequested && !backgroundChild {
                        let configuration = try AppConfig.load(explicitConfigPath: configFilePath)
                        let tunnelMode = tunnelModeOverride ?? configuration.tunnelMode
                        if try VPNController.handleConnectRequestForActiveSession(targetMode: tunnelMode,
                                                                                  configFilePath: configFilePath) {
                            break
                        }
                    }

                    if !foregroundRequested && !backgroundChild {
                        try DetachedConnectLauncher.launch(configFilePath: configFilePath,
                                                           verbosityOverride: verbosityOverride,
                                                           tunnelModeOverride: tunnelModeOverride,
                                                           allowSleep: allowSleep)
                        break
                    }
                    let configuration = try AppConfig.load(explicitConfigPath: configFilePath)
                    let profilePath = try configuration.resolvedProfilePath(explicitConfigPath: configFilePath)
                    let effectiveAllowSleep = allowSleep || configuration.allowSleep
                    _ = NSApplication.shared
                    NSApplication.shared.setActivationPolicy(.accessory)
                    let resolvedConfigFilePath = AppConfig.resolvedConfigURL(explicitConfigPath: configFilePath)?.path
                    let controller = try VPNController(profilePath: profilePath,
                                                       configFilePath: resolvedConfigFilePath,
                                                       configuration: configuration,
                                                       verbosity: verbosityOverride ?? configuration.verbosity,
                                                       tunnelMode: tunnelModeOverride ?? configuration.tunnelMode,
                                                       allowSleep: effectiveAllowSleep,
                                                       backgroundChild: backgroundChild,
                                                       startupStatusFilePath: startupStatusFilePath)
                    RuntimeState.controller = controller
                    try controller.start()
                    NSApplication.shared.run()
                    let failureMessage = controller.terminalFailureMessage()
                    RuntimeState.controller = nil
                    if let failureMessage {
                        throw DetachedConnectError.launcherFailed(failureMessage)
                    }
                } catch {
                    if backgroundChild {
                        DetachedStartupStatus.writeFailure(message: error.localizedDescription,
                                                          to: startupStatusFilePath)
                    }
                    throw error
                }
            case .disconnect(let force):
                try VPNController.disconnectExistingSession(force: force)
            case .status:
                VPNController.printStatus()
            case .logs(let tailCount):
                Diagnostics.printLogs(tailCount: tailCount)
            case .doctor:
                Diagnostics.printDoctor()
            case .version:
                print("\(AppIdentity.executableName) \(AppIdentity.version)")
            case .setup(let profileSourcePath):
                try Setup.installSudoers(profileSourcePath: profileSourcePath)
            case .uninstall(let purge):
                try Setup.uninstall(purge: purge)
            case .installShellIntegration(let preferredShellPath, let legacySourcePaths):
                let updatedRCFile = try ShellIntegration.install(preferredShellPath: preferredShellPath,
                                                                legacySourcePaths: legacySourcePaths)
                print("Installed cwru-ovpn shell shortcuts in \(updatedRCFile.path).")
#if CWRU_OVPN_INCLUDE_SELF_TEST
            case .selfTest:
                try SelfTest.run()
#endif
            case .cleanupWatchdog(let parentPID, let parentStartTime):
                CleanupWatchdog.run(parentPID: parentPID, parentStartTime: parentStartTime)
            case .help:
                CLI.printHelp()
            }
        } catch {
            fputs(renderUserFacingError(error), stderr)
            exit(1)
        }
    }
}
