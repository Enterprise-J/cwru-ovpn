import AppKit
import Darwin
import Foundation

#if !arch(arm64)
#error("cwru-ovpn requires Apple Silicon.")
#endif

@MainActor
private enum RuntimeState {
    static var controller: VPNController?
}

enum DetachedConnectLauncher {
    private static let launchDeadlineSeconds: TimeInterval = 90

    static func launch(configFilePath: String?,
                       verbosityOverride: AppVerbosity?,
                       tunnelModeOverride: AppTunnelMode?,
                       tunnelMode: AppTunnelMode) throws {
        let executablePath = try ExecutionIdentity.currentExecutablePath()
        let statusChannel = try makeStartupStatusChannel()

        print("Starting VPN in \(tunnelMode.modeDescription) mode.")
        let effectiveVerbosity = verbosityOverride ?? .daily
        if effectiveVerbosity == .debug {
            print("Event log: \(RuntimePaths.eventLogFile.path)")
        }

        let process = try ChildProcess.launch(arguments: childArguments(configFilePath: configFilePath,
                                                                        tunnelModeOverride: tunnelModeOverride),
                                              standardOutput: statusChannel)
        let childPID = Int32(process.processIdentifier)
        guard let childStartTime = captureChildStartTime(childPID) else {
            process.signal(SIGTERM)
            for _ in 0..<100 where process.isRunning {
                usleep(100_000)
            }
            if process.isRunning {
                process.signal(SIGKILL)
            }
            process.waitUntilExit()
            let detail = DetachedStartupStatus.load(from: statusChannel)?.message
                ?? "Could not establish the background VPN controller process identity."
            throw VPNControllerError.operationFailed(detail)
        }
        try waitForConnection(childPID: childPID,
                              expectedExecutablePath: executablePath,
                              expectedStartTime: childStartTime,
                              statusChannel: statusChannel)
    }

    private static func makeStartupStatusChannel() throws -> FileHandle {
        try RuntimePaths.withPrivilegedStateDirectoryAnchor { _, _, _ in }
        var template = Array(RuntimePaths.privilegedStateDirectory.appendingPathComponent("startup-status.XXXXXX").path.utf8CString)
        let descriptor = template.withUnsafeMutableBufferPointer { mkstemp($0.baseAddress!) }
        guard descriptor >= 0 else {
            throw FileIO.failure("Failed to create the startup status channel", errno)
        }
        _ = template.withUnsafeBufferPointer { unlink($0.baseAddress!) }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    private static func captureChildStartTime(_ childPID: Int32) -> ProcessStartTime? {
        for attempt in 0..<10 {
            if let startTime = processStartTime(childPID) {
                return startTime
            }
            guard processExists(childPID), attempt < 9 else {
                return nil
            }
            usleep(10_000)
        }
        return nil
    }

    private static func childArguments(configFilePath: String?,
                                       tunnelModeOverride: AppTunnelMode?) -> [String] {
        var arguments = ["connect"]
        if let configFilePath {
            arguments += ["--config", URL(fileURLWithPath: AppConfig.expandUserPath(configFilePath)).standardized.path]
        }
        if let tunnelModeOverride {
            arguments += ["--mode", tunnelModeOverride.rawValue]
        }
        arguments.append("--background-child")
        return arguments
    }

    static func waitForConnection(childPID: Int32,
                                  expectedExecutablePath: String,
                                  expectedStartTime: ProcessStartTime,
                                  statusChannel: FileHandle,
                                  sessionStore: StateDirectory = StateDirectory()) throws {
        var announcedAuth = false
        var deadline = ContinuousClock.now + .seconds(launchDeadlineSeconds)
        let monitor = BlockingEventMonitor(directoryURLs: [sessionStore.url], processIDs: [childPID])

        while true {
            if let session = SessionState.load(from: sessionStore),
               session.pid == childPID,
               session.executablePath == expectedExecutablePath,
               session.processStartTime == expectedStartTime {
                switch session.phase {
                case .authPending:
                    if !announcedAuth {
                        print("Opening sign-in window.")
                        announcedAuth = true
                        deadline = authenticationWaitDeadline(from: .now)
                    }
                case .connected:
                    if processMatchesExecutable(childPID,
                                                expectedExecutablePath: expectedExecutablePath,
                                                expectedStartTime: expectedStartTime) {
                        print("Connected.")
                        return
                    }
                case .failed:
                    let detail = session.diagnosticDetail ?? "The VPN session failed before connecting."
                    throw VPNControllerError.operationFailed(detail)
                case .disconnected:
                    let detail = session.diagnosticDetail ?? "The VPN session ended before connecting."
                    throw VPNControllerError.operationFailed(detail)
                case .connecting, .disconnecting:
                    break
                }
            }

            if let startupStatus = DetachedStartupStatus.load(from: statusChannel) {
                throw VPNControllerError.operationFailed(startupStatus.message)
            }

            let childStillRunning =
                processMatchesExecutable(childPID,
                                         expectedExecutablePath: expectedExecutablePath,
                                         expectedStartTime: expectedStartTime)
            if !childStillRunning {
                let startupDetail = DetachedStartupStatus.load(from: statusChannel)?.message
                throw VPNControllerError.operationFailed(
                    startupDetail ?? "The background VPN controller exited before reporting a connected session."
                )
            }

            if ContinuousClock.now >= deadline {
                terminateChildIfStillLaunching(childPID: childPID,
                                               expectedExecutablePath: expectedExecutablePath,
                                               expectedStartTime: expectedStartTime)
                throw VPNControllerError.operationFailed(
                    "Timed out while waiting for the background VPN controller to report startup status."
                )
            }

            _ = monitor.wait(until: .now() + .milliseconds(500))
        }
    }

    static func authenticationWaitDeadline(from instant: ContinuousClock.Instant) -> ContinuousClock.Instant {
        instant + .seconds(WebAuthRecovery.maximumWaitSeconds + 2 * launchDeadlineSeconds)
    }

    private static func terminateChildIfStillLaunching(childPID: Int32,
                                                       expectedExecutablePath: String,
                                                       expectedStartTime: ProcessStartTime) {
        func childStillMatches() -> Bool {
            processMatchesExecutable(childPID,
                                     expectedExecutablePath: expectedExecutablePath,
                                     expectedStartTime: expectedStartTime)
        }

        guard childStillMatches() else {
            return
        }
        _ = kill(childPID, SIGTERM)
        for _ in 0..<20 {
            guard childStillMatches() else {
                return
            }
            usleep(100_000)
        }
        if childStillMatches() {
            _ = kill(childPID, SIGKILL)
        }
    }
}

@main
enum CWRUOVPNMain {
    @MainActor
    static func replaceController(intent: PrivilegedConnectIntent, mode: DaemonExecutionMode, lock: ControllerLock, previous: SessionState) throws {
        let next = try VPNController(intent: intent, executionMode: mode, inheritedLock: lock)
        try next.start(replacing: previous)
        RuntimeState.controller = next
    }

    static func main() {
        do {
            if ExecutionIdentity.isPrivileged { setenv("HOME", "/var/empty", 1) }
            switch try CLI.parse(arguments: Array(CommandLine.arguments.dropFirst())) {
            case .connect(let configFilePath,
                          let verbosityOverride,
                          let tunnelModeOverride,
                          let foregroundRequested,
                          let backgroundChild):
                try requireRoot(for: "connect")
                do {
                    if !backgroundChild {
                        let configuration = try AppConfig.load(explicitConfigPath: configFilePath)
                        let tunnelMode = tunnelModeOverride ?? configuration.tunnelMode
                        if try SessionControl.handleConnectRequestForActiveSession(targetMode: tunnelMode,
                                                                                   configFilePath: configFilePath) {
                            break
                        }
                        if !foregroundRequested {
                            try DetachedConnectLauncher.launch(configFilePath: configFilePath,
                                                               verbosityOverride: verbosityOverride,
                                                               tunnelModeOverride: tunnelModeOverride,
                                                               tunnelMode: tunnelMode)
                            break
                        }
                    }
                    let intent = try PrivilegedConnectIntent.resolve(configFilePath: configFilePath,
                                                                     verbosityOverride: verbosityOverride,
                                                                     tunnelModeOverride: tunnelModeOverride)
                    let controller = try VPNController(intent: intent, executionMode: backgroundChild ? .detached(reportsStartupStatus: true) : .foreground)
                    RuntimeState.controller = controller
                    try controller.start()
                    CFRunLoopRun()
                } catch {
                    if backgroundChild {
                        DetachedStartupStatus.report(error.localizedDescription)
                    }
                    throw error
                }
            case .disconnect(let force):
                try requireRoot(for: "disconnect")
                try SessionControl.disconnectExistingSession(force: force)
            case .status:
                SessionControl.printStatus()
            case .logs(let tailCount):
                try Diagnostics.printLogs(tailCount: tailCount)
            case .doctor:
                Diagnostics.printDoctor()
            case .userInterface:
                try ChildProcess.enterUserInterface()
                try UserInterfaceAgent.run()
            case .verifyBundle(let path):
                try AppIdentity.verifyApplication(at: URL(fileURLWithPath: path, isDirectory: true))
            case .version:
                print("\(AppIdentity.executableName) \(AppIdentity.version)")
            case .setup(let profileSourcePath):
                try requireRoot(for: "setup")
                try Setup.install(profileSourcePath: profileSourcePath)
            case .uninstall(let purge):
                try requireRoot(for: "uninstall")
                try Setup.uninstall(purge: purge)
            case .installShellIntegration(let preferredShellPath):
                let updatedRCFile = try ShellIntegration.install(preferredShellPath: preferredShellPath)
                print("Installed cwru-ovpn shell shortcuts in \(updatedRCFile.path).")
            case .cleanupWatchdog(let parentPID, let parentStartTime):
                try requireRoot(for: "cleanup-watchdog")
                CleanupWatchdog.run(parentPID: parentPID, parentStartTime: parentStartTime)
            case .showAlert(let message):
                try ChildProcess.enterUserInterface()
                UserAlert.showInCurrentProcess(message)
            case .help:
                CLI.printHelp()
            }
        } catch {
            fputs("\(redactSensitiveText(error.localizedDescription))\n", stderr)
            exit(1)
        }
    }

    private static func requireRoot(for command: String) throws {
        guard ExecutionIdentity.isPrivileged else {
            throw CLIError.requiresRoot(command)
        }
    }
}
