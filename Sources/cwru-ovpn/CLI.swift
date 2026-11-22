import Darwin
import Foundation

enum CLICommand {
    case connect(configFilePath: String?,
                 verbosityOverride: AppVerbosity?,
                 tunnelModeOverride: AppTunnelMode?,
                 foregroundRequested: Bool,
                 backgroundChild: Bool)
    case disconnect(force: Bool)
    case status
    case logs(tailCount: Int)
    case doctor
    case version
    case userInterface
    case verifyBundle(String)
    case setup(profileSourcePath: String?)
    case uninstall(purge: Bool)
    case installShellIntegration(preferredShellPath: String?)
    case cleanupWatchdog(parentPID: Int32, parentStartTime: ProcessStartTime)
    case showAlert(message: String)
    case help
}

enum CLIError: LocalizedError {
    case requiresRoot(String)
    case missingProfile
    case missingValue(String)
    case unexpectedArgument(String)
    case invalidVerbosity(String)
    case invalidTunnelMode(String)
    case invalidPID(String)
    case invalidTailCount(String)

    var errorDescription: String? {
        switch self {
        case .requiresRoot(let command):
            return "Run \(command) with sudo."
        case .missingProfile:
            return "No VPN profile was found at ~/.cwru-ovpn/profile.ovpn. Install one with setup --profile PATH."
        case .missingValue(let argument):
            return "Missing value for \(argument)."
        case .unexpectedArgument(let argument):
            return "Unexpected argument: \(argument)"
        case .invalidVerbosity(let value):
            return "Invalid verbosity '\(value)'. Use silent, daily, or debug."
        case .invalidTunnelMode(let value):
            return "Invalid tunnel mode '\(value)'. Use split or full."
        case .invalidPID(let value):
            return "Invalid PID '\(value)'."
        case .invalidTailCount(let value):
            return "Invalid tail count '\(value)'. Use a positive integer."
        }
    }
}

private struct OptionScanner {
    private let arguments: [String]
    private var index = 1

    init(_ arguments: [String]) {
        self.arguments = arguments
    }

    mutating func next() -> String? {
        guard index < arguments.count else {
            return nil
        }
        defer { index += 1 }
        return arguments[index]
    }

    mutating func value(for option: String) throws -> String {
        guard let value = next(), !value.hasPrefix("--") else {
            throw CLIError.missingValue(option)
        }
        return value
    }

    mutating func requireEmpty() throws {
        if let extra = next() {
            throw CLIError.unexpectedArgument(extra)
        }
    }

    mutating func flag(_ name: String) throws -> Bool {
        var present = false
        while let option = next() {
            guard option == name else {
                throw CLIError.unexpectedArgument(option)
            }
            present = true
        }
        return present
    }

    mutating func singleValue(for name: String) throws -> String? {
        var value: String?
        while let option = next() {
            guard option == name else {
                throw CLIError.unexpectedArgument(option)
            }
            value = try self.value(for: option)
        }
        return value
    }
}

enum CLI {
    static func parse(arguments: [String]) throws -> CLICommand {
        guard let command = arguments.first else {
            return .help
        }
        var options = OptionScanner(arguments)

        switch command {
        case "help", "--help", "-h":
            try options.requireEmpty()
            return .help
        case "status":
            try options.requireEmpty()
            return .status
        case "doctor":
            try options.requireEmpty()
            return .doctor
        case "ui-agent":
            try options.requireEmpty()
            return .userInterface
        case "verify-bundle":
            let path = try options.value(for: command)
            try options.requireEmpty()
            return .verifyBundle(path)
        case "version", "--version":
            try options.requireEmpty()
            return .version
        case "disconnect":
            return .disconnect(force: try options.flag("--force"))
        case "uninstall":
            return .uninstall(purge: try options.flag("--purge"))
        case "setup":
            return .setup(profileSourcePath: try options.singleValue(for: "--profile"))
        case "install-shell-integration":
            return .installShellIntegration(preferredShellPath: try options.singleValue(for: "--shell"))
        case "show-alert":
            guard let message = try options.singleValue(for: "--message") else {
                throw CLIError.missingValue("--message")
            }
            return .showAlert(message: message)
        case "logs":
            var tailCount = 40
            while let option = options.next() {
                guard option == "--tail" else {
                    throw CLIError.unexpectedArgument(option)
                }
                let value = try options.value(for: option)
                guard let parsed = Int(value), parsed > 0 else {
                    throw CLIError.invalidTailCount(value)
                }
                tailCount = parsed
            }
            return .logs(tailCount: tailCount)
        case "cleanup-watchdog":
            var parentPID: Int32?
            var seconds: UInt64?
            var microseconds: UInt64?
            while let option = options.next() {
                switch option {
                case "--parent-pid":
                    let value = try options.value(for: option)
                    guard let parsed = Int32(value), parsed > 1 else {
                        throw CLIError.invalidPID(value)
                    }
                    parentPID = parsed
                case "--parent-start-seconds":
                    seconds = try Self.unsigned(try options.value(for: option))
                case "--parent-start-microseconds":
                    microseconds = try Self.unsigned(try options.value(for: option))
                default:
                    throw CLIError.unexpectedArgument(option)
                }
            }
            guard let parentPID else {
                throw CLIError.missingValue("--parent-pid")
            }
            guard let seconds else {
                throw CLIError.missingValue("--parent-start-seconds")
            }
            guard let microseconds else {
                throw CLIError.missingValue("--parent-start-microseconds")
            }
            return .cleanupWatchdog(parentPID: parentPID,
                                    parentStartTime: ProcessStartTime(seconds: seconds, microseconds: microseconds))
        case "connect":
            var configFilePath: String?
            var verbosityOverride: AppVerbosity?
            var tunnelModeOverride: AppTunnelMode?
            var foregroundRequested = false
            var backgroundChild = false
            while let option = options.next() {
                switch option {
                case "--config":
                    configFilePath = try options.value(for: option)
                case "--verbosity":
                    let value = try options.value(for: option)
                    guard let parsed = AppVerbosity(rawValue: value) else {
                        throw CLIError.invalidVerbosity(value)
                    }
                    verbosityOverride = parsed
                case "--mode":
                    let value = try options.value(for: option)
                    guard let parsed = AppTunnelMode(rawValue: value) else {
                        throw CLIError.invalidTunnelMode(value)
                    }
                    tunnelModeOverride = parsed
                case "--foreground":
                    foregroundRequested = true
                case "--background-child":
                    backgroundChild = true
                default:
                    throw CLIError.unexpectedArgument(option)
                }
            }
            return .connect(configFilePath: configFilePath,
                            verbosityOverride: verbosityOverride,
                            tunnelModeOverride: tunnelModeOverride,
                            foregroundRequested: foregroundRequested,
                            backgroundChild: backgroundChild)
        default:
            throw CLIError.unexpectedArgument(command)
        }
    }

    private static func unsigned(_ value: String) throws -> UInt64 {
        guard let parsed = UInt64(value) else {
            throw CLIError.unexpectedArgument(value)
        }
        return parsed
    }

    static func printHelp() {
        print("""
        Usage: \(AppIdentity.executableName) COMMAND [OPTIONS]

        Commands:
          connect [OPTIONS]       Connect to the VPN.
            --mode MODE           Use full or split tunnel mode.
            --config PATH         Use the JSON configuration at PATH.
            --verbosity LEVEL     Set output to silent, daily (default), or debug.
            --foreground          Run the VPN session in the foreground.
          disconnect [--force]    Disconnect the active VPN session. During stale-session
                                  cleanup, --force can renew DHCP.
          status                  Show current tunnel, route, and DNS status.
          logs [--tail COUNT]     Show the last COUNT log lines, defaulting to 40.
          doctor                  Inspect the installation, routes, and DNS.
          setup [--profile PATH]  Run with sudo to install cwru-ovpn or approve an
                                  autologin .ovpn profile at PATH.
          uninstall [--purge]     Remove the installed app and shell shortcuts. Pass
                                  --purge to also remove ~/.cwru-ovpn.
          version                 Print the program version.
          help                    Show this help message.

        Shortcuts:
          ovpn, ovpnfull, ovpnsplit   Connect using default, full, or split mode.
          ovpnstatus                  Show current VPN connection status.
          ovpnd                       Disconnect the active VPN session.
        """)
    }
}
