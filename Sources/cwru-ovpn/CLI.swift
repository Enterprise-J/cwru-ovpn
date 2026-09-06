import Darwin
import Foundation

enum CLICommand {
    case connect(configFilePath: String?,
                 verbosityOverride: AppVerbosity?,
                 tunnelModeOverride: AppTunnelMode?,
                 foregroundRequested: Bool,
                 backgroundChild: Bool,
                 startupStatusFilePath: String?)
    case disconnect(force: Bool)
    case status
    case logs(tailCount: Int)
    case doctor
    case version
    case setup(profileSourcePath: String?)
    case uninstall(purge: Bool)
    case installShellIntegration(preferredShellPath: String?)
    case cleanupWatchdog(parentPID: Int32, parentStartTime: ProcessStartTime)
    case help
}

enum CLIError: LocalizedError {
    case missingProfile
    case missingValue(String)
    case unexpectedArgument(String)
    case invalidVerbosity(String)
    case invalidTunnelMode(String)
    case invalidPID(String)
    case invalidTailCount(String)

    var errorDescription: String? {
        switch self {
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

enum CLI {
    static func parse(arguments: [String]) throws -> CLICommand {
        guard let command = arguments.first else {
            return .help
        }
        var index = 1

        if command == "help" || command == "--help" || command == "-h" {
            if index < arguments.count {
                throw CLIError.unexpectedArgument(arguments[index])
            }
            return .help
        }

        if command == "disconnect" {
            var force = false
            while index < arguments.count {
                let argument = arguments[index]
                switch argument {
                case "--force":
                    force = true
                    index += 1
                default:
                    throw CLIError.unexpectedArgument(argument)
                }
            }
            return .disconnect(force: force)
        }

        if command == "status" {
            if index < arguments.count {
                throw CLIError.unexpectedArgument(arguments[index])
            }
            return .status
        }

        if command == "logs" {
            var tailCount = 40
            while index < arguments.count {
                let argument = arguments[index]
                switch argument {
                case "--tail":
                    let value = try requiredValue(after: argument, at: index, in: arguments)
                    guard let parsedTailCount = Int(value), parsedTailCount > 0 else {
                        throw CLIError.invalidTailCount(value)
                    }
                    tailCount = parsedTailCount
                    index += 2
                default:
                    throw CLIError.unexpectedArgument(argument)
                }
            }
            return .logs(tailCount: tailCount)
        }

        if command == "doctor" {
            if index < arguments.count {
                throw CLIError.unexpectedArgument(arguments[index])
            }
            return .doctor
        }

        if command == "version" || command == "--version" {
            if index < arguments.count {
                throw CLIError.unexpectedArgument(arguments[index])
            }
            return .version
        }

        if command == "setup" {
            var profileSourcePath: String?
            while index < arguments.count {
                let argument = arguments[index]
                switch argument {
                case "--profile":
                    profileSourcePath = try requiredValue(after: argument, at: index, in: arguments)
                    index += 2
                default:
                    throw CLIError.unexpectedArgument(argument)
                }
            }
            return .setup(profileSourcePath: profileSourcePath)
        }

        if command == "install-shell-integration" {
            var preferredShellPath: String?

            while index < arguments.count {
                let argument = arguments[index]
                switch argument {
                case "--shell":
                    preferredShellPath = try requiredValue(after: argument, at: index, in: arguments)
                    index += 2
                default:
                    throw CLIError.unexpectedArgument(argument)
                }
            }

            return .installShellIntegration(preferredShellPath: preferredShellPath)
        }

        if command == "uninstall" {
            var purge = false
            while index < arguments.count {
                let argument = arguments[index]
                switch argument {
                case "--purge":
                    purge = true
                    index += 1
                default:
                    throw CLIError.unexpectedArgument(argument)
                }
            }
            return .uninstall(purge: purge)
        }

        if command == "cleanup-watchdog" {
            var parentPID: Int32?
            var parentStartSeconds: UInt64?
            var parentStartMicroseconds: UInt64?
            while index < arguments.count {
                let argument = arguments[index]
                switch argument {
                case "--parent-pid":
                    let value = try requiredValue(after: argument, at: index, in: arguments)
                    guard let parsed = Int32(value),
                          parsed > 1 else {
                        throw CLIError.invalidPID(value)
                    }
                    parentPID = parsed
                    index += 2
                case "--parent-start-seconds":
                    let value = try requiredValue(after: argument, at: index, in: arguments)
                    guard let parsed = UInt64(value) else {
                        throw CLIError.unexpectedArgument(value)
                    }
                    parentStartSeconds = parsed
                    index += 2
                case "--parent-start-microseconds":
                    let value = try requiredValue(after: argument, at: index, in: arguments)
                    guard let parsed = UInt64(value) else {
                        throw CLIError.unexpectedArgument(value)
                    }
                    parentStartMicroseconds = parsed
                    index += 2
                default:
                    throw CLIError.unexpectedArgument(argument)
                }
            }
            guard let parentPID else {
                throw CLIError.missingValue("--parent-pid")
            }
            switch (parentStartSeconds, parentStartMicroseconds) {
            case let (seconds?, microseconds?):
                return .cleanupWatchdog(
                    parentPID: parentPID,
                    parentStartTime: ProcessStartTime(seconds: seconds, microseconds: microseconds)
                )
            default:
                throw CLIError.missingValue(parentStartSeconds == nil ? "--parent-start-seconds" : "--parent-start-microseconds")
            }
        }

        if command != "connect" {
            throw CLIError.unexpectedArgument(command)
        }

        var configFilePath: String?
        var verbosityOverride: AppVerbosity?
        var tunnelModeOverride: AppTunnelMode?
        var foregroundRequested = false
        var backgroundChild = false
        var startupStatusFilePath: String?
        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--config":
                configFilePath = try requiredValue(after: argument, at: index, in: arguments)
                index += 2
            case "--verbosity":
                let value = try requiredValue(after: argument, at: index, in: arguments)
                guard let parsed = AppVerbosity(rawValue: value) else {
                    throw CLIError.invalidVerbosity(value)
                }
                verbosityOverride = parsed
                index += 2
            case "--mode":
                let value = try requiredValue(after: argument, at: index, in: arguments)
                guard let parsed = AppTunnelMode(rawValue: value) else {
                    throw CLIError.invalidTunnelMode(value)
                }
                tunnelModeOverride = parsed
                index += 2
            case "--foreground":
                foregroundRequested = true
                index += 1
            case "--background-child":
                backgroundChild = true
                index += 1
            case "--startup-status-file":
                startupStatusFilePath = try requiredValue(after: argument, at: index, in: arguments)
                index += 2
            default:
                throw CLIError.unexpectedArgument(argument)
            }
        }

        return .connect(configFilePath: configFilePath,
                        verbosityOverride: verbosityOverride,
                        tunnelModeOverride: tunnelModeOverride,
                        foregroundRequested: foregroundRequested,
                        backgroundChild: backgroundChild,
                        startupStatusFilePath: startupStatusFilePath)
    }

    private static func requiredValue(after argument: String,
                                      at index: Int,
                                      in arguments: [String]) throws -> String {
        let valueIndex = index + 1
        guard valueIndex < arguments.count else {
            throw CLIError.missingValue(argument)
        }
        return arguments[valueIndex]
    }

    static func printHelp() {
        print("""
        Usage: \(AppIdentity.executableName) <command> [options]

        Commands:
          connect      Connect using the approved profile and configured or selected tunnel mode
          disconnect   Disconnect the current session (use --force to drop stuck state)
          status       Show the current connection status
          logs         Show recent event log entries
          doctor       Show diagnostic information for troubleshooting
          setup        Install the privileged binary and sudoers rules
          uninstall    Remove the privileged binary, sudoers rule, shell shortcuts, and scoped DNS resolver files
          version      Print the version number
          help         Show this help message

        Connect options:
          --config PATH        Path to the config JSON file
          --verbosity LEVEL    Logging level: silent, daily, debug (default: daily)
          --mode MODE          Tunnel mode: full or split
          --foreground         Keep the controller attached to the terminal

        Setup options:
          --profile PATH       Copy a .ovpn profile to ~/.cwru-ovpn/profile.ovpn before installing sudoers

        Uninstall options:
          Run this command with sudo so it can verify the privileged session lock
          --purge              Also remove ~/.cwru-ovpn after uninstalling shell integration

        Logs options:
          --tail COUNT         Show the last COUNT log entries (default: 40)

        Shell functions (after setup):
          ovpn         Connect using the configured or default tunnel mode
          ovpnfull     Connect or switch to full-tunnel mode
          ovpnsplit    Connect or switch to split-tunnel mode
          ovpnd        Disconnect the current session
          ovpnstatus   Show the current status

        Internal helper commands (not for interactive use):
          install-shell-integration   Update the managed shell block (used by setup.sh)
          cleanup-watchdog            Restore routes and DNS after controller exit
        """)
    }
}
