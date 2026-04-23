import Foundation

enum CLICommand {
    case connect(configFilePath: String?,
                 verbosityOverride: AppVerbosity?,
                 tunnelModeOverride: AppTunnelMode?,
                 allowSleep: Bool,
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
    case installShellIntegration(preferredShellPath: String?, legacySourcePaths: [String])
#if CWRU_OVPN_INCLUDE_SELF_TEST
    case selfTest
#endif
    case cleanupWatchdog(parentPID: Int32, parentStartTime: ProcessStartTime?)
    case help
}

enum CLIError: LocalizedError {
    case missingConfigFile
    case missingConfig
    case missingValue(String)
    case unexpectedArgument(String)
    case invalidVerbosity(String)
    case invalidTunnelMode(String)
    case invalidPID(String)

    var errorDescription: String? {
        switch self {
        case .missingConfigFile:
            return "No config file was found. Create ~/.cwru-ovpn/config.json or pass --config PATH."
        case .missingConfig:
            return "No VPN profile path is configured. Set `profilePath` in the config file."
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
                case "--force", "-f":
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
                    let nextIndex = index + 1
                    guard nextIndex < arguments.count else {
                        throw CLIError.missingValue(argument)
                    }
                    guard let parsedTailCount = Int(arguments[nextIndex]), parsedTailCount > 0 else {
                        throw CLIError.unexpectedArgument(arguments[nextIndex])
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

#if CWRU_OVPN_INCLUDE_SELF_TEST
        if command == "self-test" {
            if index < arguments.count {
                throw CLIError.unexpectedArgument(arguments[index])
            }
            return .selfTest
        }
#endif

        if command == "setup" {
            var profileSourcePath: String?
            while index < arguments.count {
                let argument = arguments[index]
                switch argument {
                case "--profile":
                    let nextIndex = index + 1
                    guard nextIndex < arguments.count else {
                        throw CLIError.missingValue(argument)
                    }
                    profileSourcePath = arguments[nextIndex]
                    index += 2
                default:
                    throw CLIError.unexpectedArgument(argument)
                }
            }
            return .setup(profileSourcePath: profileSourcePath)
        }

        if command == "install-shell-integration" {
            var preferredShellPath: String?
            var legacySourcePaths: [String] = []

            while index < arguments.count {
                let argument = arguments[index]
                switch argument {
                case "--shell":
                    let nextIndex = index + 1
                    guard nextIndex < arguments.count else {
                        throw CLIError.missingValue(argument)
                    }
                    preferredShellPath = arguments[nextIndex]
                    index += 2
                case "--legacy-source":
                    let nextIndex = index + 1
                    guard nextIndex < arguments.count else {
                        throw CLIError.missingValue(argument)
                    }
                    legacySourcePaths.append(arguments[nextIndex])
                    index += 2
                default:
                    throw CLIError.unexpectedArgument(argument)
                }
            }

            return .installShellIntegration(preferredShellPath: preferredShellPath,
                                            legacySourcePaths: legacySourcePaths)
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
                    let nextIndex = index + 1
                    guard nextIndex < arguments.count else {
                        throw CLIError.missingValue(argument)
                    }
                    guard let parsed = Int32(arguments[nextIndex]),
                          parsed > 1 else {
                        throw CLIError.invalidPID(arguments[nextIndex])
                    }
                    parentPID = parsed
                    index += 2
                case "--parent-start-seconds":
                    let nextIndex = index + 1
                    guard nextIndex < arguments.count else {
                        throw CLIError.missingValue(argument)
                    }
                    guard let parsed = UInt64(arguments[nextIndex]) else {
                        throw CLIError.unexpectedArgument(arguments[nextIndex])
                    }
                    parentStartSeconds = parsed
                    index += 2
                case "--parent-start-microseconds":
                    let nextIndex = index + 1
                    guard nextIndex < arguments.count else {
                        throw CLIError.missingValue(argument)
                    }
                    guard let parsed = UInt64(arguments[nextIndex]) else {
                        throw CLIError.unexpectedArgument(arguments[nextIndex])
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
            let parentStartTime: ProcessStartTime?
            switch (parentStartSeconds, parentStartMicroseconds) {
            case (nil, nil):
                parentStartTime = nil
            case let (seconds?, microseconds?):
                parentStartTime = ProcessStartTime(seconds: seconds, microseconds: microseconds)
            default:
                throw CLIError.missingValue(parentStartSeconds == nil ? "--parent-start-seconds" : "--parent-start-microseconds")
            }
            return .cleanupWatchdog(parentPID: parentPID, parentStartTime: parentStartTime)
        }

        if command != "connect" {
            throw CLIError.unexpectedArgument(command)
        }

        var configFilePath: String?
        var verbosityOverride: AppVerbosity?
        var tunnelModeOverride: AppTunnelMode?
        var allowSleep = false
        var foregroundRequested = false
        var backgroundChild = false
        var startupStatusFilePath: String?
        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "--config":
                let nextIndex = index + 1
                guard nextIndex < arguments.count else {
                    throw CLIError.missingValue(argument)
                }
                configFilePath = arguments[nextIndex]
                index += 2
            case "--verbosity":
                let nextIndex = index + 1
                guard nextIndex < arguments.count else {
                    throw CLIError.missingValue(argument)
                }
                guard let parsed = AppVerbosity(rawValue: arguments[nextIndex]) else {
                    throw CLIError.invalidVerbosity(arguments[nextIndex])
                }
                verbosityOverride = parsed
                index += 2
            case "--mode", "--tunnel-mode":
                let nextIndex = index + 1
                guard nextIndex < arguments.count else {
                    throw CLIError.missingValue(argument)
                }
                guard let parsed = AppTunnelMode(rawValue: arguments[nextIndex]) else {
                    throw CLIError.invalidTunnelMode(arguments[nextIndex])
                }
                tunnelModeOverride = parsed
                index += 2
            case "--foreground":
                foregroundRequested = true
                index += 1
            case "--allow-sleep":
                allowSleep = true
                index += 1
            case "--background-child":
                backgroundChild = true
                index += 1
            case "--startup-status-file":
                let nextIndex = index + 1
                guard nextIndex < arguments.count else {
                    throw CLIError.missingValue(argument)
                }
                startupStatusFilePath = arguments[nextIndex]
                index += 2
            default:
                throw CLIError.unexpectedArgument(argument)
            }
        }

        return .connect(configFilePath: configFilePath,
                        verbosityOverride: verbosityOverride,
                        tunnelModeOverride: tunnelModeOverride,
                        allowSleep: allowSleep,
                        foregroundRequested: foregroundRequested,
                        backgroundChild: backgroundChild,
                        startupStatusFilePath: startupStatusFilePath)
    }

    static func printHelp() {
        var commandLines = [
            "  connect      Connect in the mode configured in the config file",
            "  disconnect   Disconnect the current session (use --force to drop stuck state)",
            "  status       Show the current connection status",
            "  logs         Show recent event log entries",
            "  doctor       Show diagnostic information for troubleshooting",
            "  setup        Install sudoers rules for passwordless operation",
            "  uninstall    Remove the sudoers rule, shell shortcuts, and scoped DNS resolver files",
            "  version      Print the version number",
        ]
    #if CWRU_OVPN_INCLUDE_SELF_TEST
        commandLines.append("  self-test    Run built-in smoke tests")
    #endif
        commandLines.append("  help         Show this help message")

        print("""
        Usage: \(AppIdentity.executableName) <command> [options]

        Commands:
        \(commandLines.joined(separator: "\n"))

        Connect options:
          --config PATH        Path to the config JSON file
          --verbosity LEVEL    Logging level: silent, daily, debug (default: daily)
          --mode MODE          Tunnel mode: full or split (default from config)
          --allow-sleep        Allow idle sleep for this run
          --foreground         Keep the controller attached to the terminal

        Setup options:
          --profile PATH       Copy a .ovpn profile to ~/.cwru-ovpn/profile.ovpn before installing sudoers

        Uninstall options:
          --purge              Also remove ~/.cwru-ovpn after uninstalling shell integration

        Logs options:
          --tail COUNT         Show the last COUNT log entries (default: 40)

        Shell functions (after setup):
          ovpn         Connect using the default mode from config
          ovpnfull     Connect in full-tunnel mode
          ovpnsplit    Connect in split-tunnel mode
          ovpnd        Disconnect the current session
          ovpnstatus   Show the current status

        Internal helper commands (not for interactive use):
          install-shell-integration   Update the managed shell block (used by setup.sh)
          cleanup-watchdog            Restore routes and DNS after controller exit
        """)
    }
}
