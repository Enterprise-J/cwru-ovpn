import Foundation

enum SetupError: LocalizedError {
    case missingProfileSource(String)
    case unsafePath(String)
    case validationFailed(String)

    var errorDescription: String? {
        switch self {
        case .missingProfileSource(let path):
            return "No OpenVPN profile was found at \(path)."
        case .unsafePath(let message):
            return message
        case .validationFailed(let message):
            return "Generated sudoers rules failed validation.\n\(message)"
        }
    }
}

enum Setup {
    static func installSudoers(profileSourcePath: String?) throws {
        let executablePath = URL(fileURLWithPath: CommandLine.arguments[0])
            .resolvingSymlinksInPath()
            .standardized.path
        let environment = ProcessInfo.processInfo.environment
        let username = environment["SUDO_USER"].flatMap { $0.isEmpty ? nil : $0 } ?? NSUserName()

        try assertSafeForSudoersUser(username)

        // Sudoers does not support quoted paths or standard shell escaping.
        // Reject paths with characters that would break the rule syntax.
        try assertSafeForSudoers(path: executablePath, label: "Executable path")

        try ensureHomeStateDirectory()
        if let profileSourcePath {
            let installedProfileURL = try installProfile(from: profileSourcePath)
            print("Copied VPN profile to \(installedProfileURL.path).")
        } else if !FileManager.default.fileExists(atPath: RuntimePaths.homeProfileFile.path) {
            print("No VPN profile was copied. Place one at \(RuntimePaths.homeProfileFile.path) or rerun setup --profile /path/to/profile.ovpn.")
        }

        let sudoersBody = renderSudoers(username: username,
                                        executablePath: executablePath)

        let tempURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("cwru-ovpn.sudoers.\(UUID().uuidString)")
        try sudoersBody.appending("\n").write(to: tempURL, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let validation = try validateSudoersFile(at: tempURL.path)
        guard validation.exitCode == 0 else {
            throw SetupError.validationFailed(validation.stderr.isEmpty ? validation.stdout : validation.stderr)
        }

        _ = try Shell.run("/bin/mkdir",
                          arguments: ["-p", "/etc/sudoers.d"],
                          requirePrivileges: true)
        _ = try Shell.run("/bin/cp",
                          arguments: [tempURL.path, "/etc/sudoers.d/cwru-ovpn"],
                          requirePrivileges: true)
        _ = try Shell.run("/bin/chmod",
                          arguments: ["440", "/etc/sudoers.d/cwru-ovpn"],
                          requirePrivileges: true)

        print("Installed the sudoers rule at /etc/sudoers.d/cwru-ovpn.")
        print("Passwordless commands now cover the standard cwru-ovpn connect invocations, plus disconnect, status, and plain setup.")
        print("cwru-ovpn connect supports the existing approved options: --mode full|split, --verbosity debug, --foreground, and --allow-sleep.")
    }

    static func uninstall(purge: Bool) throws {
        let sudoersPath = "/etc/sudoers.d/cwru-ovpn"
        if FileManager.default.fileExists(atPath: sudoersPath) {
            _ = try Shell.run("/bin/rm", arguments: [sudoersPath], requirePrivileges: true)
            print("Removed sudoers rule at \(sudoersPath).")
        } else {
            print("No sudoers rule found at \(sudoersPath) — nothing to remove.")
        }

        if let config = try? AppConfig.load(explicitConfigPath: nil) {
            for domain in config.splitTunnel.effectiveResolverDomains {
                let resolverPath = ResolverPaths.fileURL(for: domain).path
                if FileManager.default.fileExists(atPath: resolverPath) {
                    _ = try Shell.run("/bin/rm", arguments: ["-f", resolverPath], allowNonZero: true, requirePrivileges: true)
                    print("Removed resolver file at \(resolverPath).")
                }
            }
        }

        let updatedRCFiles = try ShellIntegration.remove()
        for rcFile in updatedRCFiles {
            print("Removed cwru-ovpn shell shortcuts from \(rcFile.path).")
        }

        let helperPath = ShellIntegration.installedHelperURL.path
        if FileManager.default.fileExists(atPath: helperPath) {
            try FileManager.default.removeItem(atPath: helperPath)
            print("Removed shell helper at \(helperPath).")
        }

        if purge {
            let stateDirectory = RuntimePaths.homeStateDirectory.path
            if FileManager.default.fileExists(atPath: stateDirectory) {
                try FileManager.default.removeItem(atPath: stateDirectory)
                print("Removed state directory at \(stateDirectory).")
            }
        } else {
            print("Left \(RuntimePaths.homeStateDirectory.path) in place. Re-run uninstall --purge to remove profiles, configs, binaries, and logs.")
        }
    }

    // MARK: - Helpers

    static func renderSudoers(username: String,
                              executablePath: String) -> String {
        permittedInvocations(executablePath: executablePath)
            .map { "\(username) ALL=(root) NOPASSWD: \($0.joined(separator: " "))" }
            .joined(separator: "\n")
    }

    static func validateSudoersFile(at path: String) throws -> ShellResult {
        try Shell.run("/usr/sbin/visudo",
                      arguments: ["-c", "-f", path],
                      allowNonZero: true)
    }

    private static func permittedInvocations(executablePath: String) -> [[String]] {
        let connectCommands = permittedConnectInvocations(executablePath: executablePath)
        let fixedCommands = [
            [executablePath, "disconnect"],
            [executablePath, "disconnect", "-f"],
            [executablePath, "disconnect", "--force"],
            [executablePath, "status"],
            [executablePath, "setup"],
        ]
        return connectCommands + fixedCommands
    }

    private static func permittedConnectInvocations(executablePath: String) -> [[String]] {
        let base = [executablePath, "connect"]
        let modeVariants: [[String]] = [
            [],
            ["--mode", "full"],
            ["--mode", "split"],
        ]
        let runtimeVariants: [[String]] = [
            [],
            ["--verbosity", "debug"],
            ["--verbosity", "debug", "--foreground"],
        ]
        let sleepVariants: [[String]] = [
            [],
            ["--allow-sleep"],
        ]

        var commands: [[String]] = []
        for mode in modeVariants {
            for runtime in runtimeVariants {
                for sleep in sleepVariants {
                    commands.append(base + mode + runtime + sleep)
                }
            }
        }
        return commands
    }

    private static func ensureHomeStateDirectory() throws {
        try FileManager.default.createDirectory(at: RuntimePaths.homeStateDirectory,
                                                withIntermediateDirectories: true)
        try RuntimePaths.secureDirectory(at: RuntimePaths.homeStateDirectory)
    }

    @discardableResult
    private static func installProfile(from sourcePath: String) throws -> URL {
        let sourceURL = URL(fileURLWithPath: AppConfig.expandUserPath(sourcePath)).standardized
        guard FileManager.default.fileExists(atPath: sourceURL.path) else {
            throw SetupError.missingProfileSource(sourceURL.path)
        }

        let destinationURL = RuntimePaths.homeProfileFile
        if sourceURL.path != destinationURL.path {
            let data = try Data(contentsOf: sourceURL)
            try data.write(to: destinationURL, options: .atomic)
        }
        try RuntimePaths.secureFile(at: destinationURL)
        return destinationURL
    }

    private static let sudoersPathAllowedCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-+")
    private static let sudoersUserAllowedCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")

    private static func assertSafeForSudoersUser(_ username: String) throws {
        guard !username.isEmpty,
              !username.hasPrefix("-"),
              username.unicodeScalars.allSatisfy({ sudoersUserAllowedCharacters.contains($0) }) else {
            throw SetupError.unsafePath(
                "Username contains unsupported characters for sudoers rules: \(username)"
            )
        }
    }

    /// Asserts that a path is safe for literal inclusion in a sudoers rule.
    /// Sudoers has no quoting mechanism for paths; spaces, backslashes, and
    /// comment characters would silently corrupt the rule.
    private static func assertSafeForSudoers(path: String, label: String) throws {
        guard !path.isEmpty, path.hasPrefix("/") else {
            throw SetupError.unsafePath("\(label) must be an absolute path: \(path)")
        }

        if let bad = path.unicodeScalars.first(where: { !sudoersPathAllowedCharacters.contains($0) }) {
            throw SetupError.unsafePath(
                "\(label) contains '\(bad)', which is not allowed in sudoers rules: \(path)"
            )
        }

        if path.contains("..") {
            throw SetupError.unsafePath("\(label) must not contain '..' path segments: \(path)")
        }
    }
}
