import CryptoKit
import Darwin
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
        let targetUser = try ExecutionIdentity.currentUser()
        let sourceExecutablePath = try ExecutionIdentity.currentExecutablePath()

        try ensureHomeStateDirectory()
        if let profileSourcePath {
            let installedProfileURL = try installProfile(from: profileSourcePath)
            print("Copied VPN profile to \(installedProfileURL.path).")
        } else if !FileManager.default.fileExists(atPath: RuntimePaths.homeProfileFile.path) {
            print("No VPN profile was copied. Place one at \(RuntimePaths.homeProfileFile.path) or rerun setup --profile /path/to/profile.ovpn.")
        }

        let installedExecutablePath = try installPrivilegedExecutable(from: sourceExecutablePath)

        try assertSafeForSudoers(path: installedExecutablePath, label: "Executable path")
        let installedExecutableDigest = try executableSHA256(at: installedExecutablePath)

        let sudoersBody = renderSudoers(userID: targetUser.userID,
                                        executablePath: installedExecutablePath,
                                        executableDigest: installedExecutableDigest)

        let tempURL = try RuntimePaths.createTemporaryFile(prefix: "sudoers")
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
        print("Installed the privileged binary at \(installedExecutablePath).")
        print("Passwordless commands now cover connect, connect --mode full|split, those same forms with --verbosity debug, the debug foreground variants, and each of those with trailing --allow-sleep, pinned to the installed binary's SHA-256 digest.")
        print("Disconnect (plain, -f, or --force) and plain setup are also covered.")
    }

    static func uninstall(purge: Bool) throws {
        let sudoersPath = "/etc/sudoers.d/cwru-ovpn"
        let privilegedExecutablePath = RuntimePaths.privilegedExecutable.path
        if FileManager.default.fileExists(atPath: privilegedExecutablePath) {
            _ = try Shell.run("/bin/rm", arguments: ["-f", privilegedExecutablePath], requirePrivileges: true)
            print("Removed privileged binary at \(privilegedExecutablePath).")
        }

        let privilegedDirectoryPath = RuntimePaths.privilegedExecutableDirectory.path
        if FileManager.default.fileExists(atPath: privilegedDirectoryPath),
           let contents = try? FileManager.default.contentsOfDirectory(atPath: privilegedDirectoryPath),
           contents.isEmpty {
            _ = try Shell.run("/bin/rmdir",
                              arguments: [privilegedDirectoryPath],
                              allowNonZero: true,
                              requirePrivileges: true)
        }

        for domain in resolverDomainsForUninstall() {
            let resolverPath = ResolverPaths.fileURL(for: domain).path
            if FileManager.default.fileExists(atPath: resolverPath) {
                _ = try Shell.run("/bin/rm", arguments: ["-f", resolverPath], allowNonZero: true, requirePrivileges: true)
                print("Removed resolver file at \(resolverPath).")
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
            print("Left \(RuntimePaths.homeStateDirectory.path) in place. Re-run uninstall --purge to remove profiles, configs, and logs.")
        }

        if FileManager.default.fileExists(atPath: sudoersPath) {
            _ = try Shell.run("/bin/rm", arguments: [sudoersPath], requirePrivileges: true)
            print("Removed sudoers rule at \(sudoersPath).")
        } else {
            print("No sudoers rule found at \(sudoersPath) — nothing to remove.")
        }
    }

    static func renderSudoers(userID: uid_t,
                              executablePath: String,
                              executableDigest: String) -> String {
        renderSudoers(userSpecifier: "#\(userID)",
                      executablePath: executablePath,
                      executableDigest: executableDigest)
    }

    private static func renderSudoers(userSpecifier: String,
                                      executablePath: String,
                                      executableDigest: String) -> String {
        permittedInvocations(executablePath: executablePath)
            .map { "\(userSpecifier) ALL=(root) NOPASSWD: sha256:\(executableDigest) \($0.joined(separator: " "))" }
            .joined(separator: "\n")
    }

    static func executableSHA256(at path: String) throws -> String {
        let data = try Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe)
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
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

    private static func installPrivilegedExecutable(from sourcePath: String) throws -> String {
        let installDirectory = RuntimePaths.privilegedExecutableDirectory.path
        let installPath = RuntimePaths.privilegedExecutable.path

        _ = try Shell.run("/bin/mkdir",
                          arguments: ["-p", installDirectory],
                          requirePrivileges: true)
        _ = try Shell.run("/usr/sbin/chown",
                          arguments: ["root:wheel", installDirectory],
                          requirePrivileges: true)
        _ = try Shell.run("/bin/chmod",
                          arguments: ["755", installDirectory],
                          requirePrivileges: true)
        _ = try Shell.run("/usr/bin/install",
                          arguments: ["-o", "root", "-g", "wheel", "-m", "555", sourcePath, installPath],
                          requirePrivileges: true)

        try assertSecureExecutableHierarchy(at: installPath)
        return installPath
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

    private static func resolverDomainsForUninstall() -> [String] {
        var domains = Set<String>()

        if let config = try? AppConfig.load(explicitConfigPath: nil) {
            for domain in config.splitTunnel.effectiveResolverDomains where AppConfig.SplitTunnelConfiguration.isValidDomainName(domain) && ResolverPaths.isSafeDomainFileName(domain) {
                domains.insert(domain)
            }
        }

        if let session = SessionState.load() {
            for domain in session.appliedResolverDomains ?? [] where AppConfig.SplitTunnelConfiguration.isValidDomainName(domain) && ResolverPaths.isSafeDomainFileName(domain) {
                domains.insert(domain)
            }
        }

        return domains.sorted()
    }

    private static let sudoersPathAllowedCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-+")

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

    private static func assertSecureExecutableHierarchy(at path: String) throws {
        let resolvedPath = URL(fileURLWithPath: path)
            .resolvingSymlinksInPath()
            .standardized.path
        var currentURL = URL(fileURLWithPath: resolvedPath)

        while true {
            try assertRootOwnedAndNonWritableByNonRoot(currentURL.path)
            let parentURL = currentURL.deletingLastPathComponent()
            if parentURL.path == currentURL.path {
                break
            }
            currentURL = parentURL
        }
    }

    private static func assertRootOwnedAndNonWritableByNonRoot(_ path: String) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        guard let owner = attributes[.ownerAccountID] as? NSNumber,
              owner.intValue == 0 else {
            throw SetupError.unsafePath("Refusing to trust non-root-owned install path component: \(path)")
        }

        guard let permissions = attributes[.posixPermissions] as? NSNumber,
              permissions.intValue & 0o022 == 0 else {
            throw SetupError.unsafePath("Refusing to trust writable install path component: \(path)")
        }
    }
}
