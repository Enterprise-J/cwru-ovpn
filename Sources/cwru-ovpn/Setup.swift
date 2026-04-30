import CryptoKit
import Darwin
import Foundation

enum SetupError: LocalizedError {
    case missingProfileSource(String)
    case requiresRootSetup
    case unsafePath(String)
    case installFailed(String)
    case validationFailed(String)
    case sudoersPolicyFailed(String)

    var errorDescription: String? {
        switch self {
        case .missingProfileSource(let path):
            return "No OpenVPN profile was found at \(path)."
        case .requiresRootSetup:
            return "Run setup with sudo so the privileged binary and sudoers rule can be installed atomically."
        case .unsafePath(let message):
            return message
        case .installFailed(let message):
            return message
        case .validationFailed(let message):
            return "Generated sudoers rules failed validation.\n\(message)"
        case .sudoersPolicyFailed(let message):
            return "Generated sudoers rules failed policy self-check: \(message)"
        }
    }
}

enum Setup {
    private static let rootUserID = uid_t(0)
    private static let wheelGroupID = gid_t(0)

    static func installSudoers(profileSourcePath: String?) throws {
        guard geteuid() == 0 else {
            throw SetupError.requiresRootSetup
        }

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
        try validatePasswordlessInvocationPolicy(executablePath: installedExecutablePath)

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

        try ensureRootOwnedDirectory(at: "/etc/sudoers.d", mode: 0o755)
        try installRootOwnedFileAtomically(sourcePath: tempURL.path,
                                           destinationPath: "/etc/sudoers.d/cwru-ovpn",
                                           mode: 0o440)

        print("Installed the sudoers rule at /etc/sudoers.d/cwru-ovpn.")
        print("Installed the privileged binary at \(installedExecutablePath).")
        print("Passwordless commands now cover connect, connect --mode full|split, those same forms with --verbosity debug, the debug foreground variants, and each of those with trailing --allow-sleep, pinned to the installed binary's SHA-256 digest.")
        print("Disconnect (plain, -f, or --force) is also covered. Setup now requires interactive sudo.")
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

    static func validatePasswordlessInvocationPolicy(executablePath: String) throws {
        let permittedInvocations = permittedInvocations(executablePath: executablePath)
        let permittedSet = Set(permittedInvocations)
        guard !permittedSet.contains([executablePath, "setup"]) else {
            throw SetupError.sudoersPolicyFailed("setup must not be passwordless.")
        }

        for invocation in permittedInvocations {
            let arguments = Array(invocation.dropFirst())
            guard isCanonicalPasswordlessInvocation(arguments) else {
                throw SetupError.sudoersPolicyFailed(invocation.joined(separator: " "))
            }
        }

        for probe in deniedPasswordlessPolicyProbes(executablePath: executablePath) {
            if permittedSet.contains(probe) {
                throw SetupError.sudoersPolicyFailed("denied command was granted: \(probe.joined(separator: " "))")
            }
        }
    }

    private static func permittedInvocations(executablePath: String) -> [[String]] {
        let connectCommands = permittedConnectInvocations(executablePath: executablePath)
        let fixedCommands = [
            [executablePath, "disconnect"],
            [executablePath, "disconnect", "-f"],
            [executablePath, "disconnect", "--force"],
        ]
        return connectCommands + fixedCommands
    }

    private static func isCanonicalPasswordlessInvocation(_ arguments: [String]) -> Bool {
        guard !arguments.contains("--config"),
              !arguments.contains("--tunnel-mode"),
              !arguments.contains("--background-child"),
              !arguments.contains("--startup-status-file") else {
            return false
        }

        do {
            switch try CLI.parse(arguments: arguments) {
            case .connect(let configFilePath,
                          let verbosityOverride,
                          _,
                          _,
                          let foregroundRequested,
                          let backgroundChild,
                          let startupStatusFilePath):
                guard configFilePath == nil,
                      startupStatusFilePath == nil,
                      !backgroundChild else {
                    return false
                }
                if let verbosityOverride, verbosityOverride != .debug {
                    return false
                }
                return !foregroundRequested || verbosityOverride == .debug
            case .disconnect:
                return true
            default:
                return false
            }
        } catch {
            return false
        }
    }

    private static func deniedPasswordlessPolicyProbes(executablePath: String) -> [[String]] {
        [
            [executablePath, "setup"],
            [executablePath, "setup", "--profile", "/tmp/profile.ovpn"],
            [executablePath, "connect", "--config", "/tmp/config.json"],
            [executablePath, "connect", "--tunnel-mode", "split"],
            [executablePath, "connect", "--verbosity", "daily"],
            [executablePath, "connect", "--foreground"],
            [executablePath, "connect", "--foreground", "--verbosity", "debug"],
            [executablePath, "connect", "--background-child"],
            [executablePath, "connect", "--startup-status-file", "/tmp/status.json"],
            [executablePath, "status"],
            [executablePath, "doctor"],
            [executablePath, "logs"],
            [executablePath, "uninstall"],
        ]
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

        try ensureRootOwnedDirectory(at: installDirectory, mode: 0o755)
        try installRootOwnedFileAtomically(sourcePath: sourcePath,
                                           destinationPath: installPath,
                                           mode: 0o555)

        try assertSecureExecutableHierarchy(at: installPath)
        return installPath
    }

    private static func ensureRootOwnedDirectory(at path: String, mode: Int) throws {
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([
            .ownerAccountID: Int(rootUserID),
            .groupOwnerAccountID: Int(wheelGroupID),
            .posixPermissions: mode,
        ], ofItemAtPath: path)
        try assertRootOwnedAndNonWritableByNonRoot(path)
    }

    private static func installRootOwnedFileAtomically(sourcePath: String,
                                                       destinationPath: String,
                                                       mode: mode_t) throws {
        let destinationURL = URL(fileURLWithPath: destinationPath).standardizedFileURL
        let destinationDirectory = destinationURL.deletingLastPathComponent()
        try assertRootOwnedAndNonWritableByNonRoot(destinationDirectory.path)

        let tempURL = destinationDirectory
            .appendingPathComponent(".\(destinationURL.lastPathComponent).\(UUID().uuidString).tmp")
        var sourceFD: Int32 = -1
        var tempFD: Int32 = -1
        var renamed = false

        defer {
            if sourceFD >= 0 {
                close(sourceFD)
            }
            if tempFD >= 0 {
                close(tempFD)
            }
            if !renamed {
                try? FileManager.default.removeItem(at: tempURL)
            }
        }

        sourceFD = open(sourcePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard sourceFD >= 0 else {
            throw posixInstallFailure("Failed to open install source \(sourcePath)", errno)
        }
        try assertRegularFile(fileDescriptor: sourceFD, path: sourcePath)

        tempFD = open(tempURL.path,
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                      mode)
        guard tempFD >= 0 else {
            throw posixInstallFailure("Failed to create temporary install target \(tempURL.path)", errno)
        }

        guard fchown(tempFD, rootUserID, wheelGroupID) == 0 else {
            throw posixInstallFailure("Failed to set owner on \(tempURL.path)", errno)
        }
        guard fchmod(tempFD, mode) == 0 else {
            throw posixInstallFailure("Failed to set mode on \(tempURL.path)", errno)
        }

        try copyFileContents(from: sourceFD, to: tempFD)
        guard fsync(tempFD) == 0 else {
            throw posixInstallFailure("Failed to sync \(tempURL.path)", errno)
        }
        try assertRootOwnedRegularFile(fileDescriptor: tempFD, path: tempURL.path, mode: mode)

        guard close(tempFD) == 0 else {
            let closeError = errno
            tempFD = -1
            throw posixInstallFailure("Failed to close \(tempURL.path)", closeError)
        }
        tempFD = -1

        guard rename(tempURL.path, destinationPath) == 0 else {
            throw posixInstallFailure("Failed to atomically replace \(destinationPath)", errno)
        }
        renamed = true

        try assertRootOwnedRegularFile(path: destinationPath, mode: mode)
    }

    private static func copyFileContents(from sourceFD: Int32, to destinationFD: Int32) throws {
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)

        while true {
            let bytesRead = buffer.withUnsafeMutableBytes { rawBuffer in
                read(sourceFD, rawBuffer.baseAddress, rawBuffer.count)
            }

            if bytesRead == 0 {
                return
            }
            if bytesRead < 0 {
                if errno == EINTR {
                    continue
                }
                throw posixInstallFailure("Failed to read install source", errno)
            }

            var totalWritten = 0
            while totalWritten < bytesRead {
                let bytesWritten = buffer.withUnsafeBytes { rawBuffer in
                    write(destinationFD,
                          rawBuffer.baseAddress!.advanced(by: totalWritten),
                          bytesRead - totalWritten)
                }
                if bytesWritten < 0 {
                    if errno == EINTR {
                        continue
                    }
                    throw posixInstallFailure("Failed to write install target", errno)
                }
                totalWritten += bytesWritten
            }
        }
    }

    private static func assertRegularFile(fileDescriptor: Int32, path: String) throws {
        var fileInfo = stat()
        guard fstat(fileDescriptor, &fileInfo) == 0 else {
            throw posixInstallFailure("Failed to inspect \(path)", errno)
        }
        guard (fileInfo.st_mode & S_IFMT) == S_IFREG else {
            throw SetupError.installFailed("Refusing to install from a non-regular file: \(path)")
        }
    }

    private static func assertRootOwnedRegularFile(path: String, mode: mode_t) throws {
        let fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else {
            throw posixInstallFailure("Failed to open installed file \(path)", errno)
        }
        defer { close(fd) }
        try assertRootOwnedRegularFile(fileDescriptor: fd, path: path, mode: mode)
    }

    private static func assertRootOwnedRegularFile(fileDescriptor: Int32,
                                                   path: String,
                                                   mode: mode_t) throws {
        var fileInfo = stat()
        guard fstat(fileDescriptor, &fileInfo) == 0 else {
            throw posixInstallFailure("Failed to inspect \(path)", errno)
        }
        guard (fileInfo.st_mode & S_IFMT) == S_IFREG else {
            throw SetupError.installFailed("Refusing to trust a non-regular installed file: \(path)")
        }
        guard fileInfo.st_uid == rootUserID,
              fileInfo.st_gid == wheelGroupID else {
            throw SetupError.installFailed("Refusing to trust non-root:wheel installed file: \(path)")
        }
        guard fileInfo.st_nlink == 1 else {
            throw SetupError.installFailed("Refusing to trust installed file with link count \(fileInfo.st_nlink): \(path)")
        }
        let actualMode = mode_t(fileInfo.st_mode & 0o777)
        guard actualMode == mode else {
            throw SetupError.installFailed(
                "Refusing to trust installed file with mode \(String(format: "%03o", Int(actualMode))): \(path)"
            )
        }
    }

    private static func posixInstallFailure(_ context: String, _ error: Int32) -> SetupError {
        SetupError.installFailed("\(context): \(String(cString: strerror(error)))")
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
        var currentURL = URL(fileURLWithPath: path).standardizedFileURL

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
        var fileInfo = stat()
        guard lstat(path, &fileInfo) == 0 else {
            throw posixInstallFailure("Failed to inspect install path component \(path)", errno)
        }

        guard (fileInfo.st_mode & S_IFMT) != S_IFLNK else {
            throw SetupError.unsafePath("Refusing to trust symbolic install path component: \(path)")
        }

        guard fileInfo.st_uid == rootUserID else {
            throw SetupError.unsafePath("Refusing to trust non-root-owned install path component: \(path)")
        }

        guard fileInfo.st_mode & 0o022 == 0 else {
            throw SetupError.unsafePath("Refusing to trust writable install path component: \(path)")
        }
    }
}
