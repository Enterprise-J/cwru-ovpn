import Darwin
import Foundation

enum SetupError: LocalizedError {
    case missingProfileSource(String)
    case requiresRootSetup
    case requiresRootUninstall
    case unsafePath(String)
    case installFailed(String)
    case validationFailed(String)
    case sudoersPolicyFailed(String)

    var errorDescription: String? {
        switch self {
        case .missingProfileSource(let path):
            return "No OpenVPN profile was found at \(path)."
        case .requiresRootSetup:
            return "Run setup with sudo to install the privileged binary and its matching sudoers rule."
        case .requiresRootUninstall:
            return "Run uninstall with sudo so active-session checks and privileged cleanup use the same recovery lock."
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
        let installationGuard = try acquireInstallationGuard(operation: "setup")
        defer { withExtendedLifetime(installationGuard) {} }

        try RuntimePaths.ensureHomeStateDirectory()
        let approvedProfileData: Data?
        if let profileSourcePath {
            approvedProfileData = try self.approvedProfileData(from: profileSourcePath,
                                                               expectedOwnerUserID: targetUser.userID)
        } else {
            approvedProfileData = try RuntimePaths.readHomeStateFile(name: "profile.ovpn",
                                                                     maximumBytes: ProfileManifest.maxProfileBytes)
            if let approvedProfileData {
                try validateProfileForApproval(profileData: approvedProfileData)
            }
        }

        let paths = InstallationPaths.installed
        let installedExecutablePath = paths.executable.path
        try assertSafeForSudoers(path: installedExecutablePath, label: "Executable path")
        try validatePasswordlessInvocationPolicy(executablePath: installedExecutablePath)
        try ensureTrustedRootDirectory(at: RuntimePaths.privilegedExecutableDirectory.path, createMode: 0o755)
        try assertSecureExecutableHierarchy(at: RuntimePaths.privilegedExecutableDirectory.path)
        if FileManager.default.fileExists(atPath: installedExecutablePath) {
            try assertSecureExecutableHierarchy(at: installedExecutablePath)
        }
        try ensureTrustedRootDirectory(at: "/etc/sudoers.d", createMode: 0o755)
        let executableData = try SecureFile.readRegularFile(atPath: sourceExecutablePath,
                                                            maximumBytes: 512 * 1024 * 1024,
                                                            context: "setup executable")
        try installConfiguration(profileData: approvedProfileData,
                                 executableData: executableData,
                                 userID: targetUser.userID,
                                 groupID: targetUser.groupID,
                                 paths: paths) { staged in
            let binary = try SecureFile.readRegularFile(at: staged.executable,
                                                        maximumBytes: 512 * 1024 * 1024,
                                                        context: "staged executable",
                                                        expectedUserID: rootUserID,
                                                        expectedGroupID: wheelGroupID,
                                                        expectedMode: 0o555)
            try ExecutableTrust.validate(binary)
            guard binary == executableData else {
                throw SetupError.installFailed("The staged executable changed before validation.")
            }
            if let approvedProfileData {
                let profile = try ProfileManifest.readProfileData(at: staged.profile,
                                                                  expectedUserID: targetUser.userID)
                guard profile == approvedProfileData else {
                    throw SetupError.installFailed("The staged profile changed before validation.")
                }
                try validateProfileForApproval(profileData: profile)
            }
            let validation = try validateSudoersFile(at: staged.sudoers.path)
            guard validation.exitCode == 0 else {
                throw SetupError.validationFailed(validation.stderr.isEmpty ? validation.stdout : validation.stderr)
            }
        }
        if approvedProfileData != nil {
            print("Installed the approved VPN profile at \(paths.profile.path).")
            print("Pinned the approved VPN profile digest at \(paths.manifest.path).")
        } else {
            print("No VPN profile was copied. Place one at \(paths.profile.path) or rerun setup --profile /path/to/profile.ovpn.")
        }
        print("Installed the sudoers rule at /etc/sudoers.d/cwru-ovpn.")
        print("Installed the privileged binary at \(installedExecutablePath).")
        print("Passwordless commands now cover only connect, connect --mode full|split, disconnect, and disconnect --force, pinned to the installed binary's SHA-256 digest.")
        print("Setup now requires interactive sudo.")
    }

    static func uninstall(purge: Bool) throws {
        guard geteuid() == 0 else {
            throw SetupError.requiresRootUninstall
        }

        let installationGuard = try acquireInstallationGuard(operation: "uninstall")
        defer { withExtendedLifetime(installationGuard) {} }

        let routeManager = RouteManager()
        try routeManager.cleanupStaleLedgeredRemoteHostRoutes(excluding: [])
        guard try RemoteHostRouteLedger().entries().isEmpty else {
            throw SetupError.installFailed("A running cwru-ovpn process still owns protected remote-host routes. Stop it before uninstalling.")
        }

        let sudoersPath = "/etc/sudoers.d/cwru-ovpn"
        if FileManager.default.fileExists(atPath: sudoersPath) {
            _ = try Shell().run("/bin/rm", arguments: [sudoersPath], requirePrivileges: true)
            print("Removed sudoers rule at \(sudoersPath).")
        } else {
            print("No sudoers rule found at \(sudoersPath) — nothing to remove.")
        }

        for domain in dnsDomainsForUninstall() {
            let resolverFile = ResolverPaths.fileURL(for: domain)
            guard FileManager.default.fileExists(atPath: resolverFile.path) else {
                continue
            }
            guard routeManager.resolverFileIsManaged(at: resolverFile) else {
                print("Left unmanaged resolver file at \(resolverFile.path).")
                continue
            }
            try routeManager.removeResolverFiles(for: [domain])
            print("Removed resolver file at \(resolverFile.path).")
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

        let manifestPath = RuntimePaths.approvedProfileManifest.path
        if FileManager.default.fileExists(atPath: manifestPath) {
            _ = try Shell().run("/bin/rm", arguments: ["-f", manifestPath], requirePrivileges: true)
            print("Removed approved-profile manifest at \(manifestPath).")
        }

        let privilegedExecutablePath = RuntimePaths.privilegedExecutable.path
        if FileManager.default.fileExists(atPath: privilegedExecutablePath) {
            _ = try Shell().run("/bin/rm", arguments: ["-f", privilegedExecutablePath], requirePrivileges: true)
            print("Removed privileged binary at \(privilegedExecutablePath).")
        }

        let privilegedDirectoryPath = RuntimePaths.privilegedExecutableDirectory.path
        if FileManager.default.fileExists(atPath: privilegedDirectoryPath),
           let contents = try? FileManager.default.contentsOfDirectory(atPath: privilegedDirectoryPath),
           contents.isEmpty {
            _ = try Shell().run("/bin/rmdir",
                              arguments: [privilegedDirectoryPath],
                              allowNonZero: true,
                              requirePrivileges: true)
        }

        try cleanPrivilegedStateAfterUninstall()
    }

    static func renderSudoers(userID: uid_t,
                              executablePath: String,
                              executableDigest: String) -> String {
        permittedInvocations(executablePath: executablePath)
            .map { "#\(userID) ALL=(root) NOPASSWD: sha256:\(executableDigest) \($0.joined(separator: " "))" }
            .joined(separator: "\n")
    }

    static func validateProfileForApproval(profileData: Data) throws {
        let profileContent = String(decoding: profileData, as: UTF8.self)
        try OpenVPNProfilePolicy.validate(configContent: profileContent)
    }

    static func validateSudoersFile(at path: String) throws -> ShellResult {
        try Shell().run("/usr/sbin/visudo",
                      arguments: ["-c", "-f", path],
                      allowNonZero: true)
    }

    static func validatePasswordlessInvocationPolicy(executablePath: String) throws {
        let permittedInvocations = permittedInvocations(executablePath: executablePath)
        let permittedSet = Set(permittedInvocations)
        guard permittedSet.count == permittedInvocations.count else {
            throw SetupError.sudoersPolicyFailed("passwordless command list contains duplicate entries.")
        }
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

    static func permittedInvocations(executablePath: String) -> [[String]] {
        let connectCommands = permittedConnectInvocations(executablePath: executablePath)
        let fixedCommands = [
            [executablePath, "disconnect"],
            [executablePath, "disconnect", "--force"],
        ]
        return connectCommands + fixedCommands
    }

    static func isCanonicalPasswordlessInvocation(_ arguments: [String]) -> Bool {
        guard !arguments.contains("--config"),
              !arguments.contains("--background-child"),
              !arguments.contains("--startup-status-file") else {
            return false
        }

        do {
            switch try CLI.parse(arguments: arguments) {
            case .connect(let configFilePath,
                          let verbosityOverride,
                          _,
                          let foregroundRequested,
                          let backgroundChild,
                          let startupStatusFilePath):
                guard configFilePath == nil,
                      startupStatusFilePath == nil,
                      !backgroundChild else {
                    return false
                }
                if verbosityOverride != nil || foregroundRequested {
                    return false
                }
                return true
            case .disconnect:
                return true
            default:
                return false
            }
        } catch {
            return false
        }
    }

    static func deniedPasswordlessPolicyProbes(executablePath: String) -> [[String]] {
        [
            [executablePath, "setup"],
            [executablePath, "setup", "--profile", "/tmp/profile.ovpn"],
            [executablePath, "connect", "--config", "/tmp/config.json"],
            [executablePath, "connect", "--mode", "split", "--config", "/tmp/config.json"],
            [executablePath, "connect", "--verbosity", "debug", "--config", "/tmp/config.json"],
            [executablePath, "connect", "--verbosity", "daily"],
            [executablePath, "connect", "--verbosity", "silent"],
            [executablePath, "connect", "--verbosity", "debug"],
            [executablePath, "connect", "--mode", "split", "--verbosity", "debug"],
            [executablePath, "connect", "--foreground"],
            [executablePath, "connect", "--foreground", "--verbosity", "debug"],
            [executablePath, "connect", "--background-child"],
            [executablePath, "connect", "--background-child", "--startup-status-file", "/tmp/status.json"],
            [executablePath, "connect", "--startup-status-file", "/tmp/status.json"],
            [executablePath, "disconnect", "--force", "extra"],
            [executablePath, "status"],
            [executablePath, "doctor"],
            [executablePath, "logs"],
            [executablePath, "logs", "--tail", "1"],
            [executablePath, "uninstall"],
            [executablePath, "cleanup-watchdog", "--parent-pid", "1"],
            [executablePath, "install-shell-integration", "--shell", "/bin/zsh"],
        ]
    }

    private static func permittedConnectInvocations(executablePath: String) -> [[String]] {
        let base = [executablePath, "connect"]
        let modeVariants: [[String]] = [
            [],
            ["--mode", "full"],
            ["--mode", "split"],
        ]
        return modeVariants.map { base + $0 }
    }

    static func acquireInstallationGuard(operation: String,
                                         lockFile: URL? = nil,
                                         sessionStore: StateDirectory = StateDirectory()) throws -> ControllerLock {
        let lock: ControllerLock
        do {
            if let lockFile {
                lock = try ControllerLock(at: lockFile)
            } else {
                lock = try ControllerLock(in: sessionStore)
            }
        } catch ControllerLockError.busy {
            throw SetupError.installFailed("Disconnect the active VPN session with the currently installed version before running \(operation).")
        }

        var primaryInfo = Darwin.stat()
        let primaryExists = lstat(sessionStore.url.appendingPathComponent("session.json").path, &primaryInfo) == 0
        if !primaryExists, errno != ENOENT {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let homeMirrorExists = sessionStore.usesRuntimePaths
            ? try RuntimePaths.homeStateFileExists(name: "session.json")
            : false
        guard !primaryExists, !homeMirrorExists else {
            throw SetupError.installFailed("Disconnect with the currently installed version before running \(operation) so its recovery state can be removed safely.")
        }
        return lock
    }

    struct InstallationPaths {
        let profile: URL
        let manifest: URL
        let executable: URL
        let sudoers: URL

        static var installed: InstallationPaths {
            InstallationPaths(profile: RuntimePaths.homeProfileFile,
                              manifest: RuntimePaths.approvedProfileManifest,
                              executable: RuntimePaths.privilegedExecutable,
                              sudoers: URL(fileURLWithPath: "/etc/sudoers.d/cwru-ovpn"))
        }
    }

    static func installConfiguration(profileData: Data?,
                                     executableData: Data,
                                     userID: uid_t,
                                     groupID: gid_t,
                                     paths: InstallationPaths,
                                     systemUserID: uid_t = rootUserID,
                                     systemGroupID: gid_t = wheelGroupID,
                                     validate: (InstallationPaths) throws -> Void) throws {
        let profile = try profileData.map {
            try InstallationFile(at: paths.profile, data: $0,
                                 userID: userID, groupID: groupID, mode: 0o600)
        }
        let digest = profileData.map { Data((ProfileManifest.digest(of: $0) + "\n").utf8) }
        let manifest = try InstallationFile(at: paths.manifest, data: digest,
                                             userID: systemUserID, groupID: systemGroupID, mode: 0o644)
        let executable = try InstallationFile(at: paths.executable, data: executableData,
                                               userID: systemUserID, groupID: systemGroupID, mode: 0o555)
        let sudoersData = Data((renderSudoers(userID: userID,
                                            executablePath: paths.executable.path,
                                            executableDigest: ProfileManifest.digest(of: executableData)) + "\n").utf8)
        let sudoers = try InstallationFile(at: paths.sudoers, data: sudoersData,
                                            userID: systemUserID, groupID: systemGroupID, mode: 0o440)
        let files = [profile, manifest, executable, sudoers].compactMap { $0 }
        try validate(InstallationPaths(profile: profile?.temporaryURL ?? paths.profile,
                                       manifest: manifest.temporaryURL,
                                       executable: executable.temporaryURL,
                                       sudoers: sudoers.temporaryURL))
        do {
            for file in files {
                try file.commit()
            }
        } catch {
            var failures: [String] = []
            for file in files.reversed() {
                do {
                    try file.restore()
                } catch {
                    file.preserveTemporary = true
                    failures.append("\(file.destination.path): \(error.localizedDescription); recovery file: \(file.temporaryURL.path)")
                }
            }
            if !failures.isEmpty {
                throw SetupError.installFailed("Setup failed: \(error.localizedDescription)\nCould not fully restore the previous installation: \(failures.joined(separator: "; ")).")
            }
            throw SetupError.installFailed("Setup failed: \(error.localizedDescription)\nThe previous installation was restored.")
        }
    }

    private final class InstallationFile {
        let destination: URL
        let temporaryURL: URL
        var preserveTemporary = false
        private let directoryFD: Int32
        private let stagedFD: Int32
        private let name: String
        private let temporaryName: String
        private let original: Darwin.stat?
        private let userID: uid_t
        private let groupID: gid_t
        private let mode: mode_t
        private var committed = false

        init(at destination: URL, data: Data?, userID: uid_t, groupID: gid_t, mode: mode_t) throws {
            self.destination = destination.standardizedFileURL
            self.userID = userID
            self.groupID = groupID
            self.mode = mode
            let name = destination.lastPathComponent
            self.name = name
            try AnchoredFileIO.validateComponent(name)
            let temporaryName = ".\(name).\(UUID().uuidString).setup"
            self.temporaryName = temporaryName
            let directory = destination.deletingLastPathComponent()
            let temporaryURL = directory.appendingPathComponent(temporaryName)
            self.temporaryURL = temporaryURL
            let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            guard directoryFD >= 0 else {
                throw posixInstallFailure("Failed to open install directory \(directory.path)", errno)
            }
            var prepared = false
            var stagedFD: Int32 = -1
            defer {
                if !prepared {
                    if stagedFD >= 0 { close(stagedFD) }
                    _ = unlinkat(directoryFD, temporaryName, 0)
                    close(directoryFD)
                }
            }
            var directoryInfo = Darwin.stat()
            guard fstat(directoryFD, &directoryInfo) == 0,
                  (directoryInfo.st_mode & S_IFMT) == S_IFDIR,
                  directoryInfo.st_uid == userID,
                  directoryInfo.st_gid == groupID,
                  directoryInfo.st_mode & 0o022 == 0 else {
                throw SetupError.unsafePath("Refusing to use an unsafe install directory: \(directory.path)")
            }
            let existingFD = openat(directoryFD, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            if existingFD >= 0 {
                defer { close(existingFD) }
                try SecureFile.assertRegularFile(fileDescriptor: existingFD,
                                                 context: "installed file \(destination.path)",
                                                 expectedUserID: userID,
                                                 expectedGroupID: groupID,
                                                 expectedMode: mode)
                var info = Darwin.stat()
                guard fstat(existingFD, &info) == 0 else { throw FileIO.posixError(errno) }
                original = info
            } else if errno == ENOENT {
                original = nil
            } else {
                throw posixInstallFailure("Failed to inspect installed file \(destination.path)", errno)
            }
            if let data {
                stagedFD = openat(directoryFD, temporaryName, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, 0o600)
                guard stagedFD >= 0 else { throw FileIO.posixError(errno) }
                try FileIO.writeAll(data, to: stagedFD)
                guard fchown(stagedFD, userID, groupID) == 0,
                      fchmod(stagedFD, mode) == 0,
                      fsync(stagedFD) == 0 else { throw FileIO.posixError(errno) }
                try SecureFile.assertRegularFile(fileDescriptor: stagedFD,
                                                 context: "staged file \(temporaryURL.path)",
                                                 expectedUserID: userID,
                                                 expectedGroupID: groupID,
                                                 expectedMode: mode)
                guard fsync(directoryFD) == 0 else { throw FileIO.posixError(errno) }
            }
            self.directoryFD = directoryFD
            self.stagedFD = stagedFD
            prepared = true
        }

        deinit {
            if !preserveTemporary,
               unlinkat(directoryFD, temporaryName, 0) != 0,
               errno != ENOENT {
                fputs("\(AppIdentity.executableName): could not remove setup temporary file \(temporaryURL.path): \(String(cString: strerror(errno)))\n", stderr)
            }
            if stagedFD >= 0 { close(stagedFD) }
            close(directoryFD)
        }

        func commit() throws {
            var current = Darwin.stat()
            let result = fstatat(directoryFD, name, &current, AT_SYMLINK_NOFOLLOW)
            if let original {
                guard result == 0, current.st_dev == original.st_dev, current.st_ino == original.st_ino else {
                    throw SetupError.installFailed("The installed file changed during setup: \(destination.path)")
                }
            } else if result == 0 || errno != ENOENT {
                throw SetupError.installFailed("The install destination changed during setup: \(destination.path)")
            }
            if stagedFD >= 0 {
                try verifyName(temporaryName, fileDescriptor: stagedFD)
                let flags = original == nil ? RENAME_EXCL : RENAME_SWAP
                guard renameatx_np(directoryFD, temporaryName, directoryFD, name, UInt32(flags)) == 0 else {
                    throw posixInstallFailure("Failed to install \(destination.path)", errno)
                }
            } else if original != nil {
                guard renameatx_np(directoryFD, name, directoryFD, temporaryName, UInt32(RENAME_EXCL)) == 0 else {
                    throw posixInstallFailure("Failed to remove \(destination.path)", errno)
                }
            } else {
                return
            }
            committed = true
            if stagedFD >= 0 {
                try verifyName(name, fileDescriptor: stagedFD)
            }
            guard fsync(directoryFD) == 0 else { throw FileIO.posixError(errno) }
        }

        func restore() throws {
            guard committed else { return }
            if stagedFD >= 0 {
                try verifyName(name, fileDescriptor: stagedFD)
            }
            let result: Int32
            if let original {
                var backup = Darwin.stat()
                guard fstatat(directoryFD, temporaryName, &backup, AT_SYMLINK_NOFOLLOW) == 0,
                      backup.st_dev == original.st_dev,
                      backup.st_ino == original.st_ino else {
                    throw SetupError.installFailed("The previous installation file changed unexpectedly: \(temporaryURL.path)")
                }
                let flags = stagedFD >= 0 ? RENAME_SWAP : RENAME_EXCL
                result = renameatx_np(directoryFD, temporaryName, directoryFD, name, UInt32(flags))
            } else {
                result = renameatx_np(directoryFD, name, directoryFD, temporaryName, UInt32(RENAME_EXCL))
            }
            guard result == 0 else {
                throw posixInstallFailure("Failed to restore \(destination.path)", errno)
            }
            committed = false
            guard fsync(directoryFD) == 0 else { throw FileIO.posixError(errno) }
        }

        private func verifyName(_ name: String, fileDescriptor: Int32) throws {
            var descriptorInfo = Darwin.stat()
            var pathInfo = Darwin.stat()
            guard fstat(fileDescriptor, &descriptorInfo) == 0,
                  fstatat(directoryFD, name, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
                  descriptorInfo.st_dev == pathInfo.st_dev,
                  descriptorInfo.st_ino == pathInfo.st_ino else {
                throw SetupError.installFailed("The setup file changed unexpectedly: \(destination.deletingLastPathComponent().appendingPathComponent(name).path)")
            }
            try SecureFile.assertRegularFile(fileDescriptor: fileDescriptor,
                                             context: "setup file \(destination.path)",
                                             expectedUserID: userID,
                                             expectedGroupID: groupID,
                                             expectedMode: mode)
        }
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

    private static func ensureTrustedRootDirectory(at path: String, createMode: Int) throws {
        if FileManager.default.fileExists(atPath: path) {
            try assertRootOwnedAndNonWritableByNonRoot(path)
            return
        }
        try ensureRootOwnedDirectory(at: path, mode: createMode)
    }

    private static func posixInstallFailure(_ context: String, _ error: Int32) -> SetupError {
        SetupError.installFailed("\(context): \(String(cString: strerror(error)))")
    }

    private static func approvedProfileData(from sourcePath: String,
                                            expectedOwnerUserID: uid_t) throws -> Data {
        let sourceURL = URL(fileURLWithPath: AppConfig.expandUserPath(sourcePath)).standardized
        guard FileManager.default.fileExists(atPath: sourceURL.path) else {
            throw SetupError.missingProfileSource(sourceURL.path)
        }
        let data = try ProfileManifest.readProfileData(at: sourceURL, expectedUserID: expectedOwnerUserID)
        try validateProfileForApproval(profileData: data)
        return data
    }

    static func dnsDomainsForUninstall(resolverDirectory: URL = ResolverPaths.directory) -> [String] {
        var domains = Set<String>()

        let manager = RouteManager(resolverDirectory: resolverDirectory)
        domains.formUnion(manager.managedResolverDomainsInDirectory())
        domains.formUnion(SplitTunnelPolicy.fixedResolverDomains)

        if let session = SessionState.load() {
            for domain in session.appliedDNSDomains ?? [] where SplitTunnelPolicy.isValidDomainName(domain) && ResolverPaths.isSafeDomainFileName(domain) {
                domains.insert(domain)
            }
        }

        return domains.sorted()
    }

    private static func cleanPrivilegedStateAfterUninstall() throws {
        let directoryPath = RuntimePaths.privilegedSessionStateDirectoryPath
        var directoryInfo = Darwin.stat()
        if lstat(directoryPath, &directoryInfo) != 0 {
            guard errno == ENOENT else {
                throw posixInstallFailure("Failed to inspect privileged state directory \(directoryPath)", errno)
            }
            return
        }
        try assertRootOwnedAndNonWritableByNonRoot(directoryPath)

        let knownFiles = [
            "session-state.lock",
            "managed-reconnect-budget.json",
            "managed-reconnect-budget.lock",
            "remote-host-routes.json",
            "remote-host-routes.lock",
        ]
        for name in knownFiles {
            let path = URL(fileURLWithPath: directoryPath, isDirectory: true)
                .appendingPathComponent(name)
                .path
            var info = Darwin.stat()
            if lstat(path, &info) != 0 {
                guard errno == ENOENT else {
                    throw posixInstallFailure("Failed to inspect privileged state file \(path)", errno)
                }
                continue
            }
            try SecureFile.assertRegularFile(atPath: path,
                                                       context: "privileged uninstall state \(path)",
                                                       expectedUserID: rootUserID,
                                                       expectedGroupID: wheelGroupID,
                                                       expectedMode: 0o600)
            guard unlink(path) == 0 else {
                throw posixInstallFailure("Failed to remove privileged state file \(path)", errno)
            }
        }

        let remaining = try FileManager.default.contentsOfDirectory(atPath: directoryPath).sorted()
        let unrecognized = remaining.filter { $0 != "controller.lock" }
        if !unrecognized.isEmpty {
            print("Left unrecognized privileged state files at \(directoryPath): \(unrecognized.joined(separator: ", ")).")
        }
        print("Retained the privileged controller lock at \(directoryPath)/controller.lock as the installation synchronization anchor.")
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
        var fileInfo = Darwin.stat()
        guard Darwin.lstat(path, &fileInfo) == 0 else {
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
