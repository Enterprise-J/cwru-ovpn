import Darwin
import Foundation

enum SetupError: LocalizedError {
    case missingProfileSource(String)
    case unsafePath(String)
    case installFailed(String)
    case validationFailed(String)

    var errorDescription: String? {
        switch self {
        case .missingProfileSource(let path):
            return "No OpenVPN profile was found at \(path)."
        case .unsafePath(let message):
            return message
        case .installFailed(let message):
            return message
        case .validationFailed(let message):
            return "Generated sudoers rules failed validation.\n\(message)"
        }
    }
}

enum Setup {
    private static let rootUserID = uid_t(0)
    private static let wheelGroupID = gid_t(0)

    static func install(profileSourcePath: String?) throws {
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
            approvedProfileData = try RuntimePaths.readHomeStateFile(name: RuntimePaths.homeProfileFile.lastPathComponent,
                                                                     maximumBytes: ProfileManifest.maxProfileBytes)
            if let approvedProfileData {
                try validateProfileForApproval(profileData: approvedProfileData)
            }
        }

        let paths = InstallationPaths.installed
        let installedExecutablePath = paths.executable.path
        try assertSafeForSudoers(path: installedExecutablePath, label: "Executable path")
        for directory in [RuntimePaths.privilegedExecutableDirectory,
                          RuntimePaths.privilegedApplication,
                          paths.applicationInfo.deletingLastPathComponent(),
                          paths.codeResources.deletingLastPathComponent(),
                          paths.executable.deletingLastPathComponent()] {
            try ensureTrustedRootDirectory(at: directory.path, createMode: 0o755)
            try assertSecureExecutableHierarchy(at: directory.path)
        }
        if FileManager.default.fileExists(atPath: installedExecutablePath) {
            try assertSecureExecutableHierarchy(at: installedExecutablePath)
        }
        try ensureTrustedRootDirectory(at: RuntimePaths.sudoersFile.deletingLastPathComponent().path, createMode: 0o755)
        let executableData = try SecureFile.readRegularFile(at: URL(fileURLWithPath: sourceExecutablePath),
                                                            maximumBytes: 512 * 1024 * 1024,
                                                            context: "setup executable")
        let sourceApplication = AppIdentity.applicationDirectory(for: URL(fileURLWithPath: sourceExecutablePath))
        let applicationInfo = try SecureFile.readRegularFile(at: sourceApplication.appendingPathComponent("Contents/Info.plist"),
                                                             maximumBytes: 1024 * 1024,
                                                             context: "application identity")
        let codeResources = try SecureFile.readRegularFile(at: sourceApplication.appendingPathComponent("Contents/_CodeSignature/CodeResources"),
                                                           maximumBytes: 1024 * 1024,
                                                           context: "application signature resources")
        try AppIdentity.validateBundleInfo(applicationInfo)
        try AppIdentity.verifyBundleSignature(at: sourceApplication)
        try installConfiguration(profileData: approvedProfileData,
                                 executableData: executableData,
                                 applicationInfo: applicationInfo,
                                 codeResources: codeResources,
                                 userID: targetUser.userID,
                                 groupID: targetUser.groupID,
                                 paths: paths,
                                 verifyInstalled: { _ in
            try AppIdentity.verifyBundleSignature(at: RuntimePaths.privilegedApplication)
        }) { staged in
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
            guard try Data(contentsOf: staged.applicationInfo) == applicationInfo,
                  try Data(contentsOf: staged.codeResources) == codeResources else {
                throw SetupError.installFailed("The staged application metadata changed before validation.")
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
            print("No VPN profile was copied. Run sudo \(installedExecutablePath) setup --profile /path/to/profile.ovpn to approve and install a profile.")
        }
        print("Installed the sudoers rule at \(paths.sudoers.path).")
        print("Installed the privileged binary at \(installedExecutablePath).")
        print("Installed application identity: \(AppIdentity.bundleName) (\(AppIdentity.bundleIdentifier)).")
        print("Passwordless commands cover only connect, connect --mode full|split, disconnect, and disconnect --force, pinned to the installed binary's SHA-256 digest.")
    }

    static func uninstall(purge: Bool) throws {
        let installationGuard = try acquireInstallationGuard(operation: "uninstall")
        defer { withExtendedLifetime(installationGuard) {} }

        let routeManager = RouteManager()
        try routeManager.cleanupStaleLedgeredRemoteHostRoutes(excluding: [])
        guard try RemoteHostRouteLedger().entries().isEmpty else {
            throw SetupError.installFailed("A running cwru-ovpn process still owns protected remote-host routes. Stop it before uninstalling.")
        }

        let sudoersPath = RuntimePaths.sudoersFile.path
        if try removeFileIfPresent(atPath: sudoersPath) {
            print("Removed sudoers rule at \(sudoersPath).")
        } else {
            print("No sudoers rule found at \(sudoersPath).")
        }

        for domain in dnsDomainsForUninstall() {
            let resolverFile = ResolverPaths.fileURL(for: domain)
            if try !routeManager.removeResolverFiles(for: [domain]).isEmpty {
                print("Removed resolver file at \(resolverFile.path).")
            } else if FileManager.default.fileExists(atPath: resolverFile.path) {
                print("Left unmanaged resolver file at \(resolverFile.path).")
            }
        }

        let updatedRCFiles = try ShellIntegration.remove()
        for rcFile in updatedRCFiles {
            print("Removed cwru-ovpn shell shortcuts from \(rcFile.path).")
        }

        let helper = ShellIntegration.installedHelperURL
        let helperRemoved = try RuntimePaths.withHomeStateDirectoryAnchor { directoryFD, _, _ in
            try AnchoredFileIO.removeFileIfPresent(in: directoryFD, name: helper.lastPathComponent)
        }
        if helperRemoved {
            print("Removed shell helper at \(helper.path).")
        }

        let manifestPath = RuntimePaths.approvedProfileManifest.path
        if try removeFileIfPresent(atPath: manifestPath) {
            print("Removed approved-profile manifest at \(manifestPath).")
        }

        let privilegedExecutablePath = RuntimePaths.privilegedExecutable.path
        if try removeFileIfPresent(atPath: privilegedExecutablePath) {
            print("Removed privileged binary at \(privilegedExecutablePath).")
        }
        for file in [RuntimePaths.privilegedApplicationInfo, RuntimePaths.privilegedApplicationResources] {
            _ = try removeFileIfPresent(atPath: file.path)
        }
        for directory in [RuntimePaths.privilegedExecutable.deletingLastPathComponent(),
                          RuntimePaths.privilegedApplicationResources.deletingLastPathComponent(),
                          RuntimePaths.privilegedApplicationInfo.deletingLastPathComponent(),
                          RuntimePaths.privilegedApplication] {
            try removeDirectoryIfEmpty(directory, label: "application directory")
        }
        try removeDirectoryIfEmpty(RuntimePaths.privilegedExecutableDirectory, label: "privileged helper directory")

        try cleanPrivilegedStateAfterUninstall()

        if purge {
            if try RuntimePaths.removeHomeStateDirectory() {
                print("Removed state directory at \(RuntimePaths.homeStateDirectory.path).")
            }
        } else {
            print("Left \(RuntimePaths.homeStateDirectory.path) in place. Re-run uninstall --purge to remove profiles, configs, and logs.")
        }
    }

    private static func removeDirectoryIfEmpty(_ directory: URL, label: String) throws {
        if rmdir(directory.path) == 0 {
            print("Removed \(label) at \(directory.path).")
            return
        }
        let removeError = errno
        switch removeError {
        case ENOENT:
            return
        case ENOTEMPTY:
            let remaining = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
            print("Left \(label) at \(directory.path) because it still contains: \(remaining.joined(separator: ", ")).")
        default:
            throw posixInstallFailure("Failed to remove \(label) \(directory.path)", removeError)
        }
    }

    private static func removeFileIfPresent(atPath path: String) throws -> Bool {
        if unlink(path) == 0 {
            return true
        }
        guard errno == ENOENT else {
            throw posixInstallFailure("Failed to remove \(path)", errno)
        }
        return false
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
        for tunnelMode in AppTunnelMode.allCases {
            let connectContent = OpenVPNProfile.connectContent(profileContent, for: tunnelMode)
            try OpenVPNProfilePolicy.validate(OpenVPNProfile(content: connectContent))
        }
    }

    static func validateSudoersFile(at path: String) throws -> CommandResult {
        try CommandRunner().run("/usr/sbin/visudo",
                                arguments: ["-c", "-f", path],
                                allowNonZero: true)
    }

    static func permittedInvocations(executablePath: String) -> [[String]] {
        [
            [executablePath, "connect"],
            [executablePath, "connect", "--mode", "full"],
            [executablePath, "connect", "--mode", "split"],
            [executablePath, "disconnect"],
            [executablePath, "disconnect", "--force"],
        ]
    }

    static func acquireInstallationGuard(operation: String,
                                         sessionStore: StateDirectory = StateDirectory()) throws -> ControllerLock {
        let lock: ControllerLock
        do {
            lock = try ControllerLock(in: sessionStore)
        } catch ControllerLockError.busy {
            throw SetupError.installFailed("Disconnect the active VPN session with the currently installed version before running \(operation).")
        }

        var primaryInfo = Darwin.stat()
        let primaryPath = sessionStore.url.appendingPathComponent(SessionState.fileName).path
        let primaryExists = lstat(primaryPath, &primaryInfo) == 0
        if !primaryExists, errno != ENOENT {
            throw posixInstallFailure("Failed to inspect \(primaryPath)", errno)
        }
        let homeMirrorExists = sessionStore.usesRuntimePaths
            ? try RuntimePaths.homeStateFileExists(name: SessionState.fileName)
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
        let applicationInfo: URL
        let codeResources: URL
        let sudoers: URL

        static var installed: InstallationPaths {
            InstallationPaths(profile: RuntimePaths.homeProfileFile,
                              manifest: RuntimePaths.approvedProfileManifest,
                              executable: RuntimePaths.privilegedExecutable,
                              applicationInfo: RuntimePaths.privilegedApplicationInfo,
                              codeResources: RuntimePaths.privilegedApplicationResources,
                              sudoers: RuntimePaths.sudoersFile)
        }
    }

    static func installConfiguration(profileData: Data?,
                                     executableData: Data,
                                     applicationInfo: Data,
                                     codeResources: Data,
                                     userID: uid_t,
                                     groupID: gid_t,
                                     paths: InstallationPaths,
                                     systemUserID: uid_t = rootUserID,
                                     systemGroupID: gid_t = wheelGroupID,
                                     verifyInstalled: (InstallationPaths) throws -> Void = { _ in },
                                     validate: (InstallationPaths) throws -> Void) throws {
        let profile = try profileData.map {
            try InstallationFile(at: paths.profile, data: $0,
                                 userID: userID, groupID: groupID, mode: 0o600)
        }
        let digest = profileData.map { Data((ProfileManifest.digest(of: $0) + "\n").utf8) }
        let manifest = try InstallationFile(at: paths.manifest, data: digest,
                                            userID: systemUserID, groupID: systemGroupID, mode: 0o644)
        let bundleStaging = AppIdentity.applicationDirectory(for: paths.executable).deletingLastPathComponent()
        let executable = try InstallationFile(at: paths.executable, stagingDirectory: bundleStaging, data: executableData,
                                              userID: systemUserID, groupID: systemGroupID, mode: 0o555)
        let info = try InstallationFile(at: paths.applicationInfo, stagingDirectory: bundleStaging, data: applicationInfo,
                                        userID: systemUserID, groupID: systemGroupID, mode: 0o644)
        let resources = try InstallationFile(at: paths.codeResources, stagingDirectory: bundleStaging, data: codeResources,
                                             userID: systemUserID, groupID: systemGroupID, mode: 0o644)
        let sudoersData = Data((renderSudoers(userID: userID,
                                              executablePath: paths.executable.path,
                                              executableDigest: ProfileManifest.digest(of: executableData)) + "\n").utf8)
        let sudoers = try InstallationFile(at: paths.sudoers, data: sudoersData,
                                           userID: systemUserID, groupID: systemGroupID, mode: 0o440)
        let files = [profile, manifest, info, resources, executable, sudoers].compactMap { $0 }
        try validate(InstallationPaths(profile: profile?.temporaryURL ?? paths.profile,
                                       manifest: manifest.temporaryURL,
                                       executable: executable.temporaryURL,
                                       applicationInfo: info.temporaryURL,
                                       codeResources: resources.temporaryURL,
                                       sudoers: sudoers.temporaryURL))
        do {
            for file in files {
                try file.commit()
            }
            try verifyInstalled(paths)
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
        private let stagingDirectoryFD: Int32
        private let stagedFD: Int32
        private let name: String
        private let temporaryName: String
        private let original: Darwin.stat?
        private let userID: uid_t
        private let groupID: gid_t
        private let mode: mode_t
        private var committed = false

        init(at destination: URL, stagingDirectory: URL? = nil, data: Data?, userID: uid_t, groupID: gid_t, mode: mode_t) throws {
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
            let stagingDirectory = stagingDirectory ?? directory
            let temporaryURL = stagingDirectory.appendingPathComponent(temporaryName)
            self.temporaryURL = temporaryURL
            let directoryFD = try Self.openDirectory(directory, userID: userID, groupID: groupID)
            var prepared = false
            var stagingDirectoryFD: Int32 = -1
            var stagedFD: Int32 = -1
            defer {
                if !prepared {
                    if stagedFD >= 0 { close(stagedFD) }
                    if stagingDirectoryFD >= 0 {
                        _ = unlinkat(stagingDirectoryFD, temporaryName, 0)
                        close(stagingDirectoryFD)
                    }
                    close(directoryFD)
                }
            }
            stagingDirectoryFD = try Self.openDirectory(stagingDirectory, userID: userID, groupID: groupID)
            let existingFD = openat(directoryFD, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            if existingFD >= 0 {
                defer { close(existingFD) }
                try SecureFile.assertRegularFile(fileDescriptor: existingFD,
                                                 context: "installed file \(destination.path)",
                                                 expectedUserID: userID,
                                                 expectedGroupID: groupID,
                                                 expectedMode: mode)
                var info = Darwin.stat()
                guard fstat(existingFD, &info) == 0 else {
                    throw posixInstallFailure("Failed to inspect installed file \(destination.path)", errno)
                }
                original = info
            } else if errno == ENOENT {
                original = nil
            } else {
                throw posixInstallFailure("Failed to inspect installed file \(destination.path)", errno)
            }
            if let data {
                stagedFD = openat(stagingDirectoryFD, temporaryName, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, 0o600)
                guard stagedFD >= 0 else {
                    throw posixInstallFailure("Failed to create staged file \(temporaryURL.path)", errno)
                }
                try FileIO.writeAll(data, to: stagedFD)
                guard fchown(stagedFD, userID, groupID) == 0,
                      fchmod(stagedFD, mode) == 0,
                      fsync(stagedFD) == 0 else {
                    throw posixInstallFailure("Failed to prepare staged file \(temporaryURL.path)", errno)
                }
                try SecureFile.assertRegularFile(fileDescriptor: stagedFD,
                                                 context: "staged file \(temporaryURL.path)",
                                                 expectedUserID: userID,
                                                 expectedGroupID: groupID,
                                                 expectedMode: mode)
                guard fsync(stagingDirectoryFD) == 0 else {
                    throw posixInstallFailure("Failed to sync install directory \(stagingDirectory.path)", errno)
                }
            }
            self.directoryFD = directoryFD
            self.stagingDirectoryFD = stagingDirectoryFD
            self.stagedFD = stagedFD
            prepared = true
        }

        deinit {
            if !preserveTemporary,
               unlinkat(stagingDirectoryFD, temporaryName, 0) != 0,
               errno != ENOENT {
                fputs("\(AppIdentity.executableName): could not remove setup temporary file \(temporaryURL.path): \(String(cString: strerror(errno)))\n", stderr)
            }
            if stagedFD >= 0 { close(stagedFD) }
            close(stagingDirectoryFD)
            close(directoryFD)
        }

        private static func openDirectory(_ directory: URL, userID: uid_t, groupID: gid_t) throws -> Int32 {
            let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            guard directoryFD >= 0 else {
                throw posixInstallFailure("Failed to open install directory \(directory.path)", errno)
            }
            var directoryInfo = Darwin.stat()
            guard fstat(directoryFD, &directoryInfo) == 0,
                  (directoryInfo.st_mode & S_IFMT) == S_IFDIR,
                  directoryInfo.st_uid == userID,
                  directoryInfo.st_gid == groupID,
                  directoryInfo.st_mode & 0o022 == 0 else {
                close(directoryFD)
                throw SetupError.unsafePath("Refusing to use an unsafe install directory: \(directory.path)")
            }
            return directoryFD
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
                try verifyName(temporaryName, in: stagingDirectoryFD, path: temporaryURL, fileDescriptor: stagedFD)
                let flags = original == nil ? RENAME_EXCL : RENAME_SWAP
                guard renameatx_np(stagingDirectoryFD, temporaryName, directoryFD, name, UInt32(flags)) == 0 else {
                    throw posixInstallFailure("Failed to install \(destination.path)", errno)
                }
            } else if original != nil {
                guard renameatx_np(directoryFD, name, stagingDirectoryFD, temporaryName, UInt32(RENAME_EXCL)) == 0 else {
                    throw posixInstallFailure("Failed to remove \(destination.path)", errno)
                }
            } else {
                return
            }
            committed = true
            if stagedFD >= 0 {
                try verifyName(name, in: directoryFD, path: destination, fileDescriptor: stagedFD)
            }
            try syncDirectories()
        }

        func restore() throws {
            guard committed else { return }
            if stagedFD >= 0 {
                try verifyName(name, in: directoryFD, path: destination, fileDescriptor: stagedFD)
            }
            let result: Int32
            if let original {
                var backup = Darwin.stat()
                guard fstatat(stagingDirectoryFD, temporaryName, &backup, AT_SYMLINK_NOFOLLOW) == 0,
                      backup.st_dev == original.st_dev,
                      backup.st_ino == original.st_ino else {
                    throw SetupError.installFailed("The previous installation file changed unexpectedly: \(temporaryURL.path)")
                }
                let flags = stagedFD >= 0 ? RENAME_SWAP : RENAME_EXCL
                result = renameatx_np(stagingDirectoryFD, temporaryName, directoryFD, name, UInt32(flags))
            } else {
                result = renameatx_np(directoryFD, name, stagingDirectoryFD, temporaryName, UInt32(RENAME_EXCL))
            }
            guard result == 0 else {
                throw posixInstallFailure("Failed to restore \(destination.path)", errno)
            }
            committed = false
            try syncDirectories()
        }

        private func syncDirectories() throws {
            for (descriptor, directory) in [(directoryFD, destination.deletingLastPathComponent()),
                                            (stagingDirectoryFD, temporaryURL.deletingLastPathComponent())] {
                guard fsync(descriptor) == 0 else {
                    throw posixInstallFailure("Failed to sync install directory \(directory.path)", errno)
                }
            }
        }

        private func verifyName(_ name: String, in directory: Int32, path: URL, fileDescriptor: Int32) throws {
            var descriptorInfo = Darwin.stat()
            var pathInfo = Darwin.stat()
            guard fstat(fileDescriptor, &descriptorInfo) == 0,
                  fstatat(directory, name, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
                  descriptorInfo.st_dev == pathInfo.st_dev,
                  descriptorInfo.st_ino == pathInfo.st_ino else {
                throw SetupError.installFailed("The setup file changed unexpectedly: \(path.path)")
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
        domains.formUnion(RouteManager.webAuthBootstrapResolverDomains)
        return domains.sorted()
    }

    static func cleanPrivilegedStateAfterUninstall(in store: StateDirectory = StateDirectory()) throws {
        let knownFiles = [
            SessionState.lockName,
            ManagedReconnectBudget.fileName,
            ManagedReconnectBudget.lockName,
            RemoteHostRouteLedger.fileName,
            RemoteHostRouteLedger.lockName,
            ControllerLock.fileName,
        ]
        try store.withAnchor { directoryFD, userID, groupID in
            for name in knownFiles {
                if try AnchoredFileIO.ownedRegularFileExists(in: directoryFD,
                                                             name: name,
                                                             userID: userID,
                                                             groupID: groupID) {
                    try AnchoredFileIO.removeFileAndSync(in: directoryFD, name: name)
                }
            }
        }
        try removeDirectoryIfEmpty(store.url, label: "privileged state directory")
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
