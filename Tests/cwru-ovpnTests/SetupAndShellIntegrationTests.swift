import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct SetupAndShellIntegrationTests {
    @Test(arguments: ["regular", "symlink", "hardlink", "unexpected"])
    func applicationArchivesContainOnlyRegularBundleFiles(kind: String) throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let installer = try String(contentsOf: root.appendingPathComponent("scripts/setup.sh"), encoding: .utf8)
        let start = try #require(installer.range(of: "validate_application_archive() {"))
        let end = try #require(installer.range(of: "select_install_source() {", range: start.upperBound..<installer.endIndex))
        let validation = String(installer[start.lowerBound..<end.lowerBound]) + "\nvalidate_application_archive \"$1\"\n"
        let directory = temporaryDirectory(named: "cwru-ovpn-archive")
        defer { try? FileManager.default.removeItem(at: directory) }
        let application = directory.appendingPathComponent("cwru-ovpn.app")
        let files = ["Contents/Info.plist", "Contents/MacOS/cwru-ovpn", "Contents/_CodeSignature/CodeResources"]
        for file in files {
            let url = application.appendingPathComponent(file)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data("fixture".utf8).write(to: url)
        }
        let info = application.appendingPathComponent(files[0])
        let resources = application.appendingPathComponent(files[2])
        switch kind {
        case "symlink":
            try FileManager.default.removeItem(at: info)
            try FileManager.default.createSymbolicLink(atPath: info.path, withDestinationPath: "/private/tmp/unrelated")
        case "hardlink":
            try FileManager.default.removeItem(at: resources)
            try #require(link(info.path, resources.path) == 0)
        case "unexpected":
            try Data("unexpected".utf8).write(to: application.appendingPathComponent("extra"))
        default:
            break
        }
        let archive = directory.appendingPathComponent("application.tar.gz")
        _ = try CommandRunner().run("/usr/bin/tar", arguments: ["-czf", archive.path, "-C", directory.path, "cwru-ovpn.app"],
                                    environmentOverrides: ["COPYFILE_DISABLE": "1"])
        let result = try CommandRunner().run("/bin/bash", arguments: ["-euo", "pipefail", "-c", validation, "archive", archive.path],
                                             allowNonZero: true)
        #expect((result.exitCode == 0) == (kind == "regular"))
    }

    @Test
    func applicationBundleSealsIndependentIdentity() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let directory = temporaryDirectory(named: "cwru-ovpn-application-identity")
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("fixture.c")
        let executable = directory.appendingPathComponent("fixture")
        let application = directory.appendingPathComponent("cwru-ovpn.app")
        try "int main(void) { return 0; }\n".write(to: source, atomically: true, encoding: .utf8)
        _ = try CommandRunner().run("/usr/bin/xcrun", arguments: ["clang", source.path, "-o", executable.path],
                                    environmentOverrides: ["TMPDIR": directory.path])
        _ = try CommandRunner().run("/bin/bash", arguments: [root.appendingPathComponent("scripts/build-app-bundle.sh").path,
                                                    executable.path, application.path], timeout: 30)
        let infoURL = application.appendingPathComponent("Contents/Info.plist")
        let info = try Data(contentsOf: infoURL)
        try AppIdentity.validateBundleInfo(info)
        try AppIdentity.verifyBundleSignature(at: application)
        let bundle = try #require(Bundle(url: application))
        #expect(bundle.bundleIdentifier == AppIdentity.bundleIdentifier)
        #expect(bundle.executableURL?.lastPathComponent == AppIdentity.executableName)
        let installedDirectory = directory.appendingPathComponent("installed")
        try FileManager.default.createDirectory(at: installedDirectory, withIntermediateDirectories: false)
        let paths = try installationPaths(in: installedDirectory)
        for _ in 0..<2 {
            try Setup.installConfiguration(profileData: nil,
                                           executableData: Data(contentsOf: application.appendingPathComponent("Contents/MacOS/cwru-ovpn")),
                                           applicationInfo: info,
                                           codeResources: Data(contentsOf: application.appendingPathComponent("Contents/_CodeSignature/CodeResources")),
                                           userID: getuid(), groupID: getgid(), paths: paths,
                                           systemUserID: getuid(), systemGroupID: getgid(),
                                           verifyInstalled: { installed in
                try AppIdentity.verifyBundleSignature(at: AppIdentity.applicationDirectory(for: installed.executable))
            }) { _ in }
        }
        try expectNoSetupArtifacts(in: installedDirectory)

        var changed = try #require(PropertyListSerialization.propertyList(from: info, format: nil) as? [String: Any])
        changed["CFBundleIdentifier"] = "com.apple.Terminal"
        let changedInfo = try PropertyListSerialization.data(fromPropertyList: changed, format: .xml, options: 0)
        #expect(throws: SetupError.self) { try AppIdentity.validateBundleInfo(changedInfo) }
        try changedInfo.write(to: infoURL)
        #expect(throws: (any Error).self) { try AppIdentity.verifyBundleSignature(at: application) }
    }

    @Test
    func installMetadataUsesStructuredJSON() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent("scripts/setup.sh"), encoding: .utf8)
        let start = try #require(source.range(of: "read_dist_build_info_app_version() {"))
        let end = try #require(source.range(of: "verify_dist_build_info_file() {", range: start.upperBound..<source.endIndex))
        let functions = String(source[start.lowerBound..<end.lowerBound])
        let script = functions + "\nDIST_DIR=\"$1\"\nread_dist_build_info_artifact_field \"$2\" \"$3\"\n"
        let directory = temporaryDirectory(named: "cwru-ovpn-install-metadata")
        defer { try? FileManager.default.removeItem(at: directory) }
        let metadata = directory.appendingPathComponent("build-info.json")
        let content: [String: Any] = [
            "appVersion": AppIdentity.version,
            "artifacts": [["file": "other", "sha256": "other digest"],
                          ["sha256": "selected digest", "file": "selected"]],
        ]
        let formats: [JSONSerialization.WritingOptions] = [.sortedKeys, [.prettyPrinted, .sortedKeys]]
        for format in formats {
            try JSONSerialization.data(withJSONObject: content, options: format).write(to: metadata)
            let result = try CommandRunner().run("/bin/bash", arguments: ["-eu", "-c", script, "metadata", directory.path, "selected", "sha256"])
            #expect(result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "selected digest")
        }
        for invalid in ["{\"artifacts\":", "{\"artifacts\":[{\"file\":\"selected\",\"sha256\":42}]}"] {
            try Data(invalid.utf8).write(to: metadata)
            let result = try CommandRunner().run("/bin/bash", arguments: ["-eu", "-c", script, "metadata", directory.path, "selected", "sha256"], allowNonZero: true)
            #expect(result.exitCode != 0)
        }
    }

    @Test
    func privilegedExecutableRejectsMutableLoadPaths() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-executable-trust")
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("fixture.c")
        let executable = directory.appendingPathComponent("fixture")
        try "int main(void) { return 0; }\n".write(to: source, atomically: true, encoding: .utf8)
        let compiler = CommandRunner()
        let environment = ["TMPDIR": directory.path]
        let arguments = ["clang", "-arch", "arm64", source.path, "-o", executable.path]
        _ = try compiler.run("/usr/bin/xcrun", arguments: arguments, environmentOverrides: environment)
        let valid = try Data(contentsOf: executable)
        try ExecutableTrust.validate(valid)

        _ = try compiler.run("/usr/bin/xcrun", arguments: arguments + ["-Wl,-rpath,/opt/tools/lib"],
                             environmentOverrides: environment)
        let unsafeSearchPath = try Data(contentsOf: executable)
        #expect(throws: ExecutableTrustError.self) { try ExecutableTrust.validate(unsafeSearchPath) }

        let librarySource = directory.appendingPathComponent("library.c")
        let library = directory.appendingPathComponent("libfixture.dylib")
        try "int fixture(void) { return 0; }\n".write(to: librarySource, atomically: true, encoding: .utf8)
        _ = try compiler.run("/usr/bin/xcrun", arguments: [
            "clang", "-arch", "arm64", "-dynamiclib", librarySource.path, "-o", library.path,
            "-Wl,-install_name,@rpath/libfixture.dylib",
        ], environmentOverrides: environment)
        try "extern int fixture(void); int main(void) { return fixture(); }\n"
            .write(to: source, atomically: true, encoding: .utf8)
        _ = try compiler.run("/usr/bin/xcrun", arguments: arguments + [
            "-Xlinker", "-weak_library", "-Xlinker", library.path,
        ], environmentOverrides: environment)
        let unsafeDependency = try Data(contentsOf: executable)
        #expect(throws: ExecutableTrustError.self) { try ExecutableTrust.validate(unsafeDependency) }

        var wrongArchitecture = valid
        wrongArchitecture.replaceSubrange(4..<8, with: [0, 0, 0, 0])
        var invalidCommand = valid
        invalidCommand.replaceSubrange(36..<40, with: [0, 0, 0, 0])
        for malformed in [Data(valid.prefix(31)), Data(valid.prefix(40)), wrongArchitecture, invalidCommand] {
            #expect(throws: ExecutableTrustError.self) { try ExecutableTrust.validate(malformed) }
        }
    }

    @Test(arguments: [false, true])
    func setupCommitsMatchingInstallationFiles(existing: Bool) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-setup-commit")
        defer { try? FileManager.default.removeItem(at: directory) }
        let paths = try installationPaths(in: directory)
        let profile = Data("client\n".utf8)
        let executable = Data("new executable".utf8)
        let files = [(paths.profile, 0o600), (paths.manifest, 0o644), (paths.executable, 0o555),
                     (paths.applicationInfo, 0o644), (paths.codeResources, 0o644), (paths.sudoers, 0o440)]
        if existing {
            for (file, mode) in files {
                try Data("previous contents".utf8).write(to: file)
                try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: file.path)
            }
        }
        try Setup.installConfiguration(profileData: profile,
                                       executableData: executable,
                                       applicationInfo: Data("application info".utf8),
                                       codeResources: Data("signature resources".utf8),
                                       userID: getuid(), groupID: getgid(), paths: paths,
                                       systemUserID: getuid(), systemGroupID: getgid()) { staged in
            let stagedProfile = try Data(contentsOf: staged.profile)
            let stagedExecutable = try Data(contentsOf: staged.executable)
            let stagedManifest = try String(contentsOf: staged.manifest, encoding: .utf8)
            let stagedSudoers = try String(contentsOf: staged.sudoers, encoding: .utf8)
            #expect(try Data(contentsOf: staged.applicationInfo) == Data("application info".utf8))
            #expect(try Data(contentsOf: staged.codeResources) == Data("signature resources".utf8))
            #expect(stagedProfile == profile)
            #expect(stagedExecutable == executable)
            #expect(stagedManifest == ProfileManifest.digest(of: profile) + "\n")
            #expect(stagedSudoers.contains("sha256:\(ProfileManifest.digest(of: executable))"))
            for (destination, _) in files {
                if existing {
                    let current = try String(contentsOf: destination, encoding: .utf8)
                    #expect(current == "previous contents")
                } else {
                    #expect(!FileManager.default.fileExists(atPath: destination.path))
                }
            }
        }
        for (file, mode) in files {
            _ = try SecureFile.readRegularFile(at: file, maximumBytes: 1024 * 1024, context: "installed fixture",
                                               expectedUserID: getuid(), expectedGroupID: getgid(), expectedMode: mode_t(mode))
        }
        #expect(try Data(contentsOf: paths.profile) == profile)
        #expect(try Data(contentsOf: paths.executable) == executable)
        #expect(try Data(contentsOf: paths.applicationInfo) == Data("application info".utf8))
        #expect(try Data(contentsOf: paths.codeResources) == Data("signature resources".utf8))
        #expect(try String(contentsOf: paths.manifest, encoding: .utf8) == ProfileManifest.digest(of: profile) + "\n")
        #expect(try String(contentsOf: paths.sudoers, encoding: .utf8).contains("sha256:\(ProfileManifest.digest(of: executable))"))
        try expectNoSetupArtifacts(in: directory)
    }

    @Test(arguments: [false, true], ["validation", "profile", "manifest", "applicationInfo", "codeResources", "executable", "sudoers", "installed"])
    func setupRestoresInstallationAfterFailure(existing: Bool, failure: String) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-setup-rollback")
        defer { try? FileManager.default.removeItem(at: directory) }
        let paths = try installationPaths(in: directory)
        let files = [(paths.profile, 0o600), (paths.manifest, 0o644), (paths.executable, 0o555),
                     (paths.applicationInfo, 0o644), (paths.codeResources, 0o644), (paths.sudoers, 0o440)]
        let oldProfile = Data("client\nremote old.example 1194\n".utf8)
        let oldExecutable = Data("previous executable".utf8)
        let originals = [
            paths.profile: oldProfile,
            paths.manifest: Data((ProfileManifest.digest(of: oldProfile) + "\n").utf8),
            paths.executable: oldExecutable,
            paths.applicationInfo: Data("previous application info".utf8),
            paths.codeResources: Data("previous signature resources".utf8),
            paths.sudoers: Data((Setup.renderSudoers(userID: getuid(), executablePath: paths.executable.path,
                                                   executableDigest: ProfileManifest.digest(of: oldExecutable)) + "\n").utf8),
        ]
        var originalInodes: [URL: ino_t] = [:]
        if existing {
            for (file, mode) in files {
                try #require(originals[file]).write(to: file)
                try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: file.path)
                var info = Darwin.stat()
                try #require(lstat(file.path, &info) == 0)
                originalInodes[file] = info.st_ino
            }
        }
        #expect(throws: (any Error).self) {
            try Setup.installConfiguration(profileData: Data("client\n".utf8),
                                           executableData: Data("new executable".utf8),
                                           applicationInfo: Data("new application info".utf8),
                                           codeResources: Data("new signature resources".utf8),
                                           userID: getuid(), groupID: getgid(), paths: paths,
                                           systemUserID: getuid(), systemGroupID: getgid(),
                                           verifyInstalled: { _ in
                if failure == "installed" { throw POSIXError(.EINVAL) }
            }) { staged in
                if failure == "installed" { return }
                if failure == "validation" {
                    throw POSIXError(.EINVAL)
                }
                let failedFile: URL
                switch failure {
                case "profile": failedFile = staged.profile
                case "manifest": failedFile = staged.manifest
                case "applicationInfo": failedFile = staged.applicationInfo
                case "codeResources": failedFile = staged.codeResources
                case "executable": failedFile = staged.executable
                default: failedFile = staged.sudoers
                }
                try FileManager.default.removeItem(at: failedFile)
            }
        }
        for (file, mode) in files {
            if existing {
                #expect(try Data(contentsOf: file) == originals[file])
                var info = Darwin.stat()
                try #require(lstat(file.path, &info) == 0)
                #expect(info.st_ino == originalInodes[file])
                #expect(info.st_mode & 0o777 == mode_t(mode))
            } else {
                #expect(!FileManager.default.fileExists(atPath: file.path))
            }
        }
        try expectNoSetupArtifacts(in: directory)
    }

    @Test
    func setupRestoresRemovedManifestOnLaterFailure() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-setup-manifest-rollback")
        defer { try? FileManager.default.removeItem(at: directory) }
        let paths = try installationPaths(in: directory)
        try "previous approval\n".write(to: paths.manifest, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: paths.manifest.path)
        #expect(throws: (any Error).self) {
            try Setup.installConfiguration(profileData: nil,
                                           executableData: Data("new executable".utf8),
                                           applicationInfo: Data("new application info".utf8),
                                           codeResources: Data("new signature resources".utf8),
                                           userID: getuid(), groupID: getgid(), paths: paths,
                                           systemUserID: getuid(), systemGroupID: getgid()) { staged in
                try FileManager.default.removeItem(at: staged.executable)
            }
        }
        #expect(try String(contentsOf: paths.manifest, encoding: .utf8) == "previous approval\n")
        #expect(!FileManager.default.fileExists(atPath: paths.executable.path))
        #expect(!FileManager.default.fileExists(atPath: paths.sudoers.path))
        try expectNoSetupArtifacts(in: directory)
    }

    private func installationPaths(in directory: URL) throws -> Setup.InstallationPaths {
        let profileDirectory = directory.appendingPathComponent("user-state", isDirectory: true)
        let helperDirectory = directory.appendingPathComponent("helper", isDirectory: true)
        let sudoersDirectory = directory.appendingPathComponent("sudoers", isDirectory: true)
        let application = helperDirectory.appendingPathComponent("cwru-ovpn.app/Contents", isDirectory: true)
        for path in [profileDirectory, helperDirectory, sudoersDirectory,
                     application.deletingLastPathComponent(), application,
                     application.appendingPathComponent("MacOS"), application.appendingPathComponent("_CodeSignature")] {
            try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
        }
        return Setup.InstallationPaths(profile: profileDirectory.appendingPathComponent("profile.ovpn"),
                                       manifest: helperDirectory.appendingPathComponent("approved-profile.sha256"),
                                       executable: application.appendingPathComponent("MacOS/cwru-ovpn"),
                                       applicationInfo: application.appendingPathComponent("Info.plist"),
                                       codeResources: application.appendingPathComponent("_CodeSignature/CodeResources"),
                                       sudoers: sudoersDirectory.appendingPathComponent("cwru-ovpn"))
    }

    private func expectNoSetupArtifacts(in directory: URL) throws {
        let enumerator = try #require(FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil))
        #expect(!enumerator.allObjects.compactMap { $0 as? URL }.contains { $0.pathExtension == "setup" })
    }

    @Test(arguments: [false, true], [false, true])
    func fileLocksAreExclusive(duplicateDescriptor: Bool, controller: Bool) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-file-lock")
        defer { try? FileManager.default.removeItem(at: directory) }
        let lockFile = directory.appendingPathComponent("controller.lock")
        var duplicate: Int32 = -1
        defer { if duplicate >= 0 { close(duplicate) } }
        weak var releasedLock: ControllerLock?
        let whileLocked = {
            for _ in 0..<2 {
                #expect(throws: ControllerLockError.self) {
                    _ = try controllerLock(at: lockFile)
                }
            }
            if duplicateDescriptor {
                var expected = stat()
                try #require(lstat(lockFile.path, &expected) == 0)
                let descriptor = try #require((0..<getdtablesize()).first { descriptor in
                    var info = stat()
                    return fstat(descriptor, &info) == 0 && info.st_dev == expected.st_dev && info.st_ino == expected.st_ino
                })
                duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
                try #require(duplicate >= 0)
            }
        }
        if controller {
            let firstLock = try controllerLock(at: lockFile)
            releasedLock = firstLock
            defer { withExtendedLifetime(firstLock) {} }
            try whileLocked()
        } else {
            try StateDirectory(directory: directory).withExclusiveLock(named: lockFile.lastPathComponent) { _, _, _ in
                try whileLocked()
            }
        }
        #expect(releasedLock == nil)
        _ = try controllerLock(at: lockFile)
    }

    @Test
    func uninstallFailurePreservesLifecycleLock() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-uninstall-lock")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory.appendingPathComponent("state"))
        let lock = try ControllerLock(in: store)
        defer { withExtendedLifetime(lock) {} }
        try FileManager.default.createSymbolicLink(
            at: store.url.appendingPathComponent(SessionState.lockName),
            withDestinationURL: directory.appendingPathComponent("untrusted"))

        #expect(throws: (any Error).self) {
            try Setup.cleanPrivilegedStateAfterUninstall(in: store)
        }
        #expect(throws: ControllerLockError.self) {
            _ = try ControllerLock(in: store)
        }
    }

    @Test
    func uninstallRemovesPrivilegedState() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-uninstall-state")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory.appendingPathComponent("state"))
        let lock = try ControllerLock(in: store)
        defer { withExtendedLifetime(lock) {} }
        let files = [SessionState.lockName, ManagedReconnectBudget.fileName, ManagedReconnectBudget.lockName,
                     RemoteHostRouteLedger.fileName, RemoteHostRouteLedger.lockName, "unrecognized"]
        try store.withAnchor { directoryFD, userID, groupID in
            for name in files {
                try AnchoredFileIO.writeOwnedRegularFileAtomically(Data(), in: directoryFD, name: name,
                                                                   userID: userID, groupID: groupID)
            }
        }
        try Setup.cleanPrivilegedStateAfterUninstall(in: store)
        #expect(try FileManager.default.contentsOfDirectory(atPath: store.url.path) == ["unrecognized"])

        try FileManager.default.removeItem(at: store.url.appendingPathComponent("unrecognized"))
        try Setup.cleanPrivilegedStateAfterUninstall(in: store)
        #expect(!FileManager.default.fileExists(atPath: store.url.path))
        _ = try ControllerLock(in: store)
    }

    @Test
    func setupRejectsPersistedSessionState() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-setup-session-guard")
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let store = StateDirectory(
            directory: directory.appendingPathComponent("state", isDirectory: true))
        let session = makeSessionState(
            pid: 41,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: nil,
            physicalGateway: "192.0.2.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true)
        try session.save(in: store)
        #expect(
            throws: (any Error).self,
            "Setup should refuse to replace the helper while recovery state exists."
        ) {
            _ = try Setup.acquireInstallationGuard(operation: "setup", sessionStore: store)
        }

        try SessionState.remove(from: store)
        _ = try Setup.acquireInstallationGuard(operation: "setup", sessionStore: store)
    }

    @Test
    func shellIntegrationBlocks() throws {
        let installedHelperPath = "/Users/test/My Tools/.cwru-ovpn/cwru-ovpn.zsh"
        let initialContent = """
            export PATH="/opt/tools/bin:$PATH"

            # >>> cwru-ovpn >>>
            source \(installedHelperPath)
            # <<< cwru-ovpn <<<
            """

        let installedContent = try ShellIntegration.installBlock(
            into: initialContent,
            helperPath: installedHelperPath)
        #expect(
            installedContent.contains("source '/Users/test/My Tools/.cwru-ovpn/cwru-ovpn.zsh'"),
            "Shell integration should quote helper paths safely in shell rc files.")

        let removedContent = try ShellIntegration.removeBlock(from: installedContent)
        #expect(
            !removedContent.contains("cwru-ovpn"),
            "Removing shell integration should drop the managed marker block.")
        #expect(
            removedContent.contains("export PATH"),
            "Removing shell integration should preserve unrelated shell content.")

        let formattingFixture = "first\n\n\nsecond"
        let formattingInstalled = try ShellIntegration.installBlock(
            into: formattingFixture,
            helperPath: installedHelperPath)
        let formattingRemoved = try ShellIntegration.removeBlock(from: formattingInstalled)
        #expect(
            formattingRemoved == formattingFixture,
            "Installing and removing shell integration must preserve unrelated bytes exactly.")

        #expect(
            throws: (any Error).self,
            "Shell integration should reject an orphan start marker instead of appending a second block."
        ) {
            _ = try ShellIntegration.installBlock(
                into: "before\n\(ShellIntegration.startMarker)\nsource bad\n",
                helperPath: installedHelperPath)
        }
        #expect(throws: (any Error).self, "Shell integration should reject an orphan end marker.") {
            _ = try ShellIntegration.removeBlock(from: "before\n\(ShellIntegration.endMarker)\n")
        }
    }

    @Test
    func shellIntegrationPreservesCRLFAndMixedContent() throws {
        let prefix = "export TEST=1\r\n\r\n"
        let suffix = "export OTHER=2\n\r\n"
        let block = "\(ShellIntegration.startMarker)\r\nsource old-helper\r\n\(ShellIntegration.endMarker)\r\n"
        let content = prefix + block + suffix
        #expect(try ShellIntegration.removeBlock(from: content) == prefix + suffix)

        let installed = try ShellIntegration.installBlock(into: content, helperPath: "/tmp/helper")
        #expect(installed.components(separatedBy: ShellIntegration.startMarker).count == 2)
        #expect(try ShellIntegration.removeBlock(from: installed) == prefix + suffix)

        for original in ["first\r\n\r\nsecond", "first\r\n", "first\nsecond\r\n", "first\r", "\r", "first\r\r"] {
            let updated = try ShellIntegration.installBlock(into: original, helperPath: "/tmp/helper")
            #expect(try ShellIntegration.removeBlock(from: updated) == original)
        }
        #expect(throws: ShellIntegrationError.self) {
            try ShellIntegration.removeBlock(from: "before\r\n\(ShellIntegration.startMarker)\r\nsource helper\r\n")
        }
    }

    @Test
    func shellIntegrationPrivilegedFileAssertions() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-shell-rc")
        defer { try? FileManager.default.removeItem(at: directory) }
        let owner = ResolvedUserIdentity(
            username: NSUserName(),
            userID: getuid(),
            groupID: getgid(),
            homeDirectory: directory)

        let trusted = directory.appendingPathComponent("zshrc")
        try "export PATH=/opt/tools/bin:$PATH\n".write(
            to: trusted, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: trusted.path)
        try ShellIntegration.replaceRCFile(
            at: trusted,
            expectedContent: "export PATH=/opt/tools/bin:$PATH\n",
            updatedContent: "export PATH=/opt/tools/bin:$PATH\n",
            owner: owner)

        let symlinkPath = directory.appendingPathComponent("zshrc-symlink")
        try #require(
            symlink(trusted.path, symlinkPath.path) == 0,
            "Failed to create shell rc symlink fixture.")
        #expect(
            throws: (any Error).self,
            "Privileged shell integration should reject symlinked rc files."
        ) {
            try ShellIntegration.replaceRCFile(
                at: symlinkPath,
                expectedContent: "export PATH=/opt/tools/bin:$PATH\n",
                updatedContent: "changed\n",
                owner: owner)
        }

        let hardlinkSource = directory.appendingPathComponent("zshrc-hardlink-source")
        let hardlinkPath = directory.appendingPathComponent("zshrc-hardlink")
        try "source ~/.profile\n".write(to: hardlinkSource, atomically: true, encoding: .utf8)
        try #require(
            Darwin.link(hardlinkSource.path, hardlinkPath.path) == 0,
            "Failed to create shell rc hardlink fixture.")
        #expect(
            throws: (any Error).self,
            "Privileged shell integration should reject hardlinked rc files."
        ) {
            try ShellIntegration.replaceRCFile(
                at: hardlinkSource,
                expectedContent: "source ~/.profile\n",
                updatedContent: "changed\n",
                owner: owner)
        }

        let writable = directory.appendingPathComponent("zshrc-writable")
        try "export TEST=1\n".write(to: writable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o666], ofItemAtPath: writable.path)
        do {
            try ShellIntegration.replaceRCFile(
                at: writable,
                expectedContent: "export TEST=1\n",
                updatedContent: "changed\n",
                owner: owner)
            try #require(
                Bool(false), "Shell integration should reject group- or world-writable rc files.")
        } catch ShellIntegrationError.writableRCFile(let path) {
            #expect(
                path == writable.path,
                "Unsafe shell-file permission errors should identify the affected file.")
            #expect(
                ShellIntegrationError.writableRCFile(path).localizedDescription.contains(
                    "chmod go-w"),
                "Unsafe shell-file permission errors should provide an actionable repair command.")
        }

        let anchored = directory.appendingPathComponent("zshrc-anchored")
        try "before\n".write(to: anchored, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o640], ofItemAtPath: anchored.path)
        _ = try CommandRunner().run(
            "/usr/bin/xattr",
            arguments: ["-w", "com.cwru-ovpn.test-fixture", "preserved", anchored.path])
        _ = try CommandRunner().run(
            "/bin/chmod",
            arguments: ["+a", "everyone allow read", anchored.path])
        try ShellIntegration.replaceRCFile(
            at: anchored,
            expectedContent: "before\n",
            updatedContent: "after\n",
            owner: owner)
        let anchoredContent = try String(contentsOf: anchored, encoding: .utf8)
        let anchoredPermissions =
            (try FileManager.default.attributesOfItem(atPath: anchored.path)[.posixPermissions]
            as? NSNumber)?.intValue
        let anchoredXattr = try CommandRunner().run(
            "/usr/bin/xattr",
            arguments: ["-p", "com.cwru-ovpn.test-fixture", anchored.path]
        ).stdout
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let anchoredACL = try CommandRunner().run("/bin/ls", arguments: ["-lde", anchored.path]).stdout
        #expect(
            anchoredContent == "after\n" && anchoredPermissions == 0o640,
            "Anchored shell rc replacement should preserve content integrity and permissions.")
        #expect(
            anchoredXattr == "preserved",
            "Anchored shell rc replacement should preserve extended attributes.")
        #expect(
            anchoredACL.contains(" allow read"),
            "Anchored shell rc replacement should preserve access-control entries: \(anchoredACL)")
        #expect(
            throws: (any Error).self,
            "Anchored shell rc replacement should reject a concurrent content change."
        ) {
            try ShellIntegration.replaceRCFile(
                at: anchored,
                expectedContent: "stale\n",
                updatedContent: "unexpected\n",
                owner: owner)
        }
        let contentAfterRejectedChange = try String(contentsOf: anchored, encoding: .utf8)
        #expect(
            contentAfterRejectedChange == "after\n",
            "A rejected concurrent shell rc change must leave the current file untouched.")
    }

    @Test
    func uninstallDiscoversMarkerOwnedResolvers() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-uninstall-resolver-scan")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }
        let managedDomain = "orphaned-managed.example"
        let unmanagedDomain = "unmanaged.example"
        try "\(RouteManager.resolverManagedMarker)\nnameserver 192.0.2.53\n".write(
            to: resolverDirectory.appendingPathComponent(managedDomain),
            atomically: true,
            encoding: .utf8
        )
        try "nameserver 192.0.2.54\n".write(
            to: resolverDirectory.appendingPathComponent(unmanagedDomain),
            atomically: true,
            encoding: .utf8
        )
        let embeddedMarkerDomain = "embedded-marker.example"
        try "nameserver 192.0.2.55\n\(RouteManager.resolverManagedMarker)\n".write(
            to: resolverDirectory.appendingPathComponent(embeddedMarkerDomain),
            atomically: true,
            encoding: .utf8
        )
        let domains = Setup.dnsDomainsForUninstall(resolverDirectory: resolverDirectory)
        #expect(
            domains.contains(managedDomain),
            "Uninstall should discover marker-owned resolver files absent from current config and session state."
        )
        #expect(
            !domains.contains(unmanagedDomain),
            "Uninstall must not claim unmanaged resolver files discovered by directory scan.")
        #expect(
            !domains.contains(embeddedMarkerDomain),
            "Uninstall must require the ownership marker on the resolver file's first line.")
    }

    @Test
    func rejectedShellFileClosesItsDescriptor() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-rc-descriptor")
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent(".zshrc")
        try Data("original".utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o666], ofItemAtPath: file.path)
        let owner = ResolvedUserIdentity(username: "test", userID: getuid(), groupID: getgid(), homeDirectory: directory)
        for _ in 0..<4 {
            #expect(throws: ShellIntegrationError.self) {
                try ShellIntegration.replaceRCFile(at: file, expectedContent: "original", updatedContent: "updated", owner: owner)
            }
        }
        let descriptors = (0..<1024).filter { descriptor in
            var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            return fcntl(Int32(descriptor), F_GETPATH, &buffer) == 0
                && String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self) == file.path
        }
        #expect(descriptors.isEmpty)
    }
}
