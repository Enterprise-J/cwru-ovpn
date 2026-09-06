import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct SetupAndShellIntegrationTests {
    @Test
    func privilegedExecutableRejectsMutableLoadPaths() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-executable-trust")
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("fixture.c")
        let executable = directory.appendingPathComponent("fixture")
        try "int main(void) { return 0; }\n".write(to: source, atomically: true, encoding: .utf8)
        let compiler = Shell()
        let arguments = ["clang", "-arch", "arm64", source.path, "-o", executable.path]
        _ = try compiler.run("/usr/bin/xcrun", arguments: arguments)
        let valid = try Data(contentsOf: executable)
        try ExecutableTrust.validate(valid)

        _ = try compiler.run("/usr/bin/xcrun", arguments: arguments + ["-Wl,-rpath,/opt/tools/lib"])
        let unsafeSearchPath = try Data(contentsOf: executable)
        #expect(throws: ExecutableTrustError.self) { try ExecutableTrust.validate(unsafeSearchPath) }

        let librarySource = directory.appendingPathComponent("library.c")
        let library = directory.appendingPathComponent("libfixture.dylib")
        try "int fixture(void) { return 0; }\n".write(to: librarySource, atomically: true, encoding: .utf8)
        _ = try compiler.run("/usr/bin/xcrun", arguments: [
            "clang", "-arch", "arm64", "-dynamiclib", librarySource.path, "-o", library.path,
            "-Wl,-install_name,@rpath/libfixture.dylib",
        ])
        try "extern int fixture(void); int main(void) { return fixture(); }\n"
            .write(to: source, atomically: true, encoding: .utf8)
        _ = try compiler.run("/usr/bin/xcrun", arguments: arguments + [
            "-Xlinker", "-weak_library", "-Xlinker", library.path,
        ])
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
        let files = [(paths.profile, 0o600), (paths.manifest, 0o644), (paths.executable, 0o555), (paths.sudoers, 0o440)]
        if existing {
            for (file, mode) in files {
                try Data("previous contents".utf8).write(to: file)
                try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: file.path)
            }
        }
        try Setup.installConfiguration(profileData: profile,
                                       executableData: executable,
                                       userID: getuid(), groupID: getgid(), paths: paths,
                                       systemUserID: getuid(), systemGroupID: getgid()) { staged in
            let stagedProfile = try Data(contentsOf: staged.profile)
            let stagedExecutable = try Data(contentsOf: staged.executable)
            let stagedManifest = try String(contentsOf: staged.manifest, encoding: .utf8)
            let stagedSudoers = try String(contentsOf: staged.sudoers, encoding: .utf8)
            #expect(stagedProfile == profile)
            #expect(stagedExecutable == executable)
            #expect(stagedManifest == ProfileManifest.digest(of: profile) + "\n")
            #expect(stagedSudoers.contains("sha256:\(ProfileManifest.digest(of: executable))"))
            for destination in [paths.profile, paths.manifest, paths.executable, paths.sudoers] {
                if existing {
                    let current = try String(contentsOf: destination, encoding: .utf8)
                    #expect(current == "previous contents")
                } else {
                    #expect(!FileManager.default.fileExists(atPath: destination.path))
                }
            }
        }
        for (file, mode) in files {
            try SecureFile.assertRegularFile(atPath: file.path, context: "installed fixture",
                                             expectedUserID: getuid(), expectedGroupID: getgid(), expectedMode: mode_t(mode))
        }
        #expect(try Data(contentsOf: paths.profile) == profile)
        #expect(try Data(contentsOf: paths.executable) == executable)
        #expect(try String(contentsOf: paths.manifest, encoding: .utf8) == ProfileManifest.digest(of: profile) + "\n")
        #expect(try String(contentsOf: paths.sudoers, encoding: .utf8).contains("sha256:\(ProfileManifest.digest(of: executable))"))
        try expectNoSetupArtifacts(in: directory)
    }

    @Test(arguments: [false, true], ["validation", "profile", "manifest", "executable", "sudoers"])
    func setupRestoresInstallationAfterFailure(existing: Bool, failure: String) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-setup-rollback")
        defer { try? FileManager.default.removeItem(at: directory) }
        let paths = try installationPaths(in: directory)
        let files = [(paths.profile, 0o600), (paths.manifest, 0o644), (paths.executable, 0o555), (paths.sudoers, 0o440)]
        let oldProfile = Data("client\nremote old.example 1194\n".utf8)
        let oldExecutable = Data("previous executable".utf8)
        let originals = [
            paths.profile: oldProfile,
            paths.manifest: Data((ProfileManifest.digest(of: oldProfile) + "\n").utf8),
            paths.executable: oldExecutable,
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
                                           userID: getuid(), groupID: getgid(), paths: paths,
                                           systemUserID: getuid(), systemGroupID: getgid()) { staged in
                if failure == "validation" {
                    throw POSIXError(.EINVAL)
                }
                let failedFile: URL
                switch failure {
                case "profile": failedFile = staged.profile
                case "manifest": failedFile = staged.manifest
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
        for path in [profileDirectory, helperDirectory, sudoersDirectory] {
            try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
        }
        return Setup.InstallationPaths(profile: profileDirectory.appendingPathComponent("profile.ovpn"),
                                       manifest: helperDirectory.appendingPathComponent("approved-profile.sha256"),
                                       executable: helperDirectory.appendingPathComponent("cwru-ovpn"),
                                       sudoers: sudoersDirectory.appendingPathComponent("cwru-ovpn"))
    }

    private func expectNoSetupArtifacts(in directory: URL) throws {
        let enumerator = try #require(FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil))
        #expect(!enumerator.allObjects.compactMap { $0 as? URL }.contains { $0.pathExtension == "setup" })
    }

    @Test
    func setupInstallationLockIsExclusive() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-setup-lock")
        defer { try? FileManager.default.removeItem(at: directory) }
        let lockFile = directory.appendingPathComponent("controller.lock")
        do {
            let firstLock = try ControllerLock(at: lockFile)
            defer { withExtendedLifetime(firstLock) {} }
            #expect(throws: ControllerLockError.self) {
                _ = try ControllerLock(at: lockFile)
            }
        }
        _ = try ControllerLock(at: lockFile)
    }

    @Test
    func setupRejectsPersistedSessionState() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-setup-session-guard")
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let store = StateDirectory(
            directory: directory.appendingPathComponent("state", isDirectory: true))
        let lockFile = directory.appendingPathComponent("controller.lock")
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
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true)
        try session.save(to: store)
        #expect(
            throws: (any Error).self,
            "Setup should refuse to replace the helper while recovery state exists."
        ) {
            _ = try Setup.acquireInstallationGuard(
                operation: "setup",
                lockFile: lockFile,
                sessionStore: store)
        }

        try SessionState.remove(from: store)
        _ = try Setup.acquireInstallationGuard(
            operation: "setup",
            lockFile: lockFile,
            sessionStore: store)
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
        _ = try Shell().run(
            "/usr/bin/xattr",
            arguments: ["-w", "com.cwru-ovpn.test-fixture", "preserved", anchored.path])
        _ = try Shell().run(
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
        let anchoredXattr = try Shell().run(
            "/usr/bin/xattr",
            arguments: ["-p", "com.cwru-ovpn.test-fixture", anchored.path]
        ).stdout
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let anchoredACL = try Shell().run("/bin/ls", arguments: ["-lde", anchored.path]).stdout
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
