import COpenVPN3Wrapper
import Darwin
import Foundation
import Synchronization
import Testing

@testable import cwru_ovpn

@Suite
struct SecureFilesystemTests {
    @Test
    func homeStateParentSwapIsContained() throws {
        let parent = temporaryDirectory(named: "cwru-ovpn-home-parent-swap")
        defer { try? FileManager.default.removeItem(at: parent) }
        let state = parent.appendingPathComponent("state", isDirectory: true)
        let original = parent.appendingPathComponent("state-original", isDirectory: true)
        let removedOriginal = parent.appendingPathComponent(
            "state-removed-original", isDirectory: true)
        let victim = parent.appendingPathComponent("victim", isDirectory: true)
        for directory in [state, victim] {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700])
        }
        let stateSession = state.appendingPathComponent("session.json")
        let victimSession = victim.appendingPathComponent("session.json")
        try Data("state-old".utf8).write(to: stateSession)
        try Data("victim".utf8).write(to: victimSession)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: stateSession.path)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: victimSession.path)

        try AnchoredFileIO.withDirectory(
            at: state,
            parentUserID: getuid(),
            parentGroupID: getgid(),
            userID: getuid(),
            groupID: getgid()
        ) { directoryFD in
            try FileManager.default.moveItem(at: state, to: original)
            guard symlink(victim.path, state.path) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try AnchoredFileIO.writeOwnedRegularFileAtomically(
                Data("state-new".utf8),
                in: directoryFD,
                name: "session.json",
                userID: getuid(),
                groupID: getgid())
        }
        let victimSessionAfterWrite = try Data(contentsOf: victimSession)
        let originalSessionAfterWrite = try Data(
            contentsOf: original.appendingPathComponent("session.json"))
        #expect(
            victimSessionAfterWrite == Data("victim".utf8),
            "Home session writes should not follow a replacement state-directory symlink.")
        #expect(
            originalSessionAfterWrite == Data("state-new".utf8),
            "Home session writes should remain bound to the opened state directory.")

        try FileManager.default.removeItem(at: state)
        try FileManager.default.moveItem(at: original, to: state)
        try AnchoredFileIO.withDirectory(
            at: state,
            parentUserID: getuid(),
            parentGroupID: getgid(),
            userID: getuid(),
            groupID: getgid()
        ) { directoryFD in
            try FileManager.default.moveItem(at: state, to: removedOriginal)
            guard symlink(victim.path, state.path) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try AnchoredFileIO.removeFileIfPresent(in: directoryFD, name: "session.json")
        }
        let victimSessionAfterRemoval = try Data(contentsOf: victimSession)
        #expect(
            victimSessionAfterRemoval == Data("victim".utf8),
            "Home session removal should not follow a replacement state-directory symlink.")
        #expect(
            !FileManager.default.fileExists(
                atPath: removedOriginal.appendingPathComponent("session.json").path),
            "Home session removal should stay inside the opened state directory.")
    }

    @Test
    func setupProfileParentSwapIsContained() throws {
        let parent = temporaryDirectory(named: "cwru-ovpn-profile-parent-swap")
        defer { try? FileManager.default.removeItem(at: parent) }
        let state = parent.appendingPathComponent("state", isDirectory: true)
        let original = parent.appendingPathComponent("state-original", isDirectory: true)
        let victim = parent.appendingPathComponent("victim", isDirectory: true)
        for directory in [state, victim] {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700])
        }
        let source = parent.appendingPathComponent("source.ovpn")
        let sourceData = Data("client\nremote vpn.case.edu 1194 udp\n".utf8)
        try sourceData.write(to: source)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: source.path)
        let stateProfile = state.appendingPathComponent("profile.ovpn")
        let victimProfile = victim.appendingPathComponent("profile.ovpn")
        try Data("state-old".utf8).write(to: stateProfile)
        try Data("victim".utf8).write(to: victimProfile)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: stateProfile.path)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: victimProfile.path)

        let installedData = try ProfileManifest.readProfileData(
            at: source,
            expectedUserID: getuid())
        try Setup.validateProfileForApproval(profileData: installedData)
        try AnchoredFileIO.withDirectory(
            at: state,
            parentUserID: getuid(),
            parentGroupID: getgid(),
            userID: getuid(),
            groupID: getgid()
        ) { directoryFD in
            try FileManager.default.moveItem(at: state, to: original)
            guard symlink(victim.path, state.path) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
            try AnchoredFileIO.writeOwnedRegularFileAtomically(
                installedData,
                in: directoryFD,
                name: "profile.ovpn",
                userID: getuid(),
                groupID: getgid())
        }
        #expect(
            installedData == sourceData,
            "Setup should pin the profile bytes that were actually validated.")
        let victimProfileData = try Data(contentsOf: victimProfile)
        let originalProfileData = try Data(
            contentsOf: original.appendingPathComponent("profile.ovpn"))
        #expect(
            victimProfileData == Data("victim".utf8),
            "Setup profile installation should not follow a replacement state-directory symlink.")
        #expect(
            originalProfileData == sourceData,
            "Setup profile installation should remain bound to the opened state directory.")
    }

    @Test
    func anchoredStateIORejectsUnsafeNodes() throws {
        for value in ["", ".", "..", "../x", "a/b", "/absolute", "nul\0name"] {
            #expect(
                throws: (any Error).self, "Anchored state I/O should reject unsafe path components."
            ) {
                try AnchoredFileIO.validateComponent(value)
            }
        }

        let parent = temporaryDirectory(named: "cwru-ovpn-unsafe-anchor")
        defer { try? FileManager.default.removeItem(at: parent) }
        let victim = parent.appendingPathComponent("victim", isDirectory: true)
        let state = parent.appendingPathComponent("state", isDirectory: true)
        try FileManager.default.createDirectory(
            at: victim,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        guard symlink(victim.path, state.path) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        #expect(throws: (any Error).self, "Home state I/O should reject a symbolic-link directory.")
        {
            try AnchoredFileIO.withDirectory(
                at: state,
                parentUserID: getuid(),
                parentGroupID: getgid(),
                userID: getuid(),
                groupID: getgid()
            ) { _ in }
        }

        try FileManager.default.removeItem(at: state)
        try FileManager.default.createDirectory(
            at: state,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o755])
        #expect(
            throws: (any Error).self,
            "Home state I/O should reject an existing directory with unsafe permissions."
        ) {
            try AnchoredFileIO.withDirectory(
                at: state,
                parentUserID: getuid(),
                parentGroupID: getgid(),
                userID: getuid(),
                groupID: getgid()
            ) { _ in }
        }
        let permissions =
            try FileManager.default.attributesOfItem(atPath: state.path)[.posixPermissions]
            as? NSNumber
        #expect(
            permissions?.intValue == 0o755,
            "Anchored directory validation should not chmod an existing unsafe directory.")
    }

    @Test
    func runtimePathSecurityAttributesRejectUnsafeNodes() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-secure-node")
        defer { try? FileManager.default.removeItem(at: directory) }

        let target = directory.appendingPathComponent("target")
        let link = directory.appendingPathComponent("link")
        let hardlink = directory.appendingPathComponent("hardlink")
        try "safe\n".write(to: target, atomically: true, encoding: .utf8)
        guard symlink(target.path, link.path) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        guard Darwin.link(target.path, hardlink.path) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        var rejectedSymlink = false
        do {
            try RuntimePaths.secureFile(at: link)
        } catch {
            rejectedSymlink = true
        }
        #expect(
            rejectedSymlink,
            "Runtime path hardening should reject symlinks before applying file attributes.")

        var rejectedDirectoryAsFile = false
        do {
            try RuntimePaths.secureFile(at: directory)
        } catch {
            rejectedDirectoryAsFile = true
        }
        #expect(
            rejectedDirectoryAsFile,
            "Runtime path hardening should reject directories when securing regular files.")

        var rejectedHardlink = false
        do {
            try RuntimePaths.secureFile(at: hardlink)
        } catch {
            rejectedHardlink = true
        }
        #expect(
            rejectedHardlink,
            "Runtime path hardening should reject hardlinked files before applying file attributes."
        )

        let secured = directory.appendingPathComponent("secured")
        try "state\n".write(to: secured, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o666], ofItemAtPath: secured.path)
        try RuntimePaths.secureSessionStateFile(at: secured)
        let securedAttributes = try FileManager.default.attributesOfItem(atPath: secured.path)
        #expect(
            (securedAttributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
            "Recovery-file hardening should enforce ownership by the effective user.")
        #expect(
            (securedAttributes[.groupOwnerAccountID] as? NSNumber)?.uint32Value == getgid(),
            "Recovery-file hardening should enforce the effective user's primary group.")
        #expect(
            (securedAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o600,
            "Recovery-file hardening should verify root-only/current-user-only mode after applying it."
        )
    }

    @Test
    func controllerLockRejectsUnsafeFiles() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-controller-lock")
        defer { try? FileManager.default.removeItem(at: directory) }

        let regularLock = directory.appendingPathComponent("controller.lock")
        _ = try ControllerLock(at: regularLock)
        #expect(
            FileManager.default.fileExists(atPath: regularLock.path),
            "Controller lock helper should create a regular lock file.")

        let symlinkTarget = directory.appendingPathComponent("symlink-target")
        let symlinkLock = directory.appendingPathComponent("controller-symlink.lock")
        try "existing\n".write(to: symlinkTarget, atomically: true, encoding: .utf8)
        try #require(
            symlink(symlinkTarget.path, symlinkLock.path) == 0,
            "Failed to create controller lock symlink fixture.")
        #expect(
            throws: (any Error).self, "Controller lock open should reject symlinks before writing."
        ) {
            _ = try ControllerLock(at: symlinkLock)
        }
        #expect(
            (try? String(contentsOf: symlinkTarget, encoding: .utf8)) == "existing\n",
            "Rejected symlink controller locks must not modify their target.")

        let hardlinkTarget = directory.appendingPathComponent("hardlink-target")
        let hardlinkLock = directory.appendingPathComponent("controller-hardlink.lock")
        try "existing\n".write(to: hardlinkTarget, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: hardlinkTarget.path)
        try #require(
            Darwin.link(hardlinkTarget.path, hardlinkLock.path) == 0,
            "Failed to create controller lock hardlink fixture.")
        #expect(
            throws: (any Error).self, "Controller lock open should reject hardlinks before writing."
        ) {
            _ = try ControllerLock(at: hardlinkLock)
        }
        #expect(
            (try? String(contentsOf: hardlinkTarget, encoding: .utf8)) == "existing\n",
            "Rejected hardlinked controller locks must not modify their target.")

        let directoryLock = directory.appendingPathComponent("controller-directory.lock")
        try FileManager.default.createDirectory(
            at: directoryLock, withIntermediateDirectories: true)
        #expect(throws: (any Error).self, "Controller lock open should reject non-regular files.") {
            _ = try ControllerLock(at: directoryLock)
        }
    }

    @Test
    func resolverFileAssertionsRejectUnsafeFiles() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-resolver-file-assertions")
        defer { try? FileManager.default.removeItem(at: directory) }

        let userID = getuid()
        let groupID = getgid()
        let trusted = directory.appendingPathComponent("resolver")
        try "nameserver 129.22.4.32\n".write(to: trusted, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: trusted.path)

        try SecureFile.assertRegularFile(
            atPath: trusted.path,
            context: "resolver file",
            expectedUserID: userID,
            expectedGroupID: groupID,
            expectedMode: 0o644)

        let symlinkPath = directory.appendingPathComponent("resolver-symlink")
        try #require(
            symlink(trusted.path, symlinkPath.path) == 0,
            "Failed to create resolver assertion symlink fixture.")
        #expect(throws: (any Error).self, "Resolver file assertion should reject symlinks.") {
            try SecureFile.assertRegularFile(
                atPath: symlinkPath.path,
                context: "resolver file",
                expectedUserID: userID,
                expectedGroupID: groupID,
                expectedMode: 0o644)
        }

        let hardlinkSource = directory.appendingPathComponent("resolver-hardlink-source")
        let hardlinkPath = directory.appendingPathComponent("resolver-hardlink")
        try "nameserver 129.22.4.32\n".write(to: hardlinkSource, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: hardlinkSource.path)
        try #require(
            Darwin.link(hardlinkSource.path, hardlinkPath.path) == 0,
            "Failed to create resolver assertion hardlink fixture.")
        #expect(throws: (any Error).self, "Resolver file assertion should reject hardlinked files.")
        {
            try SecureFile.assertRegularFile(
                atPath: hardlinkSource.path,
                context: "resolver file",
                expectedUserID: userID,
                expectedGroupID: groupID,
                expectedMode: 0o644)
        }

        let wrongMode = directory.appendingPathComponent("resolver-wrong-mode")
        try "nameserver 129.22.4.32\n".write(to: wrongMode, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: wrongMode.path)
        #expect(throws: (any Error).self, "Resolver file assertion should reject unexpected modes.")
        {
            try SecureFile.assertRegularFile(
                atPath: wrongMode.path,
                context: "resolver file",
                expectedUserID: userID,
                expectedGroupID: groupID,
                expectedMode: 0o644)
        }

        let wrongUserID = userID == 0 ? uid_t(501) : uid_t(0)
        let wrongGroupID = groupID == 0 ? gid_t(20) : gid_t(0)
        #expect(
            throws: (any Error).self, "Resolver file assertion should reject unexpected ownership."
        ) {
            try SecureFile.assertRegularFile(
                atPath: trusted.path,
                context: "resolver file",
                expectedUserID: wrongUserID,
                expectedGroupID: wrongGroupID,
                expectedMode: 0o644)
        }
    }

    @Test
    func resolverAtomicMutationProtectsUnmanagedFiles() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-resolver-atomic-mutation")
        defer { try? FileManager.default.removeItem(at: directory) }
        let manager = makeRouteManager(
            splitTunnelPolicy: SplitTunnelPolicy(
                ipv4Routes: [],
                dnsDomains: [],
                dnsServers: [],
            ),
            shell: Shell(),
            resolverDirectory: directory
        )

        let resolverFile = directory.appendingPathComponent("case.edu")
        let quarantineFile = directory.appendingPathComponent("case.edu.quarantine")
        try "user-managed resolver\n".write(to: resolverFile, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: resolverFile.path)

        #expect(
            throws: (any Error).self,
            "Atomic resolver mutation should restore an unmanaged file instead of replacing it."
        ) {
            _ = try manager.quarantineExistingManagedResolverFile(
                at: resolverFile,
                to: quarantineFile)
        }
        let restoredContents = try String(contentsOf: resolverFile, encoding: .utf8)
        #expect(
            restoredContents == "user-managed resolver\n",
            "An unmanaged resolver raced into place must remain at its original path.")
        #expect(
            !FileManager.default.fileExists(atPath: quarantineFile.path),
            "Rejecting an unmanaged resolver should restore it from quarantine.")

        try FileManager.default.removeItem(at: resolverFile)
        try manager.resolverContents(for: "case.edu", nameServers: ["129.22.4.32"])
            .write(to: resolverFile, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: resolverFile.path)
        let staleTemporary = directory.appendingPathComponent(".case.edu.recovery.tmp")
        try manager.resolverContents(for: "case.edu", nameServers: ["129.22.4.33"])
            .write(to: staleTemporary, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: staleTemporary.path)
        try manager.recoverManagedResolverArtifacts(for: resolverFile)
        #expect(
            !FileManager.default.fileExists(atPath: staleTemporary.path),
            "Resolver recovery should remove stale managed temporary files when the active resolver exists."
        )

        try FileManager.default.removeItem(at: resolverFile)
        let emptyTemporary = directory.appendingPathComponent(".case.edu.empty.tmp")
        try Data().write(to: emptyTemporary)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: emptyTemporary.path)
        let partialTemporary = directory.appendingPathComponent(".case.edu.partial.tmp")
        try "# cwru".write(to: partialTemporary, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: partialTemporary.path)
        try manager.recoverManagedResolverArtifacts(for: resolverFile)
        #expect(
            !FileManager.default.fileExists(atPath: emptyTemporary.path),
            "Resolver recovery should remove an empty interrupted temporary file.")
        #expect(
            !FileManager.default.fileExists(atPath: partialTemporary.path),
            "Resolver recovery should remove a partially written temporary file.")
        #expect(
            !FileManager.default.fileExists(atPath: resolverFile.path),
            "Resolver recovery should not promote interrupted temporary files.")

        try manager.resolverContents(for: "case.edu", nameServers: ["129.22.4.32"])
            .write(to: resolverFile, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: resolverFile.path)
        try manager.removeManagedResolverFileAtomically(at: resolverFile)
        #expect(
            !FileManager.default.fileExists(atPath: resolverFile.path),
            "Atomic resolver cleanup should remove a verified cwru-ovpn-managed file.")
    }

    @Test
    func setupFileAssertionsRejectUnsafeFiles() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-setup-file-assertions")
        defer { try? FileManager.default.removeItem(at: directory) }

        let userID = getuid()
        let groupID = getgid()
        let trusted = directory.appendingPathComponent("installed")
        try "binary\n".write(to: trusted, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o555], ofItemAtPath: trusted.path)

        try assertInstallSource(path: trusted.path)
        let trustedProfileData = try ProfileManifest.readProfileData(at: trusted)
        #expect(
            trustedProfileData == Data("binary\n".utf8),
            "Profile source import should read regular files.")
        try assertInstalledFile(
            path: trusted.path,
            userID: userID,
            groupID: groupID,
            mode: 0o555)

        let symlinkSource = directory.appendingPathComponent("source-symlink")
        try #require(
            symlink(trusted.path, symlinkSource.path) == 0,
            "Failed to create install source symlink fixture.")
        #expect(throws: (any Error).self, "Install source assertion should reject symlinks.") {
            try assertInstallSource(path: symlinkSource.path)
        }
        #expect(throws: (any Error).self, "Profile source import should reject symlinks.") {
            _ = try ProfileManifest.readProfileData(at: symlinkSource)
        }
        #expect(throws: (any Error).self, "Installed file assertion should reject symlinks.") {
            try assertInstalledFile(
                path: symlinkSource.path,
                userID: userID,
                groupID: groupID,
                mode: 0o555)
        }

        let hardlinkSource = directory.appendingPathComponent("installed-hardlink-source")
        let hardlinkPath = directory.appendingPathComponent("installed-hardlink")
        try "binary\n".write(to: hardlinkSource, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o555], ofItemAtPath: hardlinkSource.path)
        try #require(
            Darwin.link(hardlinkSource.path, hardlinkPath.path) == 0,
            "Failed to create installed file hardlink fixture.")
        #expect(
            throws: (any Error).self, "Installed file assertion should reject hardlinked files."
        ) {
            try assertInstalledFile(
                path: hardlinkSource.path,
                userID: userID,
                groupID: groupID,
                mode: 0o555)
        }
        #expect(
            throws: (any Error).self, "Install source assertion should reject hardlinked files."
        ) {
            try assertInstallSource(path: hardlinkSource.path)
        }

        let wrongMode = directory.appendingPathComponent("installed-wrong-mode")
        try "binary\n".write(to: wrongMode, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: wrongMode.path)
        #expect(
            throws: (any Error).self, "Installed file assertion should reject unexpected modes."
        ) {
            try assertInstalledFile(
                path: wrongMode.path,
                userID: userID,
                groupID: groupID,
                mode: 0o555)
        }

        let wrongUserID = userID == 0 ? uid_t(501) : uid_t(0)
        let wrongGroupID = groupID == 0 ? gid_t(20) : gid_t(0)
        #expect(
            throws: (any Error).self, "Installed file assertion should reject unexpected ownership."
        ) {
            try assertInstalledFile(
                path: trusted.path,
                userID: wrongUserID,
                groupID: wrongGroupID,
                mode: 0o555)
        }
    }

    @Test(arguments: ["assert", "read", "logs"])
    func regularFileChecksRejectFIFOWithoutWaiting(operation: String) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-fifo")
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("input").path
        try #require(mkfifo(path, 0o600) == 0)
        let started = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        let rejected = Mutex(false)
        Thread.detachNewThread {
            defer { finished.signal() }
            started.signal()
            do {
                if operation == "assert" {
                    try SecureFile.assertRegularFile(atPath: path, context: "FIFO")
                } else if operation == "logs" {
                    _ = try Diagnostics.tailLines(from: URL(fileURLWithPath: path), count: 1)
                } else {
                    _ = try SecureFile.readRegularFile(atPath: path, maximumBytes: 1024, context: "FIFO")
                }
            } catch {
                rejected.withLock { $0 = true }
            }
        }
        try #require(started.wait(timeout: .now() + 5) == .success)
        let result = finished.wait(timeout: .now() + 1)
        if result == .timedOut {
            let writer = open(path, O_WRONLY | O_NONBLOCK)
            if writer >= 0 { close(writer) }
            _ = finished.wait(timeout: .now() + 1)
        }
        #expect(result == .success)
        #expect(rejected.withLock { $0 })
    }

}
