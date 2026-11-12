import Foundation
import Darwin

enum RuntimePaths {
    static var userHomeDirectory: URL {
        if let sudoIdentity = try? ExecutionIdentity.validatedSudoUserIfAvailable() {
            return sudoIdentity.homeDirectory
        }
        return FileManager.default.homeDirectoryForCurrentUser
    }

    static var homeStateDirectory: URL {
        userHomeDirectory.appendingPathComponent(AppIdentity.stateDirectoryName, isDirectory: true)
    }

    static var homeConfigFile: URL {
        homeStateDirectory.appendingPathComponent("config.json")
    }

    static var homeProfileFile: URL {
        homeStateDirectory.appendingPathComponent("profile.ovpn")
    }

    static var eventLogFile: URL {
        homeStateDirectory.appendingPathComponent(EventLog.fileName)
    }

    static let sudoersFile = URL(fileURLWithPath: "/etc/sudoers.d/\(AppIdentity.executableName)")

    static let privilegedExecutableDirectory = URL(fileURLWithPath: "/Library/PrivilegedHelperTools", isDirectory: true)
        .appendingPathComponent(AppIdentity.executableName, isDirectory: true)

    static let privilegedApplication = privilegedExecutableDirectory
        .appendingPathComponent("\(AppIdentity.executableName).app", isDirectory: true)

    static let privilegedExecutable = privilegedApplication
        .appendingPathComponent("Contents/MacOS/\(AppIdentity.executableName)")

    static let privilegedApplicationInfo = privilegedApplication.appendingPathComponent("Contents/Info.plist")

    static let privilegedApplicationResources = privilegedApplication.appendingPathComponent("Contents/_CodeSignature/CodeResources")

    static let approvedProfileManifest = privilegedExecutableDirectory.appendingPathComponent("approved-profile.sha256")

    static let privilegedSessionStateDirectory = URL(fileURLWithPath: "/var/db", isDirectory: true)
        .appendingPathComponent(AppIdentity.executableName, isDirectory: true)

    static var sessionStateDirectory: URL {
        getuid() == 0 ? privilegedSessionStateDirectory : homeStateDirectory
    }

    static var sessionStateFile: URL {
        sessionStateDirectory.appendingPathComponent(SessionState.fileName)
    }

    static func ensureSessionStateDirectory() throws {
        try withSessionStateDirectoryAnchor { _, _, _ in }
    }

    static func ensureHomeStateDirectory() throws {
        try withHomeStateDirectoryAnchor { _, _, _ in }
    }

    static func withHomeStateDirectoryAnchor<T>(createIfMissing: Bool = true,
                                                body: (Int32, uid_t, gid_t) throws -> T) throws -> T {
        let owner = try ExecutionIdentity.currentUser()
        return try AnchoredFileIO.withDirectory(at: homeStateDirectory,
                                                parentUserID: owner.userID,
                                                parentGroupID: owner.groupID,
                                                userID: owner.userID,
                                                groupID: owner.groupID,
                                                createIfMissing: createIfMissing) { directoryFD in
            try body(directoryFD, owner.userID, owner.groupID)
        }
    }

    static func withSessionStateDirectoryAnchor<T>(createIfMissing: Bool = true,
                                                   body: (Int32, uid_t, gid_t) throws -> T) throws -> T {
        guard getuid() == 0 else {
            return try withHomeStateDirectoryAnchor(createIfMissing: createIfMissing, body: body)
        }
        return try AnchoredFileIO.withDirectory(at: privilegedSessionStateDirectory,
                                                parentUserID: 0,
                                                parentGroupID: 0,
                                                userID: 0,
                                                groupID: 0,
                                                createIfMissing: createIfMissing) { directoryFD in
            try body(directoryFD, 0, 0)
        }
    }

    static func writeHomeStateFileAtomically(_ data: Data,
                                             name: String) throws {
        try withHomeStateDirectoryAnchor { directoryFD, userID, groupID in
            try AnchoredFileIO.writeOwnedRegularFileAtomically(data,
                                                               in: directoryFD,
                                                               name: name,
                                                               userID: userID,
                                                               groupID: groupID)
        }
    }

    static func readHomeStateFile(name: String,
                                  maximumBytes: Int) throws -> Data? {
        try withHomeStateDirectoryAnchor { directoryFD, userID, groupID in
            try AnchoredFileIO.readOwnedRegularFile(in: directoryFD,
                                                    name: name,
                                                    userID: userID,
                                                    groupID: groupID,
                                                    maximumBytes: maximumBytes)
        }
    }

    static func homeStateFileExists(name: String) throws -> Bool {
        try withHomeStateDirectoryAnchor { directoryFD, userID, groupID in
            try AnchoredFileIO.ownedRegularFileExists(in: directoryFD,
                                                      name: name,
                                                      userID: userID,
                                                      groupID: groupID)
        }
    }

    static func removeHomeStateFile(name: String) throws {
        try withHomeStateDirectoryAnchor { directoryFD, _, _ in
            try AnchoredFileIO.removeFileAndSync(in: directoryFD, name: name)
        }
    }

    static func removeHomeStateDirectory() throws -> Bool {
        let owner = try ExecutionIdentity.currentUser()
        return try AnchoredFileIO.removeDirectoryTree(at: homeStateDirectory,
                                                      parentUserID: owner.userID,
                                                      parentGroupID: owner.groupID)
    }
}
