import Darwin
import Foundation

struct StateDirectory: Sendable {
    private let directory: URL?
    private let userID: uid_t
    private let groupID: gid_t

    init() {
        directory = nil
        userID = getuid()
        groupID = getgid()
    }

    init(directory: URL, userID: uid_t = getuid(), groupID: gid_t = getgid()) {
        self.directory = directory.standardizedFileURL
        self.userID = userID
        self.groupID = groupID
    }

    var usesRuntimePaths: Bool {
        directory == nil
    }

    var url: URL {
        directory ?? RuntimePaths.sessionStateDirectory
    }

    func withAnchor<T>(_ body: (Int32, uid_t, gid_t) throws -> T) throws -> T {
        guard let directory else {
            return try RuntimePaths.withSessionStateDirectoryAnchor(body: body)
        }
        return try AnchoredFileIO.withDirectory(at: directory,
                                                parentUserID: userID,
                                                parentGroupID: groupID,
                                                userID: userID,
                                                groupID: groupID) { directoryFD in
            try body(directoryFD, userID, groupID)
        }
    }

    func withExclusiveLock<T>(named name: String, _ body: (Int32, uid_t, gid_t) throws -> T) throws -> T {
        try withAnchor { directoryFD, userID, groupID in
            try AnchoredFileIO.withExclusiveLock(in: directoryFD, name: name, userID: userID, groupID: groupID) {
                try body(directoryFD, userID, groupID)
            }
        }
    }
}
