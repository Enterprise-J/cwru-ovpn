import Darwin
import Foundation

enum AnchoredFileIO {
    static func withDirectory<T>(at directory: URL,
                                 parentUserID: uid_t,
                                 parentGroupID: gid_t,
                                 userID: uid_t,
                                 groupID: gid_t,
                                 body: (Int32) throws -> T) throws -> T {
        let name = directory.lastPathComponent
        try validateComponent(name)
        let parent = directory.deletingLastPathComponent()
        let parentFD = open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard parentFD >= 0 else {
            throw FileIO.posixError(errno)
        }
        defer { close(parentFD) }
        try validateDirectory(fileDescriptor: parentFD, userID: parentUserID, groupID: parentGroupID, mode: nil)

        let created = name.withCString { mkdirat(parentFD, $0, 0o700) } == 0
        if !created, errno != EEXIST {
            throw FileIO.posixError(errno)
        }

        let directoryFD = name.withCString {
            openat(parentFD, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        }
        guard directoryFD >= 0 else {
            throw FileIO.posixError(errno)
        }
        defer { close(directoryFD) }

        if created {
            try own(directoryFD, userID: userID, groupID: groupID, mode: 0o700)
        }
        try validateDirectory(fileDescriptor: directoryFD, userID: userID, groupID: groupID, mode: 0o700)
        return try body(directoryFD)
    }

    static func openOwnedRegularFileForAppend(in directoryFD: Int32,
                                              name: String,
                                              userID: uid_t,
                                              groupID: gid_t) throws -> Int32 {
        try openOwnedRegularFile(in: directoryFD, name: name, flags: O_RDWR | O_APPEND, userID: userID, groupID: groupID)
    }

    static func openOwnedRegularFileForLock(in directoryFD: Int32,
                                            name: String,
                                            userID: uid_t,
                                            groupID: gid_t) throws -> Int32 {
        try openOwnedRegularFile(in: directoryFD, name: name, flags: O_RDWR, userID: userID, groupID: groupID)
    }

    static func withExclusiveLock<T>(in directoryFD: Int32,
                                     name: String,
                                     userID: uid_t,
                                     groupID: gid_t,
                                     body: () throws -> T) throws -> T {
        let lockFD = try openOwnedRegularFileForLock(in: directoryFD, name: name, userID: userID, groupID: groupID)
        defer { close(lockFD) }
        guard flock(lockFD, LOCK_EX) == 0 else {
            throw FileIO.posixError(errno)
        }
        return try body()
    }

    static func writeOwnedRegularFileAtomically(_ data: Data,
                                                in directoryFD: Int32,
                                                name: String,
                                                userID: uid_t,
                                                groupID: gid_t) throws {
        try validateComponent(name)
        if let existingFD = try openIfPresent(in: directoryFD, name: name) {
            defer { close(existingFD) }
            try validateRegularFile(fileDescriptor: existingFD, userID: userID, groupID: groupID, mode: 0o600)
        }

        let temporaryName = ".\(name).\(UUID().uuidString).tmp"
        let temporaryFD = temporaryName.withCString {
            openat(directoryFD, $0, O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, 0o600)
        }
        guard temporaryFD >= 0 else {
            throw FileIO.posixError(errno)
        }
        var renamed = false
        defer {
            close(temporaryFD)
            if !renamed {
                _ = temporaryName.withCString { unlinkat(directoryFD, $0, 0) }
            }
        }

        try FileIO.writeAll(data, to: temporaryFD)
        guard fsync(temporaryFD) == 0 else {
            throw FileIO.posixError(errno)
        }
        try own(temporaryFD, userID: userID, groupID: groupID, mode: 0o600)
        try validateRegularFile(fileDescriptor: temporaryFD, userID: userID, groupID: groupID, mode: 0o600)

        let renameResult = temporaryName.withCString { temporaryPointer in
            name.withCString { renameat(directoryFD, temporaryPointer, directoryFD, $0) }
        }
        guard renameResult == 0 else {
            throw FileIO.posixError(errno)
        }
        renamed = true

        var temporaryInfo = stat()
        guard fstat(temporaryFD, &temporaryInfo) == 0 else {
            throw FileIO.posixError(errno)
        }
        var installedInfo = stat()
        let statResult = name.withCString { fstatat(directoryFD, $0, &installedInfo, AT_SYMLINK_NOFOLLOW) }
        guard statResult == 0,
              temporaryInfo.st_dev == installedInfo.st_dev,
              temporaryInfo.st_ino == installedInfo.st_ino else {
            throw FileIO.posixError(statResult == 0 ? EIO : errno)
        }
        try validateRegularFile(info: installedInfo, userID: userID, groupID: groupID, mode: 0o600)
        guard fsync(directoryFD) == 0 else {
            throw FileIO.posixError(errno)
        }
    }

    static func readOwnedRegularFile(in directoryFD: Int32,
                                     name: String,
                                     userID: uid_t,
                                     groupID: gid_t,
                                     maximumBytes: Int) throws -> Data? {
        try validateComponent(name)
        guard let fileFD = try openIfPresent(in: directoryFD, name: name) else {
            return nil
        }
        defer { close(fileFD) }
        var info = stat()
        guard fstat(fileFD, &info) == 0 else {
            throw FileIO.posixError(errno)
        }
        try validateRegularFile(info: info, userID: userID, groupID: groupID, mode: 0o600)
        guard info.st_size <= maximumBytes else {
            throw FileIO.posixError(EFBIG)
        }
        return try FileIO.readAll(from: fileFD, maximumBytes: maximumBytes)
    }

    static func ownedRegularFileExists(in directoryFD: Int32,
                                       name: String,
                                       userID: uid_t,
                                       groupID: gid_t) throws -> Bool {
        try validateComponent(name)
        guard let fileFD = try openIfPresent(in: directoryFD, name: name) else {
            return false
        }
        defer { close(fileFD) }
        try validateRegularFile(fileDescriptor: fileFD, userID: userID, groupID: groupID, mode: 0o600)
        return true
    }

    static func removeFileIfPresent(in directoryFD: Int32, name: String) throws {
        try validateComponent(name)
        let result = name.withCString { unlinkat(directoryFD, $0, 0) }
        guard result == 0 || errno == ENOENT else {
            throw FileIO.posixError(errno)
        }
    }

    static func removeFileAndSync(in directoryFD: Int32, name: String) throws {
        try removeFileIfPresent(in: directoryFD, name: name)
        guard fsync(directoryFD) == 0 else {
            throw FileIO.posixError(errno)
        }
    }

    static func validateComponent(_ value: String) throws {
        guard !value.isEmpty,
              value != ".",
              value != "..",
              !value.contains("/"),
              !value.utf8.contains(0) else {
            throw FileIO.posixError(EINVAL)
        }
    }

    private static func openOwnedRegularFile(in directoryFD: Int32,
                                             name: String,
                                             flags: Int32,
                                             userID: uid_t,
                                             groupID: gid_t) throws -> Int32 {
        try validateComponent(name)
        let openFlags = flags | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        var created = true
        var fileFD = name.withCString { openat(directoryFD, $0, openFlags | O_CREAT | O_EXCL, 0o600) }
        if fileFD < 0, errno == EEXIST {
            created = false
            fileFD = name.withCString { openat(directoryFD, $0, openFlags) }
        }
        guard fileFD >= 0 else {
            throw FileIO.posixError(errno)
        }
        do {
            if created {
                try own(fileFD, userID: userID, groupID: groupID, mode: 0o600)
            }
            try validateRegularFile(fileDescriptor: fileFD, userID: userID, groupID: groupID, mode: 0o600)
            return fileFD
        } catch {
            close(fileFD)
            throw error
        }
    }

    private static func openIfPresent(in directoryFD: Int32, name: String) throws -> Int32? {
        let fileFD = name.withCString { openat(directoryFD, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK) }
        if fileFD < 0, errno == ENOENT {
            return nil
        }
        guard fileFD >= 0 else {
            throw FileIO.posixError(errno)
        }
        return fileFD
    }

    private static func own(_ fileDescriptor: Int32, userID: uid_t, groupID: gid_t, mode: mode_t) throws {
        guard fchown(fileDescriptor, userID, groupID) == 0, fchmod(fileDescriptor, mode) == 0 else {
            throw FileIO.posixError(errno)
        }
    }

    private static func validateDirectory(fileDescriptor: Int32, userID: uid_t, groupID: gid_t, mode: mode_t?) throws {
        var info = stat()
        guard fstat(fileDescriptor, &info) == 0 else {
            throw FileIO.posixError(errno)
        }
        guard (info.st_mode & S_IFMT) == S_IFDIR else {
            throw FileIO.posixError(EFTYPE)
        }
        guard info.st_uid == userID,
              info.st_gid == groupID,
              mode == nil || mode_t(info.st_mode & 0o777) == mode else {
            throw FileIO.posixError(EPERM)
        }
    }

    private static func validateRegularFile(fileDescriptor: Int32, userID: uid_t, groupID: gid_t, mode: mode_t) throws {
        var info = stat()
        guard fstat(fileDescriptor, &info) == 0 else {
            throw FileIO.posixError(errno)
        }
        try validateRegularFile(info: info, userID: userID, groupID: groupID, mode: mode)
    }

    private static func validateRegularFile(info: stat, userID: uid_t, groupID: gid_t, mode: mode_t) throws {
        guard (info.st_mode & S_IFMT) == S_IFREG else {
            throw FileIO.posixError(EFTYPE)
        }
        guard info.st_nlink == 1 else {
            throw FileIO.posixError(EMLINK)
        }
        guard info.st_uid == userID,
              info.st_gid == groupID,
              mode_t(info.st_mode & 0o777) == mode else {
            throw FileIO.posixError(EPERM)
        }
    }
}
