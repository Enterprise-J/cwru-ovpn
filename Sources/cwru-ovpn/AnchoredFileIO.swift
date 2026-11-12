import Darwin
import Foundation

enum AnchoredFileIO {
    static func withDirectory<T>(at directory: URL,
                                 parentUserID: uid_t,
                                 parentGroupID: gid_t,
                                 userID: uid_t,
                                 groupID: gid_t,
                                 createIfMissing: Bool = true,
                                 body: (Int32) throws -> T) throws -> T {
        try withParentDirectory(of: directory, userID: parentUserID, groupID: parentGroupID) { parentFD, name in
            var created = false
            if createIfMissing {
                created = name.withCString { mkdirat(parentFD, $0, 0o700) } == 0
                if !created, errno != EEXIST {
                    throw FileIO.failure("Failed to create \(directory.path)", errno)
                }
            }

            let directoryFD = name.withCString { openat(parentFD, $0, directoryOpenFlags) }
            guard directoryFD >= 0 else {
                throw FileIO.failure("Failed to open \(directory.path)", errno)
            }
            defer { close(directoryFD) }

            if created {
                try own(directoryFD, context: directory.path, userID: userID, groupID: groupID, mode: 0o700)
            }
            try validateDirectory(fileDescriptor: directoryFD,
                                  path: directory.path,
                                  userID: userID,
                                  groupID: groupID,
                                  mode: 0o700)
            return try body(directoryFD)
        }
    }

    static func removeDirectoryTree(at directory: URL,
                                    parentUserID: uid_t,
                                    parentGroupID: gid_t) throws -> Bool {
        try withParentDirectory(of: directory, userID: parentUserID, groupID: parentGroupID) { parentFD, name in
            try removeTree(in: parentFD, name: name)
        }
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
            throw FileIO.failure("Failed to lock \(name)", errno)
        }
        defer { _ = flock(lockFD, LOCK_UN) }
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
            let info = try SecureFile.regularFileInfo(fileDescriptor: existingFD,
                                                      context: name,
                                                      expectedUserID: userID,
                                                      expectedGroupID: groupID,
                                                      expectedMode: 0o600)
            if info.st_size == data.count,
               try FileIO.readAll(from: existingFD, maximumBytes: data.count) == data {
                var currentInfo = stat()
                if fstatat(directoryFD, name, &currentInfo, AT_SYMLINK_NOFOLLOW) == 0,
                   currentInfo.st_dev == info.st_dev,
                   currentInfo.st_ino == info.st_ino {
                    try SecureFile.validateRegularFile(info: currentInfo,
                                                       context: name,
                                                       expectedUserID: userID,
                                                       expectedGroupID: groupID,
                                                       expectedMode: 0o600)
                    return
                }
            }
        }

        let temporaryName = ".\(name).\(UUID().uuidString).tmp"
        let temporaryFD = temporaryName.withCString {
            openat(directoryFD, $0, O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, 0o600)
        }
        guard temporaryFD >= 0 else {
            throw FileIO.failure("Failed to create \(temporaryName)", errno)
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
            throw FileIO.failure("Failed to sync \(temporaryName)", errno)
        }
        try own(temporaryFD, context: temporaryName, userID: userID, groupID: groupID, mode: 0o600)
        try SecureFile.assertRegularFile(fileDescriptor: temporaryFD,
                                         context: temporaryName,
                                         expectedUserID: userID,
                                         expectedGroupID: groupID,
                                         expectedMode: 0o600)

        let renameResult = temporaryName.withCString { temporaryPointer in
            name.withCString { renameat(directoryFD, temporaryPointer, directoryFD, $0) }
        }
        guard renameResult == 0 else {
            throw FileIO.failure("Failed to install \(name)", errno)
        }
        renamed = true

        var temporaryInfo = stat()
        guard fstat(temporaryFD, &temporaryInfo) == 0 else {
            throw FileIO.failure("Failed to inspect \(name)", errno)
        }
        var installedInfo = stat()
        guard name.withCString({ fstatat(directoryFD, $0, &installedInfo, AT_SYMLINK_NOFOLLOW) }) == 0 else {
            throw FileIO.failure("Failed to inspect \(name)", errno)
        }
        guard temporaryInfo.st_dev == installedInfo.st_dev,
              temporaryInfo.st_ino == installedInfo.st_ino else {
            throw FileIO.posixError(EIO, "\(name) changed while it was being installed.")
        }
        try SecureFile.validateRegularFile(info: installedInfo,
                                           context: name,
                                           expectedUserID: userID,
                                           expectedGroupID: groupID,
                                           expectedMode: 0o600)
        try syncDirectory(directoryFD, holding: name)
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
        let info = try SecureFile.regularFileInfo(fileDescriptor: fileFD,
                                                  context: name,
                                                  expectedUserID: userID,
                                                  expectedGroupID: groupID,
                                                  expectedMode: 0o600,
                                                  allowUnlinked: true)
        guard info.st_size <= maximumBytes else {
            throw FileIO.posixError(EFBIG, "Refusing to read \(name): file exceeds \(maximumBytes) bytes.")
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
        try SecureFile.assertRegularFile(fileDescriptor: fileFD,
                                         context: name,
                                         expectedUserID: userID,
                                         expectedGroupID: groupID,
                                         expectedMode: 0o600)
        return true
    }

    static func removeFileIfPresent(in directoryFD: Int32, name: String) throws -> Bool {
        try validateComponent(name)
        let result = name.withCString { unlinkat(directoryFD, $0, 0) }
        guard result == 0 || errno == ENOENT else {
            throw FileIO.failure("Failed to remove \(name)", errno)
        }
        return result == 0
    }

    static func removeFileAndSync(in directoryFD: Int32, name: String) throws {
        _ = try removeFileIfPresent(in: directoryFD, name: name)
        try syncDirectory(directoryFD, holding: name)
    }

    static func validateComponent(_ value: String) throws {
        guard !value.isEmpty,
              value != ".",
              value != "..",
              !value.contains("/"),
              !value.utf8.contains(0) else {
            throw FileIO.posixError(EINVAL, "Invalid file name \(value.debugDescription).")
        }
    }

    private static let directoryOpenFlags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK

    private static func withParentDirectory<T>(of directory: URL,
                                               userID: uid_t,
                                               groupID: gid_t,
                                               body: (Int32, String) throws -> T) throws -> T {
        let name = directory.lastPathComponent
        try validateComponent(name)
        let parent = directory.deletingLastPathComponent()
        let parentFD = open(parent.path, directoryOpenFlags)
        guard parentFD >= 0 else {
            throw FileIO.failure("Failed to open \(parent.path)", errno)
        }
        defer { close(parentFD) }
        try validateDirectory(fileDescriptor: parentFD,
                              path: parent.path,
                              userID: userID,
                              groupID: groupID,
                              mode: nil)
        return try body(parentFD, name)
    }

    private static func removeTree(in directoryFD: Int32, name: String) throws -> Bool {
        var info = stat()
        guard name.withCString({ fstatat(directoryFD, $0, &info, AT_SYMLINK_NOFOLLOW) }) == 0 else {
            guard errno == ENOENT else {
                throw FileIO.failure("Failed to inspect \(name)", errno)
            }
            return false
        }
        guard (info.st_mode & S_IFMT) == S_IFDIR else {
            guard name.withCString({ unlinkat(directoryFD, $0, 0) }) == 0 else {
                throw FileIO.failure("Failed to remove \(name)", errno)
            }
            return true
        }

        let treeFD = name.withCString { openat(directoryFD, $0, directoryOpenFlags) }
        guard treeFD >= 0 else {
            throw FileIO.failure("Failed to open \(name)", errno)
        }
        guard let stream = fdopendir(treeFD) else {
            let streamError = errno
            close(treeFD)
            throw FileIO.failure("Failed to list \(name)", streamError)
        }
        defer { closedir(stream) }

        var entryNames: [String] = []
        while let entry = readdir(stream) {
            let entryName = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) {
                    String(cString: $0)
                }
            }
            if entryName != ".", entryName != ".." {
                entryNames.append(entryName)
            }
        }
        for entryName in entryNames {
            _ = try removeTree(in: treeFD, name: entryName)
        }
        guard name.withCString({ unlinkat(directoryFD, $0, AT_REMOVEDIR) }) == 0 else {
            throw FileIO.failure("Failed to remove \(name)", errno)
        }
        return true
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
            throw FileIO.failure("Failed to open \(name)", errno)
        }
        do {
            if created {
                try own(fileFD, context: name, userID: userID, groupID: groupID, mode: 0o600)
            }
            try SecureFile.assertRegularFile(fileDescriptor: fileFD,
                                             context: name,
                                             expectedUserID: userID,
                                             expectedGroupID: groupID,
                                             expectedMode: 0o600)
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
            throw FileIO.failure("Failed to open \(name)", errno)
        }
        return fileFD
    }

    private static func syncDirectory(_ directoryFD: Int32, holding name: String) throws {
        guard fsync(directoryFD) == 0 else {
            throw FileIO.failure("Failed to sync the directory holding \(name)", errno)
        }
    }

    private static func own(_ fileDescriptor: Int32, context: String, userID: uid_t, groupID: gid_t, mode: mode_t) throws {
        guard fchown(fileDescriptor, userID, groupID) == 0, fchmod(fileDescriptor, mode) == 0 else {
            throw FileIO.failure("Failed to set the ownership of \(context)", errno)
        }
    }

    private static func validateDirectory(fileDescriptor: Int32,
                                          path: String,
                                          userID: uid_t,
                                          groupID: gid_t,
                                          mode: mode_t?) throws {
        var info = stat()
        guard fstat(fileDescriptor, &info) == 0 else {
            throw FileIO.failure("Failed to inspect \(path)", errno)
        }
        guard (info.st_mode & S_IFMT) == S_IFDIR else {
            throw FileIO.posixError(EFTYPE, "Refusing to use \(path): not a directory.")
        }
        guard info.st_uid == userID, info.st_gid == groupID else {
            throw FileIO.posixError(EPERM, "Refusing to use \(path): expected owner uid \(userID) and gid \(groupID), found uid \(info.st_uid) and gid \(info.st_gid).")
        }
        if let mode, mode_t(info.st_mode & 0o7777) != mode {
            throw FileIO.posixError(EPERM, "Refusing to use \(path): expected mode \(FileIO.octal(mode)), found mode \(FileIO.octal(info.st_mode)).")
        }
    }
}
