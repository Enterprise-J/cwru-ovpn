import Darwin
import Foundation

enum SecureFile {
    static func assertRegularFile(fileDescriptor: Int32,
                                  context: String,
                                  expectedUserID: uid_t? = nil,
                                  expectedGroupID: gid_t? = nil,
                                  expectedMode: mode_t? = nil,
                                  allowUnlinked: Bool = false) throws {
        _ = try regularFileInfo(fileDescriptor: fileDescriptor,
                                context: context,
                                expectedUserID: expectedUserID,
                                expectedGroupID: expectedGroupID,
                                expectedMode: expectedMode,
                                allowUnlinked: allowUnlinked)
    }

    static func readRegularFile(at url: URL,
                                maximumBytes: Int,
                                context: String,
                                expectedUserID: uid_t? = nil,
                                expectedGroupID: gid_t? = nil,
                                expectedMode: mode_t? = nil) throws -> Data {
        let fd = try open(url.path, context: context)
        defer { close(fd) }
        let info = try regularFileInfo(fileDescriptor: fd,
                                       context: context,
                                       expectedUserID: expectedUserID,
                                       expectedGroupID: expectedGroupID,
                                       expectedMode: expectedMode,
                                       allowUnlinked: true)
        guard info.st_size <= maximumBytes else {
            throw FileIO.posixError(EFBIG, "Refusing to read \(context): file exceeds \(maximumBytes) bytes.")
        }
        return try FileIO.readAll(from: fd, maximumBytes: maximumBytes)
    }

    static func regularFileInfo(fileDescriptor: Int32,
                                context: String,
                                expectedUserID: uid_t? = nil,
                                expectedGroupID: gid_t? = nil,
                                expectedMode: mode_t? = nil,
                                allowUnlinked: Bool = false) throws -> stat {
        var info = stat()
        guard fstat(fileDescriptor, &info) == 0 else {
            throw FileIO.failure("Failed to inspect \(context)", errno)
        }
        try validateRegularFile(info: info,
                                context: context,
                                expectedUserID: expectedUserID,
                                expectedGroupID: expectedGroupID,
                                expectedMode: expectedMode,
                                allowUnlinked: allowUnlinked)
        return info
    }

    static func validateRegularFile(info: stat,
                                    context: String,
                                    expectedUserID: uid_t? = nil,
                                    expectedGroupID: gid_t? = nil,
                                    expectedMode: mode_t? = nil,
                                    allowUnlinked: Bool = false) throws {
        guard (info.st_mode & S_IFMT) == S_IFREG else {
            throw FileIO.posixError(EFTYPE, "Refusing to trust non-regular \(context).")
        }
        guard info.st_nlink == 1 || (allowUnlinked && info.st_nlink == 0) else {
            throw FileIO.posixError(EMLINK, "Refusing to trust hardlinked \(context).")
        }
        if let expectedUserID, info.st_uid != expectedUserID {
            throw FileIO.posixError(EPERM, "Refusing to trust \(context): expected owner uid \(expectedUserID), found uid \(info.st_uid).")
        }
        if let expectedGroupID, info.st_gid != expectedGroupID {
            throw FileIO.posixError(EPERM, "Refusing to trust \(context): expected group gid \(expectedGroupID), found gid \(info.st_gid).")
        }
        if let expectedMode, mode_t(info.st_mode & 0o7777) != expectedMode {
            throw FileIO.posixError(EPERM, "Refusing to trust \(context): expected mode \(FileIO.octal(expectedMode)), found mode \(FileIO.octal(info.st_mode)).")
        }
    }

    private static func open(_ path: String, context: String) throws -> Int32 {
        let fd = Darwin.open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else {
            throw FileIO.failure("Failed to open \(context)", errno)
        }
        return fd
    }
}
