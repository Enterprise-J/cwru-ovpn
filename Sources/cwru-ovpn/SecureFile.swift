import Darwin
import Foundation

enum SecureFile {
    static func assertRegularFile(atPath path: String,
                                  context: String,
                                  expectedUserID: uid_t? = nil,
                                  expectedGroupID: gid_t? = nil,
                                  expectedMode: mode_t? = nil) throws {
        let fd = try open(path, context: context)
        defer { close(fd) }
        try assertRegularFile(fileDescriptor: fd,
                              context: context,
                              expectedUserID: expectedUserID,
                              expectedGroupID: expectedGroupID,
                              expectedMode: expectedMode)
    }

    static func assertRegularFile(fileDescriptor: Int32,
                                  context: String,
                                  expectedUserID: uid_t? = nil,
                                  expectedGroupID: gid_t? = nil,
                                  expectedMode: mode_t? = nil) throws {
        _ = try regularFileInfo(fileDescriptor: fileDescriptor,
                                context: context,
                                expectedUserID: expectedUserID,
                                expectedGroupID: expectedGroupID,
                                expectedMode: expectedMode)
    }

    static func readRegularFile(at url: URL,
                                maximumBytes: Int,
                                context: String,
                                expectedUserID: uid_t? = nil,
                                expectedGroupID: gid_t? = nil,
                                expectedMode: mode_t? = nil) throws -> Data {
        try readRegularFile(atPath: url.path,
                            maximumBytes: maximumBytes,
                            context: context,
                            expectedUserID: expectedUserID,
                            expectedGroupID: expectedGroupID,
                            expectedMode: expectedMode)
    }

    static func readRegularFile(atPath path: String,
                                maximumBytes: Int,
                                context: String,
                                expectedUserID: uid_t? = nil,
                                expectedGroupID: gid_t? = nil,
                                expectedMode: mode_t? = nil) throws -> Data {
        let fd = try open(path, context: context)
        defer { close(fd) }
        let info = try regularFileInfo(fileDescriptor: fd,
                                       context: context,
                                       expectedUserID: expectedUserID,
                                       expectedGroupID: expectedGroupID,
                                       expectedMode: expectedMode)
        guard info.st_size <= maximumBytes else {
            throw refusal(EFBIG, "Refusing to read \(context): file exceeds \(maximumBytes) bytes.")
        }
        return try FileIO.readAll(from: fd, maximumBytes: maximumBytes)
    }

    private static func open(_ path: String, context: String) throws -> Int32 {
        let fd = Darwin.open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else {
            throw FileIO.failure("Failed to open \(context)", errno)
        }
        return fd
    }

    private static func regularFileInfo(fileDescriptor: Int32,
                                        context: String,
                                        expectedUserID: uid_t?,
                                        expectedGroupID: gid_t?,
                                        expectedMode: mode_t?) throws -> stat {
        var info = stat()
        guard fstat(fileDescriptor, &info) == 0 else {
            throw FileIO.failure("Failed to inspect \(context)", errno)
        }
        guard (info.st_mode & S_IFMT) == S_IFREG else {
            throw refusal(EFTYPE, "Refusing to trust non-regular \(context).")
        }
        guard info.st_nlink == 1 else {
            throw refusal(EMLINK, "Refusing to trust hardlinked \(context).")
        }
        if let expectedUserID, info.st_uid != expectedUserID {
            throw refusal(EPERM, "Refusing to trust \(context) with owner uid \(info.st_uid).")
        }
        if let expectedGroupID, info.st_gid != expectedGroupID {
            throw refusal(EPERM, "Refusing to trust \(context) with group gid \(info.st_gid).")
        }
        if let expectedMode, mode_t(info.st_mode & 0o777) != expectedMode {
            throw refusal(EPERM, "Refusing to trust \(context) with mode \(String(format: "%03o", Int(info.st_mode & 0o777))).")
        }
        return info
    }

    private static func refusal(_ code: Int32, _ message: String) -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(code), userInfo: [NSLocalizedDescriptionKey: message])
    }
}
