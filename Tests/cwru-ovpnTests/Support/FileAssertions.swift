import Darwin
import Foundation

@testable import cwru_ovpn

func assertInstallSource(path: String) throws {
    let fileDescriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard fileDescriptor >= 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    defer { close(fileDescriptor) }
    try SecureFile.assertRegularFile(
        fileDescriptor: fileDescriptor,
        context: "install source \(path)")
}

func assertInstalledFile(
    path: String,
    userID: uid_t,
    groupID: gid_t,
    mode: mode_t
) throws {
    try SecureFile.assertRegularFile(
        atPath: path,
        context: "installed file \(path)",
        expectedUserID: userID,
        expectedGroupID: groupID,
        expectedMode: mode)
}

func writeOwnedFixture(_ data: Data, in directory: URL, name: String) throws {
    try AnchoredFileIO.withDirectory(
        at: directory,
        parentUserID: getuid(),
        parentGroupID: getgid(),
        userID: getuid(),
        groupID: getgid()
    ) { directoryFD in
        try AnchoredFileIO.writeOwnedRegularFileAtomically(
            data,
            in: directoryFD,
            name: name,
            userID: getuid(),
            groupID: getgid())
    }
}
