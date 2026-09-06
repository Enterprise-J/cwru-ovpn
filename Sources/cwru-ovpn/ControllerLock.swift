import Darwin
import Foundation

enum ControllerLockError: LocalizedError {
    case busy

    var errorDescription: String? {
        "Another VPN controller or recovery operation is running. Wait a moment and retry."
    }
}

final class ControllerLock {
    private let fileDescriptor: Int32

    init(in store: StateDirectory = StateDirectory(), fileName: String = "controller.lock") throws {
        let descriptor = try store.withAnchor { directoryFD, userID, groupID in
            try AnchoredFileIO.openOwnedRegularFileForLock(in: directoryFD,
                                                           name: fileName,
                                                           userID: userID,
                                                           groupID: groupID)
        }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            let lockError = errno
            close(descriptor)
            if lockError == EWOULDBLOCK {
                throw ControllerLockError.busy
            }
            throw FileIO.posixError(lockError)
        }
        fileDescriptor = descriptor
    }

    convenience init(at file: URL) throws {
        try self.init(in: StateDirectory(directory: file.deletingLastPathComponent()),
                      fileName: file.lastPathComponent)
    }

    deinit {
        close(fileDescriptor)
    }
}
