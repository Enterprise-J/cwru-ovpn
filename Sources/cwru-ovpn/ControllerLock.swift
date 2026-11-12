import Darwin
import Foundation

enum ControllerLockError: LocalizedError {
    case busy

    var errorDescription: String? {
        "Another VPN controller or recovery operation is running. Wait a moment and retry."
    }
}

final class ControllerLock {
    static let fileName = "controller.lock"

    private let fileDescriptor: Int32

    init(in store: StateDirectory = StateDirectory(),
         fileName: String = ControllerLock.fileName,
         createDirectoryIfMissing: Bool = true) throws {
        fileDescriptor = try store.withAnchor(createIfMissing: createDirectoryIfMissing) { directoryFD, userID, groupID in
            let descriptor = try AnchoredFileIO.openOwnedRegularFileForLock(in: directoryFD,
                                                                            name: fileName,
                                                                            userID: userID,
                                                                            groupID: groupID)
            do {
                guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
                    let lockError = errno
                    if lockError == EWOULDBLOCK {
                        throw ControllerLockError.busy
                    }
                    throw FileIO.failure("Failed to lock \(fileName)", lockError)
                }
                var descriptorInfo = stat()
                var pathInfo = stat()
                guard fstat(descriptor, &descriptorInfo) == 0,
                      fstatat(directoryFD, fileName, &pathInfo, AT_SYMLINK_NOFOLLOW) == 0,
                      descriptorInfo.st_dev == pathInfo.st_dev,
                      descriptorInfo.st_ino == pathInfo.st_ino else {
                    throw ControllerLockError.busy
                }
                return descriptor
            } catch {
                _ = flock(descriptor, LOCK_UN)
                close(descriptor)
                throw error
            }
        }
    }

    deinit {
        _ = flock(fileDescriptor, LOCK_UN)
        close(fileDescriptor)
    }
}
