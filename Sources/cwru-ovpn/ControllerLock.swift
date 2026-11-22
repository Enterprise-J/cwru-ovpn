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
                try AnchoredFileIO.lock(descriptor, in: directoryFD, name: fileName, nonblocking: true)
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
