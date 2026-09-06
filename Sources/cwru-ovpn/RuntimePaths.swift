import Foundation
import Darwin

enum RuntimePaths {
    private enum OwnershipPolicy {
        case currentUser
        case sudoUserWhenAvailable
    }

    private static let resolutionLock = NSLock()
    nonisolated(unsafe) private static var cachedStateDirectories: [String: URL] = [:]
    nonisolated(unsafe) private static var cachedSessionStateDirectories: [String: URL] = [:]

    static var homeStateDirectory: URL {
        return resolvedHomeDirectory().appendingPathComponent(AppIdentity.stateDirectoryName, isDirectory: true)
    }

    static var userHomeDirectory: URL {
        resolvedHomeDirectory()
    }

    static var homeConfigFile: URL {
        homeStateDirectory.appendingPathComponent("config.json")
    }

    static var homeProfileFile: URL {
        homeStateDirectory.appendingPathComponent("profile.ovpn")
    }

    static var privilegedExecutableDirectory: URL {
        URL(fileURLWithPath: "/Library/PrivilegedHelperTools", isDirectory: true)
            .appendingPathComponent("cwru-ovpn", isDirectory: true)
    }

    static var privilegedExecutable: URL {
        privilegedExecutableDirectory.appendingPathComponent(AppIdentity.executableName)
    }

    static var approvedProfileManifest: URL {
        privilegedExecutableDirectory.appendingPathComponent("approved-profile.sha256")
    }

    static var stateDirectory: URL {
        cachedDirectory(cache: &cachedStateDirectories,
                        key: "state:\(getuid()):\(homeStateDirectory.path)",
                        resolver: resolveStateDirectory)
    }

    static var sessionStateDirectory: URL {
        cachedDirectory(cache: &cachedSessionStateDirectories,
                        key: "session:\(getuid()):\(homeStateDirectory.path)",
                        resolver: resolveSessionStateDirectory)
    }

    static var sessionStateFile: URL {
        sessionStateDirectory.appendingPathComponent("session.json")
    }

    static var eventLogFile: URL {
        stateDirectory.appendingPathComponent("events.ndjson")
    }

    static var homeSessionStateFile: URL {
        homeStateDirectory.appendingPathComponent("session.json")
    }

    static var privilegedSessionStateDirectoryPath: String {
        privilegedSessionStateDirectory.path
    }

    static func createTemporaryFile(prefix: String) throws -> URL {
        let directory: URL
        let secureFileAtURL: (URL) throws -> Void

        if getuid() == 0 {
            try ensureSessionStateDirectory()
            directory = sessionStateDirectory
            secureFileAtURL = secureSessionStateFile(at:)
        } else {
            try ensureStateDirectory()
            directory = stateDirectory
            secureFileAtURL = secureFile(at:)
        }

        var template = Array(directory.appendingPathComponent("\(prefix).XXXXXX").path.utf8CString)
        let fd = template.withUnsafeMutableBufferPointer { mkstemp($0.baseAddress!) }
        guard fd >= 0 else {
            throw FileIO.posixError(errno)
        }
        let path = template.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        var keepFile = false
        defer {
            if !keepFile {
                unlink(path)
            }
        }

        guard fchmod(fd, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            let chmodError = errno
            close(fd)
            throw FileIO.posixError(chmodError)
        }
        guard close(fd) == 0 else {
            throw FileIO.posixError(errno)
        }

        let url = URL(fileURLWithPath: path).standardizedFileURL
        try secureFileAtURL(url)
        keepFile = true
        return url
    }

    static func ensureStateDirectory() throws {
        try withStateDirectoryAnchor { _, _, _ in }
    }

    static func ensureSessionStateDirectory() throws {
        try withSessionStateDirectoryAnchor { _, _, _ in }
    }

    static func ensureHomeStateDirectory() throws {
        try withHomeStateDirectoryAnchor { _, _, _ in }
    }

    static func withStateDirectoryAnchor<T>(body: (Int32, uid_t, gid_t) throws -> T) throws -> T {
        let directory = stateDirectory
        let policy: OwnershipPolicy = directory.path == homeStateDirectory.path
            ? .sudoUserWhenAvailable
            : .currentUser
        return try withDirectoryAnchor(at: directory,
                                       ownershipPolicy: policy,
                                       body: body)
    }

    static func withHomeStateDirectoryAnchor<T>(body: (Int32, uid_t, gid_t) throws -> T) throws -> T {
        try withDirectoryAnchor(at: homeStateDirectory,
                                ownershipPolicy: .sudoUserWhenAvailable,
                                body: body)
    }

    static func withSessionStateDirectoryAnchor<T>(body: (Int32, uid_t, gid_t) throws -> T) throws -> T {
        let policy: OwnershipPolicy = getuid() == 0 ? .currentUser : .sudoUserWhenAvailable
        return try withDirectoryAnchor(at: sessionStateDirectory,
                                       ownershipPolicy: policy,
                                       body: body)
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

    static func secureFile(at url: URL) throws {
        try applySecurityAttributes(to: url,
                                    permissions: 0o600,
                                    ownershipPolicy: .sudoUserWhenAvailable)
    }

    static func secureSessionStateFile(at url: URL) throws {
        if getuid() == 0 {
            try applySecurityAttributes(to: url,
                                        permissions: 0o600,
                                        ownershipPolicy: .currentUser)
        } else {
            try secureFile(at: url)
        }
    }

    private static func resolvedHomeDirectory() -> URL {
        if let sudoIdentity = try? ExecutionIdentity.validatedSudoUserIfAvailable() {
            return sudoIdentity.homeDirectory
        }
        return FileManager.default.homeDirectoryForCurrentUser
    }

    private static func resolveStateDirectory() -> URL {
        let homeCandidate = homeStateDirectory
        if canUseDirectory(homeCandidate, ownershipPolicy: .sudoUserWhenAvailable) {
            return homeCandidate
        }

        let tempCandidate = tempStateDirectory
        if canUseDirectory(tempCandidate, ownershipPolicy: .currentUser) {
            return tempCandidate
        }

        return homeCandidate
    }

    private static func cachedDirectory(cache: inout [String: URL],
                                        key: String,
                                        resolver: () -> URL) -> URL {
        resolutionLock.lock()
        defer { resolutionLock.unlock() }

        if let cached = cache[key] {
            return cached
        }

        let resolved = resolver()
        cache[key] = resolved
        return resolved
    }

    private static func resolveSessionStateDirectory() -> URL {
        if getuid() == 0 {
            return privilegedSessionStateDirectory
        }

        let homeCandidate = homeStateDirectory
        if canUseDirectory(homeCandidate, ownershipPolicy: .currentUser) {
            return homeCandidate
        }

        let tempCandidate = tempStateDirectory
        if canUseDirectory(tempCandidate, ownershipPolicy: .currentUser) {
            return tempCandidate
        }

        return homeCandidate
    }

    private static var privilegedSessionStateDirectory: URL {
        URL(fileURLWithPath: "/var/db", isDirectory: true)
            .appendingPathComponent("cwru-ovpn", isDirectory: true)
    }

    private static var tempStateDirectory: URL {
        URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("cwru-ovpn-\(getuid())", isDirectory: true)
    }

    private static func canUseDirectory(_ directory: URL, ownershipPolicy: OwnershipPolicy) -> Bool {
        do {
            return try withDirectoryAnchor(at: directory,
                                           ownershipPolicy: ownershipPolicy) { directoryFD, userID, groupID in
                let probeName = ".probe-\(UUID().uuidString)"
                let probeFD = try AnchoredFileIO.openOwnedRegularFileForAppend(in: directoryFD,
                                                                               name: probeName,
                                                                               userID: userID,
                                                                               groupID: groupID)
                close(probeFD)
                try AnchoredFileIO.removeFileIfPresent(in: directoryFD, name: probeName)
                return true
            }
        } catch {
            return false
        }
    }

    private static func withDirectoryAnchor<T>(at directory: URL,
                                               ownershipPolicy: OwnershipPolicy,
                                               body: (Int32, uid_t, gid_t) throws -> T) throws -> T {
        let ownership = try expectedOwnership(for: ownershipPolicy)
        return try AnchoredFileIO.withDirectory(at: directory,
                                                parentUserID: ownership.userID,
                                                parentGroupID: ownership.groupID,
                                                userID: ownership.userID,
                                                groupID: ownership.groupID) { directoryFD in
            try body(directoryFD, ownership.userID, ownership.groupID)
        }
    }

    private static func expectedOwnership(for ownershipPolicy: OwnershipPolicy) throws -> (userID: uid_t, groupID: gid_t) {
        switch ownershipPolicy {
        case .currentUser:
            return (getuid(), getgid())
        case .sudoUserWhenAvailable:
            let identity = try ExecutionIdentity.currentUser()
            return (identity.userID, identity.groupID)
        }
    }

    private static func applySecurityAttributes(to url: URL,
                                                permissions: Int,
                                                ownershipPolicy: OwnershipPolicy) throws {
        let fd = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        let openError = errno
        guard fd >= 0 else {
            if openError == ELOOP {
                throw NSError(domain: NSPOSIXErrorDomain,
                              code: Int(ELOOP),
                              userInfo: [NSLocalizedDescriptionKey: "Refusing to use a symbolic link for \(url.path)."])
            }
            throw FileIO.posixError(openError)
        }
        defer { close(fd) }

        var fileInfo = Darwin.stat()
        let statResult = Darwin.fstat(fd, &fileInfo)
        let statError = errno
        guard statResult == 0 else {
            throw FileIO.posixError(statError)
        }

        guard (fileInfo.st_mode & S_IFMT) == S_IFREG else {
            throw NSError(domain: NSPOSIXErrorDomain,
                          code: Int(EFTYPE),
                          userInfo: [NSLocalizedDescriptionKey: "Refusing to secure an unexpected filesystem node at \(url.path)."])
        }

        if fileInfo.st_nlink != 1 {
            throw NSError(domain: NSPOSIXErrorDomain,
                          code: Int(EMLINK),
                          userInfo: [NSLocalizedDescriptionKey: "Refusing to secure a hardlinked file at \(url.path)."])
        }

        let expectedOwnership = try expectedOwnership(for: ownershipPolicy)

        if (fileInfo.st_uid != expectedOwnership.userID || fileInfo.st_gid != expectedOwnership.groupID),
           fchown(fd, expectedOwnership.userID, expectedOwnership.groupID) != 0 {
            let chownError = errno
            throw FileIO.posixError(chownError)
        }

        guard fchmod(fd, mode_t(permissions)) == 0 else {
            let chmodError = errno
            throw FileIO.posixError(chmodError)
        }

        var securedInfo = Darwin.stat()
        guard Darwin.fstat(fd, &securedInfo) == 0 else {
            let statError = errno
            throw FileIO.posixError(statError)
        }
        guard securedInfo.st_uid == expectedOwnership.userID,
              securedInfo.st_gid == expectedOwnership.groupID,
              mode_t(securedInfo.st_mode & 0o777) == mode_t(permissions) else {
            throw NSError(domain: NSPOSIXErrorDomain,
                          code: Int(EPERM),
                          userInfo: [NSLocalizedDescriptionKey: "Failed to enforce ownership or mode for \(url.path)."])
        }
    }
}
