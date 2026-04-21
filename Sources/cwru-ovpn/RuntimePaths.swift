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
        if getuid() != 0,
           let raw = getenv("CWRU_OVPN_HOME_STATE_DIR") {
            let overridden = String(cString: raw)
            if !overridden.isEmpty {
                return URL(fileURLWithPath: overridden, isDirectory: true).standardized
            }
        }
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

        var template = Array(directory
            .appendingPathComponent("\(prefix).XXXXXX")
            .path
            .utf8CString)
        let fd = template.withUnsafeMutableBufferPointer { buffer -> Int32 in
            guard let baseAddress = buffer.baseAddress else {
                return -1
            }
            return mkstemp(baseAddress)
        }
        let createError = errno
        guard fd >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: createError) ?? .EIO)
        }

        guard fchmod(fd, mode_t(S_IRUSR | S_IWUSR)) == 0 else {
            let chmodError = errno
            close(fd)
            throw POSIXError(POSIXErrorCode(rawValue: chmodError) ?? .EIO)
        }

        guard close(fd) == 0 else {
            let closeError = errno
            throw POSIXError(POSIXErrorCode(rawValue: closeError) ?? .EIO)
        }

        let path = template.withUnsafeBufferPointer { buffer -> String in
            guard let baseAddress = buffer.baseAddress else {
                return ""
            }
            return String(cString: baseAddress)
        }
        guard !path.isEmpty else {
            throw POSIXError(.EIO)
        }

        let url = URL(fileURLWithPath: path).standardizedFileURL
        try secureFileAtURL(url)
        return url
    }

    static func ensureStateDirectory() throws {
        try FileManager.default.createDirectory(at: stateDirectory, withIntermediateDirectories: true)
        try secureDirectory(at: stateDirectory)
    }

    static func ensureSessionStateDirectory() throws {
        try FileManager.default.createDirectory(at: sessionStateDirectory, withIntermediateDirectories: true)
        if getuid() == 0 {
            try securePrivilegedDirectory(at: sessionStateDirectory)
        } else {
            try secureDirectory(at: sessionStateDirectory)
        }
    }

    static func secureFile(at url: URL) throws {
        try applySecurityAttributes(to: url,
                                    permissions: 0o600,
                                    ownershipPolicy: .sudoUserWhenAvailable)
    }

    static func secureDirectory(at url: URL) throws {
        try applySecurityAttributes(to: url,
                                    permissions: 0o700,
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
        let environment = ProcessInfo.processInfo.environment
        if getuid() == 0,
           let sudoUser = environment["SUDO_USER"],
           !sudoUser.isEmpty,
           let homePath = NSHomeDirectoryForUser(sudoUser) {
            return URL(fileURLWithPath: homePath, isDirectory: true)
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
        URL(fileURLWithPath: "/var/run", isDirectory: true)
            .appendingPathComponent("cwru-ovpn", isDirectory: true)
    }

    private static var tempStateDirectory: URL {
        URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("cwru-ovpn-\(getuid())", isDirectory: true)
    }

    private static func canUseDirectory(_ directory: URL, ownershipPolicy: OwnershipPolicy) -> Bool {
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try applySecurityAttributes(to: directory,
                                        permissions: 0o700,
                                        ownershipPolicy: ownershipPolicy)
            let probe = directory.appendingPathComponent(".probe-\(UUID().uuidString)")
            try Data().write(to: probe, options: .atomic)
            try applySecurityAttributes(to: probe,
                                        permissions: 0o600,
                                        ownershipPolicy: ownershipPolicy)
            try FileManager.default.removeItem(at: probe)
            return true
        } catch {
            return false
        }
    }

    private static func securePrivilegedDirectory(at url: URL) throws {
        try applySecurityAttributes(to: url,
                                    permissions: 0o700,
                                    ownershipPolicy: .currentUser)
    }

    private static func applySecurityAttributes(to url: URL,
                                                permissions: Int,
                                                ownershipPolicy: OwnershipPolicy) throws {
        try assertNotSymbolicLink(at: url)

        var attributes: [FileAttributeKey: Any] = [
            .posixPermissions: permissions
        ]

        if ownershipPolicy == .sudoUserWhenAvailable,
           getuid() == 0 {
            let environment = ProcessInfo.processInfo.environment
            if let sudoUID = environment["SUDO_UID"].flatMap(Int.init),
               let sudoGID = environment["SUDO_GID"].flatMap(Int.init) {
                attributes[.ownerAccountID] = sudoUID
                attributes[.groupOwnerAccountID] = sudoGID
            }
        }

        try FileManager.default.setAttributes(attributes, ofItemAtPath: url.path)
    }

    private static func assertNotSymbolicLink(at url: URL) throws {
        var fileInfo = stat()
        let result = lstat(url.path, &fileInfo)
        let lstatError = errno
        guard result == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: lstatError) ?? .EIO)
        }

        guard (fileInfo.st_mode & S_IFMT) != S_IFLNK else {
            throw NSError(domain: NSPOSIXErrorDomain,
                          code: Int(ELOOP),
                          userInfo: [NSLocalizedDescriptionKey: "Refusing to use a symbolic link for \(url.path)."])
        }
    }
}
