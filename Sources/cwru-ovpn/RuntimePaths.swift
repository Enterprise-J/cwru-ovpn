import Foundation
import Darwin

enum RuntimePaths {
    private enum OwnershipPolicy {
        case currentUser
        case sudoUserWhenAvailable
    }

    static var homeStateDirectory: URL {
        if let rawValue = getenv("CWRU_OVPN_HOME_STATE_DIR") {
            let overridden = String(cString: rawValue)
            if !overridden.isEmpty {
                return URL(fileURLWithPath: overridden, isDirectory: true).standardized
            }
        }

        if let overridden = ProcessInfo.processInfo.environment["CWRU_OVPN_HOME_STATE_DIR"], !overridden.isEmpty {
            return URL(fileURLWithPath: overridden, isDirectory: true).standardized
        }
        return resolvedHomeDirectory().appendingPathComponent(AppIdentity.stateDirectoryName, isDirectory: true)
    }

    static var homeConfigFile: URL {
        homeStateDirectory.appendingPathComponent("config.json")
    }

    static var homeProfileFile: URL {
        homeStateDirectory.appendingPathComponent("profile.ovpn")
    }

    static var stateDirectory: URL {
        resolveStateDirectory()
    }

    static var sessionStateDirectory: URL {
        resolveSessionStateDirectory()
    }

    static var sessionStateFile: URL {
        sessionStateDirectory.appendingPathComponent("session.json")
    }

    static var eventLogFile: URL {
        stateDirectory.appendingPathComponent("events.ndjson")
    }

    static var legacySessionStateFile: URL {
        homeStateDirectory.appendingPathComponent("session.json")
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
        if let sudoUser = environment["SUDO_USER"],
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
        var attributes: [FileAttributeKey: Any] = [
            .posixPermissions: permissions
        ]

        if ownershipPolicy == .sudoUserWhenAvailable {
            let environment = ProcessInfo.processInfo.environment
            if let sudoUID = environment["SUDO_UID"].flatMap(Int.init),
               let sudoGID = environment["SUDO_GID"].flatMap(Int.init) {
                attributes[.ownerAccountID] = sudoUID
                attributes[.groupOwnerAccountID] = sudoGID
            }
        }

        try FileManager.default.setAttributes(attributes, ofItemAtPath: url.path)
    }
}
