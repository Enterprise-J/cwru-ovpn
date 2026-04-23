import Darwin
import Foundation

struct ResolvedUserIdentity {
    let username: String
    let userID: uid_t
    let groupID: gid_t
    let homeDirectory: URL
}

enum ExecutionIdentityError: LocalizedError {
    case inconsistentSudoEnvironment(String)
    case couldNotResolveUser(uid_t)
    case couldNotResolveExecutablePath

    var errorDescription: String? {
        switch self {
        case .inconsistentSudoEnvironment(let message):
            return message
        case .couldNotResolveUser(let userID):
            return "Could not resolve the local account for uid \(userID)."
        case .couldNotResolveExecutablePath:
            return "Could not determine the current executable path."
        }
    }
}

enum ExecutionIdentity {
    static func currentUser() throws -> ResolvedUserIdentity {
        if let sudoIdentity = try validatedSudoUserIfAvailable() {
            return sudoIdentity
        }

        return try userIdentity(for: getuid())
    }

    static func validatedSudoUserIfAvailable() throws -> ResolvedUserIdentity? {
        guard getuid() == 0 else {
            return nil
        }

        let environment = ProcessInfo.processInfo.environment
        let sudoUser = environment["SUDO_USER"].flatMap { $0.isEmpty ? nil : $0 }
        let sudoUID = environment["SUDO_UID"].flatMap { $0.isEmpty ? nil : $0 }
        let sudoGID = environment["SUDO_GID"].flatMap { $0.isEmpty ? nil : $0 }

        if sudoUser == nil, sudoUID == nil, sudoGID == nil {
            return nil
        }

        guard let sudoUser, let sudoUID, let sudoGID else {
            throw ExecutionIdentityError.inconsistentSudoEnvironment(
                "Refusing to use a partial sudo identity. SUDO_USER, SUDO_UID, and SUDO_GID must either all be set or all be absent."
            )
        }

        guard let userID = UInt32(sudoUID),
              let groupID = UInt32(sudoGID) else {
            throw ExecutionIdentityError.inconsistentSudoEnvironment(
                "Refusing to use an invalid sudo identity. SUDO_UID and SUDO_GID must be numeric."
            )
        }

        let identity = try userIdentity(for: userID)
        guard identity.username == sudoUser else {
            throw ExecutionIdentityError.inconsistentSudoEnvironment(
                "Refusing to use a mismatched sudo identity. SUDO_USER does not match the passwd entry for SUDO_UID."
            )
        }

        guard identity.groupID == groupID else {
            throw ExecutionIdentityError.inconsistentSudoEnvironment(
                "Refusing to use a mismatched sudo identity. SUDO_GID does not match the passwd entry for SUDO_UID."
            )
        }

        return identity
    }

    static func currentExecutablePath() throws -> String {
        var size = UInt32(MAXPATHLEN)
        var buffer = [CChar](repeating: 0, count: Int(size))

        while _NSGetExecutablePath(&buffer, &size) != 0 {
            guard size > 0 else {
                throw ExecutionIdentityError.couldNotResolveExecutablePath
            }
            buffer = [CChar](repeating: 0, count: Int(size))
        }

        let pathBytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        let path = String(decoding: pathBytes, as: UTF8.self)
        guard !path.isEmpty else {
            throw ExecutionIdentityError.couldNotResolveExecutablePath
        }

        return URL(fileURLWithPath: path)
            .resolvingSymlinksInPath()
            .standardized.path
    }

    private static func userIdentity(for userID: uid_t) throws -> ResolvedUserIdentity {
        guard let passwd = getpwuid(userID) else {
            throw ExecutionIdentityError.couldNotResolveUser(userID)
        }

        let username = String(cString: passwd.pointee.pw_name)
        let homeDirectoryPath = String(cString: passwd.pointee.pw_dir)

        return ResolvedUserIdentity(username: username,
                                    userID: userID,
                                    groupID: passwd.pointee.pw_gid,
                                    homeDirectory: URL(fileURLWithPath: homeDirectoryPath, isDirectory: true))
    }
}
