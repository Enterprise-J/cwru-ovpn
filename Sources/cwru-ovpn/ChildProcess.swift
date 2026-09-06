import Darwin
import Foundation

enum ChildProcess {
    private static let basePrivilegedEnvironment = [
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    ]

    static func launch(arguments: [String]) throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: try ExecutionIdentity.currentExecutablePath())
        process.arguments = arguments
        process.environment = environment()
        process.standardInput = FileHandle(forReadingAtPath: "/dev/null")
        process.standardOutput = FileHandle(forWritingAtPath: "/dev/null")
        process.standardError = FileHandle(forWritingAtPath: "/dev/null")
        try process.run()
        return process
    }

    static func environment() -> [String: String] {
        guard getuid() == 0 else {
            return ProcessInfo.processInfo.environment
        }

        return sanitizedPrivilegedEnvironment(sudoIdentity: try? ExecutionIdentity.validatedSudoUserIfAvailable())
    }

    static func sanitizedPrivilegedEnvironment(sudoIdentity: ResolvedUserIdentity?) -> [String: String] {
        var environment = basePrivilegedEnvironment

        guard let sudoIdentity else {
            return environment
        }

        environment["SUDO_USER"] = sudoIdentity.username
        environment["SUDO_UID"] = String(sudoIdentity.userID)
        environment["SUDO_GID"] = String(sudoIdentity.groupID)
        environment["HOME"] = sudoIdentity.homeDirectory.path
        environment["USER"] = sudoIdentity.username
        environment["LOGNAME"] = sudoIdentity.username
        return environment
    }
}
