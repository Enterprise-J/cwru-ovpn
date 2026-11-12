import Darwin
import Foundation

enum ChildProcess {
    static func launch(arguments: [String], standardOutput: FileHandle? = nil) throws -> Process {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: try ExecutionIdentity.currentExecutablePath())
        process.arguments = arguments
        process.environment = sanitizedPrivilegedEnvironment(
            sudoIdentity: try ExecutionIdentity.validatedSudoUserIfAvailable()
        )
        process.standardInput = FileHandle(forReadingAtPath: "/dev/null")
        process.standardOutput = standardOutput ?? FileHandle(forWritingAtPath: "/dev/null")
        process.standardError = FileHandle(forWritingAtPath: "/dev/null")
        try process.run()
        return process
    }

    static func sanitizedPrivilegedEnvironment(sudoIdentity: ResolvedUserIdentity?) -> [String: String] {
        var environment = CommandRunner.subprocessEnvironment

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
