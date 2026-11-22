import Darwin
import Foundation

final class ChildProcess: @unchecked Sendable {
    let processIdentifier: pid_t
    private let lock = NSLock()
    private let finished = DispatchGroup()
    private var running = true

    private init(pid: pid_t) {
        processIdentifier = pid
        finished.enter()
        let source = DispatchSource.makeProcessSource(identifier: pid, eventMask: .exit, queue: .global())
        source.setEventHandler { [self] in
            lock.lock()
            var status: Int32 = 0
            while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
            running = false
            lock.unlock()
            finished.leave()
            source.cancel()
            source.setEventHandler(handler: nil)
        }
        source.activate()
    }

    var isRunning: Bool { lock.withLock { running } }

    func signal(_ number: Int32) {
        lock.withLock { if running { _ = kill(processIdentifier, number) } }
    }

    func waitUntilExit() { finished.wait() }

    static func launch(arguments: [String], standardOutput: FileHandle? = nil,
                       input: Int32? = nil) throws -> ChildProcess {
        let identity = try ExecutionIdentity.validatedSudoUserIfAvailable()
        let executable = try ExecutionIdentity.currentExecutablePath()
        let null = open("/dev/null", O_RDWR | O_CLOEXEC)
        guard null >= 0 else { throw FileIO.failure("Failed to open /dev/null", errno) }
        defer { close(null) }
        return try ChildProcess(pid: CommandRunner.spawnProcessGroup(executablePath: executable, arguments: arguments,
            environment: sanitizedPrivilegedEnvironment(sudoIdentity: identity), inputDescriptor: input,
            outputDescriptor: standardOutput?.fileDescriptor ?? null, errorDescriptor: null))
    }

    static func enterUserInterface() throws {
        if ExecutionIdentity.isPrivileged {
            guard let identity = try ExecutionIdentity.validatedSudoUserIfAvailable(), identity.userID != 0 else {
                throw VPNControllerError.operationFailed("The VPN user interface requires a logged-in macOS user.")
            }
            let path = try ExecutionIdentity.currentExecutablePath()
            let arguments = try CStringVector([path] + Array(CommandLine.arguments.dropFirst()))
            let environment = try CStringVector(["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C",
                                                 "HOME=" + identity.homeDirectory.path, "USER=" + identity.username,
                                                 "LOGNAME=" + identity.username])
            guard initgroups(identity.username, Int32(bitPattern: identity.groupID)) == 0,
                  setgid(identity.groupID) == 0, setuid(identity.userID) == 0,
                  getuid() == identity.userID, geteuid() == identity.userID,
                  getgid() == identity.groupID, getegid() == identity.groupID else {
                throw POSIXError(.EPERM)
            }
            _ = arguments.withUnsafeMutablePointer { argv in
                environment.withUnsafeMutablePointer { env in execve(path, argv, env) }
            }
            throw FileIO.failure("Failed to enter the user interface session", errno)
        }
        guard getuid() != 0, geteuid() == getuid(), getegid() == getgid() else { throw POSIXError(.EPERM) }
    }

    static func sanitizedPrivilegedEnvironment(sudoIdentity: ResolvedUserIdentity?) -> [String: String] {
        var environment = CommandRunner.subprocessEnvironment
        environment["HOME"] = "/var/empty"
        environment["USER"] = "root"
        environment["LOGNAME"] = "root"
        if let sudoIdentity {
            environment["SUDO_USER"] = sudoIdentity.username
            environment["SUDO_UID"] = String(sudoIdentity.userID)
            environment["SUDO_GID"] = String(sudoIdentity.groupID)
        }
        return environment
    }
}
