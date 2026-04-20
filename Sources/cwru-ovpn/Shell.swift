import Foundation

struct ShellResult {
    let exitCode: Int32
    let stdout: String
    let stderr: String
}

struct ShellInvocation {
    let launchPath: String
    let arguments: [String]
    let input: Data?
    let allowNonZero: Bool
    let requirePrivileges: Bool
}

private final class PipeCollector: @unchecked Sendable {
    private let handle: FileHandle
    private let completion = DispatchSemaphore(value: 0)
    private var data = Data()

    init(handle: FileHandle) {
        self.handle = handle
    }

    func start() {
        DispatchQueue.global().async { [self] in
            data = handle.readDataToEndOfFile()
            completion.signal()
        }
    }

    func finish() -> Data {
        completion.wait()
        return data
    }
}

enum ShellError: LocalizedError {
    case commandFailed(String, Int32, String)

    var errorDescription: String? {
        switch self {
        case .commandFailed(let command, let exitCode, let stderr):
            return "Command failed (\(exitCode)): \(command)\n\(stderr)"
        }
    }
}

enum Shell {
#if CWRU_OVPN_INCLUDE_SELF_TEST
    private static let testHookLock = NSLock()
    nonisolated(unsafe) private static var testHook: ((ShellInvocation) throws -> ShellResult?)?

    static func withTestHook<T>(_ hook: @escaping (ShellInvocation) throws -> ShellResult?,
                                perform body: () throws -> T) rethrows -> T {
        testHookLock.lock()
        let previousHook = testHook
        testHook = hook
        testHookLock.unlock()

        defer {
            testHookLock.lock()
            testHook = previousHook
            testHookLock.unlock()
        }

        return try body()
    }

    private static func invokeTestHook(_ invocation: ShellInvocation) throws -> ShellResult? {
        testHookLock.lock()
        let hook = testHook
        testHookLock.unlock()
        return try hook?(invocation)
    }
#endif

    @discardableResult
    static func run(_ launchPath: String,
                    arguments: [String],
                    input: Data? = nil,
                    allowNonZero: Bool = false,
                    requirePrivileges: Bool = false) throws -> ShellResult {
        let invocation = ShellInvocation(launchPath: launchPath,
                                         arguments: arguments,
                                         input: input,
                                         allowNonZero: allowNonZero,
                                         requirePrivileges: requirePrivileges)

#if CWRU_OVPN_INCLUDE_SELF_TEST
        if let hookedResult = try invokeTestHook(invocation) {
            if !allowNonZero && hookedResult.exitCode != 0 {
                throw ShellError.commandFailed(([launchPath] + arguments).joined(separator: " "),
                                               hookedResult.exitCode,
                                               hookedResult.stderr)
            }
            return hookedResult
        }
#endif

        let process = Process()
        process.executableURL = URL(fileURLWithPath: requirePrivileges && getuid() != 0 ? "/usr/bin/sudo" : launchPath)
        process.arguments = requirePrivileges && getuid() != 0 ? [launchPath] + arguments : arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        if let input {
            let inputPipe = Pipe()
            process.standardInput = inputPipe
            try process.run()
            inputPipe.fileHandleForWriting.write(input)
            inputPipe.fileHandleForWriting.closeFile()
        } else {
            try process.run()
        }

        // Read stdout and stderr concurrently on background threads before calling
        // waitUntilExit(). If the child writes more than the pipe buffer (~64 KB),
        // it will block on the write while the parent is stuck in waitUntilExit() —
        // a classic deadlock. Draining the pipes first prevents this.
        let stdoutCollector = PipeCollector(handle: stdoutPipe.fileHandleForReading)
        let stderrCollector = PipeCollector(handle: stderrPipe.fileHandleForReading)
        stdoutCollector.start()
        stderrCollector.start()
        process.waitUntilExit()
        let stdoutData = stdoutCollector.finish()
        let stderrData = stderrCollector.finish()

        let stdout = String(decoding: stdoutData, as: UTF8.self)
        let stderr = String(decoding: stderrData, as: UTF8.self)
        let result = ShellResult(exitCode: process.terminationStatus, stdout: stdout, stderr: stderr)

        if !allowNonZero && result.exitCode != 0 {
            throw ShellError.commandFailed(([launchPath] + arguments).joined(separator: " "), result.exitCode, stderr)
        }

        return result
    }
}
