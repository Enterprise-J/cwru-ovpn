import Darwin
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
    let environment: [String: String]?
}

private final class CStringVector {
    private var pointers: [UnsafeMutablePointer<CChar>?]

    init(_ strings: [String]) throws {
        var allocated: [UnsafeMutablePointer<CChar>] = []
        do {
            for string in strings {
                guard !string.utf8.contains(0) else {
                    throw POSIXError(.EINVAL)
                }
                guard let pointer = strdup(string) else {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .ENOMEM)
                }
                allocated.append(pointer)
            }
        } catch {
            allocated.forEach { free($0) }
            throw error
        }
        pointers = allocated.map(Optional.some) + [nil]
    }

    func withUnsafeMutablePointer<T>(
        _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> T
    ) -> T {
        pointers.withUnsafeMutableBufferPointer { buffer in
            body(buffer.baseAddress!)
        }
    }

    deinit {
        for case let pointer? in pointers {
            free(pointer)
        }
    }
}

private final class PipeCollector: @unchecked Sendable {
    private let handle: FileHandle
    private let queue = DispatchQueue(label: "cwru-ovpn.shell.pipe-collector")
    private let source: DispatchSourceRead
    private var data = Data()
    private var finished = false

    init(handle: FileHandle) throws {
        self.handle = handle
        let flags = fcntl(handle.fileDescriptor, F_GETFL)
        guard flags >= 0,
              fcntl(handle.fileDescriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        source = DispatchSource.makeReadSource(fileDescriptor: handle.fileDescriptor,
                                               queue: queue)
        source.setCancelHandler {
            try? handle.close()
        }
        source.setEventHandler { [weak self] in
            guard let self else {
                return
            }
            if source.data == 0 {
                finished = true
                source.cancel()
                return
            }
            drainAvailable()
        }
        source.activate()
    }

    func finish() -> Data {
        queue.sync {
            guard !finished else {
                return data
            }
            drainAvailable()
            finished = true
            source.cancel()
            return data
        }
    }

    private func drainAvailable() {
        guard !finished else {
            return
        }
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let bytesRead = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(handle.fileDescriptor,
                            bytes.baseAddress,
                            bytes.count)
            }
            if bytesRead < 0 {
                if errno == EINTR {
                    continue
                }
                return
            }
            guard bytesRead > 0 else {
                return
            }
            data.append(contentsOf: buffer.prefix(bytesRead))
        }
    }

    deinit {
        source.cancel()
    }
}

enum ShellError: LocalizedError {
    case commandFailed(String, Int32, String)
    case timedOut(String, TimeInterval, String)

    var errorDescription: String? {
        switch self {
        case .commandFailed(let command, let exitCode, let stderr):
            return "Command failed (\(exitCode)): \(command)\n\(stderr)"
        case .timedOut(let command, let timeout, let stderr):
            return "Command timed out after \(String(format: "%.1f", timeout)) seconds: \(command)\n\(stderr)"
        }
    }
}

struct Shell: @unchecked Sendable {
    typealias Handler = (ShellInvocation) throws -> ShellResult

    private let handler: Handler?

    init() {
        handler = nil
    }

    init(handler: @escaping Handler) {
        self.handler = handler
    }

    private static let privilegedSubprocessEnvironment = [
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    ]

    static func subprocessEnvironment(requirePrivileges: Bool,
                                      effectiveUserID: uid_t = geteuid()) -> [String: String]? {
        requirePrivileges || effectiveUserID == 0 ? privilegedSubprocessEnvironment : nil
    }

    private static func resolvedEnvironment(requirePrivileges: Bool,
                                            overrides: [String: String]?) -> [String: String]? {
        let base = subprocessEnvironment(requirePrivileges: requirePrivileges)
        guard let overrides, !overrides.isEmpty else {
            return base
        }
        var merged = base ?? ProcessInfo.processInfo.environment
        for (key, value) in overrides {
            merged[key] = value
        }
        return merged
    }

    static func shouldReportTimeout(waitTimedOut: Bool, processExitedAtBoundary: Bool) -> Bool {
        waitTimedOut && !processExitedAtBoundary
    }

    private static func requireSpawnSuccess(_ result: Int32) throws {
        guard result == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: result) ?? .EIO)
        }
    }

    private static func spawnProcessGroup(executablePath: String,
                                          arguments: [String],
                                          environment: [String: String],
                                          inputDescriptor: Int32?,
                                          outputDescriptor: Int32,
                                          errorDescriptor: Int32) throws -> pid_t {
        var fileActions: posix_spawn_file_actions_t?
        try requireSpawnSuccess(posix_spawn_file_actions_init(&fileActions))
        defer { posix_spawn_file_actions_destroy(&fileActions) }

        if let inputDescriptor {
            try requireSpawnSuccess(posix_spawn_file_actions_adddup2(&fileActions,
                                                                      inputDescriptor,
                                                                      STDIN_FILENO))
        } else {
            try requireSpawnSuccess(posix_spawn_file_actions_addinherit_np(&fileActions,
                                                                            STDIN_FILENO))
        }
        try requireSpawnSuccess(posix_spawn_file_actions_adddup2(&fileActions,
                                                                  outputDescriptor,
                                                                  STDOUT_FILENO))
        try requireSpawnSuccess(posix_spawn_file_actions_adddup2(&fileActions,
                                                                  errorDescriptor,
                                                                  STDERR_FILENO))

        let duplicatedDescriptors = [inputDescriptor, outputDescriptor, errorDescriptor].compactMap { $0 }
        for descriptor in Set(duplicatedDescriptors) where descriptor > STDERR_FILENO {
            try requireSpawnSuccess(posix_spawn_file_actions_addclose(&fileActions, descriptor))
        }

        var attributes: posix_spawnattr_t?
        try requireSpawnSuccess(posix_spawnattr_init(&attributes))
        defer { posix_spawnattr_destroy(&attributes) }
        try requireSpawnSuccess(posix_spawnattr_setpgroup(&attributes, 0))
        var defaultSignals = sigset_t()
        sigemptyset(&defaultSignals)
        for signalNumber in [SIGINT, SIGTERM, SIGUSR1, SIGHUP, SIGPIPE] {
            sigaddset(&defaultSignals, signalNumber)
        }
        try requireSpawnSuccess(posix_spawnattr_setsigdefault(&attributes, &defaultSignals))
        var signalMask = sigset_t()
        sigemptyset(&signalMask)
        try requireSpawnSuccess(posix_spawnattr_setsigmask(&attributes, &signalMask))
        let flags = Int16(POSIX_SPAWN_SETPGROUP
            | POSIX_SPAWN_SETSIGDEF
            | POSIX_SPAWN_SETSIGMASK
            | POSIX_SPAWN_CLOEXEC_DEFAULT)
        try requireSpawnSuccess(posix_spawnattr_setflags(&attributes, flags))

        let argumentVector = try CStringVector([executablePath] + arguments)
        let environmentVector = try CStringVector(environment.sorted { $0.key < $1.key }.map {
            "\($0.key)=\($0.value)"
        })
        var processID: pid_t = 0
        let spawnResult = executablePath.withCString { executablePointer in
            argumentVector.withUnsafeMutablePointer { argumentPointer in
                environmentVector.withUnsafeMutablePointer { environmentPointer in
                    posix_spawn(&processID,
                                executablePointer,
                                &fileActions,
                                &attributes,
                                argumentPointer,
                                environmentPointer)
                }
            }
        }
        try requireSpawnSuccess(spawnResult)
        return processID
    }

    private static func reapExitedProcess(_ processID: pid_t) throws -> Int32? {
        var status: Int32 = 0
        while true {
            let result = waitpid(processID, &status, WNOHANG)
            if result == processID {
                return status
            }
            if result == 0 {
                return nil
            }
            if errno != EINTR {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .ECHILD)
            }
        }
    }

    private static func waitForProcess(_ processID: pid_t) throws -> Int32 {
        var status: Int32 = 0
        while waitpid(processID, &status, 0) < 0 {
            if errno != EINTR {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .ECHILD)
            }
        }
        return status
    }

    private static func exitCode(from waitStatus: Int32) -> Int32 {
        let terminationSignal = waitStatus & 0o177
        if terminationSignal == 0 {
            return (waitStatus >> 8) & 0xff
        }
        return terminationSignal
    }

    private static func signalProcessGroup(_ processID: pid_t, signal: Int32) {
        guard processID > 1 else {
            return
        }
        if kill(-processID, signal) != 0, errno != ESRCH {
            _ = kill(processID, signal)
        }
    }

    private static func makeInputPipe() throws -> Pipe {
        let pipe = Pipe()
        guard fcntl(pipe.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else {
            let errorCode = POSIXErrorCode(rawValue: errno) ?? .EIO
            pipe.fileHandleForReading.closeFile()
            pipe.fileHandleForWriting.closeFile()
            throw POSIXError(errorCode)
        }
        return pipe
    }

    private static func writeInput(_ input: Data, to descriptor: Int32) {
        input.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else {
                return
            }
            var offset = 0
            while offset < bytes.count {
                let bytesWritten = Darwin.write(descriptor,
                                                baseAddress.advanced(by: offset),
                                                bytes.count - offset)
                if bytesWritten > 0 {
                    offset += bytesWritten
                    continue
                }
                if bytesWritten < 0, errno == EINTR {
                    continue
                }
                return
            }
        }
    }

    @discardableResult
    func run(_ launchPath: String,
             arguments: [String],
             input: Data? = nil,
             allowNonZero: Bool = false,
             requirePrivileges: Bool = false,
             environmentOverrides: [String: String]? = nil,
             timeout: TimeInterval = 30) throws -> ShellResult {
        let effectiveTimeout = max(0.1, timeout)
        let environment = Self.resolvedEnvironment(requirePrivileges: requirePrivileges,
                                                   overrides: environmentOverrides)
        let invocation = ShellInvocation(launchPath: launchPath,
                                         arguments: arguments,
                                         input: input,
                                         allowNonZero: allowNonZero,
                                         requirePrivileges: requirePrivileges,
                                         environment: environment)

        if let handler {
            let handledResult = try handler(invocation)
            if !allowNonZero && handledResult.exitCode != 0 {
                throw ShellError.commandFailed(([launchPath] + arguments).joined(separator: " "),
                                               handledResult.exitCode,
                                               handledResult.stderr)
            }
            return handledResult
        }

        let executablePath = requirePrivileges && geteuid() != 0 ? "/usr/bin/sudo" : launchPath
        let processArguments = requirePrivileges && geteuid() != 0 ? [launchPath] + arguments : arguments
        let processEnvironment = environment ?? ProcessInfo.processInfo.environment

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        let stdoutCollector = try PipeCollector(handle: stdoutPipe.fileHandleForReading)
        let stderrCollector = try PipeCollector(handle: stderrPipe.fileHandleForReading)

        let inputWriteCompletion = DispatchGroup()
        var inputPipe: Pipe?
        if input != nil {
            inputPipe = try Self.makeInputPipe()
        }

        let processID: pid_t
        do {
            processID = try Self.spawnProcessGroup(executablePath: executablePath,
                                                   arguments: processArguments,
                                                   environment: processEnvironment,
                                                   inputDescriptor: inputPipe?.fileHandleForReading.fileDescriptor,
                                                   outputDescriptor: stdoutPipe.fileHandleForWriting.fileDescriptor,
                                                   errorDescriptor: stderrPipe.fileHandleForWriting.fileDescriptor)
        } catch {
            stdoutPipe.fileHandleForWriting.closeFile()
            stderrPipe.fileHandleForWriting.closeFile()
            inputPipe?.fileHandleForReading.closeFile()
            inputPipe?.fileHandleForWriting.closeFile()
            _ = stdoutCollector.finish()
            _ = stderrCollector.finish()
            throw error
        }

        let terminationCompletion = DispatchSemaphore(value: 0)
        let processExitSource = DispatchSource.makeProcessSource(identifier: processID,
                                                                 eventMask: .exit,
                                                                 queue: .global(qos: .utility))
        processExitSource.setEventHandler {
            terminationCompletion.signal()
        }
        processExitSource.activate()
        defer { processExitSource.cancel() }

        stdoutPipe.fileHandleForWriting.closeFile()
        stderrPipe.fileHandleForWriting.closeFile()
        inputPipe?.fileHandleForReading.closeFile()
        if let input, let inputPipe {
            let inputHandle = inputPipe.fileHandleForWriting
            inputWriteCompletion.enter()
            DispatchQueue.global().async {
                defer {
                    inputHandle.closeFile()
                    inputWriteCompletion.leave()
                }
                Self.writeInput(input, to: inputHandle.fileDescriptor)
            }
        }
        let waitTimedOut = terminationCompletion.wait(timeout: .now() + effectiveTimeout) == .timedOut
        let boundaryStatus = waitTimedOut ? try Self.reapExitedProcess(processID) : nil
        let timedOut = Self.shouldReportTimeout(waitTimedOut: waitTimedOut,
                                                processExitedAtBoundary: boundaryStatus != nil)
        let waitStatus: Int32
        if timedOut {
            Self.signalProcessGroup(processID, signal: SIGTERM)
            _ = terminationCompletion.wait(timeout: .now() + 2)
            Self.signalProcessGroup(processID, signal: SIGKILL)
            waitStatus = try Self.waitForProcess(processID)
        } else if let boundaryStatus {
            waitStatus = boundaryStatus
        } else {
            waitStatus = try Self.waitForProcess(processID)
        }
        inputWriteCompletion.wait()
        let stdoutData = stdoutCollector.finish()
        let stderrData = stderrCollector.finish()

        let stdout = String(decoding: stdoutData, as: UTF8.self)
        let stderr = String(decoding: stderrData, as: UTF8.self)
        let result = ShellResult(exitCode: Self.exitCode(from: waitStatus), stdout: stdout, stderr: stderr)

        if timedOut {
            throw ShellError.timedOut(([launchPath] + arguments).joined(separator: " "),
                                      effectiveTimeout,
                                      stderr)
        }

        if !allowNonZero && result.exitCode != 0 {
            throw ShellError.commandFailed(([launchPath] + arguments).joined(separator: " "), result.exitCode, stderr)
        }

        return result
    }
}
