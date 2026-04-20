import Darwin
import Foundation

/// Returns true if the process with the given PID exists and is accessible.
func processExists(_ pid: Int32) -> Bool {
    guard pid > 0 else {
        return false
    }
    if kill(pid, 0) == 0 {
        return true
    }
    return errno == EPERM
}

/// Returns the executable path for a process, or nil if it cannot be resolved.
func processExecutablePath(_ pid: Int32) -> String? {
    guard pid > 0 else {
        return nil
    }

    var pathBuffer = [UInt8](repeating: 0, count: Int(PROC_PIDPATHINFO_SIZE))
    let copied = pathBuffer.withUnsafeMutableBufferPointer { buffer -> Int32 in
        guard let baseAddress = buffer.baseAddress else {
            return 0
        }
        return proc_pidpath(pid, baseAddress, UInt32(buffer.count))
    }
    if copied > 0 {
        let length = pathBuffer.firstIndex(of: 0) ?? Int(copied)
        let resolved = String(decoding: pathBuffer[..<length], as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if resolved.hasPrefix("/") {
            return resolved
        }
    }

    guard let result = try? Shell.run("/bin/ps",
                                      arguments: ["-p", String(pid), "-o", "comm="],
                                      allowNonZero: true),
          result.exitCode == 0 else {
        return nil
    }

    let output = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !output.isEmpty else {
        return nil
    }

    return output.hasPrefix("/") ? output : nil
}

/// Returns true when a process PID resolves to the expected executable path.
func processMatchesExecutable(_ pid: Int32, expectedExecutablePath: String) -> Bool {
    guard let actualPath = processExecutablePath(pid) else {
        return false
    }

    let normalizedExpected = URL(fileURLWithPath: expectedExecutablePath)
        .resolvingSymlinksInPath()
        .standardized.path

    guard actualPath.hasPrefix("/") else {
        return false
    }

    let normalizedActual = URL(fileURLWithPath: actualPath)
        .resolvingSymlinksInPath()
        .standardized.path

    return normalizedActual == normalizedExpected
}
