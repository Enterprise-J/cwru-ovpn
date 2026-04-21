import Darwin
import Foundation

struct ProcessStartTime: Codable, Equatable {
    let seconds: UInt64
    let microseconds: UInt64
}

func processExists(_ pid: Int32) -> Bool {
    guard pid > 0 else {
        return false
    }
    if kill(pid, 0) == 0 {
        return true
    }
    return errno == EPERM
}

func processStartTime(_ pid: Int32) -> ProcessStartTime? {
    guard let info = processBSDInfo(pid) else {
        return nil
    }

    return ProcessStartTime(seconds: info.pbi_start_tvsec,
                            microseconds: info.pbi_start_tvusec)
}

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

func processMatchesExecutable(_ pid: Int32,
                              expectedExecutablePath: String,
                              expectedStartTime: ProcessStartTime? = nil) -> Bool {
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

    guard normalizedActual == normalizedExpected else {
        return false
    }

    if let expectedStartTime {
        return processStartTime(pid) == expectedStartTime
    }

    return true
}

private func processBSDInfo(_ pid: Int32) -> proc_bsdinfo? {
    guard pid > 0 else {
        return nil
    }

    var info = proc_bsdinfo()
    let infoSize = Int32(MemoryLayout<proc_bsdinfo>.stride)
    let size = withUnsafeMutablePointer(to: &info) { pointer in
        proc_pidinfo(pid,
                     PROC_PIDTBSDINFO,
                     UInt64(0),
                     pointer,
                     infoSize)
    }

    guard size == infoSize,
          info.pbi_pid == UInt32(pid) else {
        return nil
    }

    return info
}
