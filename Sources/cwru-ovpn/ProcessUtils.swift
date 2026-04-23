import Darwin
import Foundation

struct ProcessStartTime: Codable, Equatable {
    let seconds: UInt64
    let microseconds: UInt64
}

func processStartTimeMatches(actualStartTime: ProcessStartTime?,
                             expectedStartTime: ProcessStartTime?) -> Bool {
    guard let expectedStartTime else {
        return true
    }

    // Treat an unreadable start time as inconclusive instead of tearing down a live session.
    guard let actualStartTime else {
        return true
    }

    return actualStartTime == expectedStartTime
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

func processExists(_ pid: Int32, expectedStartTime: ProcessStartTime?) -> Bool {
    guard processExists(pid) else {
        return false
    }

    return processStartTimeMatches(actualStartTime: processStartTime(pid),
                                   expectedStartTime: expectedStartTime)
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
        if resolved.hasPrefix("/") {
            return resolved
        }
    }

    return nil
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
