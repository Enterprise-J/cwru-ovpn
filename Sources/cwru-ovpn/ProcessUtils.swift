import Darwin
import Foundation

struct ProcessStartTime: Codable, Equatable {
    let seconds: UInt64
    let microseconds: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case seconds
        case microseconds
    }

    init(seconds: UInt64, microseconds: UInt64) {
        self.seconds = seconds
        self.microseconds = microseconds
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownJSONKeys(in: decoder,
                                  allowedBy: CodingKeys.self,
                                  context: "process start time")
        let container = try decoder.container(keyedBy: CodingKeys.self)
        seconds = try container.decode(UInt64.self, forKey: .seconds)
        microseconds = try container.decode(UInt64.self, forKey: .microseconds)
    }
}

enum ProcessIdentityAssessment: Equatable {
    case notRunning
    case matched
    case mismatched
    case unavailable

    var permitsReadOnlyStatus: Bool {
        self == .matched || self == .unavailable
    }

    var isVerifiedMatch: Bool {
        self == .matched
    }

    var indicatesStaleOwner: Bool {
        self == .notRunning || self == .mismatched
    }
}

private enum ProcessLookupResult<Value> {
    case found(Value)
    case notRunning
    case unavailable
}

func processStartTimeMatches(actualStartTime: ProcessStartTime?,
                             expectedStartTime: ProcessStartTime) -> Bool {
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

func processExists(_ pid: Int32, expectedStartTime: ProcessStartTime) -> Bool {
    guard processExists(pid) else {
        return false
    }

    return processStartTimeMatches(actualStartTime: processStartTime(pid),
                                   expectedStartTime: expectedStartTime)
}

func processStartTime(_ pid: Int32) -> ProcessStartTime? {
    guard case .found(let info) = processBSDInfoResult(pid) else {
        return nil
    }

    return ProcessStartTime(seconds: info.pbi_start_tvsec,
                            microseconds: info.pbi_start_tvusec)
}

func processMatchesExecutable(_ pid: Int32,
                              expectedExecutablePath: String,
                              expectedStartTime: ProcessStartTime) -> Bool {
    processIdentityAssessment(pid,
                              expectedExecutablePath: expectedExecutablePath,
                              expectedStartTime: expectedStartTime).isVerifiedMatch
}

func processIdentityAssessment(_ pid: Int32,
                               expectedExecutablePath: String,
                               expectedStartTime: ProcessStartTime) -> ProcessIdentityAssessment {
    guard processExists(pid) else {
        return .notRunning
    }

    let actualExecutablePath: String
    switch processExecutablePathResult(pid) {
    case .found(let path):
        actualExecutablePath = path
    case .notRunning:
        return .notRunning
    case .unavailable:
        return .unavailable
    }

    let actualStartTime: ProcessStartTime
    switch processBSDInfoResult(pid) {
    case .found(let info):
        actualStartTime = ProcessStartTime(seconds: info.pbi_start_tvsec,
                                           microseconds: info.pbi_start_tvusec)
    case .notRunning:
        return .notRunning
    case .unavailable:
        return .unavailable
    }

    return processIdentityAssessment(processExists: true,
                                     actualExecutablePath: actualExecutablePath,
                                     expectedExecutablePath: expectedExecutablePath,
                                     actualStartTime: actualStartTime,
                                     expectedStartTime: expectedStartTime)
}

private func processExecutablePathResult(_ pid: Int32) -> ProcessLookupResult<String> {
    guard pid > 0 else {
        return .notRunning
    }

    var pathBuffer = [UInt8](repeating: 0, count: Int(MAXPATHLEN) * 4)
    errno = 0
    let copied = pathBuffer.withUnsafeMutableBufferPointer { buffer -> Int32 in
        guard let baseAddress = buffer.baseAddress else {
            return 0
        }
        return proc_pidpath(pid, baseAddress, UInt32(buffer.count))
    }
    let lookupError = errno
    if copied > 0 {
        let length = pathBuffer.firstIndex(of: 0) ?? Int(copied)
        let resolved = String(decoding: pathBuffer[..<length], as: UTF8.self)
        if resolved.hasPrefix("/") {
            return .found(resolved)
        }
    }

    if lookupError == ESRCH {
        return .notRunning
    }

    return processExists(pid) ? .unavailable : .notRunning
}

func processIdentityAssessment(processExists: Bool,
                               actualExecutablePath: String?,
                               expectedExecutablePath: String,
                               actualStartTime: ProcessStartTime?,
                               expectedStartTime: ProcessStartTime) -> ProcessIdentityAssessment {
    guard processExists else {
        return .notRunning
    }

    guard let actualExecutablePath else {
        return .unavailable
    }

    let normalizedExpected = URL(fileURLWithPath: expectedExecutablePath)
        .resolvingSymlinksInPath()
        .standardized.path

    let normalizedActual = URL(fileURLWithPath: actualExecutablePath)
        .resolvingSymlinksInPath()
        .standardized.path

    guard normalizedActual == normalizedExpected else {
        return .mismatched
    }

    guard let actualStartTime else {
        return .unavailable
    }
    guard actualStartTime == expectedStartTime else {
        return .mismatched
    }

    return .matched
}

private func processBSDInfoResult(_ pid: Int32) -> ProcessLookupResult<proc_bsdinfo> {
    guard pid > 0 else {
        return .notRunning
    }

    var info = proc_bsdinfo()
    let infoSize = Int32(MemoryLayout<proc_bsdinfo>.stride)
    errno = 0
    let size = withUnsafeMutablePointer(to: &info) { pointer in
        proc_pidinfo(pid,
                     PROC_PIDTBSDINFO,
                     UInt64(0),
                     pointer,
                     infoSize)
    }
    let lookupError = errno

    guard size == infoSize,
          info.pbi_pid == UInt32(pid) else {
        if lookupError == ESRCH {
            return .notRunning
        }
        return processExists(pid) ? .unavailable : .notRunning
    }

    return .found(info)
}
