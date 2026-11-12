import Darwin
import Foundation

struct VPNEventBuffer {
    struct Event {
        let name: String
        let info: String
        let isError: Bool
        let isFatal: Bool
        let generation: Int
    }

    static let maximumNameBytes = 256
    static let maximumInfoBytes = 1024 * 1024
    static let maximumPendingBytes = 8 * 1024 * 1024
    static let maximumPendingEvents = 256

    private var events: [Event] = []
    private var pendingBytes = 0
    private var overflowed = false

    static func readCString(_ pointer: UnsafePointer<CChar>?, maximumBytes: Int) -> String? {
        guard let pointer else { return "" }
        let count = strnlen(pointer, maximumBytes + 1)
        guard count <= maximumBytes else { return nil }
        return String(decoding: UnsafeRawBufferPointer(start: pointer, count: count), as: UTF8.self)
    }

    mutating func append(name: String?, info: String?, isError: Bool, isFatal: Bool,
                         generation: Int) -> Bool {
        guard !overflowed else { return false }
        let shouldSchedule = events.isEmpty
        if let name, let info,
           name.utf8.count <= Self.maximumNameBytes,
           info.utf8.count <= Self.maximumInfoBytes,
           events.count < Self.maximumPendingEvents,
           name.utf8.count + info.utf8.count <= Self.maximumPendingBytes - pendingBytes {
            events.append(Event(name: name, info: info, isError: isError,
                                isFatal: isFatal, generation: generation))
            pendingBytes += name.utf8.count + info.utf8.count
        } else {
            overflowed = true
            events.append(Event(name: "EVENT_OVERFLOW",
                                info: "OpenVPN event limits exceeded. Disconnecting to restore network configuration.",
                                isError: true, isFatal: true, generation: generation))
        }
        return shouldSchedule
    }

    mutating func drain() -> [Event] {
        let pending = events
        events = []
        pendingBytes = 0
        return pending
    }
}
