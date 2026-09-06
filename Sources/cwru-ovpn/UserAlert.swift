import AppKit
import Foundation

@MainActor
final class PendingAlertGate {
    private var pendingCount = 0
    private var idleHandlers: [@MainActor () -> Void] = []

    var hasPendingAlerts: Bool {
        pendingCount > 0
    }

    func enter() {
        pendingCount += 1
    }

    func leave() {
        guard pendingCount > 0 else {
            return
        }
        pendingCount -= 1
        guard pendingCount == 0, !idleHandlers.isEmpty else {
            return
        }

        let handlers = idleHandlers
        idleHandlers = []
        for handler in handlers {
            handler()
        }
    }

    func whenIdle(_ handler: @escaping @MainActor () -> Void) {
        guard pendingCount > 0 else {
            handler()
            return
        }
        idleHandlers.append(handler)
    }
}

enum UserAlert {
    @MainActor private static let gate = PendingAlertGate()

    static func showCritical(message: String) {
        let sanitized = sanitizedMessage(message)

        if Thread.isMainThread {
            MainActor.assumeIsolated {
                presentCriticalAlert(message: sanitized)
            }
            return
        }

        let completion = DispatchSemaphore(value: 0)
        Task { @MainActor in
            presentCriticalAlert(message: sanitized)
            completion.signal()
        }
        completion.wait()
    }

    @MainActor
    static func scheduleCritical(message: String) {
        let sanitized = sanitizedMessage(message)

        gate.enter()
        DispatchQueue.main.async {
            MainActor.assumeIsolated {
                presentCriticalAlert(message: sanitized)
                gate.leave()
            }
        }
    }

    @MainActor
    static func whenNoAlertIsPending(_ handler: @escaping @MainActor () -> Void) {
        gate.whenIdle(handler)
    }

    private static func sanitizedMessage(_ value: String) -> String {
        value.unicodeScalars.reduce(into: "") { result, scalar in
            if isLineOrTabScalar(scalar) {
                result += " "
            } else if isSafeAlertTextScalar(scalar) {
                result += String(scalar)
            }
        }
    }

    private static func isLineOrTabScalar(_ scalar: Unicode.Scalar) -> Bool {
        scalar == "\n" || scalar == "\r" || scalar == "\t"
            || scalar == "\u{2028}" || scalar == "\u{2029}"
    }

    private static func isSafeAlertTextScalar(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x20...0x7E, 0xA0...0x10FFFF:
            return true
        default:
            return false
        }
    }

    @MainActor
    private static func presentCriticalAlert(message: String) {
        _ = NSApplication.shared
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = AppIdentity.bundleName
        alert.informativeText = message
        NSApplication.shared.activate(ignoringOtherApps: true)
        gate.enter()
        defer { gate.leave() }
        alert.runModal()
    }
}
