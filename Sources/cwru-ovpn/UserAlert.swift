import AppKit
import Foundation

enum UserAlert {
    static func showCritical(message: String) {
        if ProcessInfo.processInfo.environment["CWRU_OVPN_SUPPRESS_USER_ALERTS"] == "1" {
            return
        }

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

    private static func sanitizedMessage(_ value: String) -> String {
        value.unicodeScalars
            .filter(isSafeAlertTextScalar)
            .reduce(into: "") { $0 += String($1) }
    }

    private static func isSafeAlertTextScalar(_ scalar: Unicode.Scalar) -> Bool {
        if scalar == "\u{2028}" || scalar == "\u{2029}" {
            return false
        }

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
        alert.runModal()
    }
}
