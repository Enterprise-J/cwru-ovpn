import AppKit
import Foundation

enum UserAlert {
    static func present(_ message: String) {
        do {
            _ = try ChildProcess.launch(arguments: ["show-alert", "--message", message])
        } catch {
            EventLog.append(note: "Could not present a critical alert: \(error.localizedDescription)")
        }
    }

    @MainActor
    static func showInCurrentProcess(_ message: String) {
        NSApplication.shared.setActivationPolicy(.accessory)
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = AppIdentity.bundleName
        alert.informativeText = sanitizedMessage(message)
        NSApplication.shared.activate(ignoringOtherApps: true)
        alert.runModal()
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
}
