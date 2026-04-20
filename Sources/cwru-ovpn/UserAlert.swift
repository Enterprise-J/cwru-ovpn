import Foundation

enum UserAlert {
    static func showCritical(message: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", appleScriptAlert(message: message)]

        do {
            try process.run()
        } catch {
            EventLog.append(note: "Failed to show alert: \(error.localizedDescription)", phase: .disconnected)
        }
    }

    /// Builds a `display alert` AppleScript statement with both strings safely embedded.
    ///
    /// AppleScript string literals have no backslash escape sequences. The only character
    /// that requires special handling is the double-quote (`"`), which must be expressed
    /// using the built-in `quote` constant: `"before" & quote & "after"`.
    /// ASCII control characters (< 0x20) are stripped to prevent script-parse errors.
    private static func appleScriptAlert(message: String) -> String {
        "display alert \(appleScriptLiteral(AppIdentity.bundleName)) " +
        "message \(appleScriptLiteral(message)) as critical"
    }

    private static func appleScriptLiteral(_ value: String) -> String {
        let safe = value.unicodeScalars
            .filter { $0.value >= 0x20 }
            .reduce(into: "") { $0 += String($1) }
        let parts = safe.components(separatedBy: "\"")
        return parts.map { "\"\($0)\"" }.joined(separator: " & quote & ")
    }
}
