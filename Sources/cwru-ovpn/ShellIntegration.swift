import Darwin
import Foundation

enum ShellIntegration {
    static let startMarker = "# >>> cwru-ovpn >>>"
    static let endMarker = "# <<< cwru-ovpn <<<"

    static var installedHelperURL: URL {
        RuntimePaths.homeStateDirectory.appendingPathComponent("cwru-ovpn.zsh")
    }

    static func install(preferredShellPath: String?, legacySourcePaths: [String]) throws -> URL {
        _ = try ExecutionIdentity.validatedSudoUserIfAvailable()
        let targetURL = preferredRCFile(preferredShellPath: preferredShellPath)
        let current = try readRCFileIfPresent(at: targetURL)
        let updated = installBlock(into: current,
                                   helperPath: installedHelperURL.path,
                                   legacySourcePaths: legacySourcePaths)
        if updated != current {
            try write(updated, to: targetURL, defaultPermissions: 0o644)
        }
        return targetURL
    }

    static func remove() throws -> [URL] {
        _ = try ExecutionIdentity.validatedSudoUserIfAvailable()
        let helperPath = installedHelperURL.path
        var updatedFiles: [URL] = []

        for candidate in knownRCFiles() where FileManager.default.fileExists(atPath: candidate.path) {
            let current = try readRCFileIfPresent(at: candidate)
            let updated = removeBlock(from: current, helperPaths: [helperPath])
            if updated != current {
                try write(updated, to: candidate, defaultPermissions: 0o644)
                updatedFiles.append(candidate)
            }
        }

        return updatedFiles
    }

    static func installBlock(into content: String,
                             helperPath: String,
                             legacySourcePaths: [String]) -> String {
        var normalized = removeBlock(from: content,
                                     helperPaths: [helperPath] + legacySourcePaths)

        let block = [
            startMarker,
            "source \(shellQuoted(helperPath))",
            endMarker,
        ].joined(separator: "\n") + "\n"

        if normalized.isEmpty {
            return block
        }

        if !normalized.hasSuffix("\n") {
            normalized.append("\n")
        }
        if !normalized.hasSuffix("\n\n") {
            normalized.append("\n")
        }

        return normalized + block
    }

    static func removeBlock(from content: String,
                            helperPaths: [String]) -> String {
        let filtered = stripManagedBlock(from: content)
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map(String.init)
            .filter { line in
                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmed.isEmpty else {
                    return true
                }

                return !helperPaths.contains(where: {
                    let quotedPath = shellQuoted($0)
                    return trimmed == "source \($0)"
                        || trimmed == ". \($0)"
                        || trimmed == "source \(quotedPath)"
                        || trimmed == ". \(quotedPath)"
                })
            }

        var result = filtered.joined(separator: "\n")

        while result.contains("\n\n\n") {
            result = result.replacingOccurrences(of: "\n\n\n", with: "\n\n")
        }

        if result == "\n" {
            return ""
        }

        return result.trimmingCharacters(in: CharacterSet(charactersIn: "\n")) + (result.isEmpty ? "" : "\n")
    }

    private static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    private static func stripManagedBlock(from content: String) -> String {
        let lines = content.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var result: [String] = []
        var index = 0

        while index < lines.count {
            let line = lines[index]
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)

            if trimmed == startMarker {
                guard let endIndex = lines[(index + 1)...].firstIndex(where: {
                    $0.trimmingCharacters(in: .whitespacesAndNewlines) == endMarker
                }) else {
                    return content
                }
                index = endIndex + 1
                continue
            }

            result.append(line)
            index += 1
        }

        return result.joined(separator: "\n")
    }

    private static func readRCFileIfPresent(at url: URL) throws -> String {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return ""
        }

        return try String(contentsOf: url, encoding: .utf8)
    }

    private static func preferredRCFile(preferredShellPath: String?) -> URL {
        let homeDirectory = RuntimePaths.userHomeDirectory
        let shellName = preferredShellPath
            .flatMap { URL(fileURLWithPath: $0).lastPathComponent.isEmpty ? nil : URL(fileURLWithPath: $0).lastPathComponent }
            ?? "zsh"

        switch shellName {
        case "bash":
            let bashRC = homeDirectory.appendingPathComponent(".bashrc")
            if FileManager.default.fileExists(atPath: bashRC.path) {
                return bashRC
            }
            return homeDirectory.appendingPathComponent(".bash_profile")
        case "zsh":
            return homeDirectory.appendingPathComponent(".zshrc")
        default:
            return homeDirectory.appendingPathComponent(".zshrc")
        }
    }

    private static func knownRCFiles() -> [URL] {
        let homeDirectory = RuntimePaths.userHomeDirectory
        return [
            homeDirectory.appendingPathComponent(".zshrc"),
            homeDirectory.appendingPathComponent(".bashrc"),
            homeDirectory.appendingPathComponent(".bash_profile"),
        ]
    }

    private static func write(_ content: String,
                              to url: URL,
                              defaultPermissions: Int) throws {
        let fileManager = FileManager.default
        let existingAttributes = try? fileManager.attributesOfItem(atPath: url.path)
        let permissions = (existingAttributes?[.posixPermissions] as? NSNumber)?.intValue ?? defaultPermissions
        let directoryURL = url.deletingLastPathComponent()
        let tempURL = directoryURL.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")

        try content.write(to: tempURL, atomically: false, encoding: .utf8)

        var attributes: [FileAttributeKey: Any] = [
            .posixPermissions: permissions,
        ]

        if let sudoIdentity = try ExecutionIdentity.validatedSudoUserIfAvailable() {
            attributes[.ownerAccountID] = Int(sudoIdentity.userID)
            attributes[.groupOwnerAccountID] = Int(sudoIdentity.groupID)
        }

        do {
            try fileManager.setAttributes(attributes, ofItemAtPath: tempURL.path)
            guard rename(tempURL.path, url.path) == 0 else {
                let renameError = errno
                throw POSIXError(POSIXErrorCode(rawValue: renameError) ?? .EIO)
            }
        } catch {
            try? fileManager.removeItem(at: tempURL)
            throw error
        }
    }
}
