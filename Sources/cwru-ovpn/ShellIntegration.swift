import Foundation

enum ShellIntegration {
    static let startMarker = "# >>> cwru-ovpn >>>"
    static let endMarker = "# <<< cwru-ovpn <<<"

    static var installedHelperURL: URL {
        RuntimePaths.homeStateDirectory.appendingPathComponent("cwru-ovpn.zsh")
    }

    static func install(preferredShellPath: String?, legacySourcePaths: [String]) throws -> URL {
        let targetURL = preferredRCFile(preferredShellPath: preferredShellPath)
        let current = (try? String(contentsOf: targetURL, encoding: .utf8)) ?? ""
        let updated = installBlock(into: current,
                                   helperPath: installedHelperURL.path,
                                   legacySourcePaths: legacySourcePaths)
        if updated != current {
            try write(updated, to: targetURL, defaultPermissions: 0o644)
        }
        return targetURL
    }

    static func remove() throws -> [URL] {
        let helperPath = installedHelperURL.path
        var updatedFiles: [URL] = []

        for candidate in knownRCFiles() where FileManager.default.fileExists(atPath: candidate.path) {
            let current = (try? String(contentsOf: candidate, encoding: .utf8)) ?? ""
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
        var skipping = false

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed == startMarker {
                skipping = true
                continue
            }
            if skipping {
                if trimmed == endMarker {
                    skipping = false
                }
                continue
            }
            result.append(line)
        }

        return result.joined(separator: "\n")
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

        try content.write(to: url, atomically: true, encoding: .utf8)

        var attributes: [FileAttributeKey: Any] = [
            .posixPermissions: permissions,
        ]

        if getuid() == 0 {
            let environment = ProcessInfo.processInfo.environment
            if let uid = environment["SUDO_UID"].flatMap(Int.init) {
                attributes[.ownerAccountID] = uid
            }
            if let gid = environment["SUDO_GID"].flatMap(Int.init) {
                attributes[.groupOwnerAccountID] = gid
            }
        }

        try fileManager.setAttributes(attributes, ofItemAtPath: url.path)
    }
}
