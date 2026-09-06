import Darwin
import Foundation

enum ShellIntegrationError: LocalizedError {
    case malformedManagedBlock(String)
    case fileChanged(String)
    case invalidRCFile(String)
    case writableRCFile(String)

    var errorDescription: String? {
        switch self {
        case .malformedManagedBlock(let detail):
            return "The shell configuration contains malformed cwru-ovpn markers: \(detail)"
        case .fileChanged(let path):
            return "The shell configuration changed while it was being updated: \(path)"
        case .invalidRCFile(let path):
            return "Refusing to update an unsafe shell configuration file: \(path)"
        case .writableRCFile(let path):
            return "Refusing to update a shell configuration file that is writable by group or others: \(path). "
                + "Run chmod go-w on the file and retry."
        }
    }
}

enum ShellIntegration {
    static let startMarker = "# >>> cwru-ovpn >>>"
    static let endMarker = "# <<< cwru-ovpn <<<"
    private static let maxRCFileBytes = 1024 * 1024

    private struct RCFileSnapshot {
        let data: Data?

        var content: String {
            data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        }
    }

    private struct RCLine {
        let fullRange: Range<String.Index>
        let trimmed: String
    }

    static var installedHelperURL: URL {
        RuntimePaths.homeStateDirectory.appendingPathComponent("cwru-ovpn.zsh")
    }

    static func install(preferredShellPath: String?) throws -> URL {
        let owner = try ExecutionIdentity.currentUser()
        let targetURL = preferredRCFile(preferredShellPath: preferredShellPath)
        let snapshot = try readRCFileIfPresent(at: targetURL, owner: owner)
        let updated = try installBlock(into: snapshot.content,
                                       helperPath: installedHelperURL.path)
        if updated != snapshot.content {
            try replaceRCFile(at: targetURL,
                              expectedContent: snapshot.data == nil ? nil : snapshot.content,
                              updatedContent: updated,
                              owner: owner)
        }
        return targetURL
    }

    static func remove() throws -> [URL] {
        let owner = try ExecutionIdentity.currentUser()
        var updatedFiles: [URL] = []

        for candidate in knownRCFiles() {
            let snapshot = try readRCFileIfPresent(at: candidate, owner: owner)
            guard snapshot.data != nil else {
                continue
            }
            let updated = try removeBlock(from: snapshot.content)
            if updated != snapshot.content {
                try replaceRCFile(at: candidate,
                                  expectedContent: snapshot.content,
                                  updatedContent: updated,
                                  owner: owner)
                updatedFiles.append(candidate)
            }
        }

        return updatedFiles
    }

    static func installBlock(into content: String,
                             helperPath: String) throws -> String {
        let base = try stripManagedBlock(from: content)

        let block = [
            startMarker,
            "source \(shellQuoted(helperPath))",
            endMarker,
        ].joined(separator: "\n") + "\n"

        if base.isEmpty {
            return block
        }
        return base + "\n" + block
    }

    static func removeBlock(from content: String) throws -> String {
        try stripManagedBlock(from: content)
    }

    private static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    private static func stripManagedBlock(from content: String) throws -> String {
        guard let range = try managedBlockRange(in: content) else {
            return content
        }
        var result = content
        result.removeSubrange(range)
        if range.upperBound == content.endIndex, result.unicodeScalars.last == "\n" {
            result.unicodeScalars.removeLast()
        }
        return result
    }

    private static func managedBlockRange(in content: String) throws -> Range<String.Index>? {
        let lines = rcLines(in: content)
        var openStart: String.Index?
        var completed: Range<String.Index>?

        for line in lines {
            if line.trimmed == startMarker {
                guard openStart == nil, completed == nil else {
                    throw ShellIntegrationError.malformedManagedBlock("duplicate start marker")
                }
                openStart = line.fullRange.lowerBound
            } else if line.trimmed == endMarker {
                guard let blockStart = openStart, completed == nil else {
                    throw ShellIntegrationError.malformedManagedBlock("orphan end marker")
                }
                completed = blockStart..<line.fullRange.upperBound
                openStart = nil
            }
        }

        if openStart != nil {
            throw ShellIntegrationError.malformedManagedBlock("orphan start marker")
        }
        return completed
    }

    private static func rcLines(in content: String) -> [RCLine] {
        var lines: [RCLine] = []
        var start = content.startIndex
        while start < content.endIndex {
            let newline = content[start...].firstIndex(where: \.isNewline)
            let textEnd = newline ?? content.endIndex
            let fullEnd = newline.map { content.index(after: $0) } ?? content.endIndex
            let trimmed = content[start..<textEnd].trimmingCharacters(in: .whitespacesAndNewlines)
            lines.append(RCLine(fullRange: start..<fullEnd, trimmed: trimmed))
            start = fullEnd
        }
        return lines
    }

    private static func readRCFileIfPresent(at url: URL,
                                            owner: ResolvedUserIdentity) throws -> RCFileSnapshot {
        try withRCDirectory(for: url, owner: owner) { directoryFD, owner, name in
            let fileFD = name.withCString {
                openat(directoryFD, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            }
            if fileFD < 0, errno == ENOENT {
                return RCFileSnapshot(data: nil)
            }
            guard fileFD >= 0 else {
                throw FileIO.posixError(errno)
            }
            defer { close(fileFD) }
            let info = try validateRCFile(fileDescriptor: fileFD,
                                          ownerUserID: owner.userID,
                                          ownerGroupID: owner.groupID,
                                          path: url.path)
            let data = try FileIO.readAll(from: fileFD, maximumBytes: Int(info.st_size))
            guard String(data: data, encoding: .utf8) != nil else {
                throw ShellIntegrationError.invalidRCFile(url.path)
            }
            return RCFileSnapshot(data: data)
        }
    }

    private static func preferredRCFile(preferredShellPath: String?) -> URL {
        let homeDirectory = RuntimePaths.userHomeDirectory
        let shellName = preferredShellPath
            .flatMap { URL(fileURLWithPath: $0).lastPathComponent.isEmpty ? nil : URL(fileURLWithPath: $0).lastPathComponent }
            ?? "zsh"

        guard shellName == "bash" else {
            return homeDirectory.appendingPathComponent(".zshrc")
        }
        let bashRC = homeDirectory.appendingPathComponent(".bashrc")
        return FileManager.default.fileExists(atPath: bashRC.path) ? bashRC : homeDirectory.appendingPathComponent(".bash_profile")
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
                              expected: RCFileSnapshot,
                              defaultPermissions: Int,
                              owner: ResolvedUserIdentity) throws {
        let data = Data(content.utf8)
        guard data.count <= maxRCFileBytes else {
            throw POSIXError(.EFBIG)
        }

        try withRCDirectory(for: url, owner: owner) { directoryFD, owner, name in
            var sourceFD: Int32 = -1
            var sourceInfo: Darwin.stat?
            defer {
                if sourceFD >= 0 {
                    close(sourceFD)
                }
            }
            sourceFD = name.withCString {
                openat(directoryFD, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
            }
            if sourceFD >= 0 {
                let info = try validateRCFile(fileDescriptor: sourceFD,
                                              ownerUserID: owner.userID,
                                              ownerGroupID: owner.groupID,
                                              path: url.path)
                let current = try FileIO.readAll(from: sourceFD, maximumBytes: Int(info.st_size))
                guard expected.data == current else {
                    throw ShellIntegrationError.fileChanged(url.path)
                }
                sourceInfo = info
            } else {
                guard errno == ENOENT, expected.data == nil else {
                    throw ShellIntegrationError.fileChanged(url.path)
                }
            }
            let temporaryName = ".\(name).\(UUID().uuidString).tmp"
            let temporaryFD = temporaryName.withCString {
                openat(directoryFD,
                       $0,
                       O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL,
                       mode_t(0o600))
            }
            guard temporaryFD >= 0 else {
                throw FileIO.posixError(errno)
            }
            var installed = false
            defer {
                close(temporaryFD)
                if !installed {
                    _ = temporaryName.withCString { unlinkat(directoryFD, $0, 0) }
                }
            }

            try FileIO.writeAll(data, to: temporaryFD)
            if sourceFD >= 0 {
                guard fcopyfile(sourceFD,
                                temporaryFD,
                                nil,
                                copyfile_flags_t(COPYFILE_METADATA)) == 0 else {
                    throw FileIO.posixError(errno)
                }
            }

            let permissions = mode_t(sourceInfo.map { $0.st_mode & 0o7777 }
                                     ?? mode_t(defaultPermissions))
            guard fchown(temporaryFD, owner.userID, owner.groupID) == 0,
                  fchmod(temporaryFD, permissions) == 0,
                  fsync(temporaryFD) == 0 else {
                throw FileIO.posixError(errno)
            }
            _ = try validateRCFile(fileDescriptor: temporaryFD,
                                   ownerUserID: owner.userID,
                                   ownerGroupID: owner.groupID,
                                   path: url.path)

            var currentInfo = Darwin.stat()
            let currentResult = name.withCString {
                fstatat(directoryFD, $0, &currentInfo, AT_SYMLINK_NOFOLLOW)
            }
            if let sourceInfo {
                guard currentResult == 0,
                      currentInfo.st_dev == sourceInfo.st_dev,
                      currentInfo.st_ino == sourceInfo.st_ino else {
                    throw ShellIntegrationError.fileChanged(url.path)
                }
            } else {
                guard currentResult != 0, errno == ENOENT else {
                    throw ShellIntegrationError.fileChanged(url.path)
                }
            }

            let renameResult = temporaryName.withCString { temporaryPointer in
                name.withCString { namePointer in
                    renameat(directoryFD, temporaryPointer, directoryFD, namePointer)
                }
            }
            guard renameResult == 0 else {
                throw FileIO.posixError(errno)
            }
            installed = true

            var installedInfo = Darwin.stat()
            guard fstat(temporaryFD, &currentInfo) == 0,
                  name.withCString({ fstatat(directoryFD, $0, &installedInfo, AT_SYMLINK_NOFOLLOW) }) == 0,
                  currentInfo.st_dev == installedInfo.st_dev,
                  currentInfo.st_ino == installedInfo.st_ino,
                  fsync(directoryFD) == 0 else {
                throw FileIO.posixError(errno)
            }
        }
    }

    private static func withRCDirectory<T>(for url: URL,
                                           owner: ResolvedUserIdentity,
                                           body: (Int32, ResolvedUserIdentity, String) throws -> T) throws -> T {
        let homeDirectory = owner.homeDirectory.standardizedFileURL
        let parent = url.deletingLastPathComponent().standardizedFileURL
        guard parent.path == homeDirectory.path else {
            throw ShellIntegrationError.invalidRCFile(url.path)
        }
        let name = url.lastPathComponent
        try AnchoredFileIO.validateComponent(name)

        let directoryFD = open(parent.path,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard directoryFD >= 0 else {
            throw FileIO.posixError(errno)
        }
        defer { close(directoryFD) }

        var info = Darwin.stat()
        guard fstat(directoryFD, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == owner.userID,
              info.st_gid == owner.groupID,
              info.st_mode & 0o022 == 0 else {
            throw ShellIntegrationError.invalidRCFile(parent.path)
        }
        return try body(directoryFD, owner, name)
    }

    private static func validateRCFile(fileDescriptor: Int32,
                                       ownerUserID: uid_t,
                                       ownerGroupID: gid_t,
                                       path: String) throws -> Darwin.stat {
        var info = Darwin.stat()
        guard fstat(fileDescriptor, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_nlink == 1,
              info.st_uid == ownerUserID,
              info.st_gid == ownerGroupID,
              info.st_size >= 0,
              info.st_size <= maxRCFileBytes else {
            throw ShellIntegrationError.invalidRCFile(path)
        }
        guard info.st_mode & 0o022 == 0 else {
            throw ShellIntegrationError.writableRCFile(path)
        }
        return info
    }

    static func replaceRCFile(at url: URL,
                              expectedContent: String?,
                              updatedContent: String,
                              owner: ResolvedUserIdentity) throws {
        try write(updatedContent,
                  to: url,
                  expected: RCFileSnapshot(data: expectedContent.map { Data($0.utf8) }),
                  defaultPermissions: 0o644,
                  owner: owner)
    }
}
