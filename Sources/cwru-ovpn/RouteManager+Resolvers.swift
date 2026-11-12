import Foundation
import Darwin

extension RouteManager {
    enum ResolverFileStatus: Equatable {
        case missing
        case matching
        case different
    }

    func resolverFileStatus(for domain: String, nameServers: [String]) throws -> ResolverFileStatus {
        do {
            let data = try readHardenedResolverFile(at: resolverFileURL(for: domain))
            return data == Data(resolverContents(for: domain, nameServers: nameServers).utf8) ? .matching : .different
        } catch where Self.isMissingFileError(error) {
            return .missing
        }
    }

    func resolverFilesHealthCheck(using state: SessionState) -> SplitTunnelHealthCheck {
        let domains = appliedDNSDomains(using: state)
        let nameServers = policyDNSServers()
        var missing: [String] = []
        var different: [String] = []
        var invalid: [String] = []
        var unavailable: [String] = []
        for domain in domains {
            do {
                switch try resolverFileStatus(for: domain, nameServers: nameServers) {
                case .missing: missing.append(domain)
                case .different: different.append(domain)
                case .matching: break
                }
            } catch {
                let failure = error as NSError
                let detail = "\(domain) (\(error.localizedDescription))"
                if failure.domain == NSPOSIXErrorDomain,
                   [EPERM, ELOOP, EMLINK, EFTYPE, EFBIG].contains(Int32(failure.code)) {
                    invalid.append(detail)
                } else {
                    unavailable.append(detail)
                }
            }
        }
        let scan = scanManagedResolverDirectory()
        let expected = Set(domains)
        let stale = scan.managed.filter { !expected.contains($0) }
        for (domain, error) in scan.unreadable where !expected.contains(domain) {
            unavailable.append("\(domain) (\(error.localizedDescription))")
        }
        if let error = scan.directoryError {
            unavailable.append("directory \(resolverDirectory.path) (\(error.localizedDescription))")
        }
        let failures = [("missing", missing), ("different content", different), ("invalid", invalid), ("stale", stale)]
        let details = (failures + [("unavailable", unavailable)]).compactMap { label, domains in
            domains.isEmpty ? nil : "\(label): \(domains.sorted().joined(separator: ", "))"
        }
        let status: SplitTunnelCheckStatus
        if failures.contains(where: { !$0.1.isEmpty }) {
            status = .fail
        } else {
            status = unavailable.isEmpty ? .pass : .warn
        }
        return SplitTunnelHealthCheck(
            status: status,
            name: "resolvers",
            detail: details.isEmpty
                ? "\(domains.count) scoped resolver file\(domains.count == 1 ? "" : "s") match the fixed split policy"
                : "scoped files \(details.joined(separator: "; "))")
    }

    @discardableResult
    func installResolverFiles(forDomains dnsDomains: [String], nameServers: [String]) throws -> Bool {
        guard !dnsDomains.isEmpty else {
            return false
        }
        guard !nameServers.isEmpty else {
            throw RouteManagerError.missingSplitTunnelDNSServers
        }

        let staleDomains = try dnsDomains.filter { domain in
            try resolverFileStatus(for: domain, nameServers: nameServers) != .matching
        }
        guard !staleDomains.isEmpty else {
            return false
        }

        try ensureResolverDirectory()
        for domain in staleDomains {
            let resolverFile = resolverFileURL(for: domain)
            try recoverManagedResolverArtifacts(for: resolverFile)
            if FileManager.default.fileExists(atPath: resolverFile.path),
               !resolverFileIsManaged(at: resolverFile) {
                throw RouteManagerError.refusingToReplaceUnmanagedResolverFile(domain)
            }
        }
        for domain in staleDomains {
            try installManagedResolverFile(content: resolverContents(for: domain, nameServers: nameServers),
                                           at: resolverFileURL(for: domain))
        }
        return true
    }

    private func ensureResolverDirectory() throws {
        guard mkdir(resolverDirectory.path, 0o755) != 0 else {
            return
        }
        guard errno == EEXIST else {
            throw FileIO.failure("Failed to create resolver directory \(resolverDirectory.path)", errno)
        }
    }

    static let webAuthBootstrapResolverDomains = ["openvpn.com", "openvpn.net"]

    static let bootstrapDigHome = "/var/empty"

    static func isUnusableRemoteIPv4Address(_ address: String) -> Bool {
        guard let numeric = IPRoute.canonicalIPv4Address(address) else {
            return false
        }
        return numeric == 0 || (numeric >> 24) == 127
    }

    static func resolveHostUsingBootstrap(host: String,
                                          servers: [String],
                                          timeoutSeconds: Int,
                                          commandRunner: CommandRunner = CommandRunner()) -> String? {
        guard !servers.isEmpty,
              !NetworkValidation.isValidIPAddress(host),
              NetworkValidation.isValidDomainName(host) else {
            return nil
        }

        for server in servers {
            guard let result = try? commandRunner.run("/usr/bin/dig",
                                                      arguments: ["+short",
                                                                  "+time=\(timeoutSeconds)",
                                                                  "+tries=1",
                                                                  "@\(server)",
                                                                  host,
                                                                  "A"],
                                                      allowNonZero: true,
                                                      environmentOverrides: ["HOME": bootstrapDigHome],
                                                      timeout: TimeInterval(timeoutSeconds) + 1) else {
                continue
            }
            for rawLine in result.stdout.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
                let candidate = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                if NetworkValidation.isValidIPv4Address(candidate),
                   !Self.isUnusableRemoteIPv4Address(candidate) {
                    return candidate
                }
            }
        }
        return nil
    }

    static func digAnswerIsSinkholed(_ output: String) -> Bool {
        var sawAddress = false
        for rawLine in output.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let candidate = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard NetworkValidation.isValidIPv4Address(candidate) else {
                continue
            }
            guard isUnusableRemoteIPv4Address(candidate) else {
                return false
            }
            sawAddress = true
        }
        return sawAddress
    }

    static func systemResolverSinkholes(host: String,
                                        timeoutSeconds: Int,
                                        commandRunner: CommandRunner = CommandRunner()) -> Bool {
        guard NetworkValidation.isValidDomainName(host) else {
            return false
        }

        guard let result = try? commandRunner.run("/usr/bin/dig",
                                                  arguments: ["+short",
                                                              "+time=\(timeoutSeconds)",
                                                              "+tries=1",
                                                              host,
                                                              "A"],
                                                  allowNonZero: true,
                                                  environmentOverrides: ["HOME": bootstrapDigHome],
                                                  timeout: TimeInterval(timeoutSeconds) + 1) else {
            return false
        }

        return digAnswerIsSinkholed(result.stdout)
    }

    @discardableResult
    func installWebAuthBootstrapResolvers() throws -> Bool {
        guard !dnsBootstrapServers.isEmpty else {
            return false
        }
        return try installResolverFiles(forDomains: Self.webAuthBootstrapResolverDomains,
                                        nameServers: dnsBootstrapServers)
    }

    @discardableResult
    func removeWebAuthBootstrapResolvers() throws -> [String] {
        try removeResolverFiles(for: Self.webAuthBootstrapResolverDomains)
    }

    func installManagedResolverFile(content: String, at resolverFile: URL) throws {
        let directory = resolverFile.deletingLastPathComponent()
        let tempURL = directory
            .appendingPathComponent(".\(resolverFile.lastPathComponent).\(UUID().uuidString).tmp")
        var tempFD: Int32 = -1
        var removeTempOnExit = false

        defer {
            if tempFD >= 0 {
                close(tempFD)
            }
            if removeTempOnExit {
                try? FileManager.default.removeItem(at: tempURL)
            }
        }

        tempFD = open(tempURL.path,
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                      Self.resolverFileMode)
        guard tempFD >= 0 else {
            throw FileIO.failure("Failed to create temporary resolver file \(tempURL.path)", errno)
        }
        removeTempOnExit = true

        guard fchown(tempFD, resolverFileOwnership.userID, resolverFileOwnership.groupID) == 0 else {
            throw FileIO.failure("Failed to set owner on \(tempURL.path)", errno)
        }
        guard fchmod(tempFD, Self.resolverFileMode) == 0 else {
            throw FileIO.failure("Failed to set mode on \(tempURL.path)", errno)
        }

        do {
            try FileIO.writeAll(Data(content.utf8), to: tempFD)
        } catch {
            throw FileIO.failure("Failed to write resolver file \(tempURL.path)", (error as? POSIXError)?.code.rawValue ?? EIO)
        }
        guard fsync(tempFD) == 0 else {
            throw FileIO.failure("Failed to sync resolver file \(tempURL.path)", errno)
        }
        try assertHardenedResolverFile(fileDescriptor: tempFD, path: tempURL.path)

        guard close(tempFD) == 0 else {
            let closeError = errno
            tempFD = -1
            throw FileIO.failure("Failed to close resolver file \(tempURL.path)", closeError)
        }
        tempFD = -1

        var swappedExisting = false
        if renamex_np(tempURL.path, resolverFile.path, UInt32(RENAME_EXCL)) == 0 {
            removeTempOnExit = false
        } else {
            let installError = errno
            guard installError == EEXIST else {
                throw FileIO.failure("Failed to install resolver file \(resolverFile.path)", installError)
            }
            try assertManagedResolverFile(at: resolverFile)
            guard renamex_np(tempURL.path, resolverFile.path, UInt32(RENAME_SWAP)) == 0 else {
                throw FileIO.failure("Failed to replace resolver file \(resolverFile.path)", errno)
            }
            swappedExisting = true
        }

        do {
            try assertManagedResolverFile(at: resolverFile)
            if swappedExisting {
                try assertManagedResolverFile(at: tempURL)
            }
            try syncResolverDirectory(directory)
        } catch {
            if swappedExisting {
                guard renamex_np(tempURL.path, resolverFile.path, UInt32(RENAME_SWAP)) == 0 else {
                    removeTempOnExit = false
                    throw FileIO.failure("Failed to restore resolver file \(resolverFile.path)", errno)
                }
            } else {
                _ = unlink(resolverFile.path)
            }
            throw error
        }

        if swappedExisting {
            guard unlink(tempURL.path) == 0 else {
                let unlinkError = errno
                guard renamex_np(tempURL.path, resolverFile.path, UInt32(RENAME_SWAP)) == 0 else {
                    removeTempOnExit = false
                    throw FileIO.failure("Failed to restore resolver file \(resolverFile.path)", errno)
                }
                _ = unlink(tempURL.path)
                try syncResolverDirectory(directory)
                throw FileIO.failure("Failed to remove replaced resolver file \(tempURL.path)", unlinkError)
            }
            removeTempOnExit = false
        }
    }

    func recoverManagedResolverArtifacts(for resolverFile: URL) throws {
        let directory = resolverFile.deletingLastPathComponent()
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else {
            return
        }
        let prefix = ".\(resolverFile.lastPathComponent)."
        let artifacts = names
            .filter { name in
                guard name.hasPrefix(prefix) else {
                    return false
                }
                let fields = name.dropFirst(prefix.count).split(separator: ".", omittingEmptySubsequences: false)
                return fields.count == 2
                    && UUID(uuidString: String(fields[0])) != nil
                    && (fields[1] == "tmp" || fields[1] == "remove")
            }
            .sorted()
            .map { directory.appendingPathComponent($0) }
        guard !artifacts.isEmpty else {
            return
        }

        var activeExists = FileManager.default.fileExists(atPath: resolverFile.path)
        for artifact in artifacts {
            let quarantined = artifact.lastPathComponent.hasSuffix(".remove")
            guard let data = try? readHardenedResolverFile(at: artifact),
                  Self.firstLine(of: data) == Self.resolverManagedMarker
                    || (!quarantined && Self.resolverManagedMarker.utf8.starts(with: data)) else {
                continue
            }
            if quarantined && !activeExists {
                try restoreQuarantinedResolverFile(from: artifact, to: resolverFile)
                activeExists = true
            } else {
                guard unlink(artifact.path) == 0 else {
                    throw FileIO.failure("Failed to remove stale resolver file \(artifact.path)", errno)
                }
            }
        }
        try syncResolverDirectory(directory)
    }

    func syncResolverDirectory(_ directory: URL) throws {
        let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard directoryFD >= 0 else {
            throw FileIO.failure("Failed to open resolver directory \(directory.path)", errno)
        }
        defer { close(directoryFD) }
        guard fsync(directoryFD) == 0 else {
            throw FileIO.failure("Failed to sync resolver directory \(directory.path)", errno)
        }
    }

    func quarantineExistingManagedResolverFile(at resolverFile: URL,
                                               to quarantineURL: URL) throws -> Bool {
        guard renamex_np(resolverFile.path, quarantineURL.path, UInt32(RENAME_EXCL)) == 0 else {
            let renameError = errno
            if renameError == ENOENT {
                return false
            }
            throw FileIO.failure("Failed to quarantine resolver file \(resolverFile.path)", renameError)
        }

        do {
            try assertManagedResolverFile(at: quarantineURL)
            return true
        } catch {
            do {
                try restoreQuarantinedResolverFile(from: quarantineURL, to: resolverFile)
            } catch let restoreError {
                throw FileIO.failure(
                    "Resolver validation failed; the original is preserved at \(quarantineURL.path), but could not be restored to \(resolverFile.path): \(restoreError.localizedDescription)",
                    EBUSY
                )
            }
            throw error
        }
    }

    func restoreQuarantinedResolverFile(from quarantineURL: URL, to resolverFile: URL) throws {
        guard renamex_np(quarantineURL.path, resolverFile.path, UInt32(RENAME_EXCL)) == 0 else {
            throw FileIO.failure("Failed to restore resolver file \(resolverFile.path)", errno)
        }
    }

    func removeManagedResolverFileAtomically(at resolverFile: URL) throws {
        let quarantineURL = resolverFile.deletingLastPathComponent()
            .appendingPathComponent(".\(resolverFile.lastPathComponent).\(UUID().uuidString).remove")
        guard try quarantineExistingManagedResolverFile(at: resolverFile, to: quarantineURL) else {
            return
        }

        do {
            try syncResolverDirectory(resolverFile.deletingLastPathComponent())
        } catch {
            try restoreQuarantinedResolverFile(from: quarantineURL, to: resolverFile)
            throw error
        }

        guard unlink(quarantineURL.path) == 0 else {
            let unlinkError = errno
            do {
                try restoreQuarantinedResolverFile(from: quarantineURL, to: resolverFile)
            } catch let restoreError {
                throw FileIO.failure(
                    "Failed to remove managed resolver file; the original is preserved at \(quarantineURL.path), but could not be restored: \(restoreError.localizedDescription)",
                    unlinkError
                )
            }
            throw FileIO.failure("Failed to remove managed resolver file \(resolverFile.path)", unlinkError)
        }
        try syncResolverDirectory(resolverFile.deletingLastPathComponent())
    }

    func assertManagedResolverFile(at resolverFile: URL) throws {
        let data = try readHardenedResolverFile(at: resolverFile)
        guard Self.firstLine(of: data) == Self.resolverManagedMarker else {
            throw RouteManagerError.refusingToReplaceUnmanagedResolverFile(resolverFile.lastPathComponent)
        }
    }

    private func readHardenedResolverFile(at resolverFile: URL) throws -> Data {
        try SecureFile.readRegularFile(at: resolverFile,
                                       maximumBytes: Self.maxResolverFileBytes,
                                       context: "resolver file \(resolverFile.path)",
                                       expectedUserID: resolverFileOwnership.userID,
                                       expectedGroupID: resolverFileOwnership.groupID,
                                       expectedMode: Self.resolverFileMode)
    }

    private func assertHardenedResolverFile(fileDescriptor: Int32, path: String) throws {
        try SecureFile.assertRegularFile(fileDescriptor: fileDescriptor,
                                         context: "resolver file \(path)",
                                         expectedUserID: resolverFileOwnership.userID,
                                         expectedGroupID: resolverFileOwnership.groupID,
                                         expectedMode: Self.resolverFileMode)
    }

    private static func firstLine(of data: Data) -> String? {
        String(decoding: data, as: UTF8.self)
            .split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
            .first
            .map(String.init)
    }

    @discardableResult
    func removeResolverFiles(using state: SessionState) throws -> [String] {
        try removeResolverFiles(for: (appliedDNSDomains(using: state)
                                      + SplitTunnelPolicy.fixedResolverDomains
                                      + Self.webAuthBootstrapResolverDomains
                                      + managedResolverDomainsInDirectory()).uniqued())
    }

    func removeObsoleteResolverFiles(retaining domains: [String]) throws -> Bool {
        let retainedDomains = Set(domains.filter {
            NetworkValidation.isValidDomainName($0)
                && ResolverPaths.isSafeDomainFileName($0)
        })
        return try !removeResolverFiles(for: managedResolverDomainsInDirectory().filter {
            !retainedDomains.contains($0)
        }).isEmpty
    }

    @discardableResult
    func removeResolverFiles(for domains: [String]) throws -> [String] {
        var removed: [String] = []
        var firstError: Error?
        var mutationAttempted = false
        for domain in domains {
            let resolverFile = resolverFileURL(for: domain)
            do {
                try recoverManagedResolverArtifacts(for: resolverFile)
                if resolverFileIsManaged(at: resolverFile) {
                    mutationAttempted = true
                    try removeManagedResolverFileAtomically(at: resolverFile)
                    removed.append(domain)
                }
            } catch {
                firstError = firstError ?? error
            }
        }
        if let firstError {
            if mutationAttempted {
                throw RouteManagerError.dnsMutationMayHaveOccurred(firstError.localizedDescription)
            }
            throw firstError
        }
        return removed
    }

    func resolverContents(for domain: String, nameServers: [String]) -> String {
        var lines = [Self.resolverManagedMarker]
        lines.append(contentsOf: nameServers.map { "nameserver \($0)" })
        lines.append("domain \(domain)")
        lines.append("search_order 1")
        return lines.joined(separator: "\n") + "\n"
    }

    func resolverFileIsManaged(at file: URL) -> Bool {
        (try? readResolverFile(at: file)).map(Self.firstLine) == Self.resolverManagedMarker
    }

    func unmanagedResolverMatches(domain: String, nameServers: [String]) throws -> Bool {
        do {
            let data = try readResolverFile(at: resolverFileURL(for: domain))
            guard Self.firstLine(of: data) != Self.resolverManagedMarker else {
                return false
            }
            let declaredServers = String(decoding: data, as: UTF8.self).split(whereSeparator: \.isNewline)
                .compactMap { line -> String? in
                    let fields = line.split(whereSeparator: \.isWhitespace)
                    return fields.count >= 2 && fields[0] == "nameserver" ? String(fields[1]) : nil
                }
            return Set(nameServers).isSubset(of: Set(normalizedDNSServers(declaredServers)))
        } catch where Self.isMissingFileError(error) {
            return false
        }
    }

    private func readResolverFile(at file: URL) throws -> Data {
        try SecureFile.readRegularFile(at: file,
                                       maximumBytes: Self.maxResolverFileBytes,
                                       context: "resolver file \(file.path)")
    }

    struct ManagedResolverScan {
        var managed: [String] = []
        var unreadable: [String: Error] = [:]
        var directoryError: Error?
    }

    func scanManagedResolverDirectory() -> ManagedResolverScan {
        var scan = ManagedResolverScan()
        let files: [URL]
        do {
            files = try FileManager.default.contentsOfDirectory(at: resolverDirectory, includingPropertiesForKeys: nil)
        } catch {
            if !Self.isMissingFileError(error) {
                scan.directoryError = error
            }
            return scan
        }
        for file in files {
            let domain = file.lastPathComponent
            guard NetworkValidation.isValidDomainName(domain),
                  ResolverPaths.isSafeDomainFileName(domain) else {
                continue
            }
            do {
                if Self.firstLine(of: try readResolverFile(at: file)) == Self.resolverManagedMarker {
                    scan.managed.append(domain)
                }
            } catch {
                if !Self.isMissingFileError(error) {
                    scan.unreadable[domain] = error
                }
            }
        }
        scan.managed.sort()
        return scan
    }

    func managedResolverDomainsInDirectory() -> [String] {
        scanManagedResolverDirectory().managed
    }

    private static func isMissingFileError(_ error: Error) -> Bool {
        let failure = error as NSError
        return (failure.domain == NSPOSIXErrorDomain && failure.code == Int(ENOENT))
            || (failure.domain == NSCocoaErrorDomain && failure.code == NSFileReadNoSuchFileError)
    }
}
