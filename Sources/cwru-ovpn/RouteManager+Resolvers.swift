import COpenVPN3Wrapper
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
            return try withResolverDirectory { directory in
                guard let data = try directory.read(domain) else { return .missing }
                return data == Data(resolverContents(for: domain, nameServers: nameServers).utf8) ? .matching : .different
            }
        } catch where Self.isMissingFileError(error) { return .missing }
    }

    func resolverFilesHealthCheck(using state: SessionState) -> TunnelHealthCheck {
        let domains = appliedScopedDNSDomains(using: state)
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
        let status: TunnelHealthCheckStatus
        if failures.contains(where: { !$0.1.isEmpty }) {
            status = .fail
        } else {
            status = unavailable.isEmpty ? .pass : .warn
        }
        return TunnelHealthCheck(
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
            throw RouteManagerError.missingPolicyDNSServers
        }

        return try withResolverDirectory(create: true) { directory in
            let names = try AnchoredFileIO.names(in: directory.fd)
            var pending: [(String, Data)] = []
            for domain in dnsDomains.uniqued() {
                guard ResolverPaths.isSafeDomainFileName(domain) else { throw POSIXError(.EINVAL) }
                try directory.recover(domain, names: names)
                let desired = Data(resolverContents(for: domain, nameServers: nameServers).utf8)
                let current = try directory.read(domain)
                if let current, !ResolverDirectory.isManaged(current) {
                    throw RouteManagerError.refusingToReplaceUnmanagedResolverFile(domain)
                }
                if current != desired { pending.append((domain, desired)) }
            }
            for (domain, desired) in pending { try directory.install(desired, as: domain) }
            return !pending.isEmpty
        }
    }

    func withResolverDirectory<T>(create: Bool = false, _ body: (ResolverDirectory) throws -> T) throws -> T {
        let (user, group) = resolverFileOwnership
        return try AnchoredFileIO.withDirectory(at: resolverDirectory, parentUserID: user, parentGroupID: group,
                                                userID: user, groupID: group, createIfMissing: create, mode: nil) { fd in
            try body(ResolverDirectory(fd: fd, owner: user, group: group))
        }
    }

    static let webAuthBootstrapResolverDomains = ["openvpn.com", "openvpn.net"]

    static func isUnusableRemoteIPv4Address(_ address: String) -> Bool {
        guard let numeric = IPRoute.canonicalIPv4Address(address) else {
            return false
        }
        return numeric == 0 || (numeric >> 24) == 127
    }

    private final class DNSAnswers {
        var addresses: [String] = []
    }

    static func resolveAddresses(host: String, server: String?, dualStack: Bool, timeout: Int) -> [String]? {
        guard NetworkValidation.isValidDomainName(host), (1...30).contains(timeout) else { return nil }
        let answers = DNSAnswers()
        let context = Unmanaged.passUnretained(answers).toOpaque()
        let callback: cwru_address_callback_t = { context, address in
            guard let context, let address else { return }
            let answers = Unmanaged<DNSAnswers>.fromOpaque(context).takeUnretainedValue()
            if answers.addresses.count < 256 { answers.addresses.append(String(cString: address)) }
        }
        let complete: Bool
        if let server {
            complete = cwru_resolve_gateway(host, server, Int32(timeout), callback, context)
        } else {
            complete = cwru_resolve_addresses(host, dualStack, Int32(timeout), callback, context)
        }
        return complete ? answers.addresses : nil
    }

    typealias AddressLookup = (String, String?, Bool, Int) -> [String]?

    static func resolveHostUsingBootstrap(host: String, servers: [String], timeoutSeconds: Int,
                                         lookup: AddressLookup = resolveAddresses) -> String? {
        guard !NetworkValidation.isValidIPAddress(host), NetworkValidation.isValidDomainName(host) else { return nil }
        for server in servers where NetworkValidation.isValidIPAddress(server) {
            if let address = lookup(host, server, false, timeoutSeconds)?.first(where: {
                NetworkValidation.isValidIPv4Address($0) && !isUnusableRemoteIPv4Address($0)
            }) { return address }
        }
        return nil
    }

    static func systemResolverSinkholes(host: String, timeoutSeconds: Int, dualStack: Bool,
                                        lookup: AddressLookup = resolveAddresses) -> Bool {
        guard NetworkValidation.isValidDomainName(host),
              let addresses = lookup(host, nil, dualStack, timeoutSeconds), !addresses.isEmpty else { return false }
        return addresses.allSatisfy { address in
            isUnusableRemoteIPv4Address(address) || address == "::1" || address == "::"
        }
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

    @discardableResult
    func removeResolverFiles(using state: SessionState) throws -> [String] {
        try removeResolverFiles(for: (appliedScopedDNSDomains(using: state)
                                      + CampusNetworkPolicy.fixedResolverDomains
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
        do {
            return try withResolverDirectory { directory in
                let names = try AnchoredFileIO.names(in: directory.fd)
                var removed: [String] = []
                var firstError: Error?
                for domain in domains.uniqued() {
                    do {
                        guard ResolverPaths.isSafeDomainFileName(domain) else { throw POSIXError(.EINVAL) }
                        try directory.recover(domain, names: names)
                        if try directory.remove(domain) { removed.append(domain) }
                    } catch { firstError = firstError ?? error }
                }
                if let firstError {
                    if !removed.isEmpty { throw RouteManagerError.dnsMutationMayHaveOccurred(firstError.localizedDescription) }
                    throw firstError
                }
                return removed
            }
        } catch where Self.isMissingFileError(error) { return [] }
    }

    func resolverContents(for domain: String, nameServers: [String]) -> String {
        var lines = [Self.resolverManagedMarker]
        lines.append(contentsOf: nameServers.map { "nameserver \($0)" })
        lines.append("domain \(domain)")
        lines.append("search_order 1")
        return lines.joined(separator: "\n") + "\n"
    }

    func unmanagedResolverMatches(domain: String, nameServers: [String]) throws -> Bool {
        do {
            guard let data = try withResolverDirectory({ try $0.read(domain) }), !ResolverDirectory.isManaged(data) else {
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

    struct ManagedResolverScan {
        var managed: [String] = []
        var unmanaged: [String] = []
        var unreadable: [String: Error] = [:]
        var directoryError: Error?
    }

    func scanManagedResolverDirectory() -> ManagedResolverScan {
        var scan = ManagedResolverScan()
        do {
            try withResolverDirectory { directory in
                for domain in try AnchoredFileIO.names(in: directory.fd)
                where NetworkValidation.isValidDomainName(domain) && ResolverPaths.isSafeDomainFileName(domain) {
                    do {
                        if let data = try directory.read(domain) {
                            if ResolverDirectory.isManaged(data) { scan.managed.append(domain) }
                            else { scan.unmanaged.append(domain) }
                        }
                    } catch { scan.unreadable[domain] = error }
                }
            }
        } catch {
            if !Self.isMissingFileError(error) { scan.directoryError = error }
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
