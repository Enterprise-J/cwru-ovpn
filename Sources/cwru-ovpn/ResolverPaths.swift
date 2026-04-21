import Foundation
import Darwin

enum ResolverPaths {
    static var directory: URL {
        if getuid() != 0,
           let raw = getenv("CWRU_OVPN_RESOLVER_DIR") {
            let overridden = String(cString: raw)
            if !overridden.isEmpty {
                return URL(fileURLWithPath: overridden, isDirectory: true).standardized
            }
        }
        return URL(fileURLWithPath: "/etc/resolver", isDirectory: true)
    }

    static func isSafeDomainFileName(_ name: String) -> Bool {
        guard !name.isEmpty, !name.contains("/"), name != ".", name != ".." else {
            return false
        }
        return name.allSatisfy { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }
    }

    static func fileURL(for domain: String) -> URL {
        directory.appendingPathComponent(domain)
    }
}
