import Foundation
import Darwin

enum ResolverPaths {
    static var directory: URL {
        if let rawValue = getenv("CWRU_OVPN_RESOLVER_DIR") {
            let overridden = String(cString: rawValue)
            if !overridden.isEmpty {
                return URL(fileURLWithPath: overridden, isDirectory: true).standardized
            }
        }

        if let overridden = ProcessInfo.processInfo.environment["CWRU_OVPN_RESOLVER_DIR"], !overridden.isEmpty {
            return URL(fileURLWithPath: overridden, isDirectory: true).standardized
        }

        return URL(fileURLWithPath: "/etc/resolver", isDirectory: true)
    }

    static func fileURL(for domain: String) -> URL {
        directory.appendingPathComponent(domain)
    }
}
