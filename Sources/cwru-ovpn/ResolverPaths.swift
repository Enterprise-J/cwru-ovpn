import Foundation
import Darwin

enum ResolverPaths {
    static var directory: URL {
        return URL(fileURLWithPath: "/etc/resolver", isDirectory: true)
    }

    static func isSafeDomainFileName(_ name: String) -> Bool {
        guard !name.isEmpty,
              name.utf8.count <= SplitTunnelPolicy.maxDomainNameLength,
              !name.contains("/"),
              name != ".",
              name != ".." else {
            return false
        }
        return name.unicodeScalars.allSatisfy { scalar in
            switch scalar.value {
            case 0x30...0x39, 0x41...0x5A, 0x61...0x7A:
                return true
            case 0x2D, 0x2E:
                return true
            default:
                return false
            }
        }
    }

    static func fileURL(for domain: String, in directory: URL = directory) -> URL {
        guard isSafeDomainFileName(domain) else {
            preconditionFailure("Invalid DNS domain file name: \(domain)")
        }
        return directory.standardizedFileURL.appendingPathComponent(domain)
    }
}
