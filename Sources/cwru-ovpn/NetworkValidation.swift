import Darwin
import Foundation

enum NetworkValidation {
    static let maxIPv4CIDRLength = 18
    static let maxIPv6CIDRLength = 49
    static let maxIPAddressLength = 45
    static let maxDomainNameLength = 253
    static let maxDomainLabelLength = 63

    static func isValidIPv4CIDR(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= maxIPv4CIDRLength else {
            return false
        }

        let parts = value.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              let prefixLength = Int(parts[1]),
              (0...32).contains(prefixLength) else {
            return false
        }
        return isValidIPv4Address(String(parts[0]))
    }

    static func isValidIPv6CIDR(_ value: String) -> Bool {
        guard !value.isEmpty, value.count <= maxIPv6CIDRLength else {
            return false
        }

        let parts = value.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              let prefixLength = Int(parts[1]),
              (0...128).contains(prefixLength) else {
            return false
        }
        return isValidIPv6Address(String(parts[0]))
    }

    static func isValidIPv4Address(_ value: String) -> Bool {
        IPRoute.canonicalIPv4Address(value) != nil
    }

    static func isValidIPv6Address(_ value: String) -> Bool {
        guard !value.isEmpty,
              value.count <= maxIPAddressLength,
              !value.utf8.contains(0) else {
            return false
        }
        var addr = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &addr) == 1 }
    }

    static func isValidDomainName(_ value: String) -> Bool {
        guard !value.isEmpty,
              value.utf8.count <= maxDomainNameLength,
              !value.hasPrefix("."),
              !value.hasSuffix(".") else {
            return false
        }
        return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            let s = String(label)
            return !s.isEmpty
                && s.utf8.count <= maxDomainLabelLength
                && s.unicodeScalars.allSatisfy(Self.isASCIIDomainLabelScalar)
                && !s.hasPrefix("-")
                && !s.hasSuffix("-")
        }
    }

    private static func isASCIIDomainLabelScalar(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x30...0x39, 0x41...0x5A, 0x61...0x7A, 0x2D:
            return true
        default:
            return false
        }
    }

    static func isValidIPAddress(_ value: String) -> Bool {
        isValidIPv4Address(value) || isValidIPv6Address(value)
    }

    static func isSafeInterfaceName(_ value: String) -> Bool {
        !value.isEmpty
            && !value.hasPrefix("-")
            && value.count <= 32
            && value.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "." || $0 == "-" }
    }

    static func isVirtualInterfaceName(_ value: String) -> Bool {
        value.hasPrefix("utun") || value.hasPrefix("ppp")
    }

    static func isSafeNetworkServiceName(_ value: String) -> Bool {
        !value.isEmpty
            && !value.hasPrefix("-")
            && value.count <= 128
            && isPrintable(value)
    }

    static func isPrintable(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy { scalar in
            scalar.value >= 0x20 && scalar.value != 0x7F && !(0x80...0x9F).contains(scalar.value)
        }
    }
}
