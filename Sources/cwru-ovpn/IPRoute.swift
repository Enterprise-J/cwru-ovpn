import Darwin
import Foundation

struct CanonicalIPv4Route: Hashable {
    let networkAddress: UInt32
    let prefixLength: Int

    var addressString: String {
        IPRoute.ipv4String(fromAddress: networkAddress)
    }

    var routeString: String {
        "\(addressString)/\(prefixLength)"
    }
}

struct CanonicalIPv6Route: Hashable {
    let networkBytes: [UInt8]
    let prefixLength: Int
    let addressString: String

    var routeString: String {
        "\(addressString)/\(prefixLength)"
    }
}

enum IPRoute {
    static func canonicalIPv4(_ route: String) -> CanonicalIPv4Route? {
        let trimmed = route.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.utf8.contains(0) else {
            return nil
        }

        let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let octets = parts[0].split(separator: ".", omittingEmptySubsequences: false)
        guard (1...4).contains(octets.count) else {
            return nil
        }
        let prefixLength: Int
        if parts.count == 2 {
            guard let parsedPrefix = Int(parts[1]), (0...32).contains(parsedPrefix) else {
                return nil
            }
            prefixLength = parsedPrefix
        } else {
            prefixLength = octets.count * 8
        }

        var address: UInt32 = 0
        for index in 0..<4 {
            var octet: UInt32 = 0
            if index < octets.count {
                let digits = octets[index]
                guard (1...3).contains(digits.count),
                      digits.allSatisfy(\.isASCII),
                      digits.allSatisfy(\.isNumber),
                      digits.count == 1 || !digits.hasPrefix("0"),
                      let parsedOctet = UInt32(digits),
                      parsedOctet <= 255 else {
                    return nil
                }
                octet = parsedOctet
            }
            address = (address << 8) | octet
        }

        return CanonicalIPv4Route(networkAddress: address & ipv4Mask(prefixLength: prefixLength),
                                  prefixLength: prefixLength)
    }

    static func canonicalIPv6(_ route: String) -> CanonicalIPv6Route? {
        let trimmed = route.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.utf8.contains(0) else {
            return nil
        }

        let addressPart: String
        let prefixLength: Int
        if trimmed == "default" {
            addressPart = "::"
            prefixLength = 0
        } else {
            let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
            addressPart = parts[0].split(separator: "%", maxSplits: 1).first.map(String.init) ?? ""
            if parts.count == 2 {
                guard let parsedPrefix = Int(parts[1]), (0...128).contains(parsedPrefix) else {
                    return nil
                }
                prefixLength = parsedPrefix
            } else {
                prefixLength = 128
            }
        }

        var parsedAddress = in6_addr()
        guard addressPart.withCString({ inet_pton(AF_INET6, $0, &parsedAddress) }) == 1 else {
            return nil
        }

        var bytes = withUnsafeBytes(of: &parsedAddress) { Array($0) }
        for index in bytes.indices {
            let remainingBits = prefixLength - (index * 8)
            if remainingBits <= 0 {
                bytes[index] = 0
            } else if remainingBits < 8 {
                bytes[index] &= ipv6ByteMask(remainingBits: remainingBits)
            }
        }

        guard let addressString = ipv6String(fromBytes: bytes) else {
            return nil
        }
        return CanonicalIPv6Route(networkBytes: bytes, prefixLength: prefixLength, addressString: addressString)
    }

    static func canonicalIPv4Address(_ address: String) -> UInt32? {
        guard !address.isEmpty,
              address.utf8.count <= 15,
              !address.utf8.contains(0) else {
            return nil
        }
        var parsedAddress = in_addr()
        guard address.withCString({ inet_pton(AF_INET, $0, &parsedAddress) }) == 1 else {
            return nil
        }
        return UInt32(bigEndian: parsedAddress.s_addr)
    }

    static func ipv4Mask(prefixLength: Int) -> UInt32 {
        prefixLength == 0 ? 0 : ~UInt32(0) << (32 - prefixLength)
    }

    static func ipv4Address(_ address: UInt32, isIn route: CanonicalIPv4Route) -> Bool {
        (address & ipv4Mask(prefixLength: route.prefixLength)) == route.networkAddress
    }

    static func ipv4Route(_ route: CanonicalIPv4Route, contains candidate: CanonicalIPv4Route) -> Bool {
        route.prefixLength <= candidate.prefixLength
            && ipv4Address(candidate.networkAddress, isIn: route)
    }

    static func ipv6Route(_ route: CanonicalIPv6Route, contains candidate: CanonicalIPv6Route) -> Bool {
        guard route.prefixLength <= candidate.prefixLength,
              route.networkBytes.count == candidate.networkBytes.count else {
            return false
        }

        for index in route.networkBytes.indices {
            let remainingBits = route.prefixLength - (index * 8)
            if remainingBits <= 0 {
                return true
            }
            let mask = remainingBits >= 8 ? 0xFF : ipv6ByteMask(remainingBits: remainingBits)
            if (candidate.networkBytes[index] & mask) != route.networkBytes[index] {
                return false
            }
        }
        return true
    }

    static func ipv6Address(_ address: String, isIn route: CanonicalIPv6Route) -> Bool {
        canonicalIPv6("\(address)/128").map { ipv6Route(route, contains: $0) } ?? false
    }

    static func reverseResolverZone(forIPv4Address address: UInt32, prefixLength: Int) -> String? {
        guard prefixLength > 0, prefixLength <= 32, prefixLength % 8 == 0 else {
            return nil
        }
        let octets = (0..<(prefixLength / 8)).map { String((address >> UInt32(24 - $0 * 8)) & 0xFF) }
        return octets.reversed().joined(separator: ".") + ".in-addr.arpa"
    }

    static func reverseResolverZone(forIPv6AddressBytes bytes: [UInt8], prefixLength: Int) -> String? {
        guard prefixLength > 0,
              prefixLength <= 128,
              prefixLength % 4 == 0,
              bytes.count == 16 else {
            return nil
        }

        let nibbles = bytes.flatMap { [String($0 >> 4, radix: 16), String($0 & 0x0F, radix: 16)] }
        return nibbles.prefix(prefixLength / 4).reversed().joined(separator: ".") + ".ip6.arpa"
    }

    static func ipv4String(fromAddress address: UInt32) -> String {
        [address >> 24, address >> 16, address >> 8, address].map { String($0 & 0xFF) }.joined(separator: ".")
    }

    private static func ipv6ByteMask(remainingBits: Int) -> UInt8 {
        UInt8((0xFF << (8 - remainingBits)) & 0xFF)
    }

    private static func ipv6String(fromBytes bytes: [UInt8]) -> String? {
        guard bytes.count == 16 else {
            return nil
        }

        var address = in6_addr()
        withUnsafeMutableBytes(of: &address) { $0.copyBytes(from: bytes) }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
            return nil
        }
        return buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }
}
