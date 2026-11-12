import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

let mockPublicDNSServerA = "208.67.220.220"
let mockPublicDNSServerB = "208.67.222.222"

func parseRouteTableLine(_ line: String) -> RouteEntry? {
    RouteEntry(line: Substring(line))
}

func routeTouchesPublicGlobalUnicast(_ value: String) -> Bool {
    guard let route = IPRoute.canonicalIPv6(value) else {
        return false
    }
    return RouteManager.ipv6RouteTouchesPublicGlobalUnicast(route)
}
