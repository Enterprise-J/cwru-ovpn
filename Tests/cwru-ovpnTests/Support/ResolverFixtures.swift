@testable import cwru_ovpn

func scopedResolverContents(domain: String, nameServer: String) -> String {
    "\(RouteManager.resolverManagedMarker)\nnameserver \(nameServer)\ndomain \(domain)\nsearch_order 1\n"
}
