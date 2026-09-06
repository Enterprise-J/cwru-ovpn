import Foundation

struct WebAuthRequest {
    enum ParseResult {
        case unrelated
        case invalid
        case request(WebAuthRequest)
    }

    let url: URL
    let requiresExternalBrowser: Bool

    private static let allowedHost = "cwru.openvpn.com"
    private static let allowedPort = 443

    static func parseResult(info: String) -> ParseResult {
        guard info.hasPrefix("WEB_AUTH:") else {
            return .unrelated
        }

        let payload = String(info.dropFirst("WEB_AUTH:".count))
        guard let separatorIndex = payload.firstIndex(of: ":") else {
            return .invalid
        }

        let flags = payload[..<separatorIndex].split(separator: ",").map(String.init)
        let urlString = String(payload[payload.index(after: separatorIndex)...])
        guard let url = URL(string: urlString).flatMap(validatedWebAuthURL(_:)) else {
            return .invalid
        }

        return .request(WebAuthRequest(url: url,
                                       requiresExternalBrowser: flags.contains("external")))
    }

    func presentationURL(usesSystemSession: Bool) -> URL {
        guard usesSystemSession,
              var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return url
        }

        var items = (components.queryItems ?? []).filter { $0.name != "embedded" }
        items.append(URLQueryItem(name: "embedded", value: "true"))
        components.queryItems = items.isEmpty ? nil : items
        return components.url ?? url
    }

    private static func validatedWebAuthURL(_ url: URL) -> URL? {
        guard let scheme = url.scheme,
              scheme.lowercased() == "https",
              let host = url.host,
              host.lowercased() == allowedHost,
              let authority = serializedAuthority(of: url, scheme: scheme)?.lowercased(),
              authority == allowedHost || authority == "\(allowedHost):\(allowedPort)" else {
            return nil
        }

        return url
    }

    private static func serializedAuthority(of url: URL, scheme: String) -> Substring? {
        let text = url.absoluteString
        let marker = scheme + "://"
        guard text.hasPrefix(marker) else {
            return nil
        }

        return text.dropFirst(marker.count).prefix { !"/?#".contains($0) }
    }
}
