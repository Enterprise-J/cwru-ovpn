import Foundation

struct WebAuthRequest {
    let url: URL

    private static let allowedHosts: Set<String> = [
        "case.edu",
        "cwru.openvpn.com",
    ]

    private static let allowedHostSuffixes = [
        ".case.edu",
    ]

    static func parse(info: String) -> WebAuthRequest? {
        if info.hasPrefix("OPEN_URL:") {
            let rawURL = String(info.dropFirst("OPEN_URL:".count))
            guard let url = URL(string: rawURL),
                  let url = validatedWebAuthURL(url) else {
                return nil
            }
            return WebAuthRequest(url: url)
        }

        if info.hasPrefix("WEB_AUTH:") {
            let payload = String(info.dropFirst("WEB_AUTH:".count))
            guard let separatorIndex = payload.firstIndex(of: ":") else {
                return nil
            }

            let flags = payload[..<separatorIndex].split(separator: ",").map(String.init)
            let urlString = String(payload[payload.index(after: separatorIndex)...])
            let url: URL?
            if flags.contains("external") {
                url = URL(string: urlString).flatMap(validatedWebAuthURL(_:))
            } else {
                url = normalizedEmbeddedURL(from: urlString)
            }

            guard let url else {
                return nil
            }

            return WebAuthRequest(url: url)
        }

        return nil
    }

    private static func normalizedEmbeddedURL(from rawValue: String) -> URL? {
        guard var components = URLComponents(string: rawValue) else {
            return nil
        }

        var items = components.queryItems ?? []
        if !items.contains(where: { $0.name == "embedded" }) {
            items.append(URLQueryItem(name: "embedded", value: "true"))
        }
        components.queryItems = items.isEmpty ? nil : items
        guard let url = components.url else {
            return nil
        }
        return validatedWebAuthURL(url)
    }

    private static func validatedWebAuthURL(_ url: URL) -> URL? {
        guard let scheme = url.scheme?.lowercased(),
              scheme == "https",
              let host = url.host?.lowercased(),
              isAllowedWebAuthHost(host) else {
            return nil
        }

        return url
    }

    private static func isAllowedWebAuthHost(_ host: String) -> Bool {
        allowedHosts.contains(host) || allowedHostSuffixes.contains(where: { host.hasSuffix($0) })
    }
}
