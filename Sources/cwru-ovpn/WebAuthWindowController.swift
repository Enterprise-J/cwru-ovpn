import AppKit
import Foundation
import WebKit

enum WebAuthStateEvent {
    case actionRequired
    case connectSuccess
    case connectFailed
    case locationChange(String)
}

enum WebAuthPresentation {
    case embedded
    case externalBrowser
}

struct WebAuthRequest {
    let url: URL
    let hiddenInitially: Bool
    let presentation: WebAuthPresentation

    static func parse(info: String) -> WebAuthRequest? {
        if info.hasPrefix("OPEN_URL:") {
            let rawURL = String(info.dropFirst("OPEN_URL:".count))
            guard let url = URL(string: rawURL) else {
                return nil
            }
            return WebAuthRequest(url: url, hiddenInitially: false, presentation: .externalBrowser)
        }

        if info.hasPrefix("WEB_AUTH:") {
            let payload = String(info.dropFirst("WEB_AUTH:".count))
            let separatorIndex = payload.firstIndex(of: ":")
            guard let separatorIndex else {
                return nil
            }
            let flags = payload[..<separatorIndex].split(separator: ",").map(String.init)
            let urlString = String(payload[payload.index(after: separatorIndex)...])
            let presentation: WebAuthPresentation = flags.contains("external") ? .externalBrowser : .embedded
            let url: URL?
            switch presentation {
            case .externalBrowser:
                url = URL(string: urlString)
            case .embedded:
                url = normalizedEmbeddedURL(from: urlString)
            }
            guard let url else {
                return nil
            }
            return WebAuthRequest(url: url,
                                  hiddenInitially: flags.contains("hidden"),
                                  presentation: presentation)
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
        return components.url
    }
}

final class WebAuthWindowController: NSWindowController, WKNavigationDelegate, WKScriptMessageHandler {
    var onStateEvent: ((WebAuthStateEvent) -> Void)?

    private let webView: WKWebView

    init(url: URL, hiddenInitially: Bool, userAgent: String) {
        let configuration = WKWebViewConfiguration()
        let contentController = WKUserContentController()
        let bridgeScript = """
        window.appEvent = {
            postMessage: function(message) {
                window.webkit.messageHandlers.appEvent.postMessage(message);
            }
        };
        """
        contentController.addUserScript(WKUserScript(source: bridgeScript,
                                                     injectionTime: .atDocumentStart,
                                                     forMainFrameOnly: false))
        configuration.userContentController = contentController

        webView = WKWebView(frame: .zero, configuration: configuration)
        webView.customUserAgent = userAgent

        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 720),
                              styleMask: [.titled, .closable, .miniaturizable],
                              backing: .buffered,
                              defer: false)
        window.title = "\(AppIdentity.bundleName) Sign-In"
        window.center()
        window.contentView = webView

        super.init(window: window)

        contentController.add(self, name: "appEvent")
        webView.navigationDelegate = self
        load(url: url, hiddenInitially: hiddenInitially)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        return nil
    }

    func load(url: URL, hiddenInitially: Bool) {
        webView.load(URLRequest(url: url))
        if hiddenInitially {
            window?.orderOut(nil)
        } else {
            focusWebView()
        }
    }

    override func showWindow(_ sender: Any?) {
        super.showWindow(sender)
        focusWebView()
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard message.name == "appEvent",
              let dictionary = message.body as? [String: Any],
              let type = dictionary["type"] as? String else {
            return
        }

        switch type {
        case "ACTION_REQUIRED":
            onStateEvent?(.actionRequired)
        case "CONNECT_SUCCESS":
            onStateEvent?(.connectSuccess)
        case "CONNECT_FAILED":
            onStateEvent?(.connectFailed)
        case "LOCATION_CHANGE":
            if let title = dictionary["data"] as? String {
                onStateEvent?(.locationChange(title))
            }
        default:
            break
        }
    }

    private func focusWebView() {
        guard let window else {
            return
        }

        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(webView)
    }
}
