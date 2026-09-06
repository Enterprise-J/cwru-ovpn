import AppKit
import AuthenticationServices
import Foundation

private func makeExternalWebAuthSession(url: URL,
                                        prefersEphemeralSession: Bool,
                                        relay: ExternalWebAuthCompletionRelay,
                                        provider: ASWebAuthenticationPresentationContextProviding) -> ASWebAuthenticationSession {
    let callback = ASWebAuthenticationSession.Callback.customScheme("cwru-ovpn")
    let session = ASWebAuthenticationSession(url: url, callback: callback) { _, error in
        relay.finish(error: error)
    }
    session.prefersEphemeralWebBrowserSession = prefersEphemeralSession
    session.presentationContextProvider = provider
    return session
}

private final class ExternalWebAuthCompletionRelay: @unchecked Sendable {
    weak var owner: ExternalWebAuthSession?

    func finish(error: Error?) {
        Task { @MainActor [self] in
            owner?.handleCompletion(error: error)
        }
    }
}

@MainActor
final class ExternalWebAuthSession: NSObject {
    private let url: URL
    private let usesSystemSession: Bool
    private let prefersEphemeralSession: Bool
    private let completionRelay = ExternalWebAuthCompletionRelay()
    private var session: ASWebAuthenticationSession?
    private var anchorWindow: NSWindow?
    private var expectedCancellation = false

    var onUserCancelled: (() -> Void)?
    var onFailure: ((Error) -> Void)?

    init(url: URL, usesSystemSession: Bool, prefersEphemeralSession: Bool) {
        self.url = url
        self.usesSystemSession = usesSystemSession
        self.prefersEphemeralSession = prefersEphemeralSession
        super.init()
    }

    func start() -> Bool {
        guard usesSystemSession else {
            return NSWorkspace.shared.open(url)
        }

        completionRelay.owner = self
        let session = makeExternalWebAuthSession(
            url: url,
            prefersEphemeralSession: prefersEphemeralSession,
            relay: completionRelay,
            provider: self
        )
        self.session = session
        expectedCancellation = false

        ensureAnchorWindow()

        if session.start() {
            return true
        }

        if self.session === session {
            self.session = nil
        }
        teardownAnchorWindow()
        completionRelay.owner = nil
        return false
    }

    func close() {
        guard usesSystemSession else {
            return
        }

        expectedCancellation = true
        teardownAnchorWindow()
        let session = self.session
        guard let session else {
            completionRelay.owner = nil
            return
        }
        session.cancel()
    }

    fileprivate func handleCompletion(error: Error?) {
        let wasExpectedCancellation = expectedCancellation
        expectedCancellation = false
        session = nil

        teardownAnchorWindow()
        completionRelay.owner = nil

        guard !wasExpectedCancellation else {
            return
        }

        if let authError = error as? ASWebAuthenticationSessionError,
           authError.code == .canceledLogin {
            onUserCancelled?()
            return
        }

        guard let error else {
            return
        }

        onFailure?(error)
    }

    private func ensureAnchorWindow() {
        guard anchorWindow == nil else {
            return
        }

        let frame = NSRect(x: -10_000, y: -10_000, width: 1, height: 1)
        let window = NSWindow(contentRect: frame,
                              styleMask: [.borderless],
                              backing: .buffered,
                              defer: false)
        window.isOpaque = false
        window.backgroundColor = .clear
        window.alphaValue = 0.0
        window.ignoresMouseEvents = true
        window.level = .normal
        window.collectionBehavior = [.transient, .ignoresCycle, .moveToActiveSpace]
        window.isReleasedWhenClosed = false
        window.orderFront(nil)
        anchorWindow = window
    }

    private func teardownAnchorWindow() {
        anchorWindow?.orderOut(nil)
        anchorWindow?.close()
        anchorWindow = nil
    }
}

extension ExternalWebAuthSession: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for _: ASWebAuthenticationSession) -> ASPresentationAnchor {
        anchorWindow ?? NSApp.windows.first ?? ASPresentationAnchor()
    }
}
