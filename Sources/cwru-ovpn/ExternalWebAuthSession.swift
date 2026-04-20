import AppKit
import AuthenticationServices
import Foundation

private func makeExternalWebAuthSession(url: URL,
                                        relay: ExternalWebAuthCompletionRelay,
                                        provider: ASWebAuthenticationPresentationContextProviding) -> ASWebAuthenticationSession {
    let session = ASWebAuthenticationSession(url: url, callbackURLScheme: nil) { _, error in
        relay.finish(error: error)
    }
    session.prefersEphemeralWebBrowserSession = false
    session.presentationContextProvider = provider
    return session
}

private final class ExternalWebAuthCompletionRelay: @unchecked Sendable {
    weak var owner: ExternalWebAuthSession?

    func finish(error: Error?) {
        Task { @MainActor [weak owner] in
            owner?.handleCompletion(error: error)
        }
    }
}

// ExternalWebAuthSession is isolated to @MainActor, so all state mutations
// happen on the main actor. No additional locking is needed.
@MainActor
final class ExternalWebAuthSession: NSObject {
    private let url: URL
    private let completionRelay = ExternalWebAuthCompletionRelay()
    private var session: ASWebAuthenticationSession?
    private var anchorWindow: NSWindow?
    private var expectedCancellation = false

    init(url: URL) {
        self.url = url
        super.init()
        completionRelay.owner = self
    }

    func start() -> Bool {
        if session != nil {
            return true
        }

        let session = makeExternalWebAuthSession(url: url, relay: completionRelay, provider: self)
        self.session = session
        expectedCancellation = false

        ensureAnchorWindow()

        if session.start() {
            return true
        }

        if self.session === session {
            self.session = nil
        }
        expectedCancellation = false
        teardownAnchorWindow()
        return false
    }

    func close() {
        let session = self.session
        expectedCancellation = true

        guard let session else {
            teardownAnchorWindow()
            return
        }

        session.cancel()
    }

    fileprivate func handleCompletion(error: Error?) {
        let wasExpectedCancellation = expectedCancellation
        expectedCancellation = false
        session = nil

        teardownAnchorWindow()

        guard !wasExpectedCancellation,
              let error,
              let authError = error as? ASWebAuthenticationSessionError,
              authError.code != .canceledLogin else {
            return
        }

        EventLog.append(note: "Browser authentication session ended: \(error.localizedDescription)",
                        phase: .authPending)
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
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        anchorWindow ?? NSApp.windows.first ?? ASPresentationAnchor()
    }
}
