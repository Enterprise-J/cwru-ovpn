import AppKit
import Foundation

struct MenuBarSnapshot {
    let phase: SessionState.Phase
    let canRetrySignIn: Bool
    let tunnelMode: AppTunnelMode
    let requestedTunnelMode: AppTunnelMode?
    let transportDegraded: Bool
    let statusText: String
    let gatewayText: String
    let estimatedSessionText: String
}

enum MenuBarText {
    static func status(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed == "Sign-In Required" {
            return "Sign in required"
        }
        return trimmed
    }

    static func statusRowTitle(_ value: String) -> String {
        let status = Self.status(value)
        return SessionPresentation.statusLine(title: status)
    }

}

@MainActor
final class MenuBarController: NSObject {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let menu = NSMenu()
    private let titleItem = NSMenuItem(title: AppIdentity.displayName, action: nil, keyEquivalent: "")
    private let statusSeparatorItem = NSMenuItem.separator()
    private let statusItemRow = NSMenuItem(title: "Connecting", action: nil, keyEquivalent: "")
    private let modeItem = NSMenuItem(title: "Mode: Split Tunnel", action: nil, keyEquivalent: "")
    private let gatewayItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    private let estimatedSessionItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    private let actionSeparatorItem = NSMenuItem.separator()
    private let switchModeItem = NSMenuItem(title: "Switch to Full Tunnel", action: nil, keyEquivalent: "")
    private let retrySignInItem = NSMenuItem(title: "Retry sign-in", action: nil, keyEquivalent: "")
    private let disconnectItem = NSMenuItem(title: "Disconnect", action: nil, keyEquivalent: "")

    var onSwitchMode: (() -> Void)?
    var onRetrySignIn: (() -> Void)?
    var onDisconnect: (() -> Void)?

    override init() {
        super.init()

        if let button = statusItem.button {
            let indicator = SessionPresentation.statusIndicator(for: .connecting, tunnelMode: .split)
            Self.applyStatusIndicator(indicator, to: button)
            button.toolTip = "\(AppIdentity.bundleName): \(indicator) Connecting"
        }

        titleItem.isEnabled = false
        statusItemRow.isEnabled = false
        modeItem.isEnabled = false
        modeItem.isHidden = true
        gatewayItem.isEnabled = false
        gatewayItem.isHidden = true
        estimatedSessionItem.isEnabled = false
        estimatedSessionItem.isHidden = true
        actionSeparatorItem.isHidden = true
        switchModeItem.isHidden = true
        retrySignInItem.isHidden = true
        disconnectItem.isHidden = true

        switchModeItem.target = self
        switchModeItem.action = #selector(handleSwitchMode)

        retrySignInItem.target = self
        retrySignInItem.action = #selector(handleRetrySignIn)

        disconnectItem.target = self
        disconnectItem.action = #selector(handleDisconnect)

        menu.addItem(titleItem)
        menu.addItem(statusSeparatorItem)
        menu.addItem(statusItemRow)
        menu.addItem(modeItem)
        menu.addItem(gatewayItem)
        menu.addItem(estimatedSessionItem)
        menu.addItem(actionSeparatorItem)
        menu.addItem(switchModeItem)
        menu.addItem(retrySignInItem)
        menu.addItem(disconnectItem)

        statusItem.menu = menu
    }

    func update(with snapshot: MenuBarSnapshot) {
        let indicator = SessionPresentation.statusIndicator(
            for: snapshot.transportDegraded ? .connecting : snapshot.phase,
            tunnelMode: snapshot.tunnelMode
        )
        let targetMode = snapshot.tunnelMode == .split ? AppTunnelMode.full : .split
        let connected = snapshot.phase == .connected
        let statusText = MenuBarText.status(snapshot.statusText)
        statusItemRow.title = MenuBarText.statusRowTitle(snapshot.statusText)
        modeItem.title = "Mode: \(snapshot.tunnelMode.displayName)"
        modeItem.isHidden = !connected
        gatewayItem.title = snapshot.gatewayText
        gatewayItem.isHidden = !connected || snapshot.gatewayText.isEmpty
        estimatedSessionItem.title = snapshot.estimatedSessionText
        estimatedSessionItem.isHidden = !connected || snapshot.estimatedSessionText.isEmpty

        if connected {
            switchModeItem.isHidden = false
            if let requestedTunnelMode = snapshot.requestedTunnelMode {
                switchModeItem.title = "Switching to \(requestedTunnelMode.displayName)..."
                switchModeItem.isEnabled = false
            } else {
                switchModeItem.title = "Switch to \(targetMode.displayName)"
                switchModeItem.isEnabled = true
            }
        } else {
            switchModeItem.isHidden = true
            switchModeItem.isEnabled = false
        }

        retrySignInItem.isHidden = !snapshot.canRetrySignIn
        retrySignInItem.isEnabled = snapshot.canRetrySignIn

        let actionable = connected
            || snapshot.phase == .connecting
            || snapshot.phase == .authPending
        disconnectItem.title = connected ? "Disconnect" : "Cancel"
        disconnectItem.isHidden = !actionable
        disconnectItem.isEnabled = actionable
        actionSeparatorItem.isHidden = !actionable

        if let button = statusItem.button {
            Self.applyStatusIndicator(indicator, to: button)
            let tooltipDetails = [
                snapshot.gatewayText,
                snapshot.estimatedSessionText
            ].filter { !$0.isEmpty }
            if tooltipDetails.isEmpty {
                button.toolTip = "\(AppIdentity.bundleName): \(indicator) \(statusText)"
            } else {
                button.toolTip = "\(AppIdentity.bundleName): \(indicator) \(statusText) - \(tooltipDetails.joined(separator: " - "))"
            }
        }
    }

    func close() {
        NSStatusBar.system.removeStatusItem(statusItem)
    }

    private static func applyStatusIndicator(_ indicator: String, to button: NSStatusBarButton) {
        button.title = ""
        button.image = statusImage(for: indicator)
        button.imagePosition = .imageOnly
    }

    private static func statusImage(for indicator: String) -> NSImage {
        let symbolName: String
        switch indicator {
        case "◐":
            symbolName = "circle.lefthalf.filled"
        case "●":
            symbolName = "circle.fill"
        default:
            symbolName = "circle"
        }

        guard let image = NSImage(systemSymbolName: symbolName,
                                  accessibilityDescription: AppIdentity.bundleName) else {
            preconditionFailure("Required status bar symbol \(symbolName) is unavailable.")
        }
        image.isTemplate = true
        return image
    }

    @objc
    private func handleSwitchMode() {
        onSwitchMode?()
    }

    @objc
    private func handleRetrySignIn() {
        onRetrySignIn?()
    }

    @objc
    private func handleDisconnect() {
        onDisconnect?()
    }
}
