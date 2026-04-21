import AppKit
import Foundation

struct MenuBarSnapshot {
    let phase: SessionState.Phase
    let tunnelMode: AppTunnelMode
    let requestedTunnelMode: AppTunnelMode?
    let statusText: String
    let detailText: String
}

@MainActor
final class MenuBarController: NSObject {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let menu = NSMenu()
    private let titleItem = NSMenuItem(title: AppIdentity.bundleName, action: nil, keyEquivalent: "")
    private let statusItemRow = NSMenuItem(title: "Status: Connecting", action: nil, keyEquivalent: "")
    private let modeItem = NSMenuItem(title: "Mode: Split Tunnel", action: nil, keyEquivalent: "")
    private let detailItem = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    private let switchModeItem = NSMenuItem(title: "Switch to Full Tunnel", action: nil, keyEquivalent: "")
    private let disconnectItem = NSMenuItem(title: "Disconnect", action: nil, keyEquivalent: "")

    var onSwitchMode: (() -> Void)?
    var onDisconnect: (() -> Void)?

    override init() {
        super.init()

        if let button = statusItem.button {
            let indicator = VPNController.statusIndicator(for: .connecting, tunnelMode: .split)
            button.title = indicator
            button.toolTip = "\(AppIdentity.bundleName): \(indicator) Connecting"
        }

        titleItem.isEnabled = false
        statusItemRow.isEnabled = false
        modeItem.isEnabled = false
        detailItem.isEnabled = false
        detailItem.isHidden = true
        switchModeItem.isHidden = true

        switchModeItem.target = self
        switchModeItem.action = #selector(handleSwitchMode)

        disconnectItem.target = self
        disconnectItem.action = #selector(handleDisconnect)

        menu.addItem(titleItem)
        menu.addItem(.separator())
        menu.addItem(statusItemRow)
        menu.addItem(modeItem)
        menu.addItem(detailItem)
        menu.addItem(.separator())
        menu.addItem(switchModeItem)
        menu.addItem(disconnectItem)

        statusItem.menu = menu
    }

    func update(with snapshot: MenuBarSnapshot) {
        let indicator = VPNController.statusIndicator(for: snapshot.phase, tunnelMode: snapshot.tunnelMode)
        let targetMode = snapshot.tunnelMode == .split ? AppTunnelMode.full : .split
        statusItemRow.title = "Status: \(snapshot.statusText)"
        modeItem.title = "Mode: \(snapshot.tunnelMode.displayName)"
        detailItem.title = snapshot.detailText
        detailItem.isHidden = snapshot.detailText.isEmpty

        if snapshot.phase == .connected {
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

        disconnectItem.isEnabled = snapshot.phase != .disconnecting && snapshot.phase != .disconnected

        if let button = statusItem.button {
            button.title = indicator
            button.toolTip = "\(AppIdentity.bundleName): \(indicator) \(snapshot.statusText)"
        }
    }

    func close() {
        NSStatusBar.system.removeStatusItem(statusItem)
    }

    @objc
    private func handleSwitchMode() {
        onSwitchMode?()
    }

    @objc
    private func handleDisconnect() {
        onDisconnect?()
    }
}
