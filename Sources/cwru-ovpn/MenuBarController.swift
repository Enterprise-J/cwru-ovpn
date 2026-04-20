import AppKit
import Foundation

struct MenuBarSnapshot {
    let phase: SessionState.Phase
    let tunnelMode: AppTunnelMode
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
    private let disconnectItem = NSMenuItem(title: "Disconnect", action: nil, keyEquivalent: "")

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

        disconnectItem.target = self
        disconnectItem.action = #selector(handleDisconnect)

        menu.addItem(titleItem)
        menu.addItem(.separator())
        menu.addItem(statusItemRow)
        menu.addItem(modeItem)
        menu.addItem(detailItem)
        menu.addItem(.separator())
        menu.addItem(disconnectItem)

        statusItem.menu = menu
    }

    func update(with snapshot: MenuBarSnapshot) {
        let indicator = VPNController.statusIndicator(for: snapshot.phase, tunnelMode: snapshot.tunnelMode)
        statusItemRow.title = "Status: \(snapshot.statusText)"
        modeItem.title = "Mode: \(snapshot.tunnelMode.displayName)"
        detailItem.title = snapshot.detailText
        detailItem.isHidden = snapshot.detailText.isEmpty

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
    private func handleDisconnect() {
        onDisconnect?()
    }
}
