import AppKit
import Foundation

enum AppMenu {
    @MainActor
    static func installIfNeeded() {
        guard NSApplication.shared.mainMenu == nil else {
            return
        }

        let mainMenu = NSMenu()

        let appMenuItem = NSMenuItem()
        let appMenu = NSMenu()
        let appName = ProcessInfo.processInfo.processName
        appMenu.addItem(withTitle: "Quit \(appName)",
                        action: #selector(NSApplication.terminate(_:)),
                        keyEquivalent: "q")
        appMenuItem.submenu = appMenu
        mainMenu.addItem(appMenuItem)

        let editMenuItem = NSMenuItem()
        let editMenu = NSMenu(title: "Edit")
        addItem(title: "Undo", action: Selector(("undo:")), key: "z", to: editMenu)
        addItem(title: "Redo", action: Selector(("redo:")), key: "z", modifiers: [.command, .shift], to: editMenu)
        editMenu.addItem(.separator())
        addItem(title: "Cut", action: #selector(NSText.cut(_:)), key: "x", to: editMenu)
        addItem(title: "Copy", action: #selector(NSText.copy(_:)), key: "c", to: editMenu)
        addItem(title: "Paste", action: #selector(NSText.paste(_:)), key: "v", to: editMenu)
        addItem(title: "Select All", action: #selector(NSText.selectAll(_:)), key: "a", to: editMenu)
        editMenuItem.submenu = editMenu
        mainMenu.addItem(editMenuItem)

        NSApplication.shared.mainMenu = mainMenu
    }

    @MainActor
    private static func addItem(title: String,
                                action: Selector,
                                key: String,
                                modifiers: NSEvent.ModifierFlags = [.command],
                                to menu: NSMenu) {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
        item.keyEquivalentModifierMask = modifiers
        menu.addItem(item)
    }
}
