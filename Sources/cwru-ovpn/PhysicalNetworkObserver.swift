import Foundation
import SystemConfiguration

@MainActor
final class PhysicalNetworkObserver {
    private var store: SCDynamicStore?
    private var source: CFRunLoopSource?
    private var handler: (@MainActor (Set<String>) -> Void)?

    init?(handler: @escaping @MainActor (Set<String>) -> Void) {
        self.handler = handler
        var context = SCDynamicStoreContext(version: 0,
                                            info: Unmanaged.passUnretained(self).toOpaque(),
                                            retain: nil, release: nil, copyDescription: nil)
        guard let store = SCDynamicStoreCreate(nil, "cwru-ovpn.physical-network" as CFString, { _, keys, context in
            guard let context, let keys = keys as? [String] else { return }
            let observer = Unmanaged<PhysicalNetworkObserver>.fromOpaque(context).takeUnretainedValue()
            Task { @MainActor [weak observer] in
                observer?.handler?(Set(keys))
            }
        }, &context),
              SCDynamicStoreSetNotificationKeys(store, nil,
                                                ["^State:/Network/Interface/[^/]+/IPv4$"] as CFArray),
              let source = SCDynamicStoreCreateRunLoopSource(nil, store, 0) else {
            return nil
        }
        self.store = store
        self.source = source
        CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
    }

    func cancel() {
        handler = nil
        if let source {
            CFRunLoopRemoveSource(CFRunLoopGetMain(), source, .commonModes)
            CFRunLoopSourceInvalidate(source)
        }
        source = nil
        store = nil
    }

    isolated deinit {
        if let source {
            CFRunLoopRemoveSource(CFRunLoopGetMain(), source, .commonModes)
            CFRunLoopSourceInvalidate(source)
        }
    }
}
