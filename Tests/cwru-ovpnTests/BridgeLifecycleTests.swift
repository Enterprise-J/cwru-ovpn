import COpenVPN3Wrapper
import Foundation
import Testing

@Suite(.serialized)
struct BridgeLifecycleTests {
    @Test
    func setupFailureRunsWorkerAndShutdownClearsCallbacks() throws {
        let bridge = try BridgeLifecycleFixture()
        try bridge.start()
        #expect(bridge.terminalEvent.wait(timeout: .now() + 5) == .success)
        cwru_ovpn_client_shutdown(bridge.client)
        let events = bridge.events
        #expect(events.contains("CORE_STATUS"))
        #expect(!events.contains("CONNECTED"))
        #expect(!cwru_ovpn_client_is_running(bridge.client))
        cwru_ovpn_client_shutdown(bridge.client)
        cwru_ovpn_client_stop(bridge.client)
        #expect(bridge.events == events)

        var error: UnsafeMutablePointer<CChar>?
        let restarted = cwru_ovpn_client_start(
            bridge.client, BridgeLifecycleFixture.profile, nil, nil, nil, nil, &error)
        defer { cwru_ovpn_string_free(error) }
        #expect(!restarted)
        #expect(error.map { String(cString: $0).contains("single-use") } == true)
    }

    @Test
    func immediateStopAndRepeatedShutdownJoinWorker() throws {
        for _ in 0..<5 {
            let bridge = try BridgeLifecycleFixture()
            try bridge.start()
            cwru_ovpn_client_stop(bridge.client)
            cwru_ovpn_client_shutdown(bridge.client)
            cwru_ovpn_client_shutdown(bridge.client)
            #expect(!cwru_ovpn_client_is_running(bridge.client))
            #expect(!bridge.events.contains("CONNECTED"))
        }
    }

    @Test
    func clearingCallbackWaitsForActiveDelivery() throws {
        let bridge = try BridgeLifecycleFixture(blockTerminalEvent: true)
        defer { bridge.releaseEvent.signal() }
        try bridge.start()
        try #require(bridge.terminalEvent.wait(timeout: .now() + 5) == .success)
        let clearStarted = DispatchSemaphore(value: 0)
        let clearFinished = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            clearStarted.signal()
            cwru_ovpn_client_set_event_callback(bridge.client, nil, nil)
            clearFinished.signal()
        }
        try #require(clearStarted.wait(timeout: .now() + 5) == .success)
        #expect(clearFinished.wait(timeout: .now() + 0.05) == .timedOut)
        bridge.releaseEvent.signal()
        try #require(clearFinished.wait(timeout: .now() + 5) == .success)
        let events = bridge.events
        cwru_ovpn_client_shutdown(bridge.client)
        #expect(bridge.events == events)
        #expect(!cwru_ovpn_client_is_running(bridge.client))
    }
}

private final class BridgeLifecycleFixture: @unchecked Sendable {
    static let profile = """
        client
        dev tun
        proto udp
        remote 127.0.0.1 9
        <ca>
        fixture
        </ca>
        """

    let client: OpaquePointer
    let terminalEvent = DispatchSemaphore(value: 0)
    let releaseEvent = DispatchSemaphore(value: 0)
    private let blockTerminalEvent: Bool
    private let lock = NSLock()
    private var recordedEvents: [String] = []

    var events: [String] { lock.withLock { recordedEvents } }

    init(blockTerminalEvent: Bool = false) throws {
        client = try #require(cwru_ovpn_client_create())
        self.blockTerminalEvent = blockTerminalEvent
    }

    deinit {
        cwru_ovpn_client_destroy(client)
    }

    func start() throws {
        cwru_ovpn_client_set_event_callback(
            client,
            { context, name, _, _, _ in
                guard let context, let name else { return }
                Unmanaged<BridgeLifecycleFixture>.fromOpaque(context)
                    .takeUnretainedValue().record(String(cString: name))
            },
            Unmanaged.passUnretained(self).toOpaque())
        var error: UnsafeMutablePointer<CChar>?
        let started = cwru_ovpn_client_start(
            client, Self.profile, nil, nil, nil, nil, &error)
        defer { cwru_ovpn_string_free(error) }
        let message = error.map { String(cString: $0) } ?? ""
        try #require(started, "Local setup-failure worker did not start: \(message)")
    }

    private func record(_ event: String) {
        lock.withLock { recordedEvents.append(event) }
        if event == "CORE_STATUS" {
            terminalEvent.signal()
            if blockTerminalEvent {
                _ = releaseEvent.wait(timeout: .now() + 5)
            }
        }
    }
}
