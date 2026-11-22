import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite(.serialized)
struct BridgeLifecycleTests {
    @Test(arguments: [false, true])
    func transportWaitsForEndpointProtectionBeforeSending(tcp: Bool) throws {
        let listener = try BridgeTransportListener(tcp: tcp)
        let bridge = try BridgeLifecycleFixture(transportApproval: nil)
        try bridge.start(profile: try BridgeLifecycleFixture.transportProfile(port: listener.port, tcp: tcp))
        defer { cwru_ovpn_client_shutdown(bridge.client) }
        let request = try bridge.nextTransportRequest()
        #expect(cwru_ovpn_client_transport_endpoint_pending(bridge.client, request))
        #expect(!listener.receive(timeout: 100))
        #expect(!cwru_ovpn_client_complete_transport_endpoint(bridge.client, request + 1, true))
        #expect(!listener.receive(timeout: 100))
        #expect(cwru_ovpn_client_complete_transport_endpoint(bridge.client, request, true))
        try #require(listener.receive(timeout: 5_000))
        #expect(listener.clientSocket() != nil)
        #expect(!cwru_ovpn_client_complete_transport_endpoint(bridge.client, request, true))
    }

    @Test(arguments: [false, true])
    func deniedProtectionBlocksTransport(tcp: Bool) throws {
        let listener = try BridgeTransportListener(tcp: tcp)
        let bridge = try BridgeLifecycleFixture(transportApproval: false)
        try bridge.start(profile: try BridgeLifecycleFixture.transportProfile(port: listener.port, tcp: tcp))
        defer { cwru_ovpn_client_shutdown(bridge.client) }
        try #require(bridge.transportProtectionFailed.wait(timeout: .now() + 5) == .success)
        #expect(!listener.receive(timeout: 100))
    }

    @Test
    func expiredEndpointCannotReleaseALaterSocket() throws {
        let listener = try BridgeTransportListener(tcp: false)
        let bridge = try BridgeLifecycleFixture(transportApproval: nil)
        try bridge.start(profile: try BridgeLifecycleFixture.transportProfile(port: listener.port, tcp: false))
        defer { cwru_ovpn_client_shutdown(bridge.client) }
        let expired = try bridge.nextTransportRequest()
        try #require(bridge.transportProtectionFailed.wait(timeout: .now() + 12) == .success)
        #expect(!listener.receive(timeout: 100))
        let next = try bridge.nextTransportRequest()
        #expect(next != expired)
        #expect(!cwru_ovpn_client_complete_transport_endpoint(bridge.client, expired, true))
        #expect(!listener.receive(timeout: 100))
        #expect(cwru_ovpn_client_complete_transport_endpoint(bridge.client, next, true))
        #expect(listener.receive(timeout: 5_000))
    }

    @Test(arguments: [false, true])
    func rotatedTransportRejectsOldPermissionAndCancelsCleanly(tcp: Bool) throws {
        let first = try BridgeTransportListener(tcp: tcp)
        let second = try BridgeTransportListener(tcp: tcp)
        let bridge = try BridgeLifecycleFixture(transportApproval: nil)
        let profile = try BridgeLifecycleFixture.transportProfile(port: first.port, tcp: tcp)
            + "\nremote 127.0.0.1 \(second.port)\n"
        try bridge.start(profile: profile)
        defer { cwru_ovpn_client_shutdown(bridge.client) }
        let initial = try bridge.nextTransportRequest()
        #expect(cwru_ovpn_client_complete_transport_endpoint(bridge.client, initial, true))
        try #require(first.receive(timeout: 5_000))
        cwru_ovpn_client_reconnect(bridge.client, 0)
        let rotated = try bridge.nextTransportRequest()
        #expect(rotated != initial)
        #expect(!cwru_ovpn_client_complete_transport_endpoint(bridge.client, initial, true))
        #expect(!second.receive(timeout: 100))
        #expect(cwru_ovpn_client_complete_transport_endpoint(bridge.client, rotated, true))
        try #require(second.receive(timeout: 5_000))
        cwru_ovpn_client_reconnect(bridge.client, 0)
        let pending = try bridge.nextTransportRequest()
        let stopped = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            cwru_ovpn_client_shutdown(bridge.client)
            stopped.signal()
        }
        #expect(stopped.wait(timeout: .now() + 2) == .success)
        #expect(!cwru_ovpn_client_complete_transport_endpoint(bridge.client, pending, true))
        #expect(first.clientSocket() == nil)
        #expect(second.clientSocket() == nil)
        #expect(!cwru_ovpn_client_is_running(bridge.client))
    }

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
            bridge.client, BridgeLifecycleFixture.profile, "cwru-ovpn", "webauth", "", &error)
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
    func repeatedReconnectRequestsKeepWorkerStoppable() throws {
        let listener = try BridgeTransportListener(tcp: false)
        let bridge = try BridgeLifecycleFixture()
        try bridge.start(profile: try BridgeLifecycleFixture.transportProfile(port: listener.port, tcp: false))
        defer { cwru_ovpn_client_shutdown(bridge.client) }
        let initial = try bridge.nextTransportRequest()
        try #require(listener.receive(timeout: 5_000))
        for _ in 0..<128 {
            cwru_ovpn_client_reconnect(bridge.client, 0)
            Thread.sleep(forTimeInterval: 0.001)
        }
        #expect(try bridge.nextTransportRequest() != initial)
        #expect(cwru_ovpn_client_is_running(bridge.client))
        let stopped = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            cwru_ovpn_client_shutdown(bridge.client)
            stopped.signal()
        }
        #expect(stopped.wait(timeout: .now() + 2) == .success)
        #expect(!cwru_ovpn_client_is_running(bridge.client))
        #expect(listener.clientSocket() == nil)
    }

    @Test
    func endpointCompletionCanRaceWithShutdown() throws {
        let profile = try BridgeLifecycleFixture.transportProfile(port: 9, tcp: false)
        for _ in 0..<5 {
            let bridge = try BridgeLifecycleFixture(transportApproval: nil)
            try bridge.start(profile: profile)
            let request = try bridge.nextTransportRequest()
            let updates = DispatchSemaphore(value: 0)
            Thread.detachNewThread {
                for _ in 0..<100 {
                    _ = cwru_ovpn_client_complete_transport_endpoint(bridge.client, request, true)
                }
                updates.signal()
            }
            cwru_ovpn_client_stop(bridge.client)
            cwru_ovpn_client_shutdown(bridge.client)
            #expect(updates.wait(timeout: .now() + 5) == .success)
            #expect(!cwru_ovpn_client_is_running(bridge.client))
        }
    }

    @Test
    func stopDuringTransportInitializationJoinsWorker() throws {
        let profile = try BridgeLifecycleFixture.transportProfile(port: 9, tcp: false)
        for waitForTransport in [false, true] {
            for _ in 0..<5 {
                let bridge = try BridgeLifecycleFixture()
                try bridge.start(profile: profile)
                if waitForTransport {
                    try #require(bridge.transportReady.wait(timeout: .now() + 5) == .success,
                                 "The loopback transport did not start: \(bridge.events)")
                    #expect(cwru_ovpn_client_is_running(bridge.client))
                }
                cwru_ovpn_client_stop(bridge.client)
                cwru_ovpn_client_shutdown(bridge.client)
                #expect(!cwru_ovpn_client_is_running(bridge.client))
                #expect(!bridge.events.contains("CONNECTED"))
            }
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
    static func transportProfile(port: UInt16, tcp: Bool) throws -> String {
        let directory = temporaryDirectory(named: "cwru-ovpn-bridge-socket")
        defer { try? FileManager.default.removeItem(at: directory) }
        let certificate = directory.appendingPathComponent("ca.pem")
        _ = try CommandRunner().run("/usr/bin/openssl", arguments: [
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-days", "1",
            "-keyout", directory.appendingPathComponent("key.pem").path, "-out", certificate.path,
        ])
        return """
            client
            dev tun
            proto \(tcp ? "tcp-client" : "udp")
            remote 127.0.0.1 \(port)
            setenv CLIENT_CERT 0
            <ca>
            \(try String(contentsOf: certificate, encoding: .utf8))
            </ca>
            """
    }

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
    let transportReady = DispatchSemaphore(value: 0)
    let transportProtectionFailed = DispatchSemaphore(value: 0)
    let transportRequested = DispatchSemaphore(value: 0)
    let releaseEvent = DispatchSemaphore(value: 0)
    private let blockTerminalEvent: Bool
    private let transportApproval: Bool?
    private var transportRequests: [UInt64] = []
    private let lock = NSLock()
    private var recordedEvents: [String] = []

    var events: [String] { lock.withLock { recordedEvents } }

    init(blockTerminalEvent: Bool = false, transportApproval: Bool? = true) throws {
        client = try #require(cwru_ovpn_client_create())
        self.blockTerminalEvent = blockTerminalEvent
        self.transportApproval = transportApproval
    }

    func nextTransportRequest() throws -> UInt64 {
        try #require(transportRequested.wait(timeout: .now() + 5) == .success)
        return lock.withLock { transportRequests.removeFirst() }
    }

    deinit {
        cwru_ovpn_client_destroy(client)
    }

    func start(profile: String = BridgeLifecycleFixture.profile) throws {
        cwru_ovpn_client_set_event_callback(
            client,
            { context, name, info, _, _ in
                guard let context, let name else { return }
                Unmanaged<BridgeLifecycleFixture>.fromOpaque(context)
                    .takeUnretainedValue().record(String(cString: name), info: info.map { String(cString: $0) } ?? "")
            },
            Unmanaged.passUnretained(self).toOpaque())
        var error: UnsafeMutablePointer<CChar>?
        let started = cwru_ovpn_client_start(
            client, profile, "cwru-ovpn", "webauth", "", &error)
        defer { cwru_ovpn_string_free(error) }
        let message = error.map { String(cString: $0) } ?? ""
        try #require(started, "Local setup-failure worker did not start: \(message)")
    }

    private func record(_ event: String, info: String) {
        lock.withLock { recordedEvents.append(event) }
        if event == "WAIT" {
            transportReady.signal()
        }
        if event == "TRANSPORT_ENDPOINT", let field = info.split(separator: " ").first, let request = UInt64(field) {
            lock.withLock { transportRequests.append(request) }
            transportRequested.signal()
            if let transportApproval {
                _ = cwru_ovpn_client_complete_transport_endpoint(client, request, transportApproval)
            }
        }
        if event == "TRANSPORT_PROTECTION_FAILED" {
            transportProtectionFailed.signal()
        }
        if event == "CORE_STATUS" {
            terminalEvent.signal()
            if blockTerminalEvent {
                _ = releaseEvent.wait(timeout: .now() + 5)
            }
        }
    }
}

private final class BridgeTransportListener {
    let descriptor: Int32
    let port: UInt16
    let tcp: Bool
    private var accepted: Int32 = -1

    init(tcp: Bool) throws {
        let descriptor = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0)
        try #require(descriptor >= 0)
        do {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_addr.s_addr = inet_addr("127.0.0.1")
            let result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            try #require(result == 0)
            if tcp { try #require(listen(descriptor, 1) == 0) }
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let named = withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(descriptor, $0, &length)
                }
            }
            try #require(named == 0)
            self.port = UInt16(bigEndian: address.sin_port)
        } catch {
            close(descriptor)
            throw error
        }
        self.descriptor = descriptor
        self.tcp = tcp
    }

    deinit {
        if accepted >= 0 { close(accepted) }
        close(descriptor)
    }

    func receive(timeout: Int32) -> Bool {
        var descriptor = pollfd(fd: self.descriptor, events: Int16(POLLIN), revents: 0)
        guard poll(&descriptor, 1, timeout) == 1, descriptor.revents & Int16(POLLIN) != 0 else {
            return false
        }
        if tcp {
            if accepted >= 0 { close(accepted) }
            accepted = accept(self.descriptor, nil, nil)
            return accepted >= 0
        }
        var bytes = [UInt8](repeating: 0, count: 2_048)
        return recv(self.descriptor, &bytes, bytes.count, 0) > 0
    }

    func clientSocket() -> Int32? {
        let descriptors = (try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd")) ?? []
        return descriptors.compactMap(Int32.init).first { descriptor in
            var address = sockaddr_in()
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let result = withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getpeername(descriptor, $0, &length)
                }
            }
            return result == 0 && address.sin_family == AF_INET
                && address.sin_addr.s_addr == inet_addr("127.0.0.1")
                && UInt16(bigEndian: address.sin_port) == port
        }
    }
}
