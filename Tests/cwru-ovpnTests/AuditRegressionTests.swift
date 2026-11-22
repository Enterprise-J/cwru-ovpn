import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct AuditRegressionTests {
    private func session() -> SessionState {
        makeSessionState(pid: Int32.max - 1, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
                         physicalGateway: "192.0.2.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
                         originalDNSServers: ["fe80::1%en0"], originalSearchDomains: ["test_.example."],
                         originalIPv6Mode: "Automatic", tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: false)
    }

    @Test
    func systemResolverAnchorOpensThePhysicalEtcDirectory() throws {
        let manager = RouteManager()
        #expect(manager.resolverDirectory.deletingLastPathComponent().path == "/private/etc")
        #expect(ResolverPaths.fileURL(for: "case.edu", in: manager.resolverDirectory).deletingLastPathComponent().deletingLastPathComponent().path == "/private/etc")
        do {
            try manager.withResolverDirectory { directory in
                var info = stat()
                #expect(fstat(directory.fd, &info) == 0)
                #expect(info.st_uid == 0)
            }
        } catch let error as NSError where error.domain == NSPOSIXErrorDomain && error.code == Int(ENOENT) {}
    }

    @Test
    func nativeProtocolEnableFlagIsIndependentOfTheConfigurationDictionary() throws {
        let baseline = ["ConfigMethod": "Automatic", "UserOption": "unchanged"]
        var disabled = baseline as [String: Any]
        disabled["__INACTIVE__"] = 1
        let off = try ProtocolConfiguration(enabled: false, fields: disabled)
        let on = try ProtocolConfiguration(enabled: true, fields: baseline)
        #expect(try off.fields() as NSDictionary? == baseline as NSDictionary)
        #expect(try off.merging(on, from: off, for: .ipv6).matches(on, for: .ipv6))
    }

    @Test
    func mostSpecificPublishedDomainControlsOrdinaryQueries() {
        let manager = RouteManager()
        let fixture = """
            DNS configuration
            resolver #1
              domain :
              nameserver[0] : 192.0.2.53
            resolver #2
              domain : CASE.EDU.
              nameserver[0] : 129.22.4.32
            resolver #3
              domain : dept.case.edu
              nameserver[0] : 192.0.2.53
            DNS configuration (for scoped queries)
            resolver #1
              domain : case.edu
              nameserver[0] : 192.0.2.53
            """
        let list = manager.parseActiveDNSResolvers(fixture)
        #expect(list.first?.domain == nil)
        #expect(!RouteManager.scopedPublicationMatches(list, domains: ["case.edu"], servers: ["129.22.4.32"]))
        let sibling = manager.parseActiveDNSResolvers(fixture.replacingOccurrences(of: "dept.case.edu", with: "notcase.edu"))
        #expect(RouteManager.scopedPublicationMatches(sibling, domains: ["case.edu"], servers: ["129.22.4.32"]))
    }

    @Test
    func scopedDefaultAndOnlyTheTunnelsOwnLoopbackHostArePermitted() throws {
        var state = session()
        state.appliedSplitIPv6Routes = ["2606:ea00::/32"]
        let entries = ["default fe80::%utun7 UGcIg utun7", "2606:ea00::/32 link#12 Uc utun7",
                       "2606:ea00::100 lo0 UHL lo0"].compactMap(parseRouteTableLine)
        let manager = RouteManager()
        #expect(manager.splitTunnelRoutingIsSafe(tunnelName: "utun7", using: state, ipv4Entries: [], ipv6Entries: entries))
        let other = try #require(parseRouteTableLine("2606:ea00::101 lo0 UHL lo0"))
        #expect(!manager.protectedSplitIPv6RouteOverrides(on: "utun7", using: state, in: entries + [other]).isEmpty)
    }

    @Test(arguments: ["UGHSR", "UGHSB"])
    func blockedHostRouteRetainsItsForwardingSemantics(flags: String) throws {
        let entry = try #require(parseRouteTableLine("192.0.2.9 192.0.2.1 \(flags) en0"))
        let manager = RouteManager()
        #expect(!manager.ipv4RouteEntryIsRestorable(entry))
        #expect(manager.managedIPv4Route(from: entry) == nil)
    }

    @Test
    func phaseChangesPreserveAClaimedRequestAndANewerRequest() throws {
        var state = session().requestingModeSwitch(to: .full)
        let first = try #require(state.modeRequest)
        let claimed = state.claim(first)
        #expect(claimed)
        state = state.requestingModeSwitch(to: .split)
        let second = try #require(state.modeRequest)
        state.finish(first, outcome: .rolledBack, detail: "Failed before publication")
        #expect(state.modeRequest == second)
        #expect(state.modeReceipts.first?.id == first.id)
        var stop = state
        stop.stopRequestedByUser = true
        let claimedAfterStop = stop.claim(second)
        #expect(!claimedAfterStop)
    }

    @Test
    func eventOverflowPreservesOneDisconnectFromItsOwnGeneration() {
        var buffer = VPNEventBuffer()
        let overflow = buffer.append(name: nil, info: nil, isError: false, isFatal: false, generation: 7)
        #expect(overflow)
        #expect(buffer.drain().map(\.name) == ["EVENT_OVERFLOW"])
        let stale = buffer.append(name: "DISCONNECTED", info: "", isError: false, isFatal: false, generation: 6)
        #expect(!stale)
        let terminal = buffer.append(name: "DISCONNECTED", info: "", isError: false, isFatal: false, generation: 7)
        #expect(terminal)
        let duplicate = buffer.append(name: "DISCONNECTED", info: "", isError: false, isFatal: false, generation: 7)
        #expect(!duplicate)
        #expect(buffer.drain().map(\.name) == ["DISCONNECTED"])
    }

    @Test
    func rawCredentialsAreRemovedAtStateAndStartupBoundaries() throws {
        let token = "test-credential-value"
        let text = "session_token='\(token) with spaces' cwru-ovpn://name:\(token)@callback?code=\(token)#\(token)"
        let pem = "-----BEGIN PRIVATE KEY-----\n\(token)\n-----END PRIVATE KEY-----"
        var state = session()
        state.markRecoveryRequired(message: text + "\n" + pem)
        let journal = try JSONEncoder().encode(state)
        #expect(!String(decoding: journal, as: UTF8.self).contains(token))
        #expect(!DetachedStartupStatus(message: text).message.contains(token))
        #expect(!redactSensitiveText(text).contains("with spaces"))
    }

    @Test
    func leaseDomainSearchSupportsCompressionAndRejectsCycles() throws {
        var data = Data([4])
        data.append(contentsOf: "case".utf8)
        data.append(3)
        data.append(contentsOf: "edu".utf8)
        data.append(contentsOf: [0, 4])
        data.append(contentsOf: "dept".utf8)
        data.append(contentsOf: [0xc0, 0])
        #expect(try SystemNetworkServiceStore.searchList(in: data) == ["case.edu", "dept.case.edu"])
        #expect(throws: POSIXError.self) { try SystemNetworkServiceStore.searchList(in: Data([0xc0, 0])) }
    }

    @Test
    func setupPreservesUnrecognizedRecoveryData() throws {
        let directory = temporaryDirectory(named: "unrecognized-recovery")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory.appendingPathComponent("state"))
        let original = Data(#"{"unrecognized":true}"#.utf8)
        try store.withAnchor { fd, uid, gid in
            try AnchoredFileIO.writeOwnedRegularFileAtomically(original, in: fd, name: SessionState.fileName, userID: uid, groupID: gid)
        }
        #expect(throws: SetupError.self) { _ = try Setup.acquireInstallationGuard(operation: "setup", sessionStore: store) }
        #expect(try Data(contentsOf: store.url.appendingPathComponent(SessionState.fileName)) == original)
    }

    @Test @MainActor
    func interfaceChannelDeliversQueuedMessagesAfterTheReaderBecomesReady() async throws {
        var pair = [Int32](repeating: -1, count: 2)
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        var size: Int32 = 2048
        try #require(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout.size(ofValue: size))) == 0)
        var disconnected = false
        let sender = try InterfaceChannel<String, String>(owning: pair[0], onMessage: { _ in }, onClose: { disconnected = true })
        let messages = (0..<8).map { "\($0) " + String(repeating: "x", count: 1500) }
        for message in messages { sender.send(message) }
        var received: [String] = []
        let reader = try InterfaceChannel<String, String>(owning: pair[1], onMessage: { received.append($0) }, onClose: {})
        defer { sender.close(); reader.close() }
        let deadline = ContinuousClock.now + .seconds(2)
        while !disconnected, received.count != messages.count, ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(10)) }
        #expect(!disconnected)
        #expect(received == messages)
    }

    @Test(arguments: [true, false]) @MainActor
    func interfaceChannelClosesTheSocketWithQueuedWrites(explicitClose: Bool) async throws {
        var pair = [Int32](repeating: -1, count: 2)
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0)
        var peerClosed = false
        let peer = try InterfaceChannel<String, String>(owning: pair[1], onMessage: { _ in }, onClose: { peerClosed = true })
        defer { peer.close() }
        var localDisconnect = false
        var channel: InterfaceChannel<String, String>? = try InterfaceChannel(
            owning: pair[0], onMessage: { _ in }, onClose: { localDisconnect = true }
        )
        var size: Int32 = 2048
        try #require(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout.size(ofValue: size))) == 0)
        let message = String(repeating: "x", count: 4096)
        for _ in 0..<8 { channel?.send(message) }
        var readiness = pollfd(fd: pair[0], events: Int16(POLLOUT), revents: 0)
        try #require(poll(&readiness, 1, 0) == 0)

        if explicitClose {
            channel?.close()
        } else {
            channel = nil
        }

        let deadline = ContinuousClock.now + .seconds(2)
        while !peerClosed, ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(10)) }
        withExtendedLifetime(channel) {
            #expect(peerClosed)
            #expect(!localDisconnect)
        }
    }

    @Test
    func optionalFFIErrorOutputAndRequiredCallbackAreIndependent() {
        #expect(!cwru_ovpn_profile_enumerate_options(nil, nil, nil, nil))
        #expect(!cwru_ovpn_profile_enumerate_connection_block_options("remote example.edu", nil, nil, nil))
        let parsed = cwru_ovpn_profile_enumerate_options("client", { _, _, _, _ in }, nil, nil)
        #expect(parsed)
    }
}
