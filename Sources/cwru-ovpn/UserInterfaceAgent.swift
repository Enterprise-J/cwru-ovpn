import AppKit
import Darwin
import Foundation

enum InterfaceUpdate: Codable {
    case status(MenuBarSnapshot)
    case authenticate(URL, ephemeral: Bool, generation: Int)
    case closeAuthentication
}

enum InterfaceAction: Codable {
    case disconnect
    case switchMode
    case retry
    case cancelled(generation: Int)
    case authenticationFailed(generation: Int)
}

private final class InterfaceSocketSource {
    private let source: any DispatchSourceProtocol

    init(_ source: any DispatchSourceProtocol, activeSources: DispatchGroup) {
        self.source = source
        activeSources.enter()
        source.setCancelHandler { activeSources.leave() }
        source.activate()
    }

    deinit { source.cancel() }
}

@MainActor
final class InterfaceChannel<Incoming: Codable, Outgoing: Codable> {
    private struct Frame {
        let data: Data
        let replaceable: Bool
    }
    private let descriptor: Int32
    private let activeSources = DispatchGroup()
    private var reader: InterfaceSocketSource?
    private var writer: InterfaceSocketSource?
    private var outgoing: [Frame] = []
    private var writeOffset = 0
    private var buffer = Data()
    private let onMessage: (Incoming) -> Void
    private let onClose: () -> Void
    private static var maximumBytes: Int { 16 * 1024 }

    init(owning descriptor: Int32, onMessage: @escaping (Incoming) -> Void,
         onClose: @escaping () -> Void) throws {
        var enabled: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout.size(ofValue: enabled))) == 0,
              fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else {
            let reason = errno
            Darwin.close(descriptor)
            throw FileIO.failure("Failed to configure the user interface channel", reason)
        }
        self.descriptor = descriptor
        self.onMessage = onMessage
        self.onClose = onClose
        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: .main)
        source.setEventHandler { [weak self] in self?.receive() }
        reader = InterfaceSocketSource(source, activeSources: activeSources)
        activeSources.notify(queue: .main) { Darwin.close(descriptor) }
    }

    func send(_ message: Outgoing, replacingQueuedStatus: Bool = false) {
        guard reader != nil else { return }
        do {
            var data = try JSONEncoder().encode(message)
            guard data.count <= Self.maximumBytes else { throw POSIXError(.EMSGSIZE) }
            data.append(10)
            if replacingQueuedStatus, outgoing.last?.replaceable == true, outgoing.count > 1 || writeOffset == 0 {
                outgoing.removeLast()
            }
            guard outgoing.count < 64, outgoing.reduce(data.count, { $0 + $1.data.count }) <= 4 * Self.maximumBytes else {
                throw POSIXError(.ENOBUFS)
            }
            outgoing.append(Frame(data: data, replaceable: replacingQueuedStatus))
            if writer == nil { flush() }
        } catch { disconnected() }
    }

    private func flush() {
        guard reader != nil else { return }
        while let frame = outgoing.first {
            let count = frame.data.withUnsafeBytes { bytes in
                Darwin.write(descriptor, bytes.baseAddress!.advanced(by: writeOffset), bytes.count - writeOffset)
            }
            if count < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK {
                    if writer == nil {
                        let source = DispatchSource.makeWriteSource(fileDescriptor: descriptor, queue: .main)
                        source.setEventHandler { [weak self] in self?.flush() }
                        writer = InterfaceSocketSource(source, activeSources: activeSources)
                    }
                    return
                }
            }
            guard count > 0 else { disconnected(); return }
            writeOffset += count
            if writeOffset == frame.data.count {
                outgoing.removeFirst()
                writeOffset = 0
            }
        }
        writer = nil
    }

    private func receive() {
        guard reader != nil else { return }
        var chunk = [UInt8](repeating: 0, count: 4096)
        let count = Darwin.read(descriptor, &chunk, chunk.count)
        if count < 0 && (errno == EAGAIN || errno == EINTR) { return }
        guard count > 0 else { disconnected(); return }
        buffer.append(contentsOf: chunk.prefix(count))
        do {
            while let end = buffer.firstIndex(of: 10) {
                guard buffer.distance(from: buffer.startIndex, to: end) <= Self.maximumBytes else { throw POSIXError(.EMSGSIZE) }
                let message = try JSONDecoder().decode(Incoming.self, from: buffer[..<end])
                buffer.removeSubrange(...end)
                onMessage(message)
                if reader == nil { return }
            }
            if buffer.count > Self.maximumBytes { throw POSIXError(.EMSGSIZE) }
        } catch { disconnected() }
    }

    private func disconnected() {
        guard reader != nil else { return }
        close()
        onClose()
    }

    func close() {
        writer = nil
        reader = nil
        outgoing.removeAll()
    }
}

@MainActor
final class UserInterfaceAgent {
    private let menu = MenuBarController()
    private var auth: SystemWebAuthSession?
    private var channel: InterfaceChannel<InterfaceUpdate, InterfaceAction>?

    static func run() throws {
        guard getuid() != 0, geteuid() == getuid(), getegid() == getgid() else { throw POSIXError(.EPERM) }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let agent = UserInterfaceAgent()
        try agent.start()
        withExtendedLifetime(agent) { app.run() }
        agent.menu.close()
    }

    private func start() throws {
        channel = try InterfaceChannel(owning: STDIN_FILENO, onMessage: { [weak self] in self?.update($0) },
                                       onClose: { NSApplication.shared.terminate(nil) })
        menu.onDisconnect = { [weak self] in self?.channel?.send(.disconnect) }
        menu.onSwitchMode = { [weak self] in self?.channel?.send(.switchMode) }
        menu.onRetrySignIn = { [weak self] in self?.channel?.send(.retry) }
    }

    private func update(_ update: InterfaceUpdate) {
        switch update {
        case .status(let snapshot):
            menu.update(with: snapshot)
        case .closeAuthentication:
            auth?.close()
            auth = nil
        case .authenticate(let url, let ephemeral, let generation):
            auth?.close()
            guard WebAuthRequest.validatedWebAuthURL(url) != nil else {
                channel?.send(.authenticationFailed(generation: generation))
                return
            }
            let session = SystemWebAuthSession(url: url, prefersEphemeralSession: ephemeral)
            session.onUserCancelled = { [weak self] in self?.channel?.send(.cancelled(generation: generation)) }
            session.onFailure = { [weak self] _ in self?.channel?.send(.authenticationFailed(generation: generation)) }
            auth = session
            if !session.start() { channel?.send(.authenticationFailed(generation: generation)) }
        }
    }
}
