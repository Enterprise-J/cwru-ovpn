import Foundation
import Network

struct ReachabilityProbeResult {
    let checkedHosts: [String]
    let reachableHost: String?
}

enum ReachabilityProbe {
    private static let maximumConcurrentProbeCount = 8
    static let cwruDNSPort: UInt16 = 53
    private static let queue = DispatchQueue(label: "cwru-ovpn.reachability-probe.connection", qos: .utility)
    private static let workerQueue = DispatchQueue(label: "cwru-ovpn.reachability-probe.worker",
                                                   qos: .utility,
                                                   attributes: .concurrent)

    static func run(hosts: [String]) -> ReachabilityProbeResult {
        run(hosts: hosts, timeout: 2.0, probe: isReachable)
    }

    static func run(hosts: [String],
                    timeout: TimeInterval,
                    probe: @escaping @Sendable (String, TimeInterval) -> Bool) -> ReachabilityProbeResult {
        let normalizedHosts = hosts
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .uniqued()

        guard !normalizedHosts.isEmpty else {
            return ReachabilityProbeResult(checkedHosts: [], reachableHost: nil)
        }

        let race = ReachabilityRace(count: normalizedHosts.count)
        let workerCount = min(normalizedHosts.count, maximumConcurrentProbeCount)
        for _ in 0..<workerCount {
            workerQueue.async {
                while let index = race.claimNextIndex() {
                    let reachable = probe(normalizedHosts[index], timeout)
                    race.complete(index: index, reachable: reachable)
                    if reachable {
                        return
                    }
                }
            }
        }

        let reachableHost = race.wait().map { normalizedHosts[$0] }
        return ReachabilityProbeResult(checkedHosts: normalizedHosts, reachableHost: reachableHost)
    }

    private static func isReachable(host: String, timeout: TimeInterval) -> Bool {
        guard let port = NWEndpoint.Port(rawValue: cwruDNSPort) else {
            return false
        }

        let stateBox = ReachabilityStateBox()
        let semaphore = DispatchSemaphore(value: 0)
        let connection = NWConnection(host: NWEndpoint.Host(host),
                                      port: port,
                                      using: .tcp)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                stateBox.isReachable = true
                semaphore.signal()
            case .failed(_), .cancelled:
                semaphore.signal()
            default:
                break
            }
        }

        connection.start(queue: queue)
        defer {
            connection.cancel()
        }

        guard semaphore.wait(timeout: .now() + timeout) == .success else {
            return false
        }

        return stateBox.isReachable
    }
}

private final class ReachabilityRace: @unchecked Sendable {
    private let condition = NSCondition()
    private let count: Int
    private var nextIndex = 0
    private var remaining: Int
    private var reachableIndex: Int?

    init(count: Int) {
        self.count = count
        remaining = count
    }

    func claimNextIndex() -> Int? {
        condition.lock()
        defer { condition.unlock() }
        guard reachableIndex == nil, nextIndex < count else {
            return nil
        }
        defer { nextIndex += 1 }
        return nextIndex
    }

    func complete(index: Int, reachable: Bool) {
        condition.lock()
        if reachable, reachableIndex == nil {
            reachableIndex = index
        }
        remaining -= 1
        condition.broadcast()
        condition.unlock()
    }

    func wait() -> Int? {
        condition.lock()
        defer { condition.unlock() }
        while reachableIndex == nil, remaining > 0 {
            condition.wait()
        }
        return reachableIndex
    }
}

private final class ReachabilityStateBox: @unchecked Sendable {
    var isReachable = false
}
