import Foundation
import Network

struct ReachabilityProbeResult {
    let checkedHosts: [String]
    let reachableHost: String?
}

enum ReachabilityProbe {
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
        for host in normalizedHosts {
            workerQueue.async {
                race.complete(host: host, reachable: probe(host, timeout))
            }
        }

        return ReachabilityProbeResult(checkedHosts: normalizedHosts, reachableHost: race.wait())
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
    private var remaining: Int
    private var reachableHost: String?

    init(count: Int) {
        remaining = count
    }

    func complete(host: String, reachable: Bool) {
        condition.lock()
        if reachable, reachableHost == nil {
            reachableHost = host
        }
        remaining -= 1
        condition.broadcast()
        condition.unlock()
    }

    func wait() -> String? {
        condition.lock()
        defer { condition.unlock() }
        while reachableHost == nil, remaining > 0 {
            condition.wait()
        }
        return reachableHost
    }
}

private final class ReachabilityStateBox: @unchecked Sendable {
    var isReachable = false
}
