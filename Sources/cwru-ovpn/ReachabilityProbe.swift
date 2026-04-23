import Foundation
import Network

struct ReachabilityProbeResult {
    let checkedHosts: [String]
    let reachableHost: String?

    var succeeded: Bool {
        reachableHost != nil
    }
}

enum ReachabilityProbe {
    private static let queue = DispatchQueue(label: "cwru-ovpn.reachability-probe.connection", qos: .utility)

    static func run(hosts: [String], timeout: TimeInterval = 2.0) -> ReachabilityProbeResult {
        var seen = Set<String>()
        let normalizedHosts = hosts.compactMap { host -> String? in
            let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, seen.insert(trimmed).inserted else {
                return nil
            }
            return trimmed
        }

        guard !normalizedHosts.isEmpty else {
            return ReachabilityProbeResult(checkedHosts: [], reachableHost: nil)
        }

        for host in normalizedHosts {
            if isReachable(host: host, timeout: timeout) {
                return ReachabilityProbeResult(checkedHosts: normalizedHosts, reachableHost: host)
            }
        }

        return ReachabilityProbeResult(checkedHosts: normalizedHosts, reachableHost: nil)
    }

    private static func isReachable(host: String, timeout: TimeInterval) -> Bool {
        guard let port = NWEndpoint.Port(rawValue: 443) else {
            return false
        }

        let stateBox = ReachabilityStateBox()
        let semaphore = DispatchSemaphore(value: 0)
        let connection = NWConnection(host: NWEndpoint.Host(host),
                                      port: port,
                                      using: .udp)
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

private final class ReachabilityStateBox: @unchecked Sendable {
    var isReachable = false
}
