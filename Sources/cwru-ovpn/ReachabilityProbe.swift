import Foundation
import Darwin

struct ReachabilityProbeResult {
    let checkedHosts: [String]
    let reachableHost: String?
}

enum ReachabilityProbe {
    static let cwruDNSPort: UInt16 = 53
    private static let workerQueue = DispatchQueue(label: "cwru-ovpn.reachability-probe.worker",
                                                   qos: .utility,
                                                   attributes: .concurrent)

    static func run(hosts: [String], interface: String) -> ReachabilityProbeResult {
        let index = if_nametoindex(interface)
        return run(hosts: hosts, timeout: 2) { host, timeout in
            index != 0 && isReachable(host: host, interface: index, timeout: timeout)
        }
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

    private static func isReachable(host: String, interface: UInt32, timeout: TimeInterval) -> Bool {
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_port = cwruDNSPort.bigEndian
        guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else { return false }
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var index = interface
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
              setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, socklen_t(MemoryLayout.size(ofValue: index))) == 0 else { return false }
        let status = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        if status == 0 { return true }
        guard errno == EINPROGRESS else { return false }
        let deadline = DispatchTime.now() + timeout
        var ready = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        while true {
            let now = DispatchTime.now()
            guard now < deadline else { return false }
            let ms = Int32(clamping: (deadline.uptimeNanoseconds - now.uptimeNanoseconds + 999_999) / 1_000_000)
            let result = poll(&ready, 1, ms)
            if result < 0 && errno == EINTR { continue }
            var error: Int32 = 0
            var length = socklen_t(MemoryLayout<Int32>.size)
            return result == 1 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0
        }
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
