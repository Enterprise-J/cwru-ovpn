import Foundation
import Darwin

struct ReachabilityProbeResult {
    let checkedHosts: [String]
    let reachableHost: String?

    var succeeded: Bool {
        reachableHost != nil
    }
}

enum ReachabilityProbe {
    static func run(hosts: [String], timeout: TimeInterval = 2.0) -> ReachabilityProbeResult {
        let normalizedHosts = hosts.compactMap { host -> String? in
            let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }

        guard !normalizedHosts.isEmpty else {
            return ReachabilityProbeResult(checkedHosts: [], reachableHost: nil)
        }

        for host in normalizedHosts {
            if ping(host: host, timeout: timeout) {
                return ReachabilityProbeResult(checkedHosts: normalizedHosts, reachableHost: host)
            }
        }

        return ReachabilityProbeResult(checkedHosts: normalizedHosts, reachableHost: nil)
    }

    private static func ping(host: String, timeout: TimeInterval) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/ping")
        process.arguments = ["-c", "1", host]
        process.standardOutput = Pipe()
        process.standardError = Pipe()

        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in
            finished.signal()
        }

        do {
            try process.run()
        } catch {
            return false
        }

        if finished.wait(timeout: .now() + timeout) == .success {
            return process.terminationStatus == 0
        }

        if process.isRunning {
            process.terminate()
            if finished.wait(timeout: .now() + 1) == .timedOut, process.isRunning {
                kill(process.processIdentifier, SIGKILL)
                _ = finished.wait(timeout: .now() + 1)
            }
        }

        return false
    }
}
