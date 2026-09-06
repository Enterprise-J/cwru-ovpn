import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct WebAuthRecoveryTests {
    @Test
    func slowAuthenticationKeepsTheServerDeadline() throws {
        let start = Date(timeIntervalSince1970: 10_000)
        var authentication = WebAuthRecovery()
        let pendingDeadline = authentication.begin(info: "timeout 900", now: start)
        let deadline = try #require(pendingDeadline)

        #expect(deadline == start.addingTimeInterval(900))
        #expect(deadline > start.addingTimeInterval(300))
        #expect(!authentication.retryUsed)
        let repeatedDeadline = authentication.begin(info: "timeout 900", now: start.addingTimeInterval(600))
        #expect(repeatedDeadline == nil)
        #expect(authentication.deadline == deadline)
    }

    @Test(arguments: [
        ("timeout 120", 120.0),
        ("timeout 900", 900.0),
        ("timeout 900,method webauth", 900.0),
        ("method webauth,timeout 900", 900.0),
        ("timeout 900,timeout 120", 300.0),
        ("timeout 3600", 900.0),
        ("timeout 0", 300.0),
        ("timeout -1", 300.0),
        ("timeout invalid", 300.0),
        ("timeout 900 extra", 300.0),
        ("", 300.0),
    ])
    func authenticationTimeoutIsBounded(info: String, timeout: TimeInterval) {
        let start = Date(timeIntervalSince1970: 10_000)
        var authentication = WebAuthRecovery()
        let deadline = authentication.begin(info: info, now: start)
        #expect(deadline == start.addingTimeInterval(timeout))
    }

    @Test
    func explicitRetryReplacesThePendingRequestOnlyOnce() throws {
        let start = Date(timeIntervalSince1970: 10_000)
        var authentication = WebAuthRecovery()
        let idleRetry = authentication.retry()
        #expect(!idleRetry)
        let firstPendingDeadline = authentication.begin(info: "timeout 900", now: start)
        let firstDeadline = try #require(firstPendingDeadline)
        #expect(authentication.canRetry)
        let requestedRetry = authentication.retry()
        #expect(requestedRetry)
        #expect(authentication.deadline == nil)
        #expect(!authentication.canRetry)
        let duplicateRetry = authentication.retry()
        #expect(!duplicateRetry)

        let retryStart = start.addingTimeInterval(20)
        let secondPendingDeadline = authentication.begin(info: "timeout 900", now: retryStart)
        let secondDeadline = try #require(secondPendingDeadline)
        #expect(secondDeadline == retryStart.addingTimeInterval(900))
        #expect(authentication.deadline != firstDeadline)
        #expect(!authentication.canRetry)
        let secondRetry = authentication.retry()
        #expect(!secondRetry)
        #expect(authentication.deadline == secondDeadline)
    }

    @Test
    func completionInvalidatesThePendingDeadline() {
        var authentication = WebAuthRecovery()
        _ = authentication.begin(info: "timeout 900", now: Date(timeIntervalSince1970: 10_000))
        authentication.finish()
        #expect(authentication.deadline == nil)
        #expect(!authentication.canRetry)
        let completedRetry = authentication.retry()
        #expect(!completedRetry)
    }

    @Test
    func launcherAllowsBothRequestsWithoutAnUnboundedWait() {
        let start = Date(timeIntervalSince1970: 10_000)
        let firstDeadline = start.addingTimeInterval(900)
        let retryConnectionDeadline = firstDeadline.addingTimeInterval(60)
        let secondDeadline = retryConnectionDeadline.addingTimeInterval(900)
        let launcherDeadline = DetachedConnectLauncher.authenticationWaitDeadline(from: start)
        #expect(launcherDeadline > secondDeadline)
        #expect(launcherDeadline.timeIntervalSince(start) == 1_980)
    }
}
