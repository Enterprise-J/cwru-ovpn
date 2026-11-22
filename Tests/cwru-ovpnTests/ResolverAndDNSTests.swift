import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct ResolverAndDNSTests {
    @Test(arguments: [true, false])
    func cleanupRequiresReadableResolverState(recordedDomain: Bool) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-cleanup-resolver-inspection")
        defer { try? FileManager.default.removeItem(at: directory) }
        let resolverDirectory = directory.appendingPathComponent("resolver")
        let state = SessionState(pid: getpid(), executablePath: "/tmp/cwru-ovpn",
                                 processStartTime: ProcessStartTime(seconds: 1, microseconds: 0),
                                 phase: .disconnected, profilePath: "/tmp/profile.ovpn", startedAt: Date(),
                                 physicalGateway: "192.0.2.1", physicalInterface: "en0", physicalServiceID: "service-en0", tunnelMode: .split,
                                 appliedScopedDNSDomains: recordedDomain ? ["case.edu"] : nil, cleanupNeeded: true)
        let manager = RouteManager(resolverDirectory: resolverDirectory, resolverFileOwnership: (getuid(), getgid()))
        #expect(try manager.cleanupResolversRemoved(using: state))
        try Data().write(to: resolverDirectory)
        #expect(throws: (any Error).self) {
            try manager.cleanupResolversRemoved(using: state)
        }
        try FileManager.default.removeItem(at: resolverDirectory)
        try FileManager.default.createDirectory(at: resolverDirectory, withIntermediateDirectories: false)
        try Data(repeating: 0x61, count: 4097).write(to: resolverDirectory.appendingPathComponent("case.edu"))
        #expect(throws: (any Error).self) {
            try manager.cleanupResolversRemoved(using: state)
        }
    }

    @Test(arguments: ["missing", "nameserver", "domain"])
    func resolverHealthAndRepairUseTheSameContentPolicy(scenario: String) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-resolver-policy-health")
        defer { try? FileManager.default.removeItem(at: directory) }
        let policy = CampusNetworkPolicy(ipv4Routes: [], dnsDomains: ["case.edu"], dnsServers: ["129.22.4.32"])
        var state = makeSessionState(
            pid: 1120, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.appliedScopedDNSDomains = ["case.edu"]
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: ["utun7"])
        let manager = makeRouteManager(campusPolicy: policy, serviceStore: system, commandRunner: CommandRunner(handler: { try system.handle($0) }),
                                       resolverDirectory: directory)
        let file = ResolverPaths.fileURL(for: "case.edu", in: manager.resolverDirectory)
        if scenario != "missing" {
            try scopedResolverContents(domain: scenario == "domain" ? "cwru.edu" : "case.edu",
                                       nameServer: scenario == "nameserver" ? "1.1.1.1" : "129.22.4.32")
                .write(to: file, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        }
        let beforeInspection = try? Data(contentsOf: file)
        let check = try #require(manager.splitTunnelHealthChecks(using: state).first { $0.name == "resolvers" })
        #expect(check.status == .fail)
        #expect(check.detail.contains(scenario == "missing" ? "missing: case.edu" : "different content: case.edu"))
        #expect((try? Data(contentsOf: file)) == beforeInspection)

        #expect(try manager.repairResolverFiles(using: state))
        #expect(try manager.resolverFileStatus(for: "case.edu", nameServers: policy.dnsServers) == .matching)
        system.recordedCommands.removeAll()
        #expect(manager.resolverFilesHealthCheck(using: state).status == .pass)
        #expect(try !manager.repairResolverFiles(using: state))
        #expect(try !manager.installResolverFiles(forDomains: ["case.edu"], nameServers: policy.dnsServers))
        #expect(system.recordedCommands.isEmpty)
    }

    @Test(arguments: ["mode", "owner", "group"])
    func matchingResolverContentCannotBypassFileValidation(scenario: String) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-resolver-metadata-health")
        defer { try? FileManager.default.removeItem(at: directory) }
        let policy = CampusNetworkPolicy(ipv4Routes: [], dnsDomains: ["case.edu"], dnsServers: ["129.22.4.32"])
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: [])
        let manager = RouteManager(
            campusPolicy: policy, serviceStore: TestDependencies.networkServices,
            commandRunner: CommandRunner(handler: { try system.handle($0) }), resolverDirectory: directory,
            resolverFileOwnership: (scenario == "owner" ? getuid() ^ 1 : getuid(), scenario == "group" ? getgid() ^ 1 : getgid()),
            remoteHostRouteLedger: RemoteHostRouteLedger(store: StateDirectory(directory: directory)))
        var state = makeSessionState(
            pid: 1121, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.appliedScopedDNSDomains = ["case.edu"]
        let file = ResolverPaths.fileURL(for: "case.edu", in: manager.resolverDirectory)
        let data = Data(manager.resolverContents(for: "case.edu", nameServers: policy.dnsServers).utf8)
        try data.write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: scenario == "mode" ? 0o666 : 0o644], ofItemAtPath: file.path)

        let check = manager.resolverFilesHealthCheck(using: state)
        #expect(check.status == .fail && check.detail.contains("invalid: case.edu"))
        #expect(throws: (any Error).self) {
            _ = try manager.installResolverFiles(forDomains: ["case.edu"], nameServers: policy.dnsServers)
        }
        #expect(throws: (any Error).self) {
            _ = try manager.repairResolverFiles(using: state)
        }
        #expect(system.recordedCommands.isEmpty)
        #expect(try Data(contentsOf: file) == data)
    }

    @Test
    func resolverHealthPreservesInspectionFailure() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-resolver-unavailable")
        defer { try? FileManager.default.removeItem(at: directory) }
        let blockedDirectory = directory.appendingPathComponent("not-a-directory")
        try Data("occupied".utf8).write(to: blockedDirectory)
        let policy = CampusNetworkPolicy(ipv4Routes: [], dnsDomains: ["case.edu"], dnsServers: ["129.22.4.32"])
        let manager = makeRouteManager(campusPolicy: policy, commandRunner: CommandRunner(handler: { invocation in
            throw MockSystemError.unexpectedCommand(invocation.launchPath)
        }), resolverDirectory: blockedDirectory)
        var state = makeSessionState(
            pid: 1122, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.appliedScopedDNSDomains = ["case.edu"]
        let check = manager.resolverFilesHealthCheck(using: state)
        #expect(check.status == .warn)
        #expect(check.detail.contains("unavailable: case.edu"))
        #expect(!check.detail.contains("missing:"))
        #expect(throws: (any Error).self) {
            _ = try manager.installResolverFiles(forDomains: ["case.edu"], nameServers: policy.dnsServers)
        }
        #expect(try Data(contentsOf: blockedDirectory) == Data("occupied".utf8))
    }

    @Test
    func resolverHealthReportsDirectoryInspectionFailureWithoutExpectedFiles() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-resolver-enumeration-unavailable")
        defer { try? FileManager.default.removeItem(at: directory) }
        let blockedDirectory = directory.appendingPathComponent("not-a-directory")
        let original = Data("occupied".utf8)
        try original.write(to: blockedDirectory)
        let manager = makeRouteManager(
            campusPolicy: CampusNetworkPolicy(ipv4Routes: [], dnsDomains: [], dnsServers: []),
            commandRunner: CommandRunner(handler: { invocation in
                Issue.record("Resolver inspection invoked a command: \(invocation.launchPath)")
                throw MockSystemError.unexpectedCommand(invocation.launchPath)
            }), resolverDirectory: blockedDirectory)
        var state = makeSessionState(
            pid: 1123, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.appliedScopedDNSDomains = []
        let check = manager.resolverFilesHealthCheck(using: state)
        #expect(check.status == .warn)
        #expect(check.detail.contains("unavailable: directory"))
        #expect(try Data(contentsOf: blockedDirectory) == original)
    }

    @Test
    func resolverHealthReportsUnreadableExtraFile() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-extra-resolver-unavailable")
        defer { try? FileManager.default.removeItem(at: directory) }
        let policy = CampusNetworkPolicy(ipv4Routes: [], dnsDomains: ["case.edu"], dnsServers: ["129.22.4.32"])
        let manager = makeRouteManager(campusPolicy: policy, commandRunner: CommandRunner(handler: { invocation in
            Issue.record("Resolver inspection invoked a command: \(invocation.launchPath)")
            throw MockSystemError.unexpectedCommand(invocation.launchPath)
        }), resolverDirectory: directory)
        var state = makeSessionState(
            pid: 1124, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.appliedScopedDNSDomains = ["case.edu"]
        let expectedFile = ResolverPaths.fileURL(for: "case.edu", in: manager.resolverDirectory)
        let expectedData = Data(manager.resolverContents(for: "case.edu", nameServers: policy.dnsServers).utf8)
        try expectedData.write(to: expectedFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: expectedFile.path)
        let extraFile = ResolverPaths.fileURL(for: "stale.example", in: manager.resolverDirectory)
        let extraData = Data(repeating: 0x61, count: RouteManager.maxResolverFileBytes + 1)
        try extraData.write(to: extraFile)

        let check = manager.resolverFilesHealthCheck(using: state)
        #expect(check.status == .warn)
        #expect(check.detail.contains("unavailable: stale.example"))
        #expect(try Data(contentsOf: expectedFile) == expectedData)
        #expect(try Data(contentsOf: extraFile) == extraData)
        try FileManager.default.removeItem(at: extraFile)
        #expect(manager.resolverFilesHealthCheck(using: state).status == .pass)
    }

    @Test
    func installResolverFilesRequireDNSServers() throws {
        let configuration = CampusNetworkPolicy(
            ipv4Routes: [],
            dnsDomains: ["case.edu"],
            dnsServers: [],
        )
        let session = SessionState(
            pid: 4321,
            executablePath: "/tmp/cwru-ovpn",
            processStartTime: ProcessStartTime(seconds: 1, microseconds: 0),
            phase: .connected,
            profilePath: "/tmp/profile.ovpn",
            startedAt: Date(timeIntervalSince1970: 0),
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0", physicalServiceID: "service-en0",
            tunnelMode: .split,
            appliedScopedDNSDomains: ["case.edu"],
            cleanupNeeded: true
        )
        let manager = RouteManager(campusPolicy: configuration)
        do {
            try manager.installResolverFiles(forDomains: manager.appliedScopedDNSDomains(using: session),
                                             nameServers: manager.policyDNSServers())
            try #require(
                Bool(false),
                "installResolverFiles must refuse to write a scoped resolver with no DNS servers.")
        } catch RouteManagerError.missingPolicyDNSServers {
        }
    }

    @Test
    func splitTunnelRepairRemovesStaleResolverFiles() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-repair")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1010,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNS = makeTunnelDNS(servers: ["129.22.4.32"])
        session.appliedSplitIPv4Routes = ["129.22.0.0/16", "172.64.80.1/32"]
        session.appliedScopedDNSDomains = [
            "case.edu",
            "stale.example",
            "1.80.64.172.in-addr.arpa",
        ]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "172.64.80.1/32",
                    gateway: "link#1",
                    interfaceName: "utun7",
                    flags: "UHS")
            ])

        try withResolverDirectory(resolverDirectory) {
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            try scopedResolverContents(domain: "stale.example", nameServer: "129.22.4.32")
                .write(
                    to: testResolverFileURL(for: "stale.example"),
                    atomically: true,
                    encoding: .utf8)
            try scopedResolverContents(
                domain: "1.80.64.172.in-addr.arpa", nameServer: "129.22.4.32"
            )
            .write(
                to: testResolverFileURL(for: "1.80.64.172.in-addr.arpa"),
                atomically: true,
                encoding: .utf8)

            try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
                try RouteManager(campusPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }

            #expect(
                !FileManager.default.fileExists(
                    atPath: testResolverFileURL(for: "stale.example").path),
                "Split repair should remove resolver files outside the fixed policy.")
            #expect(
                !FileManager.default.fileExists(
                    atPath: testResolverFileURL(for: "1.80.64.172.in-addr.arpa").path),
                "Split repair should remove reverse resolver files outside the fixed policy.")
            #expect(
                FileManager.default.fileExists(atPath: testResolverFileURL(for: "case.edu").path),
                "Split repair should keep fixed-policy scoped resolver files.")
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/sbin/route -n delete -host 172.64.80.1 -interface utun7"),
            "Split repair should delete managed routes outside the fixed policy.")
        #expect(
            !mockSystem.recordedCommands.contains(
                "/sbin/route -n add -net 172.64.80.1/32 -interface utun7"),
            "Split repair should not re-add routes outside the fixed policy.")
    }

    @Test
    func splitTunnelHealthCleansManagedStaleResolverFiles() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-health")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1011,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNS = makeTunnelDNS(servers: ["129.22.4.32"])
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        session.appliedSplitIPv6Routes = []
        session.appliedScopedDNSDomains = ["case.edu", "22.129.in-addr.arpa"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "129.22.0.0/16",
                    gateway: "link#1",
                    interfaceName: "utun7")
            ])
        try withResolverDirectory(resolverDirectory) {
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            try scopedResolverContents(domain: "case.edu", nameServer: "129.22.4.32")
                .write(
                    to: testResolverFileURL(for: "case.edu"),
                    atomically: true,
                    encoding: .utf8)
            try scopedResolverContents(domain: "old.example", nameServer: "129.22.4.32")
                .write(
                    to: testResolverFileURL(for: "old.example"),
                    atomically: true,
                    encoding: .utf8)

            let manager = makeRouteManager(
                campusPolicy: configuration,
                serviceStore: mockSystem, commandRunner: CommandRunner(handler: { try mockSystem.handle($0) }),
                resolverDirectory: resolverDirectory)
            try {
                let checks = manager.splitTunnelHealthChecks(using: session)
                #expect(
                    checks.contains { $0.name == "resolvers" && $0.status == .fail },
                    "Split health should flag stale managed resolver files.")
                #expect(
                    checks.contains {
                        $0.name == "cwru-routes"
                            && $0.status == .warn
                            && $0.detail.contains("192.5.109.0/24")
                            && $0.detail.contains("192.5.113.0/24")
                            && $0.detail.contains("2606:ea00::/32")
                    },
                    "Split health should warn when fixed CWRU route coverage is incomplete.")
                var completeCWRUSession = session
                completeCWRUSession.appliedSplitIPv4Routes = CampusNetworkPolicy.fixedIPv4Routes
                completeCWRUSession.appliedSplitIPv6Routes = CampusNetworkPolicy.fixedIPv6Routes
                let completeCWRUChecks = manager.splitTunnelHealthChecks(using: completeCWRUSession)
                #expect(
                    !completeCWRUChecks.contains { $0.name == "cwru-routes" },
                    "Split health should not warn when fixed CWRU route coverage is complete.")
                _ = try manager.monitorSplitTunnel(using: session)
            }()

            #expect(
                !FileManager.default.fileExists(
                    atPath: testResolverFileURL(for: "old.example").path),
                "Route monitor should remove stale managed resolver files.")
        }
    }

    @Test
    func resolverFilesProtectUserOwnedFiles() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-user-owned")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        let userContent = "nameserver 9.9.9.9\ndomain case.edu\nsearch_order 1\n"
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])

        try withResolverDirectory(resolverDirectory) {
            let manager = makeRouteManager(
                campusPolicy: configuration,
                serviceStore: mockSystem, commandRunner: CommandRunner(handler: { try mockSystem.handle($0) }),
                resolverDirectory: resolverDirectory)
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            let resolverFile = testResolverFileURL(for: "case.edu")
            try userContent.write(to: resolverFile, atomically: true, encoding: .utf8)

            var didThrow = false
            do {
                try manager.installResolverFiles(
                    forDomains: ["case.edu"], nameServers: ["129.22.4.32"])
            } catch RouteManagerError.refusingToReplaceUnmanagedResolverFile {
                didThrow = true
            }
            #expect(
                didThrow,
                "Installing resolvers must refuse to overwrite an unmarked, user-owned resolver file."
            )
            try manager.removeResolverFiles(for: ["case.edu"])

            #expect(
                (try? String(contentsOf: resolverFile, encoding: .utf8)) == userContent,
                "The user-owned resolver file must be left untouched and never deleted.")

            try "admin-owned\n\(RouteManager.resolverManagedMarker)\n".write(
                to: resolverFile,
                atomically: true,
                encoding: .utf8)
            try manager.removeResolverFiles(for: ["case.edu"])
            #expect(
                FileManager.default.fileExists(atPath: resolverFile.path),
                "Cleanup should only trust the managed marker as the exact first line.")
        }
    }

    @Test
    func resolverInstallPreflightsAllTargets() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-preflight")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        let userContent = "nameserver 9.9.9.9\ndomain cwru.edu\nsearch_order 1\n"
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])

        try withResolverDirectory(resolverDirectory) {
            let manager = makeRouteManager(
                campusPolicy: configuration,
                serviceStore: mockSystem, commandRunner: CommandRunner(handler: { try mockSystem.handle($0) }),
                resolverDirectory: resolverDirectory)
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            let caseFile = testResolverFileURL(for: "case.edu")
            let cwruFile = testResolverFileURL(for: "cwru.edu")
            try userContent.write(to: cwruFile, atomically: true, encoding: .utf8)

            var didThrow = false
            do {
                try manager.installResolverFiles(
                    forDomains: ["case.edu", "cwru.edu"], nameServers: ["129.22.4.32"])
            } catch RouteManagerError.refusingToReplaceUnmanagedResolverFile {
                didThrow = true
            }
            #expect(
                didThrow,
                "Installing resolvers must refuse the batch when any target is an unmanaged user file."
            )

            #expect(
                !FileManager.default.fileExists(atPath: caseFile.path),
                "Preflight must reject before writing any file, so the writable target is never created."
            )
            #expect(
                (try? String(contentsOf: cwruFile, encoding: .utf8)) == userContent,
                "The unmanaged user resolver file must be left untouched.")
        }
    }

    @Test
    func resolverInstallSkipsRewriteWhenContentMatches() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-idempotent")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])

        try withResolverDirectory(resolverDirectory) {
            let manager = makeRouteManager(
                campusPolicy: configuration,
                serviceStore: mockSystem, commandRunner: CommandRunner(handler: { try mockSystem.handle($0) }),
                resolverDirectory: resolverDirectory)
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            let resolverFile = testResolverFileURL(for: "case.edu")
            try manager.resolverContents(for: "case.edu", nameServers: ["129.22.4.32"])
                .write(to: resolverFile, atomically: true, encoding: .utf8)

            let wroteMatchingContent = try manager.installResolverFiles(
                forDomains: ["case.edu"],
                nameServers: ["129.22.4.32"])
            #expect(
                !wroteMatchingContent,
                "Installing resolvers must skip files whose content already matches so steady-state health checks stay read-only."
            )
            #expect(
                mockSystem.recordedCommands.isEmpty,
                "A content-matched resolver install must not run any shell commands.")

            let wroteStaleContent = try manager.installResolverFiles(
                forDomains: ["case.edu"],
                nameServers: ["129.22.4.33"])
            #expect(
                wroteStaleContent,
                "Installing resolvers must rewrite files whose content is stale.")
            let rewritten = try String(contentsOf: resolverFile, encoding: .utf8)
            #expect(
                rewritten.contains("nameserver 129.22.4.33"),
                "A stale resolver file must be rewritten with the new content.")
        }
    }

    @Test
    func cleanupRemovesManagedResolversWithIncompleteState() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-incomplete-state")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        let session = makeSessionState(
            pid: 1060,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])

        try withResolverDirectory(resolverDirectory) {
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            let resolverFile = testResolverFileURL(for: "case.edu")
            try scopedResolverContents(domain: "case.edu", nameServer: "129.22.4.32")
                .write(to: resolverFile, atomically: true, encoding: .utf8)

            try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
                let cleanupSucceeded = try RouteManager(campusPolicy: configuration).cleanup(
                    using: session)
                #expect(
                    cleanupSucceeded,
                    "Cleanup should validate healthy after removing stale managed resolvers from incomplete state."
                )
            }

            #expect(
                !FileManager.default.fileExists(atPath: resolverFile.path),
                "Cleanup must remove managed resolver files even when applied DNS domains were not persisted."
            )
        }
    }

    @Test
    func fullTunnelDNSIsRestoredOnCleanup() throws {
        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1061,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.recordDNSOverride(servers: ["203.0.113.53"], domains: [])
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["203.0.113.53"],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])
        let cleanupHealthy = try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
            try RouteManager(campusPolicy: configuration).cleanup(using: session)
        }
        #expect(cleanupHealthy, "Cleanup should validate healthy once the captured DNS is back.")
        #expect(
            mockSystem.recordedCommands.contains(
                "DNS servers Wi-Fi 1.1.1.1"),
            "Full-tunnel cleanup must restore captured physical DNS whenever it differs.")
        #expect(
            mockSystem.recordedCommands.contains(
                "DNS domains Wi-Fi home"),
            "Full-tunnel cleanup must restore captured physical search domains whenever they differ."
        )
    }

    @Test
    func cleanupLeavesUnchangedPhysicalDNSAlone() throws {
        let configuration = CampusNetworkPolicy(ipv4Routes: [], dnsDomains: [], dnsServers: [])
        let session = makeSessionState(
            pid: 1063,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])
        let cleanupHealthy = try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
            try RouteManager(campusPolicy: configuration).cleanup(using: session)
        }
        #expect(cleanupHealthy, "Cleanup should validate healthy when the physical DNS never changed.")
        #expect(
            !mockSystem.recordedCommands.contains { $0.hasPrefix("/usr/sbin/networksetup -set") },
            "Cleanup must not rewrite physical DNS that still matches the captured configuration.")
    }

    @Test
    func fullTunnelCleanupValidationChecksPhysicalDNS() throws {
        let configuration = CampusNetworkPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )

        var session = makeSessionState(
            pid: 1062,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

        session.recordDNSOverride(servers: ["203.0.113.53"], domains: [])
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["203.0.113.53"],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            failingCommandFragments: ["DNS servers"])

        do {
            try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
                _ = try RouteManager(campusPolicy: configuration).cleanup(using: session)
            }
            try #require(
                Bool(false),
                "Full-tunnel cleanup should fail if captured physical DNS cannot be restored.")
        } catch RouteManagerError.dnsMutationMayHaveOccurred(let detail) {
            #expect(
                detail.contains("DNS servers Wi-Fi 1.1.1.1"),
                "Full-tunnel cleanup should attempt to restore captured physical DNS before surfacing failure."
            )
        }
    }

    @Test
    func physicalDNSCapture() throws {
        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])

        try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
            let captured = try RouteManager(campusPolicy: configuration)
                .serviceStore.activeService(for: "en0")
            #expect(
                captured?.serviceName == "Wi-Fi",
                "Physical DNS capture should resolve the active macOS network service name.")
            #expect(
                captured?.dnsServers == ["1.1.1.1"],
                "Physical DNS capture should read the original DNS servers.")
            #expect(
                captured?.searchDomains == ["home"],
                "Physical DNS capture should read the original search domains.")
            #expect(
                captured?.ipv6Mode == "Automatic",
                "Physical DNS capture should read the original IPv6 mode.")
        }

        let wiredSystem = MockSystem(
            serviceName: "USB 10/100/1000 LAN",
            physicalGateway: "192.168.7.1",
            physicalInterface: "en7",
            physicalDNSServers: ["9.9.9.9"],
            physicalSearchDomains: ["lan"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])

        try CommandRunner.withCommandHandler(system: wiredSystem, wiredSystem.handle) {
            let captured = try RouteManager(campusPolicy: configuration)
                .serviceStore.activeService(for: "en7")
            #expect(
                captured?.serviceName == "USB 10/100/1000 LAN",
                "Physical DNS capture should work for non-Wi-Fi network services.")
            #expect(
                captured?.dnsServers == ["9.9.9.9"],
                "Physical DNS capture should read DNS from the active wired service.")
            #expect(
                captured?.searchDomains == ["lan"],
                "Physical DNS capture should read search domains from the active wired service.")
        }



        let vlanSystem = MockSystem(
            serviceName: "VLAN",
            physicalGateway: "192.168.7.1",
            physicalInterface: "en0.10",
            physicalDNSServers: ["9.9.9.9"],
            physicalSearchDomains: ["lan"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])

        try CommandRunner.withCommandHandler(system: vlanSystem, vlanSystem.handle) {
            let captured = try RouteManager(campusPolicy: configuration)
                .serviceStore.activeService(for: "en0")
            #expect(
                captured == nil,
                "Physical DNS capture should not match en0 when the service Device is en0.10.")
        }
    }

    @Test
    func serviceDisplayNamesAreNotIdentifiers() throws {
        let service = MockSystem(serviceName: "-Lab Wi-Fi", physicalGateway: "192.0.2.1", physicalInterface: "en0",
                                 physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Automatic", tunnelInterfaces: [])
        let config = try #require(try service.activeService(for: "en0"))
        #expect(config.serviceName == "-Lab Wi-Fi")
        #expect(config.serviceID == "service-en0")
        #expect(try service.configuration(serviceID: config.serviceID, kind: .ipv6).enabled == true)
    }

    @Test
    func dnsBootstrapResolve() {
        var attempts: [String] = []
        let lookup: RouteManager.AddressLookup = { _, server, dualStack, _ in
            #expect(!dualStack)
            attempts.append(server ?? "")
            return server == "9.9.9.9" ? ["0.0.0.0"] : ["203.0.113.42"]
        }
        let servers = ["9.9.9.9", "1.1.1.1"]
        #expect(RouteManager.resolveHostUsingBootstrap(host: "vpn.example", servers: servers, timeoutSeconds: 2, lookup: lookup) == "203.0.113.42")
        #expect(attempts == servers)
        for host in ["203.0.113.42", "-invalid", "bad_host.example"] {
            #expect(RouteManager.resolveHostUsingBootstrap(host: host, servers: servers, timeoutSeconds: 2, lookup: lookup) == nil)
        }
        #expect(RouteManager.resolveHostUsingBootstrap(host: "vpn.example", servers: [], timeoutSeconds: 2, lookup: lookup) == nil)
        #expect(attempts == servers)
    }

    @Test
    func dnsBootstrapRetryHelpers() throws {
        #expect(
            VPNController.isOpenVPNGatewayProgressEvent("GET_CONFIG"),
            "GET_CONFIG proves the client reached a real gateway, so it must suppress the DNS bootstrap retry."
        )
        #expect(
            VPNController.isOpenVPNGatewayProgressEvent("CONNECTED"),
            "A completed connection must suppress the DNS bootstrap retry.")
        #expect(
            !VPNController.isOpenVPNGatewayProgressEvent("RESOLVE"),
            "Name resolution alone does not prove the gateway was reached, so it must not suppress the retry."
        )
        #expect(
            !VPNController.isOpenVPNGatewayProgressEvent("CONNECTING"),
            "A transport-level connect (which a sinkhole block page can also accept) must not suppress the retry."
        )

        #expect(
            VPNController.shouldPreResolveGateway(
                host: "us-cmh.gw.openvpn.com",
                bootstrapServers: ["1.1.1.1"]),
            "A gateway hostname with configured bootstrap servers is eligible for the pre-connect sinkhole check."
        )
        #expect(
            !VPNController.shouldPreResolveGateway(
                host: "us-cmh.gw.openvpn.com",
                bootstrapServers: []),
            "Without configured bootstrap servers the pre-connect check must not run.")
        #expect(
            !VPNController.shouldPreResolveGateway(
                host: "67.219.145.198",
                bootstrapServers: ["1.1.1.1"]),
            "A profile that already pins a literal IPv4 gateway has nothing to re-resolve.")
        #expect(
            !VPNController.shouldPreResolveGateway(
                host: "2606:ea00::1",
                bootstrapServers: ["1.1.1.1"]),
            "A profile that already pins a literal IPv6 gateway has nothing to re-resolve.")
    }

    @Test
    func webAuthSinkholeDetection() {
        for (answers, expected) in [(["0.0.0.0", "::1"], true), (["127.0.0.1"], true),
                                    (["0.0.0.0", "2001:db8::1"], false), ([], false)] {
            let sinkholed = RouteManager.systemResolverSinkholes(host: "cwru.openvpn.com", timeoutSeconds: 1, dualStack: true) {
                _, server, dualStack, _ in
                #expect(server == nil && dualStack)
                return answers
            }
            #expect(sinkholed == expected)
        }
    }

    @Test
    func webAuthBootstrapResolverOverride() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-webauth")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1099,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["172.19.248.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.appliedScopedDNSDomains = ["case.edu"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["172.19.248.1"],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            activeDefaultDNSServers: ["172.19.248.1"],
            activeDefaultSearchDomains: [],
            tunnelInterfaces: ["utun7"])

        try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
                let withoutBootstrap = RouteManager(campusPolicy: configuration)
                let installedWithoutBootstrap =
                    try withoutBootstrap.installWebAuthBootstrapResolvers()
                #expect(
                    !installedWithoutBootstrap,
                    "Without configured bootstrap resolvers the sign-in override must be a no-op, not an error."
                )
                #expect(
                    !FileManager.default.fileExists(
                        atPath: testResolverFileURL(for: "openvpn.com").path
                    ),
                    "The sign-in override must not write anything when no bootstrap resolvers are configured."
                )

                let manager = RouteManager(
                    campusPolicy: configuration,
                    dnsBootstrapServers: ["1.1.1.1", "8.8.8.8"])
                let installed = try manager.installWebAuthBootstrapResolvers()
                #expect(
                    installed,
                    "The sign-in override should install scoped resolver files for the OpenVPN namespace."
                )

                for domain in RouteManager.webAuthBootstrapResolverDomains {
                    let file = testResolverFileURL(for: domain)
                    let contents = try String(contentsOf: file, encoding: .utf8)
                    #expect(
                        try manager.withResolverDirectory { directory in try directory.read(file.lastPathComponent).map(ResolverDirectory.isManaged) == true },
                        "The sign-in override must carry the ownership marker so every existing sweep can reclaim it."
                    )
                    #expect(
                        contents.contains("nameserver 1.1.1.1")
                            && contents.contains("nameserver 8.8.8.8"),
                        "The sign-in override should resolve \(domain) through the configured bootstrap servers."
                    )
                }

                #expect(
                    Set(manager.staleManagedDNSDomains(using: session))
                        == Set(RouteManager.webAuthBootstrapResolverDomains),
                    "The sign-in override must register as stale against the split policy so the existing sweeps remove it if the app dies mid-sign-in."
                )

                try manager.removeWebAuthBootstrapResolvers()
                for domain in RouteManager.webAuthBootstrapResolverDomains {
                    #expect(
                        !FileManager.default.fileExists(
                            atPath: testResolverFileURL(for: domain).path
                        ), "Finishing sign-in must remove the scoped resolver file for \(domain).")
                }
            }
        }

        #expect(
            !RouteManager.webAuthBootstrapResolverDomains.contains(where: {
                CampusNetworkPolicy.fixedDNSDomains.contains($0)
            }),
            "The sign-in override must never overlap the fixed CWRU scoped domains it would otherwise clobber."
        )

        #expect(
            RouteManager.webAuthBootstrapResolverDomains.allSatisfy {
                NetworkValidation.isValidDomainName($0) && ResolverPaths.isSafeDomainFileName($0)
            },
            "The sign-in override domains must stay safe resolver file names; ResolverPaths.fileURL traps on anything else."
        )
    }

    @Test
    func splitTunnelRejectsLeakyDefaultDNS() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-leaky-dns")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1003,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNS = makeTunnelDNS(servers: ["129.22.4.32"], searchDomains: ["case.edu"])

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            activeDefaultDNSServers: ["129.22.4.32"],
            activeDefaultSearchDomains: ["case.edu"],
            tunnelInterfaces: ["utun7"],
            activeResolverPublicationDelayReads: nil)

        try withResolverDirectory(resolverDirectory) {
            do {
                try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
                    try RouteManager(campusPolicy: configuration).applySplitTunnel(
                        using: &session, persistPreparedState: persistPreparedState)
                }
                try #require(
                    Bool(false),
                    "Split tunnel should fail closed when the active default resolver stays on CWRU scoped DNS."
                )
            } catch RouteManagerError.failedToIsolateSplitTunnelDNS {
            }
        }
    }

    @Test
    func splitTunnelRejectsSupplementalDefaultSearchDomains() throws {
        let resolverDirectory = temporaryDirectory(
            named: "cwru-ovpn-resolver-search-domain-overlap")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1006,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNS = makeTunnelDNS(servers: ["129.22.4.32"], searchDomains: ["case.edu"])

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            activeDefaultDNSServers: ["1.1.1.1"],
            activeDefaultSearchDomains: ["case.edu"],
            tunnelInterfaces: ["utun7"],
            activeResolverPublicationDelayReads: nil)

        try withResolverDirectory(resolverDirectory) {
            do {
                try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
                    try RouteManager(campusPolicy: configuration).applySplitTunnel(
                        using: &session, persistPreparedState: persistPreparedState)
                }
                try #require(
                    Bool(false),
                    "Split tunnel should fail closed when the default resolver keeps a CWRU search domain."
                )
            } catch RouteManagerError.failedToIsolateSplitTunnelDNS {
            }
        }
    }

    @Test
    func splitTunnelAllowsBaselineDefaultSearchDomain() throws {
        let resolverDirectory = temporaryDirectory(
            named: "cwru-ovpn-resolver-baseline-search-domain")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1034,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: [],
            originalSearchDomains: [],
            originalDefaultSearchDomains: ["case.edu"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNS = makeTunnelDNS(servers: ["129.22.4.32"], searchDomains: ["case.edu"])

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: [],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            activeDefaultDNSServers: [mockPublicDNSServerA, mockPublicDNSServerB],
            activeDefaultSearchDomains: ["case.edu"],
            tunnelInterfaces: ["utun7"])

        try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
                try RouteManager(campusPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
        }

    }

    @Test
    func splitTunnelWaitsForDefaultSearchDomainCleanup() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-search-domain-wait")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1028,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNS = makeTunnelDNS(servers: ["129.22.4.32"], searchDomains: ["case.edu"])

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            activeDefaultDNSServers: ["1.1.1.1"],
            activeDefaultSearchDomains: ["case.edu"],
            tunnelInterfaces: ["utun7"],
            activeResolverPublicationDelayReads: 2)

        mockSystem.scheduleResolverPublication()
        try withResolverDirectory(resolverDirectory) {
            try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
                try RouteManager(campusPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
        }

    }

    @Test
    func physicalDNSRepairIsWriteFreeWhenHealthy() throws {
        var state = makeSessionState(pid: 1030, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: ["home"], originalIPv6Mode: "Automatic",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        let system = MockSystem(serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
                                physicalDNSServers: ["9.9.9.9"], physicalSearchDomains: [], ipv6Mode: "Automatic", tunnelInterfaces: [])
        let manager = RouteManager(serviceStore: system, commandRunner: CommandRunner(handler: system.handle))
        #expect(try !manager.restoreService(.dns, using: state))
        #expect(system.recordedCommands.isEmpty)
        state.recordDNSOverride(servers: ["129.22.4.32"])
        #expect(throws: RouteManagerError.self) { try manager.restoreService(.dns, using: state) }
        #expect(system.recordedCommands.isEmpty)
        let owned = MockSystem(serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
                               physicalDNSServers: ["129.22.4.32"], physicalSearchDomains: [], ipv6Mode: "Automatic", tunnelInterfaces: [])
        let owner = RouteManager(serviceStore: owned, commandRunner: CommandRunner(handler: owned.handle))
        #expect(try owner.restoreService(.dns, using: state))
        #expect(try !owner.restoreService(.dns, using: state))
        #expect(try owner.currentDNSSettings(using: state).searchDomains == ["home"])
    }

    @Test
    func fullTunnelInstallsScopedResolversAndTakesOverDefaultDNS() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-full-scoped")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu", "cwru.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1043,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            activeDefaultDNSServers: [mockPublicDNSServerA, mockPublicDNSServerB],
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "0.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
            ])

        try withResolverDirectory(resolverDirectory) {
            let manager = makeRouteManager(
                campusPolicy: configuration,
                serviceStore: mockSystem, commandRunner: CommandRunner(handler: { try mockSystem.handle($0) }),
                resolverDirectory: resolverDirectory)
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            _ = try manager.applyFullTunnelDNSConfiguration(using: &session, persistPreparedState: { _ in })

            let caseResolver = testResolverFileURL(for: "case.edu")
            #expect(
                FileManager.default.fileExists(atPath: caseResolver.path),
                "Full tunnel should install a scoped resolver for case.edu.")
            #expect(
                FileManager.default.fileExists(atPath: testResolverFileURL(for: "cwru.edu").path),
                "Full tunnel should install a scoped resolver for cwru.edu.")
            let caseContents = try String(contentsOf: caseResolver, encoding: .utf8)
            #expect(
                caseContents.contains("nameserver 129.22.4.32"),
                "Full-tunnel scoped resolvers must use CWRU DNS servers.")
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "DNS servers Wi-Fi 129.22.4.32"),
            "Full tunnel must point the physical-service default DNS at CWRU DNS.")
        #expect(
            mockSystem.recordedCommands.contains { command in
                command.hasPrefix("DNS domains Wi-Fi")
                    && command.contains("case.edu")
            },
            "Full tunnel must use the fixed scoped domains for the default search domains.")
    }

    @Test
    func fullTunnelRejectsPhysicallyRoutedPushedDNS() throws {
        let resolverDirectory = temporaryDirectory(
            named: "cwru-ovpn-resolver-full-physical-pushed-dns")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1119,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.pushedDNS = makeTunnelDNS(servers: ["192.168.1.1", "203.0.113.10"])

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "0.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "192.168.1.0/24",
                    gateway: "link#4",
                    interfaceName: "en0",
                    flags: "UCS"),
                MockSystem.RouteRecord(
                    destination: "203.0.113.10/32",
                    gateway: "192.168.1.1",
                    interfaceName: "en0",
                    flags: "UGHS"),
            ])

        withResolverDirectory(resolverDirectory) {
            let manager = makeRouteManager(campusPolicy: configuration, serviceStore: mockSystem,
                                           commandRunner: CommandRunner(handler: mockSystem.handle), resolverDirectory: resolverDirectory)
            #expect(throws: RouteManagerError.self) {
                try manager.applyFullTunnelDNSConfiguration(using: &session, persistPreparedState: { _ in })
            }
            #expect(mockSystem.recordedCommands.allSatisfy { !$0.hasPrefix("DNS servers") })
        }
    }

    @Test
    func fullTunnelDNSApplicationIsIdempotent() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-full-idempotent")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1093,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "0.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
            ])

        try withResolverDirectory(resolverDirectory) {
            let manager = makeRouteManager(
                campusPolicy: configuration,
                serviceStore: mockSystem, commandRunner: CommandRunner(handler: { try mockSystem.handle($0) }),
                resolverDirectory: resolverDirectory)
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            try manager.applyFullTunnelDNSConfiguration(using: &session, persistPreparedState: { _ in })
            try manager.applyFullTunnelDNSConfiguration(using: &session, persistPreparedState: { _ in })
        }

        let dnsSetCount = mockSystem.recordedCommands.filter {
            $0.hasPrefix("DNS servers Wi-Fi")
        }.count
        let searchSetCount = mockSystem.recordedCommands.filter {
            $0.hasPrefix("DNS domains Wi-Fi")
        }.count
        let flushCount = mockSystem.recordedCommands.filter {
            $0 == "/usr/bin/killall -HUP mDNSResponder"
        }.count
        #expect(
            dnsSetCount == 1,
            "Re-applying full-tunnel DNS must not rewrite an already-correct default resolver.")
        #expect(
            searchSetCount == 1,
            "Re-applying full-tunnel DNS must not rewrite already-correct search domains.")
        #expect(
            flushCount == 1,
            "Re-applying full-tunnel DNS must not flush the resolver cache when nothing changed.")
    }

    @Test
    func fullTunnelScopedResolversUsePushedDNSBeforePolicyDNS() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-full-pushed-dns")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        var session = makeSessionState(
            pid: 1044,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.pendingDNSWithdrawal.servers = ["10.0.0.53"]
        session.pushedDNS = makeTunnelDNS(servers: ["10.0.0.54"])

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "0.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
            ])

        try withResolverDirectory(resolverDirectory) {
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
                _ = try RouteManager(campusPolicy: configuration)
                    .applyFullTunnelDNSConfiguration(using: &session, persistPreparedState: persistPreparedState)
            }

            let resolverContents = try String(
                contentsOf: testResolverFileURL(for: "case.edu"),
                encoding: .utf8)
            #expect(
                resolverContents.contains("nameserver 10.0.0.54"),
                "Full-tunnel scoped resolvers should use the current pushed DNS servers.")
            #expect(
                !resolverContents.contains("nameserver 129.22.4.32"),
                "Fixed policy DNS servers should not override learned full-tunnel DNS servers.")
        }
    }

    @Test
    func failedDNSSnapshotIsNotAccepted() throws {
        let system = MockSystem(serviceName: "Wi-Fi", physicalGateway: "192.168.1.1",
                                physicalInterface: "en0", physicalDNSServers: ["1.1.1.1"],
                                physicalSearchDomains: [], ipv6Mode: "Automatic", tunnelInterfaces: [])
        system.failServiceRead = true
        #expect(throws: POSIXError.self) { try system.activeService(for: "en0") }
    }

    @Test
    func failedDNSInspectionDoesNotPassIsolation() throws {
        let manager = RouteManager(serviceStore: TestDependencies.networkServices, commandRunner: CommandRunner(handler: { _ in
            CommandResult(exitCode: 1, stdout: "", stderr: "inspection unavailable")
        }))
        let session = makeSessionState(
            pid: Int32.max - 18, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalServiceName: "Wi-Fi", originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: [], originalIPv6Mode: "Automatic", tunnelName: "utun7",
            tunnelMode: .split, cleanupNeeded: true)
        #expect(throws: (any Error).self) {
            _ = try manager.repairActiveDefaultResolverIsolation(using: session)
        }
    }


    @Test
    func vpnDNSWithdrawalWaitsForPublicationBeforeReturning() throws {
        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1071,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true)
        session.recordDNSOverride(servers: ["129.22.4.32"], domains: ["case.edu"])
        session.pendingDNSWithdrawal.servers = ["129.22.4.32"]
        session.appliedScopedDNSDomains = ["case.edu"]

        for publicationDelayReads in [Int?.some(2), nil] {
            let mockSystem = MockSystem(
                serviceName: "Wi-Fi",
                physicalGateway: "192.168.1.1",
                physicalInterface: "en0",
                physicalDNSServers: ["129.22.4.32"],
                physicalSearchDomains: ["case.edu"],
                ipv6Mode: "Off",
                activeDefaultDNSServers: ["129.22.4.32"],
                activeDefaultSearchDomains: ["case.edu"],
                tunnelInterfaces: ["utun7"],
                activeResolverPublicationDelayReads: publicationDelayReads)
            let published = try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
                let manager = RouteManager(campusPolicy: configuration)
                try FileManager.default.createDirectory(
                    at: manager.resolverDirectory, withIntermediateDirectories: true)
                try scopedResolverContents(domain: "case.edu", nameServer: "129.22.4.32").write(
                    to: ResolverPaths.fileURL(for: "case.edu", in: manager.resolverDirectory), atomically: true, encoding: .utf8)
                let published = try manager.withdrawVPNDNS(using: session)
                #expect(!FileManager.default.fileExists(atPath: ResolverPaths.fileURL(for: "case.edu", in: manager.resolverDirectory).path))
                return published
            }
            #expect(published == (publicationDelayReads != nil))
            let commands = mockSystem.recordedCommands
            #expect(commands.contains("DNS servers Wi-Fi 1.1.1.1"))
            #expect(commands.contains("DNS domains Wi-Fi home"))
            let scutilReads = commands.filter { $0 == "/usr/sbin/scutil --dns" }.count
            #expect(publicationDelayReads == nil ? scutilReads > 3 : scutilReads == 3)
            #expect(commands.filter { $0 == "/usr/bin/dscacheutil -flushcache" }.count == 1)
            #expect(commands.filter { $0 == "/usr/bin/killall -HUP mDNSResponder" }.count == 1)
            #expect(!commands.contains { $0.contains("/sbin/route") })
        }
    }

    @Test
    func cleanupWithdrawsDNSBeforeRemovingTunnelCoverage() throws {
        let configuration = CampusNetworkPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        var session = makeSessionState(
            pid: 1072,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunnelName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true)
        session.recordDNSOverride(servers: ["129.22.4.32"], domains: ["case.edu"])
        session.pendingDNSWithdrawal.servers = ["129.22.4.32"]
        session.appliedScopedDNSDomains = ["case.edu"]
        session.managedIPv6Routes = ["::/1", "8000::/1"].map { ManagedIPv6Route(blocking: $0) }

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["129.22.4.32"],
            physicalSearchDomains: ["case.edu"],
            ipv6Mode: "Off",
            activeDefaultDNSServers: ["129.22.4.32"],
            activeDefaultSearchDomains: ["case.edu"],
            tunnelInterfaces: ["utun7"],
            initialRoutes: ["0.0.0.0/1", "128.0.0.0/1"].map {
                MockSystem.RouteRecord(destination: $0, gateway: "link#9", interfaceName: "utun7")
            },
            initialIPv6Routes: ["::/1": "lo0", "8000::/1": "lo0"])
        let healthy = try CommandRunner.withCommandHandler(system: mockSystem, mockSystem.handle) {
            let manager = RouteManager(campusPolicy: configuration)
            try FileManager.default.createDirectory(
                at: manager.resolverDirectory, withIntermediateDirectories: true)
            try scopedResolverContents(domain: "case.edu", nameServer: "129.22.4.32").write(
                to: ResolverPaths.fileURL(for: "case.edu", in: manager.resolverDirectory), atomically: true, encoding: .utf8)
            mockSystem.releaseTunnelInterface(named: "utun7")
            return try manager.cleanup(using: session)
        }
        #expect(healthy)
        let commands = mockSystem.recordedCommands
        let dnsRestoreIndex = try #require(
            commands.firstIndex(of: "DNS servers Wi-Fi 1.1.1.1"))
        let firstRouteRemovalIndex = try #require(
            commands.firstIndex { $0.hasPrefix("/sbin/route -n delete") })
        let publishedIndex = try #require(commands[..<firstRouteRemovalIndex].lastIndex(of: "/usr/sbin/scutil --dns"))
        #expect(dnsRestoreIndex < publishedIndex && publishedIndex < firstRouteRemovalIndex)
        #expect(commands.filter { $0 == "/usr/bin/dscacheutil -flushcache" }.count == 1)
        #expect(commands.allSatisfy {
            !$0.hasPrefix("/sbin/route -n delete") || !$0.contains("utun7")
        })

        let quietSession = makeSessionState(
            pid: 1073,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true)
        let quietSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])
        let quietHealthy = try CommandRunner.withCommandHandler(system: quietSystem, quietSystem.handle) {
            try RouteManager(campusPolicy: configuration).cleanup(using: quietSession)
        }
        #expect(quietHealthy)
        #expect(!quietSystem.recordedCommands.contains {
            $0.contains("networksetup -set") || $0.contains("-flushcache") || $0.contains("-HUP")
        })
    }

}
