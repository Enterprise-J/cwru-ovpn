import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct ResolverAndDNSTests {
    @Test(arguments: ["missing", "nameserver", "domain"])
    func resolverHealthAndRepairUseTheSameContentPolicy(scenario: String) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-resolver-policy-health")
        defer { try? FileManager.default.removeItem(at: directory) }
        let policy = SplitTunnelPolicy(ipv4Routes: [], dnsDomains: ["case.edu"], dnsServers: ["129.22.4.32"])
        var state = makeSessionState(
            pid: 1120, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.appliedDNSDomains = ["case.edu"]
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: ["utun7"])
        let manager = makeRouteManager(splitTunnelPolicy: policy, shell: Shell(handler: { try system.handle($0) }),
                                       resolverDirectory: directory)
        let file = manager.resolverFileURL(for: "case.edu")
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

        #expect(try manager.validateResolverFiles(using: state))
        #expect(try manager.resolverFileStatus(for: "case.edu", nameServers: policy.dnsServers) == .matching)
        system.recordedCommands.removeAll()
        #expect(manager.resolverFilesHealthCheck(using: state).status == .pass)
        #expect(try !manager.validateResolverFiles(using: state))
        #expect(try !manager.installResolverFiles(forDomains: ["case.edu"], nameServers: policy.dnsServers))
        #expect(system.recordedCommands.isEmpty)
    }

    @Test(arguments: ["mode", "owner", "group"])
    func matchingResolverContentCannotBypassFileValidation(scenario: String) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-resolver-metadata-health")
        defer { try? FileManager.default.removeItem(at: directory) }
        let policy = SplitTunnelPolicy(ipv4Routes: [], dnsDomains: ["case.edu"], dnsServers: ["129.22.4.32"])
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: [])
        let manager = RouteManager(
            splitTunnelPolicy: policy, shell: Shell(handler: { try system.handle($0) }), resolverDirectory: directory,
            resolverFileOwnership: (scenario == "owner" ? getuid() ^ 1 : getuid(), scenario == "group" ? getgid() ^ 1 : getgid()),
            remoteHostRouteLedger: RemoteHostRouteLedger(directory: directory))
        var state = makeSessionState(
            pid: 1121, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.appliedDNSDomains = ["case.edu"]
        let file = manager.resolverFileURL(for: "case.edu")
        let data = Data(manager.resolverContents(for: "case.edu", nameServers: policy.dnsServers).utf8)
        try data.write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: scenario == "mode" ? 0o666 : 0o644], ofItemAtPath: file.path)

        let check = manager.resolverFilesHealthCheck(using: state)
        #expect(check.status == .fail && check.detail.contains("invalid: case.edu"))
        #expect(throws: (any Error).self) {
            _ = try manager.installResolverFiles(forDomains: ["case.edu"], nameServers: policy.dnsServers)
        }
        #expect(throws: (any Error).self) {
            _ = try manager.validateResolverFiles(using: state)
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
        let policy = SplitTunnelPolicy(ipv4Routes: [], dnsDomains: ["case.edu"], dnsServers: ["129.22.4.32"])
        let manager = makeRouteManager(splitTunnelPolicy: policy, shell: Shell(handler: { invocation in
            throw MockSystemError.unexpectedCommand(invocation.launchPath)
        }), resolverDirectory: blockedDirectory)
        var state = makeSessionState(
            pid: 1122, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.appliedDNSDomains = ["case.edu"]
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
            splitTunnelPolicy: SplitTunnelPolicy(ipv4Routes: [], dnsDomains: [], dnsServers: []),
            shell: Shell(handler: { invocation in
                Issue.record("Resolver inspection invoked a command: \(invocation.launchPath)")
                throw MockSystemError.unexpectedCommand(invocation.launchPath)
            }), resolverDirectory: blockedDirectory)
        var state = makeSessionState(
            pid: 1123, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.appliedDNSDomains = []
        let check = manager.resolverFilesHealthCheck(using: state)
        #expect(check.status == .warn)
        #expect(check.detail.contains("unavailable: directory"))
        #expect(try Data(contentsOf: blockedDirectory) == original)
    }

    @Test
    func resolverHealthReportsUnreadableExtraFile() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-extra-resolver-unavailable")
        defer { try? FileManager.default.removeItem(at: directory) }
        let policy = SplitTunnelPolicy(ipv4Routes: [], dnsDomains: ["case.edu"], dnsServers: ["129.22.4.32"])
        let manager = makeRouteManager(splitTunnelPolicy: policy, shell: Shell(handler: { invocation in
            Issue.record("Resolver inspection invoked a command: \(invocation.launchPath)")
            throw MockSystemError.unexpectedCommand(invocation.launchPath)
        }), resolverDirectory: directory)
        var state = makeSessionState(
            pid: 1124, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.appliedDNSDomains = ["case.edu"]
        let expectedFile = manager.resolverFileURL(for: "case.edu")
        let expectedData = Data(manager.resolverContents(for: "case.edu", nameServers: policy.dnsServers).utf8)
        try expectedData.write(to: expectedFile)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: expectedFile.path)
        let extraFile = manager.resolverFileURL(for: "stale.example")
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
    func fullTunnelDNSRequiresAServiceBeforeMutation() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-missing-full-dns-service")
        defer { try? FileManager.default.removeItem(at: directory) }
        let manager = RouteManager(
            shell: Shell { invocation in
                throw MockSystemError.unexpectedCommand(([invocation.launchPath] + invocation.arguments).joined(separator: " "))
            },
            resolverDirectory: directory)
        for name: String? in [nil, "", "-invalid", "Wi-Fi\ninvalid"] {
            var state = makeSessionState(
                pid: 42, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
                physicalGateway: "192.0.2.1", physicalInterface: "en0",
                physicalServiceName: "Wi-Fi", originalDNSServers: [],
                originalSearchDomains: [], originalIPv6Mode: "Automatic",
                tunName: "utun7", tunnelMode: .full, cleanupNeeded: true)
            state.physicalServiceName = name
            #expect(throws: RouteManagerError.self) {
                _ = try manager.applyFullTunnelDNSConfigurationIfAvailable(using: state)
            }
            #expect(throws: RouteManagerError.self) {
                try manager.setFullTunnelDefaultResolver(using: state, nameServers: ["129.22.4.3"])
            }
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
    }

    @Test
    func installResolverFilesRequireDNSServers() throws {
        let configuration = SplitTunnelPolicy(
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
            physicalInterface: "en0",
            tunnelMode: .split,
            appliedDNSDomains: ["case.edu"],
            cleanupNeeded: true
        )
        let manager = RouteManager(splitTunnelPolicy: configuration)
        do {
            try manager.installResolverFiles(using: session)
            try #require(
                Bool(false),
                "installResolverFiles must refuse to write a scoped resolver with no DNS servers.")
        } catch RouteManagerError.missingSplitTunnelDNSServers {
        }
    }

    @Test
    func splitTunnelRepairRemovesStaleResolverFiles() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-repair")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
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
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNSServers = ["129.22.4.32"]
        session.appliedSplitIPv4Routes = ["129.22.0.0/16", "172.64.80.1/32"]
        session.appliedDNSDomains = [
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

            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
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

        let configuration = SplitTunnelPolicy(
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
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNSServers = ["129.22.4.32"]
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        session.appliedSplitIPv6Routes = []
        session.appliedDNSDomains = ["case.edu", "22.129.in-addr.arpa"]

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
                splitTunnelPolicy: configuration,
                shell: Shell(handler: { try mockSystem.handle($0) }),
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
                completeCWRUSession.appliedSplitIPv4Routes = SplitTunnelPolicy.fixedIPv4Routes
                completeCWRUSession.appliedSplitIPv6Routes = SplitTunnelPolicy.fixedIPv6Routes
                let completeCWRUChecks = manager.splitTunnelHealthChecks(using: completeCWRUSession)
                #expect(
                    !completeCWRUChecks.contains { $0.name == "cwru-routes" },
                    "Split health should not warn when fixed CWRU route coverage is complete.")
                _ = try manager.monitorAndRepair(using: session)
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

        let configuration = SplitTunnelPolicy(
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
                splitTunnelPolicy: configuration,
                shell: Shell(handler: { try mockSystem.handle($0) }),
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
            #expect(
                !mockSystem.recordedCommands.contains {
                    $0.contains("/bin/rm") && $0.contains("case.edu")
                },
                "Cleanup must not issue rm against an unmarked, user-owned resolver file.")

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

        let configuration = SplitTunnelPolicy(
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
                splitTunnelPolicy: configuration,
                shell: Shell(handler: { try mockSystem.handle($0) }),
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

        let configuration = SplitTunnelPolicy(
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
                splitTunnelPolicy: configuration,
                shell: Shell(handler: { try mockSystem.handle($0) }),
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

        let configuration = SplitTunnelPolicy(
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
            tunName: "utun7",
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

            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                let cleanupSucceeded = try RouteManager(splitTunnelPolicy: configuration).cleanup(
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
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        let session = makeSessionState(
            pid: 1061,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["203.0.113.53"],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])
        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).restoreDNSConfiguration(
                using: session)
        }
        #expect(
            mockSystem.recordedCommands.contains(
                "/usr/sbin/networksetup -setdnsservers Wi-Fi 1.1.1.1"),
            "Full-tunnel cleanup must restore captured physical DNS whenever it differs.")
        #expect(
            mockSystem.recordedCommands.contains(
                "/usr/sbin/networksetup -setsearchdomains Wi-Fi home"),
            "Full-tunnel cleanup must restore captured physical search domains whenever they differ."
        )
    }

    @Test
    func fullTunnelCleanupValidationChecksPhysicalDNS() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )

        let session = makeSessionState(
            pid: 1062,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["203.0.113.53"],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            failingCommandFragments: ["/usr/sbin/networksetup -setdnsservers"])

        do {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                _ = try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
            }
            try #require(
                Bool(false),
                "Full-tunnel cleanup should fail if captured physical DNS cannot be restored.")
        } catch ShellError.commandFailed(let command, _, _) {
            #expect(
                command == "/usr/sbin/networksetup -setdnsservers Wi-Fi 1.1.1.1",
                "Full-tunnel cleanup should attempt to restore captured physical DNS before surfacing failure."
            )
        }
    }

    @Test
    func physicalDNSCapture() throws {
        let configuration = SplitTunnelPolicy(
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

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            let captured = try RouteManager(splitTunnelPolicy: configuration)
                .capturePhysicalDNSConfiguration(for: "en0")
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

        try Shell.withCommandHandler({ try wiredSystem.handle($0) }) {
            let captured = try RouteManager(splitTunnelPolicy: configuration)
                .capturePhysicalDNSConfiguration(for: "en7")
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

        #expect(
            RouteManager.networkServiceDeviceName(from: "(Hardware Port: VLAN, Device: en0.10)")
                == "en0.10",
            "Network service parsing should extract the exact Device field.")

        let vlanSystem = MockSystem(
            serviceName: "VLAN",
            physicalGateway: "192.168.7.1",
            physicalInterface: "en0.10",
            physicalDNSServers: ["9.9.9.9"],
            physicalSearchDomains: ["lan"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])

        try Shell.withCommandHandler({ try vlanSystem.handle($0) }) {
            let captured = try RouteManager(splitTunnelPolicy: configuration)
                .capturePhysicalDNSConfiguration(for: "en0")
            #expect(
                captured == nil,
                "Physical DNS capture should not match en0 when the service Device is en0.10.")
        }
    }

    @Test
    func physicalDNSCaptureRejectsUnsafeServiceName() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        let mockSystem = MockSystem(
            serviceName: String(repeating: "W", count: 129),
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])

        try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            let captured = try RouteManager(splitTunnelPolicy: configuration)
                .capturePhysicalDNSConfiguration(for: "en0")
            #expect(
                captured == nil,
                "Physical DNS capture should reject unsafe network service names before using them in networksetup calls."
            )
        }
        #expect(
            !mockSystem.recordedCommands.contains { $0.contains("-getdnsservers") },
            "Unsafe network service names should not be passed to networksetup DNS commands.")
    }

    @Test
    func dnsBootstrapResolve() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        let manager = RouteManager(
            splitTunnelPolicy: configuration,
            dnsBootstrapServers: ["9.9.9.9", "1.1.1.1"]
        )
        var recordedCommands: [String] = []
        var recordedHomes: [String?] = []
        let resolverShell = Shell(handler: { invocation -> ShellResult in
            recordedCommands.append(
                ([invocation.launchPath] + invocation.arguments).joined(separator: " "))
            recordedHomes.append(invocation.environment?["HOME"])
            guard invocation.launchPath == "/usr/bin/dig" else {
                return ShellResult(exitCode: 1, stdout: "", stderr: "unexpected command")
            }
            if invocation.arguments.contains("@9.9.9.9") {
                return ShellResult(exitCode: 0, stdout: "0.0.0.0\n", stderr: "")
            }
            return ShellResult(
                exitCode: 0, stdout: "us-cmh.gw.openvpn.com.\n203.0.113.42\n", stderr: "")
        })
        let resolved = RouteManager.resolveHostUsingBootstrap(
            host: "us-cmh.gw.openvpn.com",
            servers: manager.dnsBootstrapServers,
            timeoutSeconds: 2,
            shell: resolverShell)
        #expect(
            resolved == "203.0.113.42",
            "DNS bootstrap resolve should return the first usable address from a configured resolver, skipping sinkholed answers and CNAME lines."
        )
        #expect(
            recordedCommands.allSatisfy {
                $0.hasPrefix("/usr/bin/dig +short ") && !$0.contains(" -r ")
            },
            "DNS bootstrap resolve must invoke the system dig without the -r flag, which DiG 9.10.x on macOS rejects, while never mutating the system DNS configuration."
        )
        #expect(
            recordedHomes.allSatisfy { $0 == RouteManager.bootstrapDigHome },
            "DNS bootstrap resolve must neutralize HOME so a user-writable ~/.digrc cannot steer the root lookup."
        )
        #expect(
            recordedCommands.contains { $0.contains("@9.9.9.9") }
                && recordedCommands.contains { $0.contains("@1.1.1.1") },
            "DNS bootstrap resolve should query configured resolvers in order until one returns a usable address."
        )

        let disabledManager = RouteManager(
            splitTunnelPolicy: configuration,
            dnsBootstrapServers: []
        )
        var disabledCommands: [String] = []
        let disabledShell = Shell(handler: { invocation -> ShellResult in
            disabledCommands.append(invocation.launchPath)
            return ShellResult(exitCode: 0, stdout: "203.0.113.42\n", stderr: "")
        })
        let disabledResolved = RouteManager.resolveHostUsingBootstrap(
            host: "us-cmh.gw.openvpn.com",
            servers: disabledManager.dnsBootstrapServers,
            timeoutSeconds: 2,
            shell: disabledShell)
        #expect(
            disabledResolved == nil && disabledCommands.isEmpty,
            "An empty dnsBootstrapServers list should make DNS bootstrap resolve a no-op.")

        var literalCommands: [String] = []
        let literalShell = Shell(handler: { invocation -> ShellResult in
            literalCommands.append(invocation.launchPath)
            return ShellResult(exitCode: 0, stdout: "203.0.113.42\n", stderr: "")
        })
        let literalResolved = RouteManager.resolveHostUsingBootstrap(
            host: "203.0.113.10",
            servers: manager.dnsBootstrapServers,
            timeoutSeconds: 2,
            shell: literalShell)
        #expect(
            literalResolved == nil && literalCommands.isEmpty,
            "A remote that is already an IP literal needs no bootstrap resolution, so dig should never run."
        )

        for unsafeHost in ["-f/etc/passwd", "+tcp", "@127.0.0.1", "bad_host.example.edu"] {
            var unsafeCommands: [String] = []
            let unsafeShell = Shell(handler: { invocation -> ShellResult in
                unsafeCommands.append(invocation.launchPath)
                return ShellResult(exitCode: 0, stdout: "203.0.113.42\n", stderr: "")
            })
            let unsafeResolved = RouteManager.resolveHostUsingBootstrap(
                host: unsafeHost,
                servers: manager.dnsBootstrapServers,
                timeoutSeconds: 2,
                shell: unsafeShell)
            #expect(
                unsafeResolved == nil && unsafeCommands.isEmpty,
                "DNS bootstrap resolve must reject a remote host that is not a valid domain name before invoking dig, so profile content cannot inject dig options."
            )
        }
    }

    @Test
    func dnsBootstrapRetryHelpers() throws {
        let profile = "client\nremote us-cmh.gw.openvpn.com 1194 udp\n"
        #expect(
            VPNController.firstOpenVPNRemoteHost(in: profile) == "us-cmh.gw.openvpn.com",
            "The bootstrap retry should read the gateway hostname from the profile's first remote directive."
        )

        let crlfProfile = "client\r\nremote crlf.gw.openvpn.com 1194 udp\r\n"
        #expect(
            VPNController.firstOpenVPNRemoteHost(in: crlfProfile) == "crlf.gw.openvpn.com",
            "The bootstrap retry should parse CRLF profile remote directives.")

        let commentedFirst =
            "# remote ignored.example.com 1194 udp\nremote real.gw.example.edu 443 tcp\n"
        #expect(
            VPNController.firstOpenVPNRemoteHost(in: commentedFirst) == "real.gw.example.edu",
            "Commented-out remote lines must not be treated as the gateway host.")

        #expect(
            VPNController.firstOpenVPNRemoteHost(in: "client\ndev tun\n") == nil,
            "A profile without a remote directive has no gateway host to re-resolve.")

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
    func webAuthSinkholeDetection() throws {
        #expect(
            RouteManager.digAnswerIsSinkholed("0.0.0.0\n"),
            "An all-zero answer from the network resolver is the sinkhole signature.")
        #expect(
            RouteManager.digAnswerIsSinkholed("127.0.0.1\n"),
            "A loopback answer from the network resolver is also a sinkhole.")
        #expect(
            RouteManager.digAnswerIsSinkholed("cwru.openvpn.com.\n0.0.0.0\n"),
            "CNAME lines in the short answer must not hide the sinkholed address.")
        #expect(
            !RouteManager.digAnswerIsSinkholed("1.2.3.4\n"),
            "A routable answer means the network resolver is healthy and must not be overridden.")
        #expect(
            !RouteManager.digAnswerIsSinkholed("0.0.0.0\n1.2.3.4\n"),
            "One routable answer is enough to reach the host, so the resolver must not be overridden."
        )
        #expect(
            !RouteManager.digAnswerIsSinkholed(""),
            "An empty answer is ambiguous (offline, timeout, NXDOMAIN) and must not trigger a system DNS change."
        )
        #expect(
            !RouteManager.digAnswerIsSinkholed(
                "connection timed out; no servers could be reached\n"),
            "A resolver error must not be read as a sinkhole.")
    }

    @Test
    func webAuthBootstrapResolverOverride() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-webauth")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
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
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.appliedDNSDomains = ["case.edu"]

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
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                let withoutBootstrap = RouteManager(splitTunnelPolicy: configuration)
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
                    splitTunnelPolicy: configuration,
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
                        manager.resolverFileIsManaged(at: file),
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
                SplitTunnelPolicy.fixedDNSDomains.contains($0)
            }),
            "The sign-in override must never overlap the fixed CWRU scoped domains it would otherwise clobber."
        )

        #expect(
            RouteManager.webAuthBootstrapResolverDomains.allSatisfy {
                SplitTunnelPolicy.isValidDomainName($0) && ResolverPaths.isSafeDomainFileName($0)
            },
            "The sign-in override domains must stay safe resolver file names; ResolverPaths.fileURL traps on anything else."
        )
    }

    @Test
    func splitTunnelRejectsLeakyDefaultDNS() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-leaky-dns")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
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
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNSServers = ["129.22.4.32"]
        session.pushedSearchDomains = ["case.edu"]

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
            dnsCacheFlushAppliesDNSConfiguration: false)

        try withResolverDirectory(resolverDirectory) {
            do {
                try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                    try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
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

        let configuration = SplitTunnelPolicy(
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
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNSServers = ["129.22.4.32"]
        session.pushedSearchDomains = ["case.edu"]

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
            dnsCacheFlushAppliesDNSConfiguration: false)

        try withResolverDirectory(resolverDirectory) {
            do {
                try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                    try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
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

        let configuration = SplitTunnelPolicy(
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
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNSServers = ["129.22.4.32"]
        session.pushedSearchDomains = ["case.edu"]

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: [],
            physicalSearchDomains: [],
            ipv6Mode: "Automatic",
            activeDefaultDNSServers: [mockPublicDNSServerA, mockPublicDNSServerB],
            activeDefaultSearchDomains: ["case.edu"],
            tunnelInterfaces: ["utun7"],
            dnsCacheFlushAppliesDNSConfiguration: false)

        try withResolverDirectory(resolverDirectory) {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
        }

    }

    @Test
    func splitTunnelWaitsForDefaultSearchDomainCleanup() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-search-domain-wait")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
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
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.pushedDNSServers = ["129.22.4.32"]
        session.pushedSearchDomains = ["case.edu"]

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
            dnsCacheFlushAppliesDNSConfiguration: false,
            activeDefaultResolverClearsAfterScutilReads: 2)

        try withResolverDirectory(resolverDirectory) {
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                try RouteManager(splitTunnelPolicy: configuration).applySplitTunnel(
                    using: &session, persistPreparedState: persistPreparedState)
            }
        }

    }

    @Test
    func physicalDNSRepairIsWriteFreeWhenHealthy() throws {
        let configuration = SplitTunnelPolicy(ipv4Routes: [], dnsDomains: [], dnsServers: [])
        let session = makeSessionState(
            pid: 1030,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true)
        let manager = RouteManager(splitTunnelPolicy: configuration)

        func runRepairs(_ system: MockSystem, count: Int) throws -> (changes: [Bool], failures: [Error]) {
            var changes: [Bool] = []
            var failures: [Error] = []
            try Shell.withCommandHandler({ try system.handle($0) }) {
                for _ in 0..<count {
                    do {
                        let changed = try manager.restorePhysicalDNSConfigurationIfNeeded(using: session)
                        changes.append(changed)
                        if changed {
                            try manager.flushDNS()
                        }
                    } catch {
                        failures.append(error)
                        if VPNController.splitDNSRepairFailureRequiresFlush(error) {
                            try manager.flushDNS()
                        }
                    }
                }
            }
            return (changes, failures)
        }

        func expectSingleFlush(_ system: MockSystem) {
            #expect(system.recordedCommands.filter { $0 == "/usr/bin/dscacheutil -flushcache" }.count == 1)
            #expect(system.recordedCommands.filter { $0 == "/usr/bin/killall -HUP mDNSResponder" }.count == 1)
            #expect(system.scutilInputs.isEmpty)
        }

        let healthySystem = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic", tunnelInterfaces: ["utun7"])
        let healthyResult = try runRepairs(healthySystem, count: 2)
        #expect(healthyResult.changes == [false, false] && healthyResult.failures.isEmpty)
        #expect(healthySystem.scutilInputs.isEmpty)
        #expect(!healthySystem.recordedCommands.contains {
            $0.contains("networksetup -set") || $0.contains("-flushcache") || $0.contains("-HUP")
        })

        let driftedSystem = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: ["203.0.113.53"], physicalSearchDomains: [],
            ipv6Mode: "Automatic", tunnelInterfaces: ["utun7"])
        let driftedResult = try runRepairs(driftedSystem, count: 2)
        #expect(driftedResult.changes == [true, false] && driftedResult.failures.isEmpty)
        #expect(driftedSystem.recordedCommands.filter { $0.contains("networksetup -set") }.count == 2)
        expectSingleFlush(driftedSystem)

        let inspectionFailureSystem = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: ["203.0.113.53"], physicalSearchDomains: [],
            ipv6Mode: "Automatic", tunnelInterfaces: ["utun7"],
            failingCommandFragments: ["networksetup -getdnsservers"])
        let inspectionFailureResult = try runRepairs(inspectionFailureSystem, count: 1)
        #expect(inspectionFailureResult.changes.isEmpty && inspectionFailureResult.failures.count == 1)
        #expect(!inspectionFailureSystem.recordedCommands.contains {
            $0.contains("networksetup -set") || $0.contains("-flushcache") || $0.contains("-HUP")
        })

        let partialRepairSystem = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: ["203.0.113.53"], physicalSearchDomains: [],
            ipv6Mode: "Automatic", tunnelInterfaces: ["utun7"],
            failingCommandFragments: ["networksetup -setsearchdomains"])
        let partialRepairResult = try runRepairs(partialRepairSystem, count: 1)
        #expect(partialRepairResult.changes.isEmpty && partialRepairResult.failures.count == 1)
        #expect(VPNController.splitDNSRepairFailureRequiresFlush(try #require(partialRepairResult.failures.first)))
        expectSingleFlush(partialRepairSystem)
    }

    @Test
    func fullTunnelInstallsScopedResolversAndTakesOverDefaultDNS() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-full-scoped")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu", "cwru.edu"],
            dnsServers: ["129.22.4.32"],
        )

        let session = makeSessionState(
            pid: 1043,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
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
                splitTunnelPolicy: configuration,
                shell: Shell(handler: { try mockSystem.handle($0) }),
                resolverDirectory: resolverDirectory)
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            _ = try manager.applyFullTunnelDNSConfigurationIfAvailable(using: session)

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
                "/usr/sbin/networksetup -setdnsservers Wi-Fi 129.22.4.32"),
            "Full tunnel must point the physical-service default DNS at CWRU DNS.")
        #expect(
            mockSystem.recordedCommands.contains { command in
                command.hasPrefix("/usr/sbin/networksetup -setsearchdomains Wi-Fi")
                    && command.contains("case.edu")
            },
            "Full tunnel must use the fixed scoped domains for the default search domains.")
        #expect(
            !mockSystem.scutilInputs.contains { $0.contains("SupplementalMatchDomains") },
            "Full tunnel must not install a catch-all supplemental resolver.")
    }

    @Test
    func fullTunnelRejectsPhysicallyRoutedPushedDNS() throws {
        let resolverDirectory = temporaryDirectory(
            named: "cwru-ovpn-resolver-full-physical-pushed-dns")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
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
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.fullTunnelDNSServers = ["192.168.1.1", "203.0.113.10"]

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

        try withResolverDirectory(resolverDirectory) {
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                _ = try RouteManager(splitTunnelPolicy: configuration)
                    .applyFullTunnelDNSConfigurationIfAvailable(using: session)
            }
        }

        #expect(
            mockSystem.recordedCommands.contains(
                "/usr/sbin/networksetup -setdnsservers Wi-Fi 129.22.4.32"),
            "Full tunnel must reject a pushed DNS server whose route resolves over the physical interface."
        )
        #expect(
            !mockSystem.recordedCommands.contains {
                $0.hasPrefix("/usr/sbin/networksetup -setdnsservers Wi-Fi")
                    && $0.contains("192.168.1.1")
            },
            "Full tunnel must not persist a server-selected physical LAN resolver.")
        #expect(
            !mockSystem.recordedCommands.contains {
                $0.hasPrefix("/usr/sbin/networksetup -setdnsservers Wi-Fi")
                    && $0.contains("203.0.113.10")
            },
            "Full tunnel must not use the physically routed VPN control-channel address as a DNS server."
        )

        let unsafeConfiguration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["203.0.113.10"],
        )
        let failClosedSystem = MockSystem(
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
        do {
            try Shell.withCommandHandler({ try failClosedSystem.handle($0) }) {
                _ = try RouteManager(splitTunnelPolicy: unsafeConfiguration)
                    .applyFullTunnelDNSConfigurationIfAvailable(using: session)
            }
            try #require(
                Bool(false),
                "Full tunnel must fail closed when neither learned nor policy DNS is routed through the tunnel."
            )
        } catch RouteManagerError.failedToSecureFullTunnelDNS {
        }
        #expect(
            !failClosedSystem.recordedCommands.contains {
                $0.hasPrefix("/usr/sbin/networksetup -setdnsservers")
            },
            "Full tunnel must not mutate DNS before rejecting an entirely unsafe DNS set.")
    }

    @Test
    func fullTunnelDNSApplicationIsIdempotent() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-full-idempotent")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )

        let session = makeSessionState(
            pid: 1093,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Off",
            tunName: "utun7",
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
                splitTunnelPolicy: configuration,
                shell: Shell(handler: { try mockSystem.handle($0) }),
                resolverDirectory: resolverDirectory)
            try FileManager.default.createDirectory(
                at: resolverDirectory, withIntermediateDirectories: true)
            try manager.applyFullTunnelDNSConfigurationIfAvailable(using: session)
            try manager.applyFullTunnelDNSConfigurationIfAvailable(using: session)
        }

        let dnsSetCount = mockSystem.recordedCommands.filter {
            $0.hasPrefix("/usr/sbin/networksetup -setdnsservers Wi-Fi")
        }.count
        let searchSetCount = mockSystem.recordedCommands.filter {
            $0.hasPrefix("/usr/sbin/networksetup -setsearchdomains Wi-Fi")
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

        let configuration = SplitTunnelPolicy(
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
            tunName: "utun7",
            tunnelMode: .full,
            cleanupNeeded: true
        )
        session.fullTunnelDNSServers = ["10.0.0.53"]
        session.pushedDNSServers = ["10.0.0.54"]

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
            try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
                _ = try RouteManager(splitTunnelPolicy: configuration)
                    .applyFullTunnelDNSConfigurationIfAvailable(using: session)
            }

            let resolverContents = try String(
                contentsOf: testResolverFileURL(for: "case.edu"),
                encoding: .utf8)
            #expect(
                resolverContents.contains("nameserver 10.0.0.53"),
                "Full-tunnel scoped resolvers should prefer pushed/full-tunnel DNS servers.")
            #expect(
                !resolverContents.contains("nameserver 129.22.4.32"),
                "Fixed policy DNS servers should not override learned full-tunnel DNS servers.")
        }
    }

    @Test(arguments: ["-getdnsservers", "-getsearchdomains", "-getinfo"])
    func failedDNSSnapshotIsNotAccepted(command: String) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-dns-snapshot")
        defer { try? FileManager.default.removeItem(at: directory) }
        let system = MockSystem(serviceName: "Wi-Fi", physicalGateway: "192.168.1.1",
                                physicalInterface: "en0", physicalDNSServers: ["1.1.1.1"],
                                physicalSearchDomains: [], ipv6Mode: "Automatic", tunnelInterfaces: [])
        let manager = RouteManager(shell: Shell(handler: { invocation in
            if invocation.launchPath == "/usr/sbin/networksetup", invocation.arguments.first == command {
                return ShellResult(exitCode: 1, stdout: "", stderr: "service unavailable")
            }
            return try system.handle(invocation)
        }), resolverDirectory: directory, remoteHostRouteLedger: RemoteHostRouteLedger(directory: directory))
        #expect(throws: (any Error).self) {
            _ = try manager.capturePhysicalDNSConfiguration(for: "en0")
        }
    }

    @Test
    func failedDNSInspectionDoesNotPassIsolation() throws {
        let manager = RouteManager(shell: Shell(handler: { _ in
            ShellResult(exitCode: 1, stdout: "", stderr: "inspection unavailable")
        }))
        let session = makeSessionState(
            pid: Int32.max - 18, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalServiceName: "Wi-Fi", originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: [], originalIPv6Mode: "Automatic", tunName: "utun7",
            tunnelMode: .split, cleanupNeeded: true)
        #expect(throws: (any Error).self) {
            _ = try manager.validateActiveDefaultResolverIsolation(using: session)
        }
    }

}
