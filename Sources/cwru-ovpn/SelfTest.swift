#if CWRU_OVPN_INCLUDE_SELF_TEST

import Darwin
import Foundation

enum SelfTestError: LocalizedError {
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .failed(let message):
            return message
        }
    }
}

enum SelfTest {
    static func run() throws {
        try testReachabilityProbeConfig()
        try testAllowSleepConfig()
        try testLegacyConfigKeys()
        try testRuntimeValidationHardening()
        try testCLIConnectModes()
        try testCLIAdvancedOptions()
        try testGeneratedSudoers()
        try testRecoveryState()
        try testStatusIndicators()
        try testRouteCanonicalization()
        try testReverseResolverZoneDerivation()
        try testDetachedStartupStatus()
        try testShellIntegrationBlocks()
        try testMockedSplitTunnelFlow()
        try testMockedFullTunnelModeSwitch()
        try testMockedStaleStateRecovery()
        print("Self-test passed.")
    }

    private static func testReachabilityProbeConfig() throws {
        let defaultedData = Data(
            """
            {
              "splitTunnel": {
                "includedRoutes": [],
                "resolverDomains": [],
                "resolverNameServers": []
              }
            }
            """.utf8
        )

        let defaultedConfig = try JSONDecoder().decode(AppConfig.self, from: defaultedData)
        try expect(defaultedConfig.splitTunnel.effectiveReachabilityProbeHosts == AppConfig.SplitTunnelConfiguration.defaultReachabilityProbeHosts,
                   "Reachability probes should use the built-in defaults when config omits them.")

        let disabledData = Data(
            """
            {
              "splitTunnel": {
                "includedRoutes": [],
                "resolverDomains": [],
                "resolverNameServers": [],
                "reachabilityProbeHosts": []
              }
            }
            """.utf8
        )

        let disabledConfig = try JSONDecoder().decode(AppConfig.self, from: disabledData)
        try expect(disabledConfig.splitTunnel.effectiveReachabilityProbeHosts.isEmpty,
                   "An empty reachabilityProbeHosts list should disable probes.")

        let invalidProbeHost = AppConfig.SplitTunnelConfiguration(
            includedRoutes: [],
            resolverDomains: [],
            resolverNameServers: [],
            reachabilityProbeHosts: ["bad host"]
        )
        try expect(invalidProbeHost.validationError() != nil,
                   "Reachability probe targets should reject malformed hostnames.")
    }

    private static func testAllowSleepConfig() throws {
        let defaultedData = Data(
            """
            {
              "splitTunnel": {
                "includedRoutes": [],
                "resolverDomains": [],
                "resolverNameServers": []
              }
            }
            """.utf8
        )

        let defaultedConfig = try JSONDecoder().decode(AppConfig.self, from: defaultedData)
        try expect(!defaultedConfig.allowSleep,
                   "allowSleep should default to false when omitted from config.")

        let enabledData = Data(
            """
            {
              "allowSleep": true,
              "splitTunnel": {
                "includedRoutes": [],
                "resolverDomains": [],
                "resolverNameServers": []
              }
            }
            """.utf8
        )

        let enabledConfig = try JSONDecoder().decode(AppConfig.self, from: enabledData)
        try expect(enabledConfig.allowSleep,
                   "allowSleep should decode when explicitly enabled in config.")
    }

    private static func testLegacyConfigKeys() throws {
        let legacyData = Data(
            """
            {
              "defaultProfilePath": "~/.cwru-ovpn/profile.ovpn",
              "allowIdleSleep": true,
              "splitTunnel": {
                "includedRoutes": [],
                "resolverDomains": [],
                "resolverNameServers": []
              }
            }
            """.utf8
        )

        let legacyConfig = try JSONDecoder().decode(AppConfig.self, from: legacyData)
        try expect(legacyConfig.profilePath == "~/.cwru-ovpn/profile.ovpn",
                   "Legacy defaultProfilePath should keep decoding for existing installs.")
        try expect(legacyConfig.allowSleep,
                   "Legacy allowIdleSleep should keep decoding for existing installs.")
    }

    private static func testCLIConnectModes() throws {
        switch try CLI.parse(arguments: []) {
        case .help:
            break
        default:
            throw SelfTestError.failed("Bare CLI invocation should show help.")
        }

        switch try CLI.parse(arguments: ["connect"]) {
        case .connect(_, _, _, let allowSleep, let foregroundRequested, let backgroundChild, let startupStatusFilePath):
            try expect(!allowSleep,
                       "connect should keep preventing idle sleep by default.")
            try expect(!foregroundRequested,
                       "connect should detach from the terminal by default.")
            try expect(!backgroundChild,
                       "connect should not mark itself as the background child.")
            try expect(startupStatusFilePath == nil,
                       "connect should not set a detached startup status file by default.")
        default:
            throw SelfTestError.failed("connect should parse as the connect command.")
        }

        switch try CLI.parse(arguments: ["connect", "--foreground"]) {
        case .connect(_, _, _, let allowSleep, let foregroundRequested, let backgroundChild, let startupStatusFilePath):
            try expect(!allowSleep,
                       "connect --foreground should not change idle sleep behavior.")
            try expect(foregroundRequested,
                       "connect --foreground should honor --foreground.")
            try expect(!backgroundChild,
                       "connect --foreground should not mark itself as the background child.")
            try expect(startupStatusFilePath == nil,
                       "connect --foreground should not inject a detached startup status file.")
        default:
            throw SelfTestError.failed("connect --foreground should parse as connect.")
        }

        switch try CLI.parse(arguments: ["connect", "--allow-sleep"]) {
        case .connect(_, _, _, let allowSleep, let foregroundRequested, let backgroundChild, let startupStatusFilePath):
            try expect(allowSleep,
                       "connect --allow-sleep should allow idle sleep for this run.")
            try expect(!foregroundRequested,
                       "connect --allow-sleep should not force foreground mode.")
            try expect(!backgroundChild,
                       "connect --allow-sleep should not mark itself as the background child.")
            try expect(startupStatusFilePath == nil,
                       "connect --allow-sleep should not inject a detached startup status file.")
        default:
            throw SelfTestError.failed("connect --allow-sleep should parse as connect.")
        }

        switch try CLI.parse(arguments: ["disconnect", "-f"]) {
        case .disconnect(let force):
            try expect(force,
                       "disconnect -f should parse as a forced disconnect.")
        default:
            throw SelfTestError.failed("disconnect -f should still parse as disconnect.")
        }
    }

    private static func testCLIAdvancedOptions() throws {
        switch try CLI.parse(arguments: ["setup", "--profile", "/tmp/profile.ovpn"]) {
        case .setup(let profileSourcePath):
            try expect(profileSourcePath == "/tmp/profile.ovpn",
                       "setup should accept --profile.")
        default:
            throw SelfTestError.failed("setup --profile should parse as setup.")
        }

        switch try CLI.parse(arguments: ["connect", "--config", "/tmp/config.json"]) {
        case .connect(let configFilePath, _, _, _, _, _, let startupStatusFilePath):
            try expect(configFilePath == "/tmp/config.json",
                       "connect should accept --config for the config file.")
            try expect(startupStatusFilePath == nil,
                       "connect --config should not inject a detached startup status file.")
        default:
            throw SelfTestError.failed("connect --config should parse as connect.")
        }

        switch try CLI.parse(arguments: ["logs", "--tail", "25"]) {
        case .logs(let tailCount):
            try expect(tailCount == 25,
                       "logs --tail should accept a positive tail count.")
        default:
            throw SelfTestError.failed("logs --tail should parse as logs.")
        }

        switch try CLI.parse(arguments: ["doctor"]) {
        case .doctor:
            break
        default:
            throw SelfTestError.failed("doctor should parse as doctor.")
        }

        switch try CLI.parse(arguments: ["uninstall", "--purge"]) {
        case .uninstall(let purge):
            try expect(purge,
                       "uninstall --purge should parse as uninstall with purge enabled.")
        default:
            throw SelfTestError.failed("uninstall --purge should parse as uninstall.")
        }

        switch try CLI.parse(arguments: ["install-shell-integration", "--shell", "/bin/zsh", "--legacy-source", "/tmp/cwru-ovpn.zsh"]) {
        case .installShellIntegration(let preferredShellPath, let legacySourcePaths):
            try expect(preferredShellPath == "/bin/zsh",
                       "install-shell-integration should accept --shell.")
            try expect(legacySourcePaths == ["/tmp/cwru-ovpn.zsh"],
                       "install-shell-integration should accept --legacy-source.")
        default:
            throw SelfTestError.failed("install-shell-integration should parse as the helper command.")
        }

        try expectRejectsUnexpectedArgument(["--config", "/tmp/config.json"],
                                            command: "bare invocation",
                                            argument: "--config")
        try expectRejectsUnexpectedArgument(["--profile", "/tmp/profile.ovpn"],
                                            command: "connect",
                                            argument: "--profile")
        try expectRejectsUnexpectedArgument(["setup", "--config", "/tmp/config.json"],
                                            command: "setup",
                                            argument: "--config")
        try expectRejectsUnexpectedArgument(["disconnect", "--config", "/tmp/config.json"],
                                            command: "disconnect",
                                            argument: "--config")
        try expectRejectsUnexpectedArgument(["status", "--config", "/tmp/config.json"],
                                            command: "status",
                                            argument: "--config")
        try expectRejectsUnexpectedArgument(["uninstall", "--config", "/tmp/config.json"],
                                            command: "uninstall",
                                            argument: "--config")
    }

    private static func testGeneratedSudoers() throws {
        let username = "codex"
        let executablePath = "/tmp/cwru-ovpn"
        let sudoers = Setup.renderSudoers(username: username,
                                          executablePath: executablePath)

        let lines = sudoers.split(separator: "\n")
        try expect(lines.count == 23,
                   "Generated sudoers should cover the standard connect combinations plus disconnect (plain, -f, and --force), status, and plain setup.")
        try expect(sudoers.contains("\(username) ALL=(root) NOPASSWD: \(executablePath) connect --allow-sleep"),
                   "Generated sudoers should include the allow-sleep connect variant.")
        try expect(sudoers.contains("\(username) ALL=(root) NOPASSWD: \(executablePath) disconnect"),
                   "Generated sudoers should allow disconnect without requiring a config flag.")
        try expect(sudoers.contains("\(username) ALL=(root) NOPASSWD: \(executablePath) disconnect -f"),
                   "Generated sudoers should allow disconnect -f for shell-friendly force disconnects.")
        try expect(sudoers.contains("\(username) ALL=(root) NOPASSWD: \(executablePath) disconnect --force"),
                   "Generated sudoers should allow disconnect --force for stuck sessions.")
        try expect(sudoers.contains("\(username) ALL=(root) NOPASSWD: \(executablePath) status"),
                   "Generated sudoers should allow status without requiring a config flag.")
        try expect(sudoers.contains("\(username) ALL=(root) NOPASSWD: \(executablePath) setup"),
                   "Generated sudoers should allow plain setup.")
        try expect(!sudoers.contains("--config"),
                   "Generated sudoers should not depend on a config path.")
        try expect(!sudoers.contains("setup --profile"),
                   "Generated sudoers should not allow passwordless setup with an arbitrary profile path.")
        try expect(!sudoers.contains("--foreground --verbosity"),
                   "Generated sudoers should keep a canonical argument order.")

        let tempURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("cwru-ovpn-selftest-sudoers-\(UUID().uuidString)")
        try sudoers.appending("\n").write(to: tempURL, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let validation = try Setup.validateSudoersFile(at: tempURL.path)
        try expect(validation.exitCode == 0,
                   "Generated sudoers should pass visudo validation.")
    }

    private static func testRuntimeValidationHardening() throws {
        try expect(AppConfig.SplitTunnelConfiguration.isValidIPAddress("1.1.1.1"),
                   "IPv4 addresses should validate.")
        try expect(!AppConfig.SplitTunnelConfiguration.isValidIPAddress("1.1.1.1\nnameserver 8.8.8.8"),
                   "Injected multiline DNS payloads should be rejected.")
        try expect(AppConfig.SplitTunnelConfiguration.isValidDomainName("case.edu"),
                   "Expected resolver domains should validate.")
        try expect(!AppConfig.SplitTunnelConfiguration.isValidDomainName("case.edu/../../etc"),
                   "Path-like resolver domains should be rejected.")
    }

    private static func testRecoveryState() throws {
        var session = SessionState(
            pid: 100,
            executablePath: nil,
            phase: .disconnecting,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: "/tmp/config.json",
            startedAt: Date(timeIntervalSince1970: 0),
            lastEvent: nil,
            lastInfo: nil,
            physicalGateway: nil,
            physicalInterface: nil,
            physicalServiceName: nil,
            originalDNSServers: nil,
            originalSearchDomains: nil,
            originalIPv6Mode: nil,
            pushedDNSServers: nil,
            pushedSearchDomains: nil,
            tunName: nil,
            vpnIPv4: nil,
            serverHost: nil,
            serverIP: nil,
            tunnelMode: .split,
            requestedTunnelMode: nil,
            fullTunnelDefaultRoutes: nil,
            fullTunnelDNSServers: nil,
            fullTunnelSearchDomains: nil,
            appliedIncludedRoutes: nil,
            appliedResolverDomains: nil,
            routesApplied: false,
            cleanupNeeded: false
        )

        session.markRecoveryRequired(message: "Cleanup failed.")

        try expect(session.phase == .failed,
                   "markRecoveryRequired should set the session phase to failed.")
        try expect(session.lastEvent == "RECOVERY_REQUIRED",
                   "markRecoveryRequired should persist a recovery event marker.")
        try expect(session.lastInfo == "Cleanup failed.",
                   "markRecoveryRequired should preserve the recovery message.")
        try expect(session.cleanupNeeded,
                   "markRecoveryRequired should keep cleanupNeeded enabled.")
        try expect(VPNController.recoveryDetail(for: session, stale: true)
                    == "Cleanup failed. Run ovpnd again to retry restoring routes and DNS.",
                   "Recovery detail should guide the user to retry disconnect.")
        try expect(VPNController.statusTitle(for: .failed, stale: true, recoveryNeeded: true) == "Recovery Needed",
                   "Recovery state should have a distinct status title.")
    }

    private static func testStatusIndicators() throws {
        try expect(VPNController.statusIndicator(for: .connected, tunnelMode: .split) == "◐",
                   "Connected split tunnel should use the half-filled circle.")
        try expect(VPNController.statusIndicator(for: .connected, tunnelMode: .full) == "●",
                   "Connected full tunnel should use the filled circle.")
        try expect(VPNController.statusIndicator(for: .connecting, tunnelMode: .split) == "○",
                   "Non-connected states should use the hollow circle.")
    }

    private static func testRouteCanonicalization() throws {
        try expect(RouteManager.canonicalIPv4Route("129.22.0.0/16") == RouteManager.canonicalIPv4Route("129.22"),
                   "Octet-boundary routes should match netstat's shortened labels.")
        try expect(RouteManager.canonicalIPv4Route("129.22.32.0/20") == RouteManager.canonicalIPv4Route("129.22.32/20"),
                   "Non-octet-boundary routes should match netstat labels with explicit prefixes.")
        try expect(RouteManager.canonicalIPv4Route("129.22.32.0/20") != RouteManager.canonicalIPv4Route("129.22.48.0/20"),
                   "Distinct networks should not canonicalize to the same route.")
        try expect(RouteManager.canonicalIPv4Route("default") == nil,
                   "Non-IPv4 route labels should not canonicalize as split-tunnel routes.")
    }

    private static func testReverseResolverZoneDerivation() throws {
        try expect(AppConfig.SplitTunnelConfiguration.reverseResolverZones(forIncludedRoutes: ["129.22.0.0/16"])
                    == ["22.129.in-addr.arpa"],
                   "A /16 CIDR should derive a two-label reverse zone.")
        try expect(AppConfig.SplitTunnelConfiguration.reverseResolverZones(forIncludedRoutes: ["10.0.0.0/8"])
                    == ["10.in-addr.arpa"],
                   "A /8 CIDR should derive a one-label reverse zone.")
        try expect(AppConfig.SplitTunnelConfiguration.reverseResolverZones(forIncludedRoutes: ["129.22.32.0/20"])
                    == ["22.129.in-addr.arpa"],
                   "Sub-octet prefixes should round down to the nearest octet boundary.")
        try expect(AppConfig.SplitTunnelConfiguration.reverseResolverZones(forIncludedRoutes: ["0.0.0.0/0"])
                    == [],
                   "Routes with no octet boundary should not derive a reverse zone.")

        let config = AppConfig.SplitTunnelConfiguration(
            includedRoutes: ["129.22.0.0/16"],
            resolverDomains: ["case.edu"],
            resolverNameServers: [],
            reachabilityProbeHosts: nil
        )
        try expect(config.effectiveResolverDomains == ["case.edu", "22.129.in-addr.arpa"],
                   "effectiveResolverDomains should merge user domains with derived reverse zones.")
    }

    private static func testDetachedStartupStatus() throws {
        let tempURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("cwru-ovpn-startup-status-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: tempURL) }

        DetachedStartupStatus.writeFailure(message: "Profile missing.", to: tempURL.path)
        let loaded = DetachedStartupStatus.load(from: tempURL.path)

        try expect(loaded?.state == .failed,
                   "Detached startup status should decode the failure state.")
        try expect(loaded?.message == "Profile missing.",
                   "Detached startup status should preserve the failure message.")
    }

    private static func testShellIntegrationBlocks() throws {
        let legacyHelperPath = "/tmp/repo/scripts/cwru-ovpn.zsh"
        let installedHelperPath = "/Users/test/.cwru-ovpn/cwru-ovpn.zsh"
        let initialContent = """
        export PATH="/usr/local/bin:$PATH"

        # >>> cwru-ovpn >>>
        source \(legacyHelperPath)
        # <<< cwru-ovpn <<<
        """

        let installedContent = ShellIntegration.installBlock(into: initialContent,
                                                             helperPath: installedHelperPath,
                                                             legacySourcePaths: [legacyHelperPath])
        try expect(installedContent.contains("source \(installedHelperPath)"),
                   "Shell integration should point marker blocks at the installed helper.")
        try expect(!installedContent.contains(legacyHelperPath),
                   "Shell integration should replace legacy repo-local helper paths.")

        let removedContent = ShellIntegration.removeBlock(from: installedContent,
                                                          helperPaths: [installedHelperPath, legacyHelperPath])
        try expect(!removedContent.contains("cwru-ovpn"),
                   "Removing shell integration should drop the managed marker block.")
        try expect(removedContent.contains("export PATH"),
                   "Removing shell integration should preserve unrelated shell content.")
    }

    private static func testMockedSplitTunnelFlow() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-split")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = AppConfig.SplitTunnelConfiguration(
            includedRoutes: ["129.22.0.0/16"],
            resolverDomains: ["case.edu"],
            resolverNameServers: ["129.22.4.32"],
            reachabilityProbeHosts: nil
        )

        var session = makeSessionState(
            pid: 1001,
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

        let mockSystem = MockSystem(serviceName: "Wi-Fi",
                                    physicalGateway: "192.168.1.1",
                                    physicalInterface: "en0",
                                    physicalDNSServers: ["1.1.1.1"],
                                    physicalSearchDomains: ["home"],
                                    ipv6Mode: "Automatic",
                                    tunnelInterfaces: ["utun7"])

        try withEnvironmentVariable("CWRU_OVPN_RESOLVER_DIR", value: resolverDirectory.path) {
            try Shell.withTestHook({ try mockSystem.handle($0) }) {
                try RouteManager(configuration: configuration).applySplitTunnel(using: &session)
            }
            try expect(session.routesApplied,
                       "Applying split tunnel should mark routesApplied.")
            try expect(session.appliedResolverDomains == ["case.edu", "22.129.in-addr.arpa"],
                       "Applying split tunnel should persist the effective resolver domains.")

            let resolverFile = ResolverPaths.fileURL(for: "case.edu")
            let reverseResolverFile = ResolverPaths.fileURL(for: "22.129.in-addr.arpa")
            let resolverContents = try String(contentsOf: resolverFile, encoding: .utf8)
            try expect(resolverContents.contains("nameserver 129.22.4.32"),
                       "Applying split tunnel should install scoped resolver files with VPN DNS servers.")
            try expect(FileManager.default.fileExists(atPath: reverseResolverFile.path),
                       "Applying split tunnel should install reverse-zone resolver files for included routes.")
        }
        try expect(mockSystem.recordedCommands.contains("/sbin/route -n add -net 0.0.0.0/1 192.168.1.1"),
                   "Applying split tunnel should add the lower-half default route override.")
        try expect(mockSystem.recordedCommands.contains("/sbin/route -n add -net 129.22.0.0/16 -interface utun7"),
                   "Applying split tunnel should route included CIDRs through the tunnel interface.")
    }

    private static func testMockedFullTunnelModeSwitch() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-full")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = AppConfig.SplitTunnelConfiguration(
            includedRoutes: ["129.22.0.0/16"],
            resolverDomains: ["case.edu"],
            resolverNameServers: ["129.22.4.32"],
            reachabilityProbeHosts: nil
        )

        var session = makeSessionState(
            pid: 1002,
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
        session.appliedIncludedRoutes = ["129.22.0.0/16"]
        session.appliedResolverDomains = ["case.edu", "22.129.in-addr.arpa"]
        session.fullTunnelDNSServers = ["10.8.0.2"]
        session.fullTunnelSearchDomains = ["case.edu"]

        try withEnvironmentVariable("CWRU_OVPN_RESOLVER_DIR", value: resolverDirectory.path) {
            try FileManager.default.createDirectory(at: resolverDirectory, withIntermediateDirectories: true)
            try "nameserver 129.22.4.32\ndomain case.edu\nsearch_order 1\n".write(to: ResolverPaths.fileURL(for: "case.edu"),
                                                                                     atomically: true,
                                                                                     encoding: .utf8)

            let mockSystem = MockSystem(serviceName: "Wi-Fi",
                                        physicalGateway: "192.168.1.1",
                                        physicalInterface: "en0",
                                        physicalDNSServers: ["1.1.1.1"],
                                        physicalSearchDomains: ["home"],
                                        ipv6Mode: "Automatic",
                                        tunnelInterfaces: ["utun7"])

            try Shell.withTestHook({ try mockSystem.handle($0) }) {
                try RouteManager(configuration: configuration).switchToFullTunnel(
                    using: &session,
                    fullTunnelRoutes: [
                        ManagedIPv4Route(destination: "0.0.0.0/1", nextHopKind: .interface, nextHopValue: "utun7"),
                        ManagedIPv4Route(destination: "128.0.0.0/1", nextHopKind: .interface, nextHopValue: "utun7"),
                    ]
                )
            }

            try expect(!session.routesApplied,
                       "Switching to full tunnel should clear split-tunnel route state.")
            try expect(!FileManager.default.fileExists(atPath: ResolverPaths.fileURL(for: "case.edu").path),
                       "Switching to full tunnel should remove split-tunnel scoped resolver files.")
        }
    }

    private static func testMockedStaleStateRecovery() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-home-state")
        defer { try? FileManager.default.removeItem(at: homeStateDirectory) }
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-recovery")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let mockSystem = MockSystem(serviceName: "Wi-Fi",
                                    physicalGateway: "192.168.1.1",
                                    physicalInterface: "en0",
                                    physicalDNSServers: ["1.1.1.1"],
                                    physicalSearchDomains: ["home"],
                                    ipv6Mode: "Automatic",
                                    tunnelInterfaces: ["utun7"])

        try withEnvironmentVariable("CWRU_OVPN_HOME_STATE_DIR", value: homeStateDirectory.path) {
            try withEnvironmentVariable("CWRU_OVPN_RESOLVER_DIR", value: resolverDirectory.path) {
                let profileURL = RuntimePaths.homeProfileFile
                let configURL = RuntimePaths.homeConfigFile
                try FileManager.default.createDirectory(at: RuntimePaths.homeStateDirectory, withIntermediateDirectories: true)
                try "".write(to: profileURL, atomically: true, encoding: .utf8)
                try """
                {
                  "profilePath": "\(profileURL.path)",
                  "tunnelMode": "split",
                  "allowSleep": false,
                  "verbosity": "daily",
                  "splitTunnel": {
                    "includedRoutes": ["129.22.0.0/16"],
                    "resolverDomains": ["case.edu"],
                    "resolverNameServers": ["129.22.4.32"]
                  }
                }
                """.write(to: configURL, atomically: true, encoding: .utf8)

                var session = makeSessionState(
                    pid: Int32.max - 10,
                    profilePath: profileURL.path,
                    configFilePath: configURL.path,
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
                session.appliedIncludedRoutes = ["129.22.0.0/16"]
                session.appliedResolverDomains = ["case.edu", "22.129.in-addr.arpa"]
                try session.save()

                try FileManager.default.createDirectory(at: resolverDirectory, withIntermediateDirectories: true)
                try "nameserver 129.22.4.32\ndomain case.edu\nsearch_order 1\n".write(to: ResolverPaths.fileURL(for: "case.edu"),
                                                                                         atomically: true,
                                                                                         encoding: .utf8)

                try Shell.withTestHook({ try mockSystem.handle($0) }) {
                    try VPNController.disconnectExistingSession(force: false)
                }

                try expect(SessionState.load() == nil,
                           "Recovering stale state should remove the persisted session after healthy cleanup.")
                try expect(!FileManager.default.fileExists(atPath: ResolverPaths.fileURL(for: "case.edu").path),
                           "Recovering stale state should remove scoped resolver files.")
            }
        }
    }

    private static func withEnvironmentVariable<T>(_ name: String,
                                                   value: String,
                                                   body: () throws -> T) throws -> T {
        let previousValue = getenv(name).map { String(cString: $0) }
        setenv(name, value, 1)
        defer {
            if let previousValue {
                setenv(name, previousValue, 1)
            } else {
                unsetenv(name)
            }
        }
        return try body()
    }

    private static func temporaryDirectory(named prefix: String) -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private static func makeSessionState(pid: Int32,
                                         profilePath: String,
                                         configFilePath: String?,
                                         physicalGateway: String,
                                         physicalInterface: String,
                                         physicalServiceName: String,
                                         originalDNSServers: [String],
                                         originalSearchDomains: [String],
                                         originalIPv6Mode: String,
                                         tunName: String,
                                         tunnelMode: AppTunnelMode,
                                         cleanupNeeded: Bool) -> SessionState {
        SessionState(
            pid: pid,
            executablePath: "/tmp/cwru-ovpn",
            phase: .connected,
            profilePath: profilePath,
            configFilePath: configFilePath,
            startedAt: Date(timeIntervalSince1970: 0),
            lastEvent: nil,
            lastInfo: nil,
            physicalGateway: physicalGateway,
            physicalInterface: physicalInterface,
            physicalServiceName: physicalServiceName,
            originalDNSServers: originalDNSServers,
            originalSearchDomains: originalSearchDomains,
            originalIPv6Mode: originalIPv6Mode,
            pushedDNSServers: nil,
            pushedSearchDomains: nil,
            tunName: tunName,
            vpnIPv4: "10.8.0.10",
            serverHost: "cwru.openvpn.com",
            serverIP: "203.0.113.10",
            tunnelMode: tunnelMode,
            requestedTunnelMode: nil,
            fullTunnelDefaultRoutes: nil,
            fullTunnelDNSServers: nil,
            fullTunnelSearchDomains: nil,
            appliedIncludedRoutes: nil,
            appliedResolverDomains: nil,
            routesApplied: false,
            cleanupNeeded: cleanupNeeded
        )
    }

    private final class MockSystem {
        struct RouteRecord {
            let destination: String
            let gateway: String
            let interfaceName: String
        }

        private let serviceName: String
        private var defaultGateway: String
        private var defaultInterface: String
        private var dnsServers: [String]
        private var searchDomains: [String]
        private var ipv6Mode: String
        private let tunnelInterfaces: Set<String>
        private var routes: [RouteRecord]

        var recordedCommands: [String] = []

        init(serviceName: String,
             physicalGateway: String,
             physicalInterface: String,
             physicalDNSServers: [String],
             physicalSearchDomains: [String],
             ipv6Mode: String,
             tunnelInterfaces: Set<String>) {
            self.serviceName = serviceName
            self.defaultGateway = physicalGateway
            self.defaultInterface = physicalInterface
            self.dnsServers = physicalDNSServers
            self.searchDomains = physicalSearchDomains
            self.ipv6Mode = ipv6Mode
            self.tunnelInterfaces = tunnelInterfaces
            self.routes = [
                RouteRecord(destination: "default",
                            gateway: physicalGateway,
                            interfaceName: physicalInterface)
            ]
        }

        func handle(_ invocation: ShellInvocation) throws -> ShellResult? {
            recordedCommands.append(([invocation.launchPath] + invocation.arguments).joined(separator: " "))

            switch invocation.launchPath {
            case "/sbin/route":
                return handleRoute(arguments: invocation.arguments)
            case "/usr/sbin/netstat":
                return ShellResult(exitCode: 0, stdout: netstatOutput(), stderr: "")
            case "/usr/sbin/networksetup":
                return handleNetworkSetup(arguments: invocation.arguments)
            case "/usr/bin/dscacheutil", "/usr/bin/killall":
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            case "/bin/mkdir":
                if invocation.arguments.count == 2, invocation.arguments[0] == "-p" {
                    try FileManager.default.createDirectory(atPath: invocation.arguments[1],
                                                            withIntermediateDirectories: true,
                                                            attributes: nil)
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }
            case "/usr/bin/tee":
                guard let path = invocation.arguments.first, let input = invocation.input else {
                    throw SelfTestError.failed("tee should receive a destination path and input data.")
                }
                let url = URL(fileURLWithPath: path)
                try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
                try input.write(to: url, options: .atomic)
                return ShellResult(exitCode: 0, stdout: String(decoding: input, as: UTF8.self), stderr: "")
            case "/bin/rm":
                if let path = invocation.arguments.last {
                    try? FileManager.default.removeItem(atPath: path)
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }
            case "/sbin/ifconfig":
                let interfaceName = invocation.arguments.first ?? ""
                return ShellResult(exitCode: tunnelInterfaces.contains(interfaceName) ? 0 : 1, stdout: "", stderr: "")
            default:
                break
            }

            throw SelfTestError.failed("Unexpected shell command in mocked integration test: \(([invocation.launchPath] + invocation.arguments).joined(separator: " "))")
        }

        private func handleRoute(arguments: [String]) -> ShellResult {
            if arguments == ["-n", "get", "default"] {
                return ShellResult(exitCode: 0,
                                   stdout: "route to: default\ngateway: \(defaultGateway)\ninterface: \(defaultInterface)\n",
                                   stderr: "")
            }

            if arguments.count == 3, arguments[0] == "-n", arguments[1] == "get" {
                let gateway = arguments[2]
                return ShellResult(exitCode: 0,
                                   stdout: "route to: \(gateway)\ngateway: \(gateway)\ninterface: \(defaultInterface)\n",
                                   stderr: "")
            }

            if arguments.count >= 4, arguments[0] == "-n", arguments[1] == "add" {
                if arguments[2] == "default", arguments.count >= 4 {
                    defaultGateway = arguments[3]
                    upsertRoute(destination: "default", gateway: defaultGateway, interfaceName: defaultInterface)
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }

                if arguments[2] == "-net", arguments.count >= 4 {
                    let destination = arguments[3]
                    if let interfaceIndex = arguments.firstIndex(of: "-interface"),
                       interfaceIndex + 1 < arguments.count {
                        upsertRoute(destination: destination,
                                    gateway: "link#1",
                                    interfaceName: arguments[interfaceIndex + 1])
                    } else if arguments.count >= 5 {
                        upsertRoute(destination: destination,
                                    gateway: arguments[4],
                                    interfaceName: defaultInterface)
                    }
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }
            }

            if arguments.count >= 3, arguments[0] == "-n", arguments[1] == "delete" {
                if arguments[2] == "default" {
                    routes.removeAll { $0.destination == "default" }
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }

                if arguments[2] == "-net", arguments.count >= 4 {
                    routes.removeAll { $0.destination == arguments[3] }
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }

                if arguments[2] == "-host", arguments.count >= 4 {
                    routes.removeAll { $0.destination == arguments.last }
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }
            }

            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        }

        private func handleNetworkSetup(arguments: [String]) -> ShellResult {
            guard let command = arguments.first else {
                return ShellResult(exitCode: 1, stdout: "", stderr: "missing networksetup command")
            }

            switch command {
            case "-getdnsservers":
                return ShellResult(exitCode: 0,
                                   stdout: dnsServers.isEmpty
                                       ? "There aren't any DNS Servers set on \(serviceName).\n"
                                       : dnsServers.joined(separator: "\n") + "\n",
                                   stderr: "")
            case "-getsearchdomains":
                return ShellResult(exitCode: 0,
                                   stdout: searchDomains.isEmpty
                                       ? "There aren't any Search Domains set on \(serviceName).\n"
                                       : searchDomains.joined(separator: "\n") + "\n",
                                   stderr: "")
            case "-setdnsservers":
                dnsServers = arguments.dropFirst(2).first == "empty" ? [] : Array(arguments.dropFirst(2))
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            case "-setsearchdomains":
                searchDomains = arguments.dropFirst(2).first == "empty" ? [] : Array(arguments.dropFirst(2))
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            case "-setv6off":
                ipv6Mode = "Off"
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            case "-setv6automatic":
                ipv6Mode = "Automatic"
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            case "-setv6linklocal":
                ipv6Mode = "Link-local only"
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            case "-getinfo":
                return ShellResult(exitCode: 0,
                                   stdout: "IPv6: \(ipv6Mode)\n",
                                   stderr: "")
            case "-listnetworkserviceorder":
                return ShellResult(exitCode: 0,
                                   stdout: "(1) \(serviceName)\n(Hardware Port: Wi-Fi, Device: \(defaultInterface))\n",
                                   stderr: "")
            default:
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }
        }

        private func upsertRoute(destination: String, gateway: String, interfaceName: String) {
            routes.removeAll { $0.destination == destination }
            routes.append(RouteRecord(destination: destination, gateway: gateway, interfaceName: interfaceName))
        }

        private func netstatOutput() -> String {
            let header = """
            Routing tables

            Internet:
            Destination        Gateway            Flags               Netif Expire
            """

            let rows = routes.map { route in
                "\(route.destination)\t\(route.gateway)\tUGSc\t\(route.interfaceName)"
            }

            return header + "\n" + rows.joined(separator: "\n") + "\n"
        }
    }

    private static func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() {
            throw SelfTestError.failed(message)
        }
    }

    private static func expectRejectsUnexpectedArgument(_ arguments: [String],
                                                        command: String,
                                                        argument expectedArgument: String) throws {
        do {
            _ = try CLI.parse(arguments: arguments)
            throw SelfTestError.failed("\(command) should reject \(expectedArgument).")
        } catch CLIError.unexpectedArgument(let argument) {
            try expect(argument == expectedArgument,
                       "\(command) should reject \(expectedArgument) as an unexpected argument.")
        } catch {
            throw SelfTestError.failed("\(command) should reject \(expectedArgument) with an unexpected argument error.")
        }
    }
}

#endif
