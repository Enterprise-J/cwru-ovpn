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
        try testPreventSleepConfig()
        try testLegacyConfigKeys()
        try testLenientSplitTunnelDecoding()
        try testIncludedHostsConfig()
        try testMissingConfigErrors()
        try testRuntimeValidationHardening()
        try testWebAuthRequestValidation()
        try testCLIConnectModes()
        try testCLIAdvancedOptions()
        try testGeneratedSudoers()
        try testPrivacyModeEventLog()
        try testRecoveryState()
        try testStatusIndicators()
        try testRouteCanonicalization()
        try testReverseResolverZoneDerivation()
        try testPrivilegedShellEnvironment()
        try testDetachedStartupStatus()
        try testShellIntegrationBlocks()
        try testPhysicalDNSCapture()
        try testPhysicalDNSCaptureRejectsUnsafeServiceName()
        try testMockedSplitTunnelFlow()
        try testSplitTunnelUsesMacOSHostCacheResolver()
        try testSplitTunnelCleansDynamicRoutesAfterPartialFailure()
        try testSplitTunnelRejectsLeakyDefaultDNS()
        try testSplitTunnelAllowsSupplementalDefaultSearchDomains()
        try testMockedFullTunnelModeSwitch()
        try testMockedSplitFullSplitModeSwitchWithIncludedHosts()
        try testMockedFullTunnelDNSFallsBackToPushedResolvers()
        try testFullTunnelIPv6SafetyFailureThrows()
        try testModeSwitchWaitState()
        try testProcessStartTimeMatching()
        try testSessionStateSavePreservesPendingModeSwitch()
        try testURLRedaction()
        try testPlainTopLevelErrorOutput()
        try testMockedStaleStateRecovery()
        try testStaleCleanupWithoutConfigFile()
        try testCleanupWatchdogValidation()
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

    private static func testPreventSleepConfig() throws {
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
        try expect(defaultedConfig.preventSleep,
                   "preventSleep should default to true when omitted from config.")

        let enabledData = Data(
            """
            {
              "preventSleep": true,
              "splitTunnel": {
                "includedRoutes": [],
                "resolverDomains": [],
                "resolverNameServers": []
              }
            }
            """.utf8
        )

        let enabledConfig = try JSONDecoder().decode(AppConfig.self, from: enabledData)
        try expect(enabledConfig.preventSleep,
                   "preventSleep should decode when explicitly enabled in config.")

        let disabledData = Data(
            """
            {
              "preventSleep": false,
              "splitTunnel": {
                "includedRoutes": [],
                "resolverDomains": [],
                "resolverNameServers": []
              }
            }
            """.utf8
        )

        let disabledConfig = try JSONDecoder().decode(AppConfig.self, from: disabledData)
        try expect(!disabledConfig.preventSleep,
                   "preventSleep false should allow system sleep.")
    }

    private static func testLegacyConfigKeys() throws {
        let legacyData = Data(
            """
            {
              "defaultProfilePath": "~/.cwru-ovpn/profile.ovpn",
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
                   "Legacy defaultProfilePath should still decode.")
    }

    private static func testLenientSplitTunnelDecoding() throws {
        let emptySplitTunnelData = Data(
            """
            {
              "splitTunnel": {}
            }
            """.utf8
        )

        let decoded = try JSONDecoder().decode(AppConfig.self, from: emptySplitTunnelData)
        try expect(decoded.splitTunnel.includedRoutes.isEmpty,
                   "splitTunnel.includedRoutes should default to an empty array when omitted.")
        try expect(decoded.splitTunnel.includedHosts.isEmpty,
                   "splitTunnel.includedHosts should default to an empty array when omitted.")
        try expect(decoded.splitTunnel.resolverDomains.isEmpty,
                   "splitTunnel.resolverDomains should default to an empty array when omitted.")
        try expect(decoded.splitTunnel.resolverNameServers.isEmpty,
                   "splitTunnel.resolverNameServers should default to an empty array when omitted.")
    }

    private static func testIncludedHostsConfig() throws {
        let data = Data(
            """
            {
              "splitTunnel": {
                "includedRoutes": ["129.22.0.0/16"],
                "includedHosts": ["129.22.1.10", "vpn.case.edu"],
                "resolverDomains": ["case.edu"],
                "resolverNameServers": []
              }
            }
            """.utf8
        )

        let decoded = try JSONDecoder().decode(AppConfig.self, from: data)
        try expect(decoded.splitTunnel.includedHosts == ["129.22.1.10", "vpn.case.edu"],
                   "includedHosts should decode from config.")
        try expect(decoded.splitTunnel.effectiveIncludedRoutes == ["129.22.0.0/16", "129.22.1.10/32"],
                   "IPv4 includedHosts should expand to /32 split-tunnel routes.")
        try expect(decoded.splitTunnel.includedHostDomains == ["vpn.case.edu"],
                   "Domain includedHosts should remain available for scoped DNS.")
        try expect(decoded.splitTunnel.effectiveResolverDomains.contains("vpn.case.edu"),
                   "Domain includedHosts should be included in scoped resolver domains.")
        try expect(decoded.splitTunnel.effectiveResolverDomains.contains("10.1.22.129.in-addr.arpa"),
                   "IPv4 includedHosts should derive reverse resolver zones.")

        let invalidHost = AppConfig.SplitTunnelConfiguration(
            includedRoutes: [],
            includedHosts: ["2001:db8::1"],
            resolverDomains: [],
            resolverNameServers: [],
            reachabilityProbeHosts: nil
        )
        try expect(invalidHost.validationError()?.contains("includedHost") == true,
                   "includedHosts should reject IPv6 because split-tunnel host routing is IPv4-only.")
    }

    private static func testMissingConfigErrors() throws {
        let isolatedDirectory = temporaryDirectory(named: "cwru-ovpn-config-isolation")
        defer { try? FileManager.default.removeItem(at: isolatedDirectory) }

        try withCurrentDirectory(isolatedDirectory.path) {
            try withEnvironmentVariable("CWRU_OVPN_HOME_STATE_DIR", value: isolatedDirectory.appendingPathComponent("state", isDirectory: true).path) {
                do {
                    _ = try AppConfig.fallback.resolvedProfilePath(explicitConfigPath: nil)
                    throw SelfTestError.failed("Missing config files should raise a dedicated error.")
                } catch CLIError.missingConfigFile {
                }
            }
        }

        let temporaryConfigPath = "/tmp/cwru-ovpn-config.json"
        do {
            _ = try AppConfig.fallback.resolvedProfilePath(explicitConfigPath: temporaryConfigPath)
            throw SelfTestError.failed("Configs without profilePath should still report a missing profile path.")
        } catch CLIError.missingConfig {
        }
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
                       "connect should leave the per-run allowSleep override unset when the flag is omitted.")
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
                       "connect --foreground should not toggle the per-run allowSleep override.")
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
                       "connect --allow-sleep should allow system sleep for this run.")
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

        switch try CLI.parse(arguments: ["connect", "--tunnel-mode", "full"]) {
        case .connect(_, _, let tunnelModeOverride, _, _, _, _):
            try expect(tunnelModeOverride == .full,
                       "connect should keep accepting --tunnel-mode as an alias for --mode.")
        default:
            throw SelfTestError.failed("connect --tunnel-mode should parse as connect.")
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

        switch try CLI.parse(arguments: ["cleanup-watchdog", "--parent-pid", "42"]) {
        case .cleanupWatchdog(let parentPID, let parentStartTime):
            try expect(parentPID == 42,
                       "cleanup-watchdog should accept internal parent PIDs greater than 1.")
            try expect(parentStartTime == nil,
                       "cleanup-watchdog should not require a start-time tuple.")
        default:
            throw SelfTestError.failed("cleanup-watchdog should parse as the internal helper command.")
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
        try expectRejectsInvalidPID(["cleanup-watchdog", "--parent-pid", "1"],
                                    command: "cleanup-watchdog",
                                    pid: "1")
        try expectRejectsMissingValue(["connect", "--config"],
                                      command: "connect",
                                      argument: "--config")
        try expectRejectsMissingValue(["logs", "--tail"],
                                      command: "logs",
                                      argument: "--tail")
        try expectRejectsMissingValue(["setup", "--profile"],
                                      command: "setup",
                                      argument: "--profile")
    }

    private static func testGeneratedSudoers() throws {
        let userID: uid_t = 501
        let executablePath = "/bin/ls"
        let executableDigest = try Setup.executableSHA256(at: executablePath)
        let sudoers = Setup.renderSudoers(userID: userID,
                                          executablePath: executablePath,
                                          executableDigest: executableDigest)

        let lines = sudoers.split(separator: "\n").map(String.init)
        try expect(lines.count == 21,
                   "Generated sudoers should cover the standard connect combinations plus disconnect (plain, -f, and --force).")
        try expect(sudoers.contains("#\(userID) ALL=(root) NOPASSWD: sha256:\(executableDigest) \(executablePath) connect --allow-sleep"),
                   "Generated sudoers should include the allow-sleep connect variant.")
        try expect(!lines.contains("#\(userID) ALL=(root) NOPASSWD: sha256:\(executableDigest) \(executablePath) connect --foreground"),
                   "Generated sudoers should not grant passwordless connect --foreground without the matching debug flag.")
        try expect(sudoers.contains("#\(userID) ALL=(root) NOPASSWD: sha256:\(executableDigest) \(executablePath) disconnect"),
                   "Generated sudoers should allow disconnect without requiring a config flag.")
        try expect(sudoers.contains("#\(userID) ALL=(root) NOPASSWD: sha256:\(executableDigest) \(executablePath) disconnect -f"),
                   "Generated sudoers should allow disconnect -f for shell-friendly force disconnects.")
        try expect(sudoers.contains("#\(userID) ALL=(root) NOPASSWD: sha256:\(executableDigest) \(executablePath) disconnect --force"),
                   "Generated sudoers should allow disconnect --force for stuck sessions.")
        try expect(!sudoers.contains("#\(userID) ALL=(root) NOPASSWD: sha256:\(executableDigest) \(executablePath) setup"),
                   "Generated sudoers should not allow passwordless setup.")
        try expect(!sudoers.contains("#\(userID) ALL=(root) NOPASSWD: sha256:\(executableDigest) \(executablePath) status"),
                   "Generated sudoers should not grant passwordless access to status.")
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
        try Setup.validatePasswordlessInvocationPolicy(executablePath: executablePath)
    }

    private static func testPrivacyModeEventLog() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-private-log-state")
        defer {
            EventLog.configure(privacyMode: false)
            try? FileManager.default.removeItem(at: homeStateDirectory)
        }

        try withEnvironmentVariable("CWRU_OVPN_HOME_STATE_DIR", value: homeStateDirectory.path) {
            EventLog.configure(privacyMode: true)
            EventLog.startSession(profilePath: "/private/tmp/sensitive-profile.ovpn")
            EventLog.append(eventName: "LOG",
                            info: "OPEN_URL:https://login.example/callback?token=secret",
                            isError: false,
                            isFatal: false,
                            phase: .connecting)
            EventLog.append(note: "Learned live VPN DNS servers: 10.8.0.2",
                            phase: .connected)

            let logText = try String(contentsOf: RuntimePaths.eventLogFile, encoding: .utf8)
            try expect(logText.contains(#""privacyMode":true"#),
                       "Privacy-mode event logs should mark the session as privacy mode.")
            try expect(!logText.contains("sensitive-profile.ovpn"),
                       "Privacy-mode event logs should suppress profile paths.")
            try expect(!logText.contains("https://login.example"),
                       "Privacy-mode event logs should suppress raw event info.")
            try expect(!logText.contains("10.8.0.2"),
                       "Privacy-mode event logs should suppress note details.")
        }
    }

    private static func testRuntimeValidationHardening() throws {
        try expect(AppConfig.SplitTunnelConfiguration.isValidIPAddress("1.1.1.1"),
                   "IPv4 addresses should validate.")
        try expect(!AppConfig.SplitTunnelConfiguration.isValidIPAddress("1.1.1.1\nnameserver 8.8.8.8"),
                   "Injected multiline DNS payloads should be rejected.")
        try expect(AppConfig.SplitTunnelConfiguration.isValidIPv4Address("1.1.1.1"),
                   "IPv4-only split-tunnel host addresses should validate.")
        try expect(!AppConfig.SplitTunnelConfiguration.isValidIPv4Address("2001:db8::1"),
                   "IPv6 addresses should not validate as split-tunnel included hosts.")
        try expect(AppConfig.SplitTunnelConfiguration.isValidDomainName("case.edu"),
                   "Expected resolver domains should validate.")
        try expect(!AppConfig.SplitTunnelConfiguration.isValidDomainName("case.edu/../../etc"),
                   "Path-like resolver domains should be rejected.")
        try testValidatorTable(
            name: "CIDR",
            valid: ["0.0.0.0/0", "129.22.0.0/16", "255.255.255.255/32"],
            invalid: [
                "",
                "129.22.0.0/33",
                "129.22.0.0/-1",
                "129.22.0.0/16\n",
                String(repeating: "1", count: AppConfig.SplitTunnelConfiguration.maxIPv4CIDRLength + 1),
            ],
            validator: AppConfig.SplitTunnelConfiguration.isValidCIDR
        )
        try testValidatorTable(
            name: "IP address",
            valid: ["1.1.1.1", "2001:db8::1"],
            invalid: [
                "",
                "-1.1.1.1",
                "1.1.1.1\nnameserver 8.8.8.8",
                String(repeating: "1", count: AppConfig.SplitTunnelConfiguration.maxIPAddressLength + 1),
            ],
            validator: AppConfig.SplitTunnelConfiguration.isValidIPAddress
        )
        try testValidatorTable(
            name: "domain",
            valid: ["case.edu", "\(String(repeating: "a", count: AppConfig.SplitTunnelConfiguration.maxDomainLabelLength)).edu"],
            invalid: [
                "",
                ".case.edu",
                "case.edu.",
                "-case.edu",
                "case-.edu",
                "case.edu/../../etc",
                "bad domain",
                "bad\ncase.edu",
                "\(String(repeating: "a", count: AppConfig.SplitTunnelConfiguration.maxDomainLabelLength + 1)).edu",
                String(repeating: "a", count: AppConfig.SplitTunnelConfiguration.maxDomainNameLength + 1),
            ],
            validator: AppConfig.SplitTunnelConfiguration.isValidDomainName
        )
        try testValidatorTable(
            name: "reachability probe host",
            valid: ["cloudflare.com", "1.1.1.1", "2001:db8::1"],
            invalid: [
                "",
                "bad host",
                "host/../../etc",
                String(repeating: "a", count: AppConfig.SplitTunnelConfiguration.maxDomainNameLength + 1),
            ],
            validator: AppConfig.SplitTunnelConfiguration.isValidReachabilityProbeHost
        )
        try testValidatorTable(
            name: "resolver filename",
            valid: ["case.edu", "22.129.in-addr.arpa"],
            invalid: [
                "",
                ".",
                "..",
                "case.edu/../../etc",
                String(repeating: "a", count: AppConfig.SplitTunnelConfiguration.maxDomainNameLength + 1),
            ],
            validator: ResolverPaths.isSafeDomainFileName
        )
        try testPrivilegedCleanupInputBounds()
        let currentStartTime = processStartTime(getpid())
        try expect(currentStartTime != nil,
                   "Current-process start times should be readable for PID validation.")
        let currentExecutablePath = try ExecutionIdentity.currentExecutablePath()
        try expect(processMatchesExecutable(getpid(),
                                           expectedExecutablePath: currentExecutablePath,
                                           expectedStartTime: currentStartTime),
                   "PID validation should accept the current process when the executable path and start time both match.")
        try withEnvironmentVariable("SUDO_USER", value: "root") {
            let expanded = AppConfig.expandUserPath("~/profile.ovpn")
            try expect(!expanded.hasPrefix("/var/root/"),
                       "Non-root runs should ignore spoofed SUDO_USER values when expanding ~ paths.")
        }
    }

    private static func testValidatorTable(name: String,
                                           valid: [String],
                                           invalid: [String],
                                           validator: (String) -> Bool) throws {
        for value in valid {
            try expect(validator(value), "\(name) validator should accept '\(value)'.")
        }
        for value in invalid {
            try expect(!validator(value), "\(name) validator should reject '\(value)'.")
        }
    }

    private static func testPrivilegedCleanupInputBounds() throws {
        var base = makeSessionState(
            pid: 2001,
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
        base.appliedIncludedRoutes = ["129.22.0.0/16"]
        base.appliedResolverDomains = ["case.edu"]
        try VPNController.validateSessionForPrivilegedCleanup(base)

        let tooLongDomain = "\(String(repeating: "a", count: AppConfig.SplitTunnelConfiguration.maxDomainLabelLength + 1)).edu"
        let cases: [(String, (inout SessionState) -> Void)] = [
            ("tunnel interface", { $0.tunName = String(repeating: "u", count: 33) }),
            ("physical interface", { $0.physicalInterface = String(repeating: "e", count: 33) }),
            ("network service", { $0.physicalServiceName = String(repeating: "W", count: 129) }),
            ("server IP", { $0.serverIP = String(repeating: "1", count: AppConfig.SplitTunnelConfiguration.maxIPAddressLength + 1) }),
            ("gateway", { $0.physicalGateway = String(repeating: "1", count: AppConfig.SplitTunnelConfiguration.maxIPAddressLength + 1) }),
            ("included route", { $0.appliedIncludedRoutes = [String(repeating: "1", count: AppConfig.SplitTunnelConfiguration.maxIPv4CIDRLength + 1)] }),
            ("resolver domain", { $0.appliedResolverDomains = [tooLongDomain] }),
            ("profile path", { $0.profilePath = "/" + String(repeating: "a", count: 1024) }),
            ("profile path control", { $0.profilePath = "/tmp/profile\n.ovpn" }),
        ]

        for (label, mutate) in cases {
            var session = base
            mutate(&session)
            do {
                try VPNController.validateSessionForPrivilegedCleanup(session)
                throw SelfTestError.failed("Privileged cleanup validation should reject \(label).")
            } catch VPNControllerError.unsafeSessionState(_) {
            } catch {
                throw error
            }
        }
    }

    private static func testWebAuthRequestValidation() throws {
        let embeddedRequest = WebAuthRequest.parse(info: "WEB_AUTH::https://cwru.openvpn.com/connect")
        try expect(embeddedRequest?.url.host == "cwru.openvpn.com",
                   "Embedded WebAuth should accept the expected OpenVPN host.")
        try expect(embeddedRequest?.url.absoluteString.contains("embedded=true") == true,
                   "Embedded WebAuth should append embedded=true to the query string.")
        try expect(WebAuthRequest.parse(info: "WEB_AUTH::http://cwru.openvpn.com/connect") == nil,
                   "WebAuth should reject non-HTTPS URLs.")
        try expect(WebAuthRequest.parse(info: "WEB_AUTH::https://evil.example/connect") == nil,
                   "WebAuth should reject unexpected hosts.")

        let externalRequest = WebAuthRequest.parse(info: "OPEN_URL:https://login.case.edu/sso")
        try expect(externalRequest?.url.host == "login.case.edu",
                   "External WebAuth should accept case.edu sign-in hosts.")
    }

    private static func testRecoveryState() throws {
        var session = SessionState(
            pid: 100,
            executablePath: nil,
            processStartTime: nil,
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

    private static func testPrivilegedShellEnvironment() throws {
        var privilegedInvocation: ShellInvocation?
        _ = try Shell.withTestHook({ invocation in
            privilegedInvocation = invocation
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        }) {
            try Shell.run("/bin/echo", arguments: ["ok"], requirePrivileges: true)
        }

        try expect(privilegedInvocation?.environment == [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "LC_ALL": "C",
        ], "Privileged subprocesses should use a deterministic minimal environment.")

        var unprivilegedInvocation: ShellInvocation?
        _ = try Shell.withTestHook({ invocation in
            unprivilegedInvocation = invocation
            return ShellResult(exitCode: 0, stdout: "", stderr: "")
        }) {
            try Shell.run("/bin/echo", arguments: ["ok"])
        }

        try expect(unprivilegedInvocation?.environment == nil,
                   "Unprivileged subprocesses should keep the default inherited environment.")
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
        let permissions = (try FileManager.default.attributesOfItem(atPath: tempURL.path)[.posixPermissions] as? NSNumber)?.intValue ?? -1
        try expect(permissions & 0o077 == 0,
                   "Detached startup status should stay owner-only after atomic writes.")
    }

    private static func testShellIntegrationBlocks() throws {
        let legacyHelperPath = "/tmp/repo/scripts/cwru-ovpn.zsh"
        let installedHelperPath = "/Users/test/My Tools/.cwru-ovpn/cwru-ovpn.zsh"
        let initialContent = """
        export PATH="/usr/local/bin:$PATH"

        # >>> cwru-ovpn >>>
        source \(legacyHelperPath)
        # <<< cwru-ovpn <<<
        """

        let installedContent = ShellIntegration.installBlock(into: initialContent,
                                                             helperPath: installedHelperPath,
                                                             legacySourcePaths: [legacyHelperPath])
        try expect(installedContent.contains("source '/Users/test/My Tools/.cwru-ovpn/cwru-ovpn.zsh'"),
                   "Shell integration should quote helper paths safely in shell rc files.")
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
            includedHosts: ["129.22.200.10"],
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
                                    activeDefaultDNSServers: ["129.22.4.32"],
                                    activeDefaultSearchDomains: ["case.edu"],
                                    tunnelInterfaces: ["utun7"],
                                    initialRoutes: [
                                        MockSystem.RouteRecord(destination: "10.8.0.0/24",
                                                               gateway: "10.8.0.10",
                                                               interfaceName: "utun7")
                                    ])

        try withEnvironmentVariable("CWRU_OVPN_RESOLVER_DIR", value: resolverDirectory.path) {
            try Shell.withTestHook({ try mockSystem.handle($0) }) {
                try RouteManager(configuration: configuration).applySplitTunnel(using: &session)
            }
            try expect(session.routesApplied,
                       "Applying split tunnel should mark routesApplied.")
            try expect(session.appliedIncludedRoutes == ["129.22.0.0/16", "129.22.200.10/32"],
                       "Applying split tunnel should persist IPv4 host includes as /32 routes.")
            try expect(session.appliedResolverDomains == [
                "case.edu",
                "10.200.22.129.in-addr.arpa",
                "22.129.in-addr.arpa",
                "10.0.8.10.in-addr.arpa",
                "0.0.8.10.in-addr.arpa"
            ],
                       "Applying split tunnel should persist the effective resolver domains.")

            let resolverFile = ResolverPaths.fileURL(for: "case.edu")
            let reverseResolverFile = ResolverPaths.fileURL(for: "22.129.in-addr.arpa")
            let hostReverseResolverFile = ResolverPaths.fileURL(for: "10.200.22.129.in-addr.arpa")
            let resolverContents = try String(contentsOf: resolverFile, encoding: .utf8)
            try expect(resolverContents.contains("nameserver 129.22.4.32"),
                       "Applying split tunnel should install scoped resolver files with VPN DNS servers.")
            try expect(FileManager.default.fileExists(atPath: reverseResolverFile.path),
                       "Applying split tunnel should install reverse-zone resolver files for included routes.")
            try expect(FileManager.default.fileExists(atPath: hostReverseResolverFile.path),
                       "Applying split tunnel should install reverse-zone resolver files for included host routes.")
            try expect(mockSystem.recordedCommands.contains("/usr/sbin/chown root:wheel \(resolverFile.path)"),
                       "Applying split tunnel should enforce root:wheel ownership on resolver files.")
            try expect(mockSystem.recordedCommands.contains("/bin/chmod 0644 \(resolverFile.path)"),
                       "Applying split tunnel should enforce 0644 mode on resolver files.")
            try expect(mockSystem.recordedCommands.contains("/usr/sbin/chown root:wheel \(reverseResolverFile.path)"),
                       "Applying split tunnel should enforce root:wheel ownership on reverse-zone resolver files.")
            try expect(mockSystem.recordedCommands.contains("/bin/chmod 0644 \(reverseResolverFile.path)"),
                       "Applying split tunnel should enforce 0644 mode on reverse-zone resolver files.")
        }
        try expect(mockSystem.recordedCommands.contains("/sbin/route -n add -net 0.0.0.0/1 192.168.1.1"),
                   "Applying split tunnel should add the lower-half default route override.")
        try expect(mockSystem.recordedCommands.contains("/sbin/route -n add -net 129.22.0.0/16 -interface utun7"),
                   "Applying split tunnel should route included CIDRs through the tunnel interface.")
        try expect(mockSystem.recordedCommands.contains("/sbin/route -n add -net 129.22.200.10/32 -interface utun7"),
                   "Applying split tunnel should route included IPv4 hosts through the tunnel interface.")
        try expect(mockSystem.recordedCommands.contains("/usr/sbin/scutil --dns"),
                   "Applying split tunnel should verify that the active default resolver is not using VPN DNS.")
    }

    private static func testSplitTunnelUsesMacOSHostCacheResolver() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-host-cache")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = AppConfig.SplitTunnelConfiguration(
            includedRoutes: ["129.22.0.0/16"],
            includedHosts: ["cached.example"],
            resolverDomains: ["case.edu"],
            resolverNameServers: ["129.22.4.32"],
            reachabilityProbeHosts: nil
        )

        var session = makeSessionState(
            pid: 1009,
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

        let mockSystem = MockSystem(serviceName: "Wi-Fi",
                                    physicalGateway: "192.168.1.1",
                                    physicalInterface: "en0",
                                    physicalDNSServers: ["1.1.1.1"],
                                    physicalSearchDomains: ["home"],
                                    ipv6Mode: "Automatic",
                                    tunnelInterfaces: ["utun7"],
                                    blockedIPv6ProbeDestinations: ["2001:4860:4860::8888", "3000::1"],
                                    hostIPv4Addresses: ["cached.example": ["172.64.80.1"]])

        try withEnvironmentVariable("CWRU_OVPN_RESOLVER_DIR", value: resolverDirectory.path) {
            try Shell.withTestHook({ try mockSystem.handle($0) }) {
                try RouteManager(configuration: configuration).applySplitTunnel(using: &session)
            }
        }

        try expect(session.appliedIncludedRoutes == ["129.22.0.0/16", "172.64.80.1/32"],
                   "Split tunnel should include IPv4 addresses returned by the macOS host cache resolver.")
        try expect(mockSystem.recordedCommands.contains("/usr/bin/dscacheutil -q host -a name cached.example"),
                   "Hostname includes should query the macOS host cache resolver.")
        try expect(mockSystem.recordedCommands.contains("/sbin/route -n add -net 172.64.80.1/32 -interface utun7"),
                   "Split tunnel should add routes learned from the macOS host cache resolver.")
    }

    private static func testPhysicalDNSCapture() throws {
        let configuration = AppConfig.SplitTunnelConfiguration(
            includedRoutes: ["129.22.0.0/16"],
            resolverDomains: ["case.edu"],
            resolverNameServers: ["129.22.4.32"],
            reachabilityProbeHosts: nil
        )

        let mockSystem = MockSystem(serviceName: "Wi-Fi",
                                    physicalGateway: "192.168.1.1",
                                    physicalInterface: "en0",
                                    physicalDNSServers: ["1.1.1.1"],
                                    physicalSearchDomains: ["home"],
                                    ipv6Mode: "Automatic",
                                    tunnelInterfaces: ["utun7"])

        try Shell.withTestHook({ try mockSystem.handle($0) }) {
            let captured = try RouteManager(configuration: configuration).capturePhysicalDNSConfiguration(for: "en0")
            try expect(captured?.serviceName == "Wi-Fi",
                       "Physical DNS capture should resolve the active macOS network service name.")
            try expect(captured?.dnsServers == ["1.1.1.1"],
                       "Physical DNS capture should read the original DNS servers.")
            try expect(captured?.searchDomains == ["home"],
                       "Physical DNS capture should read the original search domains.")
            try expect(captured?.ipv6Mode == "Automatic",
                       "Physical DNS capture should read the original IPv6 mode.")
        }
    }

    private static func testPhysicalDNSCaptureRejectsUnsafeServiceName() throws {
        let configuration = AppConfig.SplitTunnelConfiguration(
            includedRoutes: ["129.22.0.0/16"],
            resolverDomains: ["case.edu"],
            resolverNameServers: ["129.22.4.32"],
            reachabilityProbeHosts: nil
        )

        let mockSystem = MockSystem(serviceName: String(repeating: "W", count: 129),
                                    physicalGateway: "192.168.1.1",
                                    physicalInterface: "en0",
                                    physicalDNSServers: ["1.1.1.1"],
                                    physicalSearchDomains: ["home"],
                                    ipv6Mode: "Automatic",
                                    tunnelInterfaces: ["utun7"])

        try Shell.withTestHook({ try mockSystem.handle($0) }) {
            let captured = try RouteManager(configuration: configuration).capturePhysicalDNSConfiguration(for: "en0")
            try expect(captured == nil,
                       "Physical DNS capture should reject unsafe network service names before using them in networksetup calls.")
        }
        try expect(!mockSystem.recordedCommands.contains { $0.contains("-getdnsservers") },
                   "Unsafe network service names should not be passed to networksetup DNS commands.")
    }

    private static func testSplitTunnelCleansDynamicRoutesAfterPartialFailure() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-partial-route-failure")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = AppConfig.SplitTunnelConfiguration(
            includedRoutes: ["129.22.0.0/16"],
            includedHosts: ["app.case.edu"],
            resolverDomains: ["case.edu"],
            resolverNameServers: ["129.22.4.32"],
            reachabilityProbeHosts: nil
        )

        var session = makeSessionState(
            pid: 1007,
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
                                    tunnelInterfaces: ["utun7"],
                                    failingRouteAdds: ["129.22.200.11/32"])
        var preparedStateWasPersistable = false
        var preparedIncludedRoutes: [String]?
        var dynamicRouteAlreadyAddedBeforePreparedState = false

        try withEnvironmentVariable("CWRU_OVPN_RESOLVER_DIR", value: resolverDirectory.path) {
            do {
                try Shell.withTestHook({ try mockSystem.handle($0) }) {
                    try RouteManager(
                        configuration: configuration,
                        ipv4Resolver: { host in host == "app.case.edu" ? ["129.22.200.10", "129.22.200.11"] : [] }
                    ).applySplitTunnel(using: &session) { preparedState in
                        preparedStateWasPersistable = true
                        preparedIncludedRoutes = preparedState.appliedIncludedRoutes
                        dynamicRouteAlreadyAddedBeforePreparedState = mockSystem.recordedCommands.contains(
                            "/sbin/route -n add -net 129.22.200.10/32 -interface utun7"
                        )
                    }
                }
                throw SelfTestError.failed("Split tunnel should fail when one resolved host route cannot be added.")
            } catch {
                try expect(preparedStateWasPersistable,
                           "Split tunnel should expose resolved host routes for persistence before adding them.")
                try expect(preparedIncludedRoutes == [
                    "129.22.0.0/16",
                    "129.22.200.10/32",
                    "129.22.200.11/32",
                ], "Prepared split-tunnel state should include all resolved host routes before dynamic route mutation.")
                try expect(!dynamicRouteAlreadyAddedBeforePreparedState,
                           "Prepared split-tunnel state should be persisted before adding resolved host routes.")
                try expect(!session.routesApplied,
                           "Split tunnel should leave routesApplied false after a partial resolved-route failure.")
                try expect(mockSystem.recordedCommands.contains("/sbin/route -n delete -net 129.22.200.10/32"),
                           "Split tunnel cleanup should delete resolved host routes that were added before failure.")
                try expect(mockSystem.recordedCommands.contains("/sbin/route -n delete -net 129.22.200.11/32"),
                           "Split tunnel cleanup should attempt to delete all prepared resolved host routes.")
            }
        }
    }

    private static func testSplitTunnelRejectsLeakyDefaultDNS() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-leaky-dns")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = AppConfig.SplitTunnelConfiguration(
            includedRoutes: ["129.22.0.0/16"],
            resolverDomains: ["case.edu"],
            resolverNameServers: ["129.22.4.32"],
            reachabilityProbeHosts: nil
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

        let mockSystem = MockSystem(serviceName: "Wi-Fi",
                                    physicalGateway: "192.168.1.1",
                                    physicalInterface: "en0",
                                    physicalDNSServers: ["1.1.1.1"],
                                    physicalSearchDomains: ["home"],
                                    ipv6Mode: "Automatic",
                                    activeDefaultDNSServers: ["129.22.4.32"],
                                    activeDefaultSearchDomains: ["case.edu"],
                                    tunnelInterfaces: ["utun7"],
                                    dnsCacheFlushAppliesDNSConfiguration: false)

        try withEnvironmentVariable("CWRU_OVPN_RESOLVER_DIR", value: resolverDirectory.path) {
            do {
                try Shell.withTestHook({ try mockSystem.handle($0) }) {
                    try RouteManager(configuration: configuration).applySplitTunnel(using: &session)
                }
                throw SelfTestError.failed("Split tunnel should fail closed when the active default resolver stays on VPN DNS.")
            } catch RouteManagerError.failedToIsolateSplitTunnelDNS {
                try expect(!session.routesApplied,
                           "Split tunnel should leave routesApplied false after failing closed on leaky default DNS.")
            }
        }
    }

    private static func testSplitTunnelAllowsSupplementalDefaultSearchDomains() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-search-domain-overlap")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = AppConfig.SplitTunnelConfiguration(
            includedRoutes: ["129.22.0.0/16"],
            resolverDomains: ["case.edu"],
            resolverNameServers: ["129.22.4.32"],
            reachabilityProbeHosts: nil
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

        let mockSystem = MockSystem(serviceName: "Wi-Fi",
                                    physicalGateway: "192.168.1.1",
                                    physicalInterface: "en0",
                                    physicalDNSServers: ["1.1.1.1"],
                                    physicalSearchDomains: ["home"],
                                    ipv6Mode: "Automatic",
                                    activeDefaultDNSServers: ["1.1.1.1"],
                                    activeDefaultSearchDomains: ["case.edu"],
                                    tunnelInterfaces: ["utun7"],
                                    dnsCacheFlushAppliesDNSConfiguration: false)

        try withEnvironmentVariable("CWRU_OVPN_RESOLVER_DIR", value: resolverDirectory.path) {
            try Shell.withTestHook({ try mockSystem.handle($0) }) {
                try RouteManager(configuration: configuration).applySplitTunnel(using: &session)
            }

            try expect(session.routesApplied,
                       "Split tunnel should stay connected when only supplemental search domains remain on the default resolver.")
        }
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
                                        tunnelInterfaces: ["utun7"],
                                        blockedIPv6ProbeDestinations: ["2001:4860:4860::8888", "3000::1"])

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
            try expect(mockSystem.recordedCommands.contains("/sbin/route -n get -inet6 2001:4860:4860::8888"),
                       "Switching to full tunnel should validate that public IPv6 no longer leaves through the physical interface.")
        }
    }

    private static func testMockedSplitFullSplitModeSwitchWithIncludedHosts() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-split-full-split")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = AppConfig.SplitTunnelConfiguration(
            includedRoutes: ["129.22.0.0/16"],
            includedHosts: ["app.case.edu"],
            resolverDomains: ["case.edu"],
            resolverNameServers: ["129.22.4.32"],
            reachabilityProbeHosts: nil
        )

        var session = makeSessionState(
            pid: 1008,
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
        session.fullTunnelDNSServers = ["10.8.0.2"]
        session.fullTunnelSearchDomains = ["case.edu"]

        let mockSystem = MockSystem(serviceName: "Wi-Fi",
                                    physicalGateway: "192.168.1.1",
                                    physicalInterface: "en0",
                                    physicalDNSServers: ["1.1.1.1"],
                                    physicalSearchDomains: ["home"],
                                    ipv6Mode: "Automatic",
                                    tunnelInterfaces: ["utun7"],
                                    blockedIPv6ProbeDestinations: ["2001:4860:4860::8888", "3000::1"])
        let manager = RouteManager(
            configuration: configuration,
            ipv4Resolver: { host in host == "app.case.edu" ? ["129.22.200.10"] : [] }
        )
        let fullTunnelRoutes = [
            ManagedIPv4Route(destination: "0.0.0.0/1", nextHopKind: .interface, nextHopValue: "utun7"),
            ManagedIPv4Route(destination: "128.0.0.0/1", nextHopKind: .interface, nextHopValue: "utun7"),
        ]

        try withEnvironmentVariable("CWRU_OVPN_RESOLVER_DIR", value: resolverDirectory.path) {
            try Shell.withTestHook({ try mockSystem.handle($0) }) {
                try manager.applySplitTunnel(using: &session)
                try manager.switchToFullTunnel(using: &session,
                                               fullTunnelRoutes: fullTunnelRoutes)
                try manager.applySplitTunnel(using: &session)
            }
        }

        let dynamicAdd = "/sbin/route -n add -net 129.22.200.10/32 -interface utun7"
        let dynamicDelete = "/sbin/route -n delete -net 129.22.200.10/32"
        try expect(mockSystem.recordedCommands.filter { $0 == dynamicAdd }.count == 2,
                   "Split-full-split mode switches should add resolved host routes each time split tunnel is applied.")
        try expect(mockSystem.recordedCommands.filter { $0 == dynamicDelete }.count >= 2,
                   "Switching away from split tunnel and back should delete stale resolved host routes.")
        try expect(session.appliedIncludedRoutes == ["129.22.0.0/16", "129.22.200.10/32"],
                   "Returning to split tunnel should preserve the current resolved host route set.")
        try expect(session.routesApplied,
                   "Returning to split tunnel should mark split routes as applied.")
    }

    private static func testMockedFullTunnelDNSFallsBackToPushedResolvers() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-full-dns")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }

        let configuration = AppConfig.SplitTunnelConfiguration(
            includedRoutes: ["129.22.0.0/16"],
            resolverDomains: ["case.edu"],
            resolverNameServers: ["129.22.4.32"],
            reachabilityProbeHosts: nil
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
        session.appliedIncludedRoutes = ["129.22.0.0/16"]
        session.appliedResolverDomains = ["case.edu", "22.129.in-addr.arpa"]
        session.pushedDNSServers = ["10.8.0.2"]
        session.pushedSearchDomains = ["case.edu"]
        session.fullTunnelDNSServers = []
        session.fullTunnelSearchDomains = []

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
                                        tunnelInterfaces: ["utun7"],
                                        blockedIPv6ProbeDestinations: ["2001:4860:4860::8888", "3000::1"])

            try Shell.withTestHook({ try mockSystem.handle($0) }) {
                try RouteManager(configuration: configuration).switchToFullTunnel(
                    using: &session,
                    fullTunnelRoutes: [
                        ManagedIPv4Route(destination: "0.0.0.0/1", nextHopKind: .interface, nextHopValue: "utun7"),
                        ManagedIPv4Route(destination: "128.0.0.0/1", nextHopKind: .interface, nextHopValue: "utun7"),
                    ]
                )
            }

            try expect(mockSystem.recordedCommands.contains("/usr/sbin/networksetup -setdnsservers Wi-Fi 10.8.0.2"),
                       "Full tunnel should fall back to pushed VPN DNS when the captured DNS snapshot is empty.")
            try expect(mockSystem.recordedCommands.contains("/usr/sbin/networksetup -setsearchdomains Wi-Fi case.edu"),
                       "Full tunnel should fall back to pushed VPN search domains when the captured DNS snapshot is empty.")
            try expect(session.fullTunnelDNSServers == ["10.8.0.2"],
                       "Full tunnel should persist the effective VPN DNS servers after falling back from an empty snapshot.")
            try expect(session.fullTunnelSearchDomains == ["case.edu"],
                       "Full tunnel should persist the effective VPN search domains after falling back from an empty snapshot.")
        }
    }

    private static func testFullTunnelIPv6SafetyFailureThrows() throws {
        let configuration = AppConfig.SplitTunnelConfiguration(
            includedRoutes: ["129.22.0.0/16"],
            resolverDomains: ["case.edu"],
            resolverNameServers: ["129.22.4.32"],
            reachabilityProbeHosts: nil
        )

        let session = makeSessionState(
            pid: 1007,
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

        let mockSystem = MockSystem(serviceName: "Wi-Fi",
                                    physicalGateway: "192.168.1.1",
                                    physicalInterface: "en0",
                                    physicalDNSServers: ["1.1.1.1"],
                                    physicalSearchDomains: ["home"],
                                    ipv6Mode: "Automatic",
                                    tunnelInterfaces: ["utun7"])

        do {
            try Shell.withTestHook({ try mockSystem.handle($0) }) {
                try RouteManager(configuration: configuration).applyFullTunnelSafety(using: session)
            }
            throw SelfTestError.failed("Full tunnel should fail closed when public IPv6 still routes over the physical interface.")
        } catch RouteManagerError.failedToRestoreFullTunnelIPv6Routes {
        }
    }

    private static func testModeSwitchWaitState() throws {
        var failedSession = makeSessionState(
            pid: 1004,
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
        failedSession.lastInfo = "Mode switch to full-tunnel failed: Failed to secure full-tunnel IPv6 traffic."

        switch VPNController.evaluateModeSwitchWaitState(session: failedSession,
                                                         pid: failedSession.pid,
                                                         targetMode: .full,
                                                         sawRequestedMode: true) {
        case .failed(let message):
            try expect(message == "Mode switch to full-tunnel failed: Failed to secure full-tunnel IPv6 traffic.",
                       "Mode switch waits should surface the persisted switch failure as soon as the request clears.")
        default:
            throw SelfTestError.failed("Mode switch waits should not keep waiting after a failed in-place switch.")
        }

        var refreshFailedSession = failedSession
        refreshFailedSession.tunnelMode = .split
        refreshFailedSession.lastEvent = "MODE_SWITCH_FAILED"
        refreshFailedSession.lastInfo = "Split-tunnel refresh failed: Invalid configuration"

        switch VPNController.evaluateModeSwitchWaitState(session: refreshFailedSession,
                                                         pid: refreshFailedSession.pid,
                                                         targetMode: .split,
                                                         sawRequestedMode: true) {
        case .failed(let message):
            try expect(message == "Split-tunnel refresh failed: Invalid configuration",
                       "Same-mode split refresh waits should surface persisted refresh failures.")
        default:
            throw SelfTestError.failed("Same-mode split refresh waits should not report success after a failed refresh.")
        }

        var completedSession = failedSession
        completedSession.tunnelMode = .full
        completedSession.lastInfo = nil

        switch VPNController.evaluateModeSwitchWaitState(session: completedSession,
                                                         pid: completedSession.pid,
                                                         targetMode: .full,
                                                         sawRequestedMode: true) {
        case .succeeded:
            break
        default:
            throw SelfTestError.failed("Mode switch waits should finish once the persisted session reaches the target mode.")
        }
    }

    private static func testProcessStartTimeMatching() throws {
        let expectedStartTime = ProcessStartTime(seconds: 123, microseconds: 456)

        try expect(processStartTimeMatches(actualStartTime: nil,
                                           expectedStartTime: expectedStartTime),
                   "Process liveness checks should treat an unreadable start time as inconclusive instead of assuming the process exited.")

        try expect(processStartTimeMatches(actualStartTime: expectedStartTime,
                                           expectedStartTime: expectedStartTime),
                   "Matching start times should validate the same process instance.")

        try expect(!processStartTimeMatches(actualStartTime: ProcessStartTime(seconds: 123, microseconds: 789),
                                            expectedStartTime: expectedStartTime),
                   "Mismatched start times should still detect PID reuse.")
    }

    private static func testSessionStateSavePreservesPendingModeSwitch() throws {
        let currentSession = makeSessionState(
            pid: 1005,
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

        var persistedSession = currentSession
        persistedSession.requestedTunnelMode = .full

        let preservedSession = VPNController.sessionStateForSave(currentState: currentSession,
                                                                 persistedState: persistedSession)
        try expect(preservedSession.requestedTunnelMode == .full,
                   "Routine controller saves should preserve a pending CLI mode switch until the signal handler consumes it.")

        var persistedRefreshSession = currentSession
        persistedRefreshSession.requestedTunnelMode = .split
        persistedRefreshSession.requestedConfigurationRefresh = true

        let preservedRefreshSession = VPNController.sessionStateForSave(currentState: currentSession,
                                                                        persistedState: persistedRefreshSession)
        try expect(preservedRefreshSession.requestedTunnelMode == .split,
                   "Routine controller saves should preserve a pending split-tunnel refresh request.")
        try expect(preservedRefreshSession.requestedConfigurationRefresh == true,
                   "Routine controller saves should preserve the pending split-tunnel refresh marker.")

        let intentionallyClearedSession = VPNController.sessionStateForSave(currentState: currentSession,
                                                                            persistedState: persistedSession,
                                                                            preservingPendingModeSwitch: false)
        try expect(intentionallyClearedSession.requestedTunnelMode == nil,
                   "Explicit switch completion saves should still be able to clear a pending mode switch.")

        var satisfiedSession = currentSession
        satisfiedSession.tunnelMode = .full

        let alreadySatisfiedSession = VPNController.sessionStateForSave(currentState: satisfiedSession,
                                                                        persistedState: persistedSession)
        try expect(alreadySatisfiedSession.requestedTunnelMode == nil,
                   "Routine saves should not resurrect a pending mode switch after the target mode is already active.")
    }

    private static func testPlainTopLevelErrorOutput() throws {
        let rendered = renderUserFacingError(SelfTestError.failed("Browser sign-in was cancelled."))
        try expect(rendered == "Browser sign-in was cancelled.\n",
                   "Top-level error output should preserve the plain user-facing message.")
    }

    private static func testURLRedaction() throws {
        let rendered = redactSensitiveText("Open https://login.example/callback#token=secret?state=abc now")
        try expect(rendered == "Open https://login.example/callback#[redacted] now",
                   "URL redaction should redact fragments that appear before query markers.")
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
                let profileURL = URL(fileURLWithPath: "/private/tmp/cwru-ovpn-stale-profile-\(UUID().uuidString).ovpn")
                let configURL = RuntimePaths.homeConfigFile
                try FileManager.default.createDirectory(at: RuntimePaths.homeStateDirectory, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: profileURL) }
                try "".write(to: profileURL, atomically: true, encoding: .utf8)
                try """
                {
                  "profilePath": "\(profileURL.path)",
                  "tunnelMode": "split",
                  "preventSleep": true,
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

    private static func testStaleCleanupWithoutConfigFile() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-home-state-missing-config")
        defer { try? FileManager.default.removeItem(at: homeStateDirectory) }
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-missing-config")
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
                let profileURL = URL(fileURLWithPath: "/private/tmp/cwru-ovpn-missing-config-\(UUID().uuidString).ovpn")
                defer { try? FileManager.default.removeItem(at: profileURL) }
                try FileManager.default.createDirectory(at: RuntimePaths.homeStateDirectory, withIntermediateDirectories: true)
                try "".write(to: profileURL, atomically: true, encoding: .utf8)

                var session = makeSessionState(
                    pid: Int32.max - 11,
                    profilePath: profileURL.path,
                    configFilePath: "/private/tmp/does-not-exist.json",
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
                           "Stale cleanup should not depend on the config file still existing.")
                try expect(!FileManager.default.fileExists(atPath: ResolverPaths.fileURL(for: "case.edu").path),
                           "Stale cleanup without a config file should still remove scoped resolver files.")
            }
        }
    }

    private static func testCleanupWatchdogValidation() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-watchdog-state")
        defer { try? FileManager.default.removeItem(at: homeStateDirectory) }

        try withEnvironmentVariable("CWRU_OVPN_HOME_STATE_DIR", value: homeStateDirectory.path) {
            try withEnvironmentVariable("CWRU_OVPN_SUPPRESS_USER_ALERTS", value: "1") {
                let profileURL = URL(fileURLWithPath: "/private/tmp/cwru-ovpn-watchdog-profile.ovpn")
                let configURL = RuntimePaths.homeConfigFile
                try FileManager.default.createDirectory(at: RuntimePaths.homeStateDirectory, withIntermediateDirectories: true)
                try """
                {
                  "profilePath": "\(profileURL.path)",
                  "tunnelMode": "split",
                  "preventSleep": true,
                  "verbosity": "daily",
                  "splitTunnel": {
                    "includedRoutes": [],
                    "resolverDomains": [],
                    "resolverNameServers": []
                  }
                }
                """.write(to: configURL, atomically: true, encoding: .utf8)

                var session = makeSessionState(
                    pid: 4242,
                    profilePath: profileURL.path,
                    configFilePath: configURL.path,
                    physicalGateway: "192.168.1.1",
                    physicalInterface: "en0",
                    physicalServiceName: "-Wi-Fi",
                    originalDNSServers: ["1.1.1.1"],
                    originalSearchDomains: ["home"],
                    originalIPv6Mode: "Automatic",
                    tunName: "utun7",
                    tunnelMode: .split,
                    cleanupNeeded: true
                )
                session.phase = .disconnecting
                try session.save()

                CleanupWatchdog.performCleanup(parentPID: session.pid,
                                               parentStartTime: session.processStartTime)

                let reloaded = SessionState.load()
                try expect(reloaded?.phase == .failed,
                           "Cleanup watchdog should preserve recovery state when validation rejects session data.")
                try expect(reloaded?.cleanupNeeded == true,
                           "Cleanup watchdog should keep cleanupNeeded enabled after a failed cleanup attempt.")
                try expect(reloaded?.lastInfo?.contains("Cleanup watchdog failed") == true,
                           "Cleanup watchdog should record the validation failure message.")
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

    private static func withCurrentDirectory<T>(_ path: String,
                                                body: () throws -> T) throws -> T {
        let previousPath = FileManager.default.currentDirectoryPath
        guard FileManager.default.changeCurrentDirectoryPath(path) else {
            throw SelfTestError.failed("Failed to change the current directory for a self-test fixture.")
        }
        defer { _ = FileManager.default.changeCurrentDirectoryPath(previousPath) }
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
            processStartTime: nil,
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
        private var activeDefaultDNSServers: [String]
        private var activeDefaultSearchDomains: [String]
        private var ipv6Mode: String
        private let tunnelInterfaces: Set<String>
        private let blockedIPv6ProbeDestinations: Set<String>
        private let failingRouteAdds: Set<String>
        private let dnsCacheFlushAppliesDNSConfiguration: Bool
        private let hostIPv4Addresses: [String: [String]]
        private var routes: [RouteRecord]
        private var ipv6DefaultRoutes: [String: String]

        var recordedCommands: [String] = []

        init(serviceName: String,
             physicalGateway: String,
             physicalInterface: String,
             physicalDNSServers: [String],
             physicalSearchDomains: [String],
             ipv6Mode: String,
             activeDefaultDNSServers: [String]? = nil,
             activeDefaultSearchDomains: [String]? = nil,
             tunnelInterfaces: Set<String>,
             blockedIPv6ProbeDestinations: Set<String> = [],
             failingRouteAdds: Set<String> = [],
             dnsCacheFlushAppliesDNSConfiguration: Bool = true,
             hostIPv4Addresses: [String: [String]] = [:],
             initialRoutes: [RouteRecord] = []) {
            self.serviceName = serviceName
            self.defaultGateway = physicalGateway
            self.defaultInterface = physicalInterface
            self.dnsServers = physicalDNSServers
            self.searchDomains = physicalSearchDomains
            self.activeDefaultDNSServers = activeDefaultDNSServers ?? physicalDNSServers
            self.activeDefaultSearchDomains = activeDefaultSearchDomains ?? physicalSearchDomains
            self.ipv6Mode = ipv6Mode
            self.tunnelInterfaces = tunnelInterfaces
            self.blockedIPv6ProbeDestinations = blockedIPv6ProbeDestinations
            self.failingRouteAdds = failingRouteAdds
            self.dnsCacheFlushAppliesDNSConfiguration = dnsCacheFlushAppliesDNSConfiguration
            self.hostIPv4Addresses = hostIPv4Addresses
            self.routes = [
                RouteRecord(destination: "default",
                            gateway: physicalGateway,
                            interfaceName: physicalInterface)
            ] + initialRoutes
            self.ipv6DefaultRoutes = [:]
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
            case "/usr/sbin/scutil":
                return handleScutil(arguments: invocation.arguments)
            case "/usr/bin/dscacheutil":
                return handleDSCacheUtil(arguments: invocation.arguments)
            case "/usr/bin/killall":
                if dnsCacheFlushAppliesDNSConfiguration {
                    activeDefaultDNSServers = dnsServers
                    activeDefaultSearchDomains = searchDomains
                }
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            case "/bin/mkdir":
                if invocation.arguments.count == 2, invocation.arguments[0] == "-p" {
                    try FileManager.default.createDirectory(atPath: invocation.arguments[1],
                                                            withIntermediateDirectories: true,
                                                            attributes: nil)
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }
            case "/usr/sbin/chown":
                if invocation.arguments.count == 2 {
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }
            case "/bin/chmod":
                if invocation.arguments.count == 2 {
                    let mode = Int(invocation.arguments[0], radix: 8) ?? 0o644
                    try FileManager.default.setAttributes([.posixPermissions: mode],
                                                          ofItemAtPath: invocation.arguments[1])
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

        private func handleDSCacheUtil(arguments: [String]) -> ShellResult {
            if arguments == ["-flushcache"] {
                if dnsCacheFlushAppliesDNSConfiguration {
                    activeDefaultDNSServers = dnsServers
                    activeDefaultSearchDomains = searchDomains
                }
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }

            if arguments.count == 5,
               arguments[0] == "-q",
               arguments[1] == "host",
               arguments[2] == "-a",
               arguments[3] == "name" {
                let host = arguments[4]
                let records = (hostIPv4Addresses[host] ?? [])
                    .map { "name: \(host)\nip_address: \($0)" }
                return ShellResult(exitCode: 0,
                                   stdout: records.joined(separator: "\n\n") + (records.isEmpty ? "" : "\n"),
                                   stderr: "")
            }

            return ShellResult(exitCode: 1, stdout: "", stderr: "unsupported dscacheutil command")
        }

        private func handleRoute(arguments: [String]) -> ShellResult {
            if arguments == ["-n", "get", "default"] {
                return ShellResult(exitCode: 0,
                                   stdout: "route to: default\ngateway: \(defaultGateway)\ninterface: \(defaultInterface)\n",
                                   stderr: "")
            }

            if arguments.count == 4, arguments[0] == "-n", arguments[1] == "get", arguments[2] == "-inet6" {
                if blockedIPv6ProbeDestinations.contains(arguments[3]) {
                    return ShellResult(exitCode: 0,
                                       stdout: "route to: \(arguments[3])\ngateway: ::1\ninterface: lo0\nflags: <UP,GATEWAY,REJECT,DONE,STATIC>\n",
                                       stderr: "")
                }
                let interfaceName = routedIPv6Interface(for: arguments[3])
                return ShellResult(exitCode: 0,
                                   stdout: "route to: \(arguments[3])\ngateway: fe80::%\(interfaceName)\ninterface: \(interfaceName)\n",
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

                if arguments[2] == "-net",
                   arguments.count >= 8,
                   arguments[3] == "-inet6" {
                    let prefixLength = arguments[6]
                    let interfaceName = arguments.last ?? defaultInterface
                    ipv6DefaultRoutes["\(arguments[4])/\(prefixLength)"] = interfaceName
                    return ShellResult(exitCode: 0, stdout: "", stderr: "")
                }

                if arguments[2] == "-net", arguments.count >= 4 {
                    let destination = arguments[3]
                    if failingRouteAdds.contains(destination) {
                        return ShellResult(exitCode: 1, stdout: "", stderr: "mock route add failure")
                    }
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

                if arguments[2] == "-net",
                   arguments.count >= 8,
                   arguments[3] == "-inet6" {
                    let prefixLength = arguments[6]
                    ipv6DefaultRoutes.removeValue(forKey: "\(arguments[4])/\(prefixLength)")
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
                                   stdout: """
                                   An asterisk (*) denotes that a network service is disabled.
                                   (1) \(serviceName)
                                   (Hardware Port: Wi-Fi, Device: \(defaultInterface))

                                   """,
                                   stderr: "")
            default:
                return ShellResult(exitCode: 0, stdout: "", stderr: "")
            }
        }

        private func handleScutil(arguments: [String]) -> ShellResult {
            guard arguments == ["--dns"] else {
                return ShellResult(exitCode: 1, stdout: "", stderr: "unsupported scutil command")
            }

            var lines = ["DNS configuration", "", "resolver #1"]
            for (index, domain) in activeDefaultSearchDomains.enumerated() {
                lines.append("  search domain[\(index)] : \(domain)")
            }
            for (index, server) in activeDefaultDNSServers.enumerated() {
                lines.append("  nameserver[\(index)] : \(server)")
            }
            lines.append("")
            lines.append("DNS configuration (for scoped queries)")

            return ShellResult(exitCode: 0,
                               stdout: lines.joined(separator: "\n") + "\n",
                               stderr: "")
        }

        private func upsertRoute(destination: String, gateway: String, interfaceName: String) {
            routes.removeAll { $0.destination == destination }
            routes.append(RouteRecord(destination: destination, gateway: gateway, interfaceName: interfaceName))
        }

        private func routedIPv6Interface(for destination: String) -> String {
            let trimmed = destination.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let firstNibble = trimmed.first ?? "0"
            let routeKey = "89abcdef".contains(firstNibble) ? "8000::/1" : "::/1"
            return ipv6DefaultRoutes[routeKey] ?? defaultInterface
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

    private static func expectRejectsInvalidPID(_ arguments: [String],
                                                command: String,
                                                pid: String) throws {
        do {
            _ = try CLI.parse(arguments: arguments)
            throw SelfTestError.failed("\(command) should reject invalid PID \(pid).")
        } catch CLIError.invalidPID(let value) {
            try expect(value == pid,
                       "\(command) should report the invalid PID value.")
        } catch {
            throw SelfTestError.failed("\(command) should reject \(pid) with an invalid PID error.")
        }
    }

    private static func expectRejectsMissingValue(_ arguments: [String],
                                                  command: String,
                                                  argument expectedArgument: String) throws {
        do {
            _ = try CLI.parse(arguments: arguments)
            throw SelfTestError.failed("\(command) should reject missing value for \(expectedArgument).")
        } catch CLIError.missingValue(let argument) {
            try expect(argument == expectedArgument,
                       "\(command) should report \(expectedArgument) as the option missing a value.")
        } catch {
            throw SelfTestError.failed("\(command) should reject \(expectedArgument) with a missing value error.")
        }
    }
}

#endif
