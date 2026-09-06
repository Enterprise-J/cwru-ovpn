import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite(.serialized)
struct ConfigurationTests {
    @Test
    func reachabilityProbeConfig() throws {
        #expect(
            SplitTunnelPolicy.fixedHealthCheckHosts == ["129.22.4.32", "129.22.104.132"],
            "Split-tunnel data-path checks should use the fixed CWRU DNS endpoints.")
        #expect(
            ReachabilityProbe.cwruDNSPort == 53,
            "CWRU split-tunnel data-path checks should use the DNS service port.")
        #expect(
            throws: (any Error).self, "The removed healthCheckHosts config key should be rejected."
        ) {
            _ = try JSONDecoder().decode(
                AppConfig.self,
                from: Data(#"{"healthCheckHosts":["129.22.4.32"]}"#.utf8)
            )
        }
    }

    @Test
    func dnsBootstrapConfig() throws {
        let defaultedConfig = try JSONDecoder().decode(AppConfig.self, from: Data("{}".utf8))
        #expect(
            defaultedConfig.effectiveDNSBootstrapServers.isEmpty,
            "DNS bootstrap should be disabled when config omits it.")

        let configuredData = Data(#"{"dnsBootstrapServers":["203.0.113.53","198.51.100.53"]}"#.utf8)

        let configuredConfig = try JSONDecoder().decode(AppConfig.self, from: configuredData)
        #expect(
            configuredConfig.effectiveDNSBootstrapServers == ["203.0.113.53", "198.51.100.53"],
            "DNS bootstrap should use explicitly configured servers.")

        let disabledData = Data(#"{"dnsBootstrapServers":[]}"#.utf8)

        let disabledConfig = try JSONDecoder().decode(AppConfig.self, from: disabledData)
        #expect(
            disabledConfig.effectiveDNSBootstrapServers.isEmpty,
            "An empty dnsBootstrapServers list should disable DNS bootstrap.")

        #expect(throws: (any Error).self, "DNS bootstrap servers should reject malformed values.") {
            _ = try JSONDecoder().decode(
                AppConfig.self,
                from: Data(#"{"dnsBootstrapServers":["bad host"]}"#.utf8)
            )
        }

        let duplicateConfig = try JSONDecoder().decode(
            AppConfig.self,
            from: Data(
                #"{"dnsBootstrapServers":[" 203.0.113.53 ","203.0.113.53","198.51.100.53"]}"#.utf8)
        )
        #expect(
            duplicateConfig.effectiveDNSBootstrapServers == ["203.0.113.53", "198.51.100.53"],
            "DNS bootstrap servers should be trimmed and deduplicated without reordering them.")
    }

    @Test
    func exampleConfigKeepsConnectivityBootstrap() throws {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let exampleConfigURL =
            packageRoot
            .appendingPathComponent("examples")
            .appendingPathComponent("cwru-ovpn.config.example.json")
        let exampleData = try Data(contentsOf: exampleConfigURL)
        let exampleConfig = try JSONDecoder().decode(AppConfig.self, from: exampleData)
        let object = try #require(
            try JSONSerialization.jsonObject(with: exampleData) as? [String: Any],
            "Example config should decode to a JSON object.")

        #expect(
            Set(object.keys) == Set(["dnsBootstrapServers"]),
            "Example config should only contain the hostile-network DNS bootstrap override.")
        #expect(
            exampleConfig.webAuthSession == .systemShared,
            "Setup's example config should use the shared system authentication session through the app default."
        )
        #expect(
            !exampleConfig.effectiveDNSBootstrapServers.isEmpty,
            "Setup's example config should keep DNS bootstrap available for filtering or sinkholing networks."
        )
        #expect(
            exampleConfig.tunnelMode == .split,
            "Example config should use split mode through the app default.")
        #expect(
            exampleConfig.privacyMode,
            "Example config should use privacy mode through the app default.")
    }

    @Test
    func preventSleepConfig() throws {
        let defaultedConfig = try JSONDecoder().decode(AppConfig.self, from: Data("{}".utf8))
        #expect(
            defaultedConfig.preventSleep,
            "preventSleep should default to true when omitted from config.")

        let enabledData = Data(#"{"preventSleep":true}"#.utf8)

        let enabledConfig = try JSONDecoder().decode(AppConfig.self, from: enabledData)
        #expect(
            enabledConfig.preventSleep,
            "preventSleep should decode when explicitly enabled in config.")

        let disabledData = Data(#"{"preventSleep":false}"#.utf8)

        let disabledConfig = try JSONDecoder().decode(AppConfig.self, from: disabledData)
        #expect(
            !disabledConfig.preventSleep,
            "preventSleep false should allow system sleep.")
    }

    @Test
    func privacyModeConfig() throws {
        let defaultedConfig = try JSONDecoder().decode(AppConfig.self, from: Data("{}".utf8))
        #expect(
            defaultedConfig.privacyMode,
            "privacyMode should default to true when omitted from config.")

        let disabledData = Data(#"{"privacyMode":false}"#.utf8)

        let disabledConfig = try JSONDecoder().decode(AppConfig.self, from: disabledData)
        #expect(
            !disabledConfig.privacyMode,
            "privacyMode should honor explicit false.")
    }

    @Test
    func webAuthSessionConfig() throws {
        let defaultedConfig = try JSONDecoder().decode(AppConfig.self, from: Data("{}".utf8))
        #expect(
            defaultedConfig.webAuthSession == .systemShared,
            "Web authentication should use the shared system session when the option is omitted.")
        #expect(
            defaultedConfig.webAuthSession.usesSystemSession(isPrivileged: false),
            "The default session must stay inside the system authentication session.")
        #expect(
            AppConfig.supportedSSOMethods == ["webauth"],
            "The client should advertise only supported authentication methods.")

        let browserConfig = try JSONDecoder().decode(
            AppConfig.self,
            from: Data(#"{"webAuthSession":"browser"}"#.utf8)
        )
        #expect(
            browserConfig.webAuthSession == .browser,
            "The default browser should remain available as an explicit option.")
        #expect(
            !browserConfig.webAuthSession.usesSystemSession(isPrivileged: false),
            "Browser mode should remain available to non-privileged callers.")
        #expect(
            browserConfig.webAuthSession.usesSystemSession(isPrivileged: true),
            "Privileged callers must force a system authentication session instead of opening the default URL handler."
        )

        let ephemeralSystemConfig = try JSONDecoder().decode(
            AppConfig.self,
            from: Data(#"{"webAuthSession":"system"}"#.utf8)
        )
        #expect(
            ephemeralSystemConfig.webAuthSession == .system,
            "An ephemeral system authentication session should remain available explicitly.")

        let sharedSystemConfig = try JSONDecoder().decode(
            AppConfig.self,
            from: Data(#"{"webAuthSession":"systemShared"}"#.utf8)
        )
        #expect(
            sharedSystemConfig.webAuthSession == .systemShared,
            "A shared system authentication session should decode explicitly as well as by default."
        )

        #expect(throws: (any Error).self, "Removed authentication-session keys should be rejected.")
        {
            _ = try JSONDecoder().decode(
                AppConfig.self,
                from: Data(#"{"useSystemAuthenticationSession":false}"#.utf8)
            )
        }
    }

    @Test
    func capturedOptionSnapshots() throws {
        let captured = """
            CAPTURED OPTIONS:
            Session Name: CWRU
            Layer: OSI_LAYER_3
            Add Routes:
            Exclude Routes:
              207.182.159.132/32
            DNS Servers:
              Priority: 0
              Addresses:
                10.8.0.2
                [2001:db8::53]:853
              Domains:
                resolver.case.edu
            DNS Search Domains:
              case.edu
            Values from dhcp-options: true
            """
        let parsedCaptured = try #require(
            VPNController.parsePushedDNSOptions(captured),
            "A complete captured-options snapshot should parse.")
        #expect(
            parsedCaptured.isAuthoritativeSnapshot,
            "A complete captured-options payload should authoritatively replace prior pushed DNS state."
        )
        #expect(
            parsedCaptured.dnsServers == ["10.8.0.2", "2001:db8::53"],
            "Captured DNS parsing should read server addresses and strip optional ports.")
        #expect(
            parsedCaptured.searchDomains == ["case.edu"],
            "Captured DNS parsing should use DNS Search Domains without treating per-server resolve domains as search domains."
        )

        let emptyCaptured = """
            CAPTURED OPTIONS:
            Session Name: CWRU
            Layer: OSI_LAYER_3
            Add Routes:
            Exclude Routes:
            """
        let parsedEmpty = try #require(
            VPNController.parsePushedDNSOptions(emptyCaptured),
            "A complete empty captured-options snapshot should parse.")
        #expect(
            parsedEmpty.isAuthoritativeSnapshot
                && parsedEmpty.dnsServers.isEmpty
                && parsedEmpty.searchDomains.isEmpty,
            "A complete empty snapshot should clear stale pushed DNS state.")
        #expect(
            VPNController.updatedPushedOptionValues(
                existing: ["10.8.0.2"],
                parsed: [],
                isAuthoritativeSnapshot: true) == nil,
            "An authoritative empty snapshot should clear an existing pushed value.")

        let truncated =
            "CAPTURED OPTIONS:\nSession Name: CWRU\nDNS Servers:\n  Addresses:\n    10.8.0.2\n"
        #expect(
            VPNController.parsePushedDNSOptions(truncated) == nil,
            "A truncated captured-options payload must not clear or replace persisted DNS state.")

        let incremental = "OPTIONS:\n[dhcp-option] [DOMAIN-SEARCH] [cwru.edu]\n"
        let parsedIncremental = try #require(
            VPNController.parsePushedDNSOptions(incremental),
            "An incremental pushed option should parse.")
        #expect(
            !parsedIncremental.isAuthoritativeSnapshot,
            "Incremental pushed options must not clear fields omitted from the event.")
        #expect(
            VPNController.updatedPushedOptionValues(
                existing: ["10.8.0.2"],
                parsed: parsedIncremental.dnsServers,
                isAuthoritativeSnapshot: false) == ["10.8.0.2"],
            "An incremental event without DNS addresses should retain existing DNS addresses.")
    }

    @Test
    func reportedClientVersionFormat() throws {
        let fields = AppIdentity.reportedClientVersion.split(separator: " ")
        #expect(
            fields.count == 2,
            "IV_GUI_VER should contain exactly one GUI identifier and one version.")
        #expect(
            fields[0] == Substring(AppIdentity.executableName),
            "IV_GUI_VER should use the executable name as its stable GUI identifier.")
        #expect(
            fields[1] == Substring(AppIdentity.version),
            "IV_GUI_VER should report the app version separately from the GUI identifier.")
    }

    @Test
    func estimatedSessionCountdownConfigKeyRejected() throws {
        let removedKeyData = Data(#"{"estimatedSessionCountdown":"11:59:00"}"#.utf8)

        do {
            _ = try JSONDecoder().decode(AppConfig.self, from: removedKeyData)
            try #require(
                Bool(false), "Config decoding should reject removed estimatedSessionCountdown keys."
            )
        } catch DecodingError.dataCorrupted {
        }
    }

    @Test
    func configDiscoveryUsesHomeConfigOnly() throws {
        let homeStateDirectory = temporaryDirectory(named: "cwru-ovpn-config-home")
        let currentDirectory = temporaryDirectory(named: "cwru-ovpn-config-current")
        defer {
            try? FileManager.default.removeItem(at: homeStateDirectory)
            try? FileManager.default.removeItem(at: currentDirectory)
        }

        let homeConfig = homeStateDirectory.appendingPathComponent("config.json")
        try FileManager.default.createDirectory(
            at: homeStateDirectory,
            withIntermediateDirectories: true)
        let currentConfig = currentDirectory.appendingPathComponent("cwru-ovpn.config.json")
        try #"{"tunnelMode":"full"}"#.write(to: homeConfig, atomically: true, encoding: .utf8)
        try #"{"tunnelMode":"full"}"#.write(to: currentConfig, atomically: true, encoding: .utf8)

        try withCurrentDirectory(currentDirectory.path) {
            let resolved = AppConfig.resolvedConfigURL(
                explicitConfigPath: nil,
                homeConfigFile: homeConfig)
            #expect(
                resolved?.path == homeConfig.standardized.path,
                "Default config discovery should prefer the home config over current-directory config."
            )

            let homeLoaded = try AppConfig.load(
                explicitConfigPath: nil,
                homeConfigFile: homeConfig)
            #expect(
                homeLoaded.tunnelMode == .full,
                "Default config discovery should load the home config when both candidates exist.")

            try FileManager.default.removeItem(at: homeConfig)
            #expect(
                AppConfig.resolvedConfigURL(
                    explicitConfigPath: nil,
                    homeConfigFile: homeConfig) == nil,
                "Default config discovery should ignore current-directory config files.")
            let defaulted = try AppConfig.load(
                explicitConfigPath: nil,
                homeConfigFile: homeConfig)
            #expect(
                defaulted.tunnelMode == AppConfig.defaults.tunnelMode,
                "Missing home config should use built-in defaults.")
        }
    }

    @Test
    func configFileReadingRejectsSymlink() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-config-symlink")
        defer { try? FileManager.default.removeItem(at: directory) }

        let target = directory.appendingPathComponent("target.json")
        let link = directory.appendingPathComponent("config-link.json")
        try #"{"privacyMode":false}"#.write(to: target, atomically: true, encoding: .utf8)

        let loaded = try AppConfig.load(explicitConfigPath: target.path)
        #expect(
            !loaded.privacyMode,
            "Config loading should accept regular config files.")

        try #require(
            symlink(target.path, link.path) == 0,
            "Failed to create config symlink fixture.")
        #expect(throws: (any Error).self, "Config loading should reject symlinked config files.") {
            _ = try AppConfig.load(explicitConfigPath: link.path)
        }
    }

    @Test
    func privilegedConnectIntent() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-intent")
        defer { try? FileManager.default.removeItem(at: directory) }

        let configURL = directory.appendingPathComponent("config.json")
        let environmentConfigURL = directory.appendingPathComponent("env-config.json")
        try #"{"tunnelMode":"split","preventSleep":true}"#.write(
            to: configURL,
            atomically: true,
            encoding: .utf8)
        try #"{"tunnelMode":"full","preventSleep":false}"#.write(
            to: environmentConfigURL,
            atomically: true,
            encoding: .utf8)

        let profileURL = directory.appendingPathComponent("profile.ovpn")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true)
        try "client\nremote vpn.case.edu 1194 udp\n".write(
            to: profileURL,
            atomically: true,
            encoding: .utf8)

        let intent = try PrivilegedConnectIntent.resolve(
            configFilePath: configURL.path,
            verbosityOverride: .debug,
            tunnelModeOverride: .full,
            homeConfigFile: configURL,
            homeProfileFile: profileURL)
        #expect(
            intent.profilePath == profileURL.standardized.path,
            "Privileged connect intent should always use the setup-installed profile path.")
        #expect(
            intent.configFilePath == configURL.standardized.path,
            "Privileged connect intent should standardize the resolved config path.")
        #expect(
            intent.verbosity == .debug,
            "Privileged connect intent should honor explicit verbosity.")
        #expect(
            intent.tunnelMode == .full,
            "Privileged connect intent should honor explicit tunnel mode.")
        #expect(
            intent.preventSleep,
            "Privileged connect intent should use preventSleep from config.")
        #expect(
            intent.configuration.privacyMode,
            "Privileged connect intent should carry the validated configuration into the controller."
        )

        try withEnvironmentVariable("CWRU_OVPN_CONFIG", value: environmentConfigURL.path) {
            let defaultIntent = try PrivilegedConnectIntent.resolve(
                configFilePath: nil,
                verbosityOverride: nil,
                tunnelModeOverride: nil,
                homeConfigFile: configURL,
                homeProfileFile: profileURL)
            #expect(
                defaultIntent.configFilePath == configURL.standardized.path,
                "Passwordless privileged connect should ignore CWRU_OVPN_CONFIG and use default config discovery."
            )
            #expect(
                defaultIntent.tunnelMode == .split,
                "Passwordless privileged connect should not let environment select the tunnel mode."
            )
            #expect(
                defaultIntent.verbosity == .daily,
                "Passwordless privileged connect should not let environment select verbosity.")
            #expect(
                defaultIntent.preventSleep,
                "Passwordless privileged connect should not let environment select preventSleep.")
        }
    }

    @Test
    func strictConfigSchema() throws {
        let removedKeys = [
            "includedIPv4Routes",
            "includedIPv4Hosts",
            "includedIPv6Routes",
            "includedIPv6Hosts",
            "dnsDomains",
            "dnsServers",
            "healthCheckHosts",
        ]
        for key in ["unexpected"] + removedKeys {
            let data = try JSONSerialization.data(withJSONObject: [key: []])
            #expect(
                throws: (any Error).self, "Config decoding should reject unsupported key \(key)."
            ) {
                _ = try JSONDecoder().decode(AppConfig.self, from: data)
            }
        }
    }

    @Test
    func fixedSplitTunnelPolicy() throws {
        let policy = SplitTunnelPolicy.fixed
        #expect(
            policy.ipv4Routes == SplitTunnelPolicy.fixedIPv4Routes,
            "The fixed split policy should contain the complete CWRU IPv4 route set.")
        #expect(
            policy.ipv6Routes == SplitTunnelPolicy.fixedIPv6Routes,
            "The fixed split policy should contain the CWRU IPv6 route.")
        #expect(
            policy.dnsDomains == ["case.edu", "cwru.edu"],
            "The fixed split policy should scope both CWRU DNS domains.")
        #expect(
            SplitTunnelPolicy.fixedResolverDomains.contains("22.129.in-addr.arpa")
                && SplitTunnelPolicy.fixedResolverDomains.contains("0.0.a.e.6.0.6.2.ip6.arpa"),
            "The fixed split policy should derive reverse resolver zones for its routes.")
        #expect(
            RouteManager().policyDNSServers() == SplitTunnelPolicy.fixedDNSServers,
            "Split scoped resolvers should always use the fixed CWRU DNS servers.")
    }

    @Test
    func missingConfigErrors() throws {
        let isolatedDirectory = temporaryDirectory(named: "cwru-ovpn-config-isolation")
        defer { try? FileManager.default.removeItem(at: isolatedDirectory) }

        let missingProfile = isolatedDirectory.appendingPathComponent("missing-profile.ovpn")
        do {
            _ = try AppConfig.approvedProfilePath(homeProfileFile: missingProfile)
            try #require(
                Bool(false),
                "A missing profile should raise the missing-profile error even without a config file."
            )
        } catch CLIError.missingProfile {
        }

        let profileState = isolatedDirectory.appendingPathComponent(
            "profile-state", isDirectory: true)
        let profileFile = profileState.appendingPathComponent("profile.ovpn")
        try FileManager.default.createDirectory(
            at: profileState,
            withIntermediateDirectories: true)
        try "client\n".write(
            to: profileFile,
            atomically: true,
            encoding: .utf8)
        let resolvedProfile = try AppConfig.approvedProfilePath(
            homeProfileFile: profileFile)
        #expect(
            resolvedProfile == profileFile.standardized.path,
            "Configs should use the setup-installed profile when it exists.")
    }

    @Test
    func runtimeValidationHardening() throws {
        #expect(
            SplitTunnelPolicy.isValidIPAddress("1.1.1.1"),
            "IPv4 addresses should validate.")
        #expect(
            !SplitTunnelPolicy.isValidIPAddress("1.1.1.1\nnameserver 8.8.8.8"),
            "Injected multiline DNS payloads should be rejected.")
        #expect(
            SplitTunnelPolicy.isValidIPv4Address("1.1.1.1"),
            "IPv4-only split-tunnel host addresses should validate.")
        #expect(
            !SplitTunnelPolicy.isValidIPv4Address("2001:db8::1"),
            "IPv6 addresses should not validate as IPv4 split-tunnel host addresses.")
        #expect(
            SplitTunnelPolicy.isValidDomainName("case.edu"),
            "Expected DNS domains should validate.")
        #expect(
            !SplitTunnelPolicy.isValidDomainName("case.edu/../../etc"),
            "Path-like DNS domains should be rejected.")
        try Self.assertValidatorTable(
            name: "IPv4 CIDR",
            valid: ["0.0.0.0/0", "129.22.0.0/16", "255.255.255.255/32"],
            invalid: [
                "",
                "129.22.0.0/33",
                "129.22.0.0/-1",
                "129.22.0.0/16\n",
                String(repeating: "1", count: SplitTunnelPolicy.maxIPv4CIDRLength + 1),
            ],
            validator: SplitTunnelPolicy.isValidIPv4CIDR
        )
        try Self.assertValidatorTable(
            name: "IP address",
            valid: ["1.1.1.1", "2001:db8::1"],
            invalid: [
                "",
                "-1.1.1.1",
                "1.1.1.1\nnameserver 8.8.8.8",
                String(repeating: "1", count: SplitTunnelPolicy.maxIPAddressLength + 1),
            ],
            validator: SplitTunnelPolicy.isValidIPAddress
        )
        try Self.assertValidatorTable(
            name: "domain",
            valid: [
                "case.edu",
                "\(String(repeating: "a", count: SplitTunnelPolicy.maxDomainLabelLength)).edu",
            ],
            invalid: [
                "",
                ".case.edu",
                "case.edu.",
                "-case.edu",
                "case-.edu",
                "case.edu/../../etc",
                "bad domain",
                "bad\ncase.edu",
                "\(String(repeating: "a", count: SplitTunnelPolicy.maxDomainLabelLength + 1)).edu",
                String(repeating: "a", count: SplitTunnelPolicy.maxDomainNameLength + 1),
            ],
            validator: SplitTunnelPolicy.isValidDomainName
        )
        try Self.assertValidatorTable(
            name: "resolver filename",
            valid: ["case.edu", "22.129.in-addr.arpa"],
            invalid: [
                "",
                ".",
                "..",
                "case.edu/../../etc",
                String(repeating: "a", count: SplitTunnelPolicy.maxDomainNameLength + 1),
            ],
            validator: ResolverPaths.isSafeDomainFileName
        )
        let currentStartTime = try #require(
            processStartTime(getpid()),
            "Current-process start times should be readable for PID validation.")
        let currentExecutablePath = try ExecutionIdentity.currentExecutablePath()
        #expect(
            processMatchesExecutable(
                getpid(),
                expectedExecutablePath: currentExecutablePath,
                expectedStartTime: currentStartTime),
            "PID validation should accept the current process when the executable path and start time both match."
        )
        try withEnvironmentVariable("SUDO_USER", value: "root") {
            let expanded = AppConfig.expandUserPath("~/profile.ovpn")
            #expect(
                !expanded.hasPrefix("/var/root/"),
                "Non-root runs should ignore spoofed SUDO_USER values when expanding ~ paths.")
        }
    }

    private static func assertValidatorTable(
        name: String,
        valid: [String],
        invalid: [String],
        validator: (String) -> Bool
    ) throws {
        for value in valid {
            #expect(validator(value), "\(name) validator should accept '\(value)'.")
        }
        for value in invalid {
            #expect(!validator(value), "\(name) validator should reject '\(value)'.")
        }
    }

    @Test(arguments: ["1.1.1.1\0", "::1\0", "1.1.1.1\0x", "::1\0x"])
    func ipAddressesRejectEmbeddedNUL(_ address: String) {
        #expect(!SplitTunnelPolicy.isValidIPAddress(address))
        #expect(!SplitTunnelPolicy.isValidIPv4Address(address))
        #expect(!SplitTunnelPolicy.isValidIPv6Address(address))
        #expect(!SplitTunnelPolicy.isValidIPv4CIDR(address + "/32"))
        #expect(!SplitTunnelPolicy.isValidIPv6CIDR(address + "/128"))
        #expect(IPRoute.canonicalIPv4Address(address) == nil)
        #expect(IPRoute.canonicalIPv4(address + "/32") == nil)
        #expect(IPRoute.canonicalIPv6(address + "/128") == nil)
    }
}
