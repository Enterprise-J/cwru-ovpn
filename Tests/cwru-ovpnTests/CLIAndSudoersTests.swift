import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct CLIAndSudoersTests {
    @Test
    func doctorDistinguishesUnavailableTunnelInterfaces() throws {
        let unavailable = Diagnostics.liveTunnelInterfaceLines(shell: Shell(handler: { invocation in
            #expect(invocation.launchPath == "/sbin/ifconfig")
            #expect(invocation.arguments == ["-l"])
            throw POSIXError(.EIO)
        }))
        #expect(unavailable.count == 1)
        #expect(unavailable[0].hasPrefix("Live utun interfaces: unavailable ("))
        #expect(unavailable[0].contains(POSIXError(.EIO).localizedDescription))

        let empty = Diagnostics.liveTunnelInterfaceLines(shell: Shell(handler: { _ in
            ShellResult(exitCode: 0, stdout: "lo0 en0\n", stderr: "")
        }))
        #expect(empty == ["Live utun interfaces: none"])

        let present = Diagnostics.liveTunnelInterfaceLines(shell: Shell(handler: { _ in
            ShellResult(exitCode: 0, stdout: "lo0 en0 utun2 utun7\n", stderr: "")
        }))
        #expect(present.first == "Live utun interfaces: utun2, utun7")
        #expect(present.count == 2)
    }

    @Test
    func cliConnectModes() throws {
        switch try CLI.parse(arguments: []) {
        case .help:
            break
        default:
            try #require(Bool(false), "Bare CLI invocation should show help.")
        }

        switch try CLI.parse(arguments: ["connect"]) {
        case .connect(
            _, _, _, let foregroundRequested, let backgroundChild, let startupStatusFilePath):
            #expect(
                !foregroundRequested,
                "connect should detach from the terminal by default.")
            #expect(
                !backgroundChild,
                "connect should not mark itself as the background child.")
            #expect(
                startupStatusFilePath == nil,
                "connect should not set a detached startup status file by default.")
        default:
            try #require(Bool(false), "connect should parse as the connect command.")
        }

        switch try CLI.parse(arguments: ["connect", "--foreground"]) {
        case .connect(
            _, _, _, let foregroundRequested, let backgroundChild, let startupStatusFilePath):
            #expect(
                foregroundRequested,
                "connect --foreground should honor --foreground.")
            #expect(
                !backgroundChild,
                "connect --foreground should not mark itself as the background child.")
            #expect(
                startupStatusFilePath == nil,
                "connect --foreground should not inject a detached startup status file.")
        default:
            try #require(Bool(false), "connect --foreground should parse as connect.")
        }

        switch try CLI.parse(arguments: ["disconnect", "--force"]) {
        case .disconnect(let force):
            #expect(
                force,
                "disconnect --force should parse as a forced disconnect.")
        default:
            try #require(Bool(false), "disconnect --force should parse as disconnect.")
        }
    }

    @Test
    func cliAdvancedOptions() throws {
        switch try CLI.parse(arguments: ["setup", "--profile", "/tmp/profile.ovpn"]) {
        case .setup(let profileSourcePath):
            #expect(
                profileSourcePath == "/tmp/profile.ovpn",
                "setup should accept --profile.")
        default:
            try #require(Bool(false), "setup --profile should parse as setup.")
        }

        switch try CLI.parse(arguments: ["connect", "--config", "/tmp/config.json"]) {
        case .connect(let configFilePath, _, _, _, _, let startupStatusFilePath):
            #expect(
                configFilePath == "/tmp/config.json",
                "connect should accept --config for the config file.")
            #expect(
                startupStatusFilePath == nil,
                "connect --config should not inject a detached startup status file.")
        default:
            try #require(Bool(false), "connect --config should parse as connect.")
        }

        switch try CLI.parse(arguments: ["logs", "--tail", "25"]) {
        case .logs(let tailCount):
            #expect(
                tailCount == 25,
                "logs --tail should accept a positive tail count.")
        default:
            try #require(Bool(false), "logs --tail should parse as logs.")
        }

        switch try CLI.parse(arguments: ["doctor"]) {
        case .doctor:
            break
        default:
            try #require(Bool(false), "doctor should parse as doctor.")
        }

        switch try CLI.parse(arguments: ["uninstall", "--purge"]) {
        case .uninstall(let purge):
            #expect(
                purge,
                "uninstall --purge should parse as uninstall with purge enabled.")
        default:
            try #require(Bool(false), "uninstall --purge should parse as uninstall.")
        }

        switch try CLI.parse(arguments: ["install-shell-integration", "--shell", "/bin/zsh"]) {
        case .installShellIntegration(let preferredShellPath):
            #expect(
                preferredShellPath == "/bin/zsh",
                "install-shell-integration should accept --shell.")
        default:
            try #require(
                Bool(false), "install-shell-integration should parse as the helper command.")
        }

        switch try CLI.parse(arguments: [
            "cleanup-watchdog",
            "--parent-pid", "42",
            "--parent-start-seconds", "123",
            "--parent-start-microseconds", "456",
        ]) {
        case .cleanupWatchdog(let parentPID, let parentStartTime):
            #expect(
                parentPID == 42,
                "cleanup-watchdog should accept internal parent PIDs greater than 1.")
            #expect(
                parentStartTime == ProcessStartTime(seconds: 123, microseconds: 456),
                "cleanup-watchdog should require the complete parent process identity.")
        default:
            try #require(
                Bool(false), "cleanup-watchdog should parse as the internal helper command.")
        }

        try expectRejectsUnexpectedArgument(
            ["--config", "/tmp/config.json"],
            command: "bare invocation",
            argument: "--config")
        try expectRejectsUnexpectedArgument(
            ["--profile", "/tmp/profile.ovpn"],
            command: "connect",
            argument: "--profile")
        try expectRejectsUnexpectedArgument(
            ["setup", "--config", "/tmp/config.json"],
            command: "setup",
            argument: "--config")
        try expectRejectsUnexpectedArgument(
            ["disconnect", "--config", "/tmp/config.json"],
            command: "disconnect",
            argument: "--config")
        try expectRejectsUnexpectedArgument(
            ["status", "--config", "/tmp/config.json"],
            command: "status",
            argument: "--config")
        try expectRejectsUnexpectedArgument(
            ["uninstall", "--config", "/tmp/config.json"],
            command: "uninstall",
            argument: "--config")
        try expectRejectsInvalidPID(
            ["cleanup-watchdog", "--parent-pid", "1"],
            command: "cleanup-watchdog",
            pid: "1")
        try expectRejectsMissingValue(
            ["cleanup-watchdog", "--parent-pid", "42"],
            command: "cleanup-watchdog",
            argument: "--parent-start-seconds")
        try expectRejectsMissingValue(
            ["connect", "--config"],
            command: "connect",
            argument: "--config")
        try expectRejectsMissingValue(
            ["logs", "--tail"],
            command: "logs",
            argument: "--tail")
        try expectRejectsMissingValue(
            ["setup", "--profile"],
            command: "setup",
            argument: "--profile")
    }

    @Test
    func generatedSudoers() throws {
        let userID: uid_t = 501
        let executablePath = "/bin/ls"
        let executableDigest = ProfileManifest.digest(of: try Data(contentsOf: URL(fileURLWithPath: executablePath)))
        let sudoers = Setup.renderSudoers(
            userID: userID,
            executablePath: executablePath,
            executableDigest: executableDigest)

        let lines = sudoers.split(separator: "\n").map(String.init)
        #expect(
            lines.count == 5,
            "Generated sudoers should cover daily connect modes plus disconnect (plain and --force)."
        )
        #expect(
            !sudoers.contains("--foreground"),
            "Generated sudoers should not grant passwordless foreground debug sessions.")
        #expect(
            !sudoers.contains("--verbosity"),
            "Generated sudoers should not grant passwordless debug verbosity.")
        #expect(
            sudoers.contains(
                "#\(userID) ALL=(root) NOPASSWD: sha256:\(executableDigest) \(executablePath) disconnect"
            ),
            "Generated sudoers should allow disconnect without requiring a config flag.")
        #expect(
            sudoers.contains(
                "#\(userID) ALL=(root) NOPASSWD: sha256:\(executableDigest) \(executablePath) disconnect --force"
            ),
            "Generated sudoers should allow disconnect --force for stuck sessions.")
        #expect(
            !sudoers.contains(
                "#\(userID) ALL=(root) NOPASSWD: sha256:\(executableDigest) \(executablePath) setup"
            ),
            "Generated sudoers should not allow passwordless setup.")
        #expect(
            !sudoers.contains(
                "#\(userID) ALL=(root) NOPASSWD: sha256:\(executableDigest) \(executablePath) status"
            ),
            "Generated sudoers should not grant passwordless access to status.")
        #expect(
            !sudoers.contains("--config"),
            "Generated sudoers should not depend on a config path.")
        #expect(
            !sudoers.contains("setup --profile"),
            "Generated sudoers should not allow passwordless setup with an arbitrary profile path.")
        #expect(
            !sudoers.contains("--foreground --verbosity"),
            "Generated sudoers should keep a canonical argument order.")
        let permittedInvocations = Setup.permittedInvocations(executablePath: executablePath)
        let permittedSet = Set(permittedInvocations)
        #expect(
            permittedSet.count == permittedInvocations.count,
            "Generated passwordless invocation list should not contain duplicates.")
        for invocation in permittedInvocations {
            let arguments = Array(invocation.dropFirst())
            #expect(
                Setup.isCanonicalPasswordlessInvocation(arguments),
                "Passwordless invocation should match the canonical connect/disconnect ABI: \(arguments.joined(separator: " "))"
            )
        }
        #expect(
            !Setup.isCanonicalPasswordlessInvocation(["connect", "--mode", "invalid"]),
            "Passwordless ABI guard should reject invalid mode values.")
        #expect(
            !Setup.isCanonicalPasswordlessInvocation(["connect", "--verbosity", "silent"]),
            "Passwordless ABI guard should reject verbosity overrides.")
        for probe in Setup.deniedPasswordlessPolicyProbes(executablePath: executablePath) {
            #expect(
                !permittedSet.contains(probe),
                "Denied invocation must not be present in generated sudoers: \(probe.joined(separator: " "))"
            )
        }

        let tempURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("cwru-ovpn-sudoers-test-\(UUID().uuidString)")
        try sudoers.appending("\n").write(to: tempURL, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let validation = try Setup.validateSudoersFile(at: tempURL.path)
        #expect(
            validation.exitCode == 0,
            "Generated sudoers should pass visudo validation.")
        try Setup.validatePasswordlessInvocationPolicy(executablePath: executablePath)
    }

    @Test
    func privilegedCleanupInputBounds() throws {
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
        base.serverIP = "203.0.113.10"
        base.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        base.appliedDNSDomains = ["case.edu"]
        base.managedRemoteIPv4Routes = [
            ManagedIPv4Route(
                destination: "203.0.113.10/32",
                nextHopKind: .gateway,
                nextHopValue: "192.168.1.1",
                interfaceName: "en0",
                isInterfaceScoped: false),
            ManagedIPv4Route(
                destination: "192.168.1.1/32",
                nextHopKind: .interface,
                nextHopValue: "en0",
                interfaceName: "en0",
                isInterfaceScoped: false),
        ]
        base.replacedRemoteIPv4Routes = [
            ManagedIPv4Route(
                destination: "203.0.113.10/32",
                nextHopKind: .gateway,
                nextHopValue: "192.168.0.1",
                interfaceName: "en0",
                isInterfaceScoped: false),
            ManagedIPv4Route(
                destination: "203.0.113.10/32",
                nextHopKind: .gateway,
                nextHopValue: "192.168.0.1",
                interfaceName: "en0",
                isInterfaceScoped: true),
            ManagedIPv4Route(
                destination: "192.168.1.1/32",
                nextHopKind: .gateway,
                nextHopValue: "192.168.0.1",
                interfaceName: "en0",
                isInterfaceScoped: false),
            ManagedIPv4Route(
                destination: "192.168.1.1/32",
                nextHopKind: .gateway,
                nextHopValue: "192.168.0.1",
                interfaceName: "en0",
                isInterfaceScoped: true),
        ]
        try base.validateForPrivilegedCleanup()

        var migratedNetworkState = base
        migratedNetworkState.serverIP = "198.51.100.20"
        migratedNetworkState.physicalGateway = "172.20.10.1"
        migratedNetworkState.physicalInterface = "en1"
        try migratedNetworkState.validateForPrivilegedCleanup()

        var preservedRouteState = migratedNetworkState
        preservedRouteState.managedRemoteIPv4Routes = nil
        preservedRouteState.replacedRemoteIPv4Routes = [base.replacedRemoteIPv4Routes![1]]
        try preservedRouteState.validateForPrivilegedCleanup()

        var manualIPv6State = base
        manualIPv6State.originalIPv6Mode = "Manual"
        try manualIPv6State.validateForPrivilegedCleanup()

        let tooLongDomain =
            "\(String(repeating: "a", count: SplitTunnelPolicy.maxDomainLabelLength + 1)).edu"
        let cases: [(String, (inout SessionState) -> Void)] = [
            ("tunnel interface", { $0.tunName = String(repeating: "u", count: 33) }),
            ("physical interface", { $0.physicalInterface = String(repeating: "e", count: 33) }),
            ("network service", { $0.physicalServiceName = String(repeating: "W", count: 129) }),
            (
                "server IP",
                {
                    $0.serverIP = String(
                        repeating: "1", count: SplitTunnelPolicy.maxIPAddressLength + 1)
                }
            ),
            (
                "gateway",
                {
                    $0.physicalGateway = String(
                        repeating: "1", count: SplitTunnelPolicy.maxIPAddressLength + 1)
                }
            ),
            ("VPN gateway IPv4", { $0.vpnGatewayIPv4 = "999.999.999.999" }),
            ("original DNS server", { $0.originalDNSServers = ["1.1.1.1\nnameserver 8.8.8.8"] }),
            (
                "original default search domain",
                { $0.originalDefaultSearchDomains = ["bad/domain"] }
            ),
            ("pushed DNS server", { $0.pushedDNSServers = ["bad dns"] }),
            ("full-tunnel DNS server", { $0.fullTunnelDNSServers = ["999.999.999.999"] }),
            ("original search domain", { $0.originalSearchDomains = ["bad domain"] }),
            ("pushed search domain", { $0.pushedSearchDomains = ["bad/domain"] }),
            ("full-tunnel search domain", { $0.fullTunnelSearchDomains = [".case.edu"] }),
            ("IPv6 mode", { $0.originalIPv6Mode = "Automatic\n-setv6off" }),
            (
                "full-tunnel route",
                {
                    $0.fullTunnelDefaultRoutes = [
                        ManagedIPv4Route(
                            destination: "bad route", nextHopKind: .gateway,
                            nextHopValue: "1.1.1.1",
                            interfaceName: "en0", isInterfaceScoped: true)
                    ]
                }
            ),
            (
                "full-tunnel route next hop",
                {
                    $0.fullTunnelDefaultRoutes = [
                        ManagedIPv4Route(
                            destination: "0.0.0.0/1", nextHopKind: .interface,
                            nextHopValue: "-utun7",
                            interfaceName: "utun7", isInterfaceScoped: false)
                    ]
                }
            ),
            (
                "scoped managed remote IPv4 route",
                {
                    $0.managedRemoteIPv4Routes = [
                        ManagedIPv4Route(
                            destination: "203.0.113.10/32", nextHopKind: .gateway,
                            nextHopValue: "192.168.1.1",
                            interfaceName: "en0", isInterfaceScoped: true)
                    ]
                }
            ),
            (
                "too many managed remote IPv4 routes",
                {
                    $0.managedRemoteIPv4Routes?.append(
                        ManagedIPv4Route(
                            destination: "203.0.113.10/32", nextHopKind: .gateway,
                            nextHopValue: "192.168.1.2",
                            interfaceName: "en0", isInterfaceScoped: false))
                }
            ),
            (
                "too many replaced remote IPv4 routes",
                { session in
                    session.replacedRemoteIPv4Routes?.append(
                        ManagedIPv4Route(
                            destination: "203.0.113.10/32",
                            nextHopKind: .gateway,
                            nextHopValue: "192.168.0.2",
                            interfaceName: "en0",
                            isInterfaceScoped: false)
                    )
                }
            ),
            (
                "duplicate managed remote IPv4 route",
                {
                    $0.managedRemoteIPv4Routes = [
                        $0.managedRemoteIPv4Routes![0], $0.managedRemoteIPv4Routes![0],
                    ]
                }
            ),
            (
                "non-host replaced remote IPv4 destination",
                {
                    $0.replacedRemoteIPv4Routes?[0] = ManagedIPv4Route(
                        destination: "198.51.100.0/24", nextHopKind: .gateway,
                        nextHopValue: "192.168.0.1",
                        interfaceName: "en0", isInterfaceScoped: false)
                }
            ),
            ("session-owned block-ipv6 route", { $0.sessionOwnedBlockedIPv6Routes = ["::/0"] }),
            (
                "split route",
                {
                    $0.appliedSplitIPv4Routes = [
                        String(repeating: "1", count: SplitTunnelPolicy.maxIPv4CIDRLength + 1)
                    ]
                }
            ),
            ("DNS domain", { $0.appliedDNSDomains = [tooLongDomain] }),
            ("profile path", { $0.profilePath = "/" + String(repeating: "a", count: 1024) }),
            ("profile path control", { $0.profilePath = "/tmp/profile\n.ovpn" }),
        ]

        for (label, mutate) in cases {
            var session = base
            mutate(&session)
            do {
                try session.validateForPrivilegedCleanup()
                try #require(Bool(false), "Privileged cleanup validation should reject \(label).")
            } catch SessionStateError.unsafeRecoveryState(_) {
            } catch {
                throw error
            }
        }
    }

    @Test
    func startupDoesNotTrustADeadControllersConnectedState() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-dead-startup")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory)
        let session = makeSessionState(
            pid: Int32.max - 19, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalServiceName: "Wi-Fi", originalDNSServers: [], originalSearchDomains: [],
            originalIPv6Mode: "Automatic", tunName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        try session.save(to: store)
        #expect(throws: (any Error).self) {
            try DetachedConnectLauncher.waitForConnection(childPID: session.pid,
                                                           expectedExecutablePath: session.executablePath,
                                                           expectedStartTime: session.processStartTime,
                                                           startupStatusFilePath: directory.appendingPathComponent("startup").path,
                                                           sessionStore: store)
        }
    }

}
