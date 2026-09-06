import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct CleanupRecoveryTests {
    @Test
    func offlineCleanupHealthMessaging() throws {
        let onlineMessages = SessionControl.unhealthyCleanupMessages(networkOffline: false)
        #expect(
            onlineMessages.console.contains("--force"),
            "Online unhealthy cleanup should keep pointing at disconnect --force.")
        #expect(
            onlineMessages.recovery.contains("Cleanup ran"),
            "Online unhealthy cleanup recovery text should describe the cleanup outcome.")

        let offlineMessages = SessionControl.unhealthyCleanupMessages(networkOffline: true)
        #expect(
            offlineMessages.console.contains("captive portal"),
            "Offline unhealthy cleanup should explain the captive-portal or offline cause.")
        #expect(
            offlineMessages.recovery.contains("Cleanup ran"),
            "Offline unhealthy cleanup recovery text should still surface via the reconnect path.")

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        let manager = RouteManager(splitTunnelPolicy: configuration)

        let present = Shell.withCommandHandler({ invocation in
            if invocation.launchPath == "/sbin/route",
                invocation.arguments == ["-n", "get", "default"]
            {
                return ShellResult(
                    exitCode: 0,
                    stdout: "   route to: default\n    gateway: 192.168.1.1\n  interface: en0\n",
                    stderr: "")
            }
            return ShellResult(exitCode: 1, stdout: "", stderr: "unexpected")
        }) {
            manager.physicalDefaultRouteIsPresent()
        }
        #expect(
            present, "A default route via en0 should count as a present physical default route.")

        let absent = Shell.withCommandHandler({ invocation in
            if invocation.launchPath == "/sbin/route",
                invocation.arguments == ["-n", "get", "default"]
            {
                return ShellResult(
                    exitCode: 2, stdout: "",
                    stderr: "route: writing to routing socket: not in table")
            }
            return ShellResult(exitCode: 1, stdout: "", stderr: "unexpected")
        }) {
            manager.physicalDefaultRouteIsPresent()
        }
        #expect(!absent, "A missing default route should be reported as offline.")

        let session = makeSessionState(
            pid: getpid(),
            profilePath: "/tmp/profile.ovpn",
            configFilePath: nil,
            physicalGateway: "172.30.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: ["home"],
            originalIPv6Mode: "Automatic",
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )

        let offlineHealthy = try Shell.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/route" else {
                return ShellResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            return ShellResult(
                exitCode: 2, stdout: "", stderr: "route: writing to routing socket: not in table")
        }) {
            try manager.cleanupDefaultRouteLooksHealthy(using: session)
        }
        #expect(
            offlineHealthy,
            "A missing default route with an unreachable physical gateway is an offline Mac, not a failed cleanup."
        )

        let strandedHealthy = try Shell.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/route" else {
                return ShellResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            if invocation.arguments == ["-n", "get", "172.30.1.1"] {
                return ShellResult(
                    exitCode: 0,
                    stdout: "   route to: 172.30.1.1\n  interface: en0\n",
                    stderr: "")
            }
            return ShellResult(
                exitCode: 2, stdout: "", stderr: "route: writing to routing socket: not in table")
        }) {
            try manager.cleanupDefaultRouteLooksHealthy(using: session)
        }
        #expect(
            !strandedHealthy,
            "A missing default route on a reachable physical gateway should still count as an unhealthy cleanup."
        )

        let tunnelDefaultHealthy = try Shell.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/route",
                invocation.arguments == ["-n", "get", "default"]
            else {
                return ShellResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            return ShellResult(
                exitCode: 0,
                stdout: "   route to: default\n    gateway: 10.8.0.1\n  interface: utun7\n",
                stderr: "")
        }) {
            try manager.cleanupDefaultRouteLooksHealthy(using: session)
        }
        #expect(
            !tunnelDefaultHealthy,
            "A default route still pointing at the tunnel should count as an unhealthy cleanup.")

        let replacedRoute = ManagedIPv4Route(
            destination: "207.182.159.132/32",
            nextHopKind: .gateway,
            nextHopValue: "172.30.1.1",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let restorableOnSameNetwork = Shell.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/route",
                invocation.arguments == ["-n", "get", "172.30.1.1"]
            else {
                return ShellResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            return ShellResult(
                exitCode: 0,
                stdout: "   route to: 172.30.1.1\n  interface: en0\n",
                stderr: "")
        }) {
            manager.replacedRemoteHostRouteIsRestorable(replacedRoute)
        }
        #expect(
            restorableOnSameNetwork,
            "A replaced host route should still be required while its gateway stays directly reachable."
        )

        let restorableAfterWiFiChange = Shell.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/route",
                invocation.arguments == ["-n", "get", "172.30.1.1"]
            else {
                return ShellResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            return ShellResult(
                exitCode: 0,
                stdout: "   route to: 172.30.1.1\n    gateway: 192.168.5.1\n  interface: en0\n",
                stderr: "")
        }) {
            manager.replacedRemoteHostRouteIsRestorable(replacedRoute)
        }
        #expect(
            !restorableAfterWiFiChange,
            "A replaced host route is unrestorable once its gateway is only reachable through another router."
        )

        let restorableWhileOffline = Shell.withCommandHandler({ _ in
            ShellResult(
                exitCode: 2, stdout: "", stderr: "route: writing to routing socket: not in table")
        }) {
            manager.replacedRemoteHostRouteIsRestorable(replacedRoute)
        }
        #expect(
            !restorableWhileOffline,
            "A replaced host route is unrestorable once its gateway is gone with the network.")

        let interfaceRoute = ManagedIPv4Route(
            destination: "207.182.159.132/32",
            nextHopKind: .interface,
            nextHopValue: "en0",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let addressedInterface = Shell.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/ifconfig", invocation.arguments == ["en0"] else {
                return ShellResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            return ShellResult(
                exitCode: 0,
                stdout: "en0: flags=8863<UP,BROADCAST>\n\tinet 172.30.1.24 netmask 0xffffff00\n",
                stderr: "")
        }) {
            manager.replacedRemoteHostRouteIsRestorable(interfaceRoute)
        }
        #expect(
            addressedInterface,
            "An interface-scoped replaced route should still be required while that interface holds an IPv4 address."
        )

        let strippedInterface = Shell.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/ifconfig", invocation.arguments == ["en0"] else {
                return ShellResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            return ShellResult(
                exitCode: 0,
                stdout: "en0: flags=8863<UP,BROADCAST>\n\tinet6 fe80::1%en0 prefixlen 64\n",
                stderr: "")
        }) {
            manager.replacedRemoteHostRouteIsRestorable(interfaceRoute)
        }
        #expect(
            !strippedInterface,
            "An interface without an IPv4 address cannot carry a restored host route.")
    }

    @Test
    func cleanupOutcomePreservesUnhealthyWakeState() throws {
        let healthyWake = VPNController.cleanupCompletionOutcome(
            cleanupHealthy: true, disconnectingAfterWake: true)
        #expect(
            healthyWake.shouldRemoveSessionState && healthyWake.recoveryMessage == nil,
            "Healthy wake-triggered cleanup should remove completed session state.")

        let unhealthyWake = VPNController.cleanupCompletionOutcome(
            cleanupHealthy: false, disconnectingAfterWake: true)
        #expect(
            !unhealthyWake.shouldRemoveSessionState,
            "Unhealthy wake-triggered cleanup should preserve session state for retry.")
        #expect(
            unhealthyWake.recoveryMessage?.contains("after wake") == true,
            "Unhealthy wake-triggered cleanup should record a wake-specific recovery message.")

        let unhealthyNormal = VPNController.cleanupCompletionOutcome(
            cleanupHealthy: false, disconnectingAfterWake: false)
        #expect(
            !unhealthyNormal.shouldRemoveSessionState,
            "Unhealthy cleanup should preserve session state outside wake handling as well.")
    }

    @Test
    func mockedStaleStateRecovery() throws {
        let stateDirectory = temporaryDirectory(named: "cwru-ovpn-recovery-state")
        defer { try? FileManager.default.removeItem(at: stateDirectory) }
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-recovery")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }
        let sessionStore = StateDirectory(directory: stateDirectory)
        let routeLedger = RemoteHostRouteLedger(
            directory: stateDirectory.appendingPathComponent("route-ledger", isDirectory: true)
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])
        let shell = Shell(handler: { try mockSystem.handle($0) })
        let profileURL = URL(
            fileURLWithPath: "/private/tmp/cwru-ovpn-stale-profile-\(UUID().uuidString).ovpn")
        defer { try? FileManager.default.removeItem(at: profileURL) }
        let configURL = stateDirectory.appendingPathComponent("config.json")
        try FileManager.default.createDirectory(
            at: stateDirectory, withIntermediateDirectories: true)
        try "".write(to: profileURL, atomically: true, encoding: .utf8)
        try #"{"tunnelMode":"split","preventSleep":true}"#.write(
            to: configURL,
            atomically: true,
            encoding: .utf8)

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
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        session.appliedDNSDomains = ["case.edu", "22.129.in-addr.arpa"]
        try session.save(to: sessionStore)

        try FileManager.default.createDirectory(
            at: resolverDirectory, withIntermediateDirectories: true)
        let resolverFile = ResolverPaths.fileURL(for: "case.edu", in: resolverDirectory)
        try scopedResolverContents(domain: "case.edu", nameServer: "129.22.4.32").write(
            to: resolverFile,
            atomically: true,
            encoding: .utf8)

        try SessionControl.disconnectExistingSession(
            force: false,
            sessionStore: sessionStore,
            shell: shell,
            resolverDirectory: resolverDirectory,
            remoteHostRouteLedger: routeLedger,
            eventLogDirectory: stateDirectory.appendingPathComponent("event-log", isDirectory: true)
        )

        #expect(
            SessionState.load(from: sessionStore) == nil,
            "Recovering stale state should remove the persisted session after healthy cleanup.")
        #expect(
            !FileManager.default.fileExists(atPath: resolverFile.path),
            "Recovering stale state should remove scoped resolver files.")
    }

    @Test
    func staleCleanupWithoutConfigFile() throws {
        let stateDirectory = temporaryDirectory(named: "cwru-ovpn-state-missing-config")
        defer { try? FileManager.default.removeItem(at: stateDirectory) }
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-missing-config")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }
        let sessionStore = StateDirectory(directory: stateDirectory)
        let routeLedger = RemoteHostRouteLedger(
            directory: stateDirectory.appendingPathComponent("route-ledger", isDirectory: true)
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])
        let shell = Shell(handler: { try mockSystem.handle($0) })
        let profileURL = URL(
            fileURLWithPath: "/private/tmp/cwru-ovpn-missing-config-\(UUID().uuidString).ovpn")
        defer { try? FileManager.default.removeItem(at: profileURL) }
        try FileManager.default.createDirectory(
            at: stateDirectory, withIntermediateDirectories: true)
        try "".write(to: profileURL, atomically: true, encoding: .utf8)

        var session = makeSessionState(
            pid: Int32.max - 11,
            profilePath: profileURL.path,
            configFilePath: stateDirectory.appendingPathComponent("missing.json").path,
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
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        session.appliedDNSDomains = ["case.edu", "22.129.in-addr.arpa"]
        try session.save(to: sessionStore)

        try FileManager.default.createDirectory(
            at: resolverDirectory, withIntermediateDirectories: true)
        let resolverFile = ResolverPaths.fileURL(for: "case.edu", in: resolverDirectory)
        try scopedResolverContents(domain: "case.edu", nameServer: "129.22.4.32").write(
            to: resolverFile,
            atomically: true,
            encoding: .utf8)

        try SessionControl.disconnectExistingSession(
            force: false,
            sessionStore: sessionStore,
            shell: shell,
            resolverDirectory: resolverDirectory,
            remoteHostRouteLedger: routeLedger,
            eventLogDirectory: stateDirectory.appendingPathComponent("event-log", isDirectory: true)
        )

        #expect(
            SessionState.load(from: sessionStore) == nil,
            "Stale cleanup should not depend on the config file still existing.")
        #expect(
            !FileManager.default.fileExists(atPath: resolverFile.path),
            "Stale cleanup without a config file should still remove scoped resolver files.")
    }

    @Test
    func forcedStaleCleanupRefreshesDHCPLease() throws {
        let stateDirectory = temporaryDirectory(named: "cwru-ovpn-state-force-dhcp")
        defer { try? FileManager.default.removeItem(at: stateDirectory) }
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-force-dhcp")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }
        let sessionStore = StateDirectory(directory: stateDirectory)
        let routeLedger = RemoteHostRouteLedger(
            directory: stateDirectory.appendingPathComponent("route-ledger", isDirectory: true)
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])
        let shell = Shell(handler: { try mockSystem.handle($0) })
        var session = makeSessionState(
            pid: Int32.max - 13,
            profilePath: "/private/tmp/cwru-ovpn-force-profile-\(UUID().uuidString).ovpn",
            configFilePath: nil,
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
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        try session.save(to: sessionStore)

        try SessionControl.disconnectExistingSession(
            force: true,
            sessionStore: sessionStore,
            shell: shell,
            resolverDirectory: resolverDirectory,
            remoteHostRouteLedger: routeLedger,
            eventLogDirectory: stateDirectory.appendingPathComponent("event-log", isDirectory: true)
        )

        #expect(
            SessionState.load(from: sessionStore) == nil,
            "Forced stale cleanup should remove persisted state.")
        let probeIndex = try #require(
            mockSystem.recordedCommands.firstIndex(of: "/usr/sbin/ipconfig getpacket en0"))
        let renewIndex = try #require(
            mockSystem.recordedCommands.firstIndex(of: "/usr/sbin/ipconfig set en0 DHCP"))
        #expect(
            probeIndex < renewIndex,
            "Forced stale cleanup should only renew DHCP after the DHCP lease probe succeeds.")
    }

    @Test
    func connectPreservesUnhealthyStaleRecoveryState() throws {
        let stateDirectory = temporaryDirectory(named: "cwru-ovpn-state-unhealthy-reconnect")
        defer { try? FileManager.default.removeItem(at: stateDirectory) }
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-unhealthy-reconnect")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }
        let sessionStore = StateDirectory(directory: stateDirectory)
        let routeLedger = RemoteHostRouteLedger(
            directory: stateDirectory.appendingPathComponent("route-ledger", isDirectory: true)
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            ignoredRouteDeletes: ["129.22.0.0/16"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "129.22.0.0/16",
                    gateway: "link#1",
                    interfaceName: "utun7")
            ])
        let shell = Shell(handler: { try mockSystem.handle($0) })
        let profileURL = URL(
            fileURLWithPath: "/private/tmp/cwru-ovpn-unhealthy-profile-\(UUID().uuidString).ovpn")
        defer { try? FileManager.default.removeItem(at: profileURL) }
        try FileManager.default.createDirectory(
            at: stateDirectory, withIntermediateDirectories: true)
        try "".write(to: profileURL, atomically: true, encoding: .utf8)

        var session = makeSessionState(
            pid: Int32.max - 12,
            profilePath: profileURL.path,
            configFilePath: nil,
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
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        try session.save(to: sessionStore)

        do {
            _ = try SessionControl.handleConnectRequestForActiveSession(
                targetMode: .split,
                configFilePath: nil,
                sessionStore: sessionStore,
                shell: shell,
                resolverDirectory: resolverDirectory,
                remoteHostRouteLedger: routeLedger,
                eventLogDirectory: stateDirectory.appendingPathComponent(
                    "event-log", isDirectory: true)
            )
            try #require(
                Bool(false),
                "Reconnect should stop when stale cleanup leaves unhealthy recovery state.")
        } catch VPNControllerError.failedToStart(let message) {
            #expect(
                message.contains("Cleanup ran"),
                "Reconnect should surface the stale cleanup recovery failure.")
            #expect(
                message.contains("disconnect --force"),
                "Reconnect failure should point at disconnect --force for recovery.")
        }

        let remainingSession = SessionState.load(from: sessionStore)
        #expect(
            remainingSession?.cleanupNeeded == true,
            "Reconnect should preserve cleanupNeeded after unhealthy stale cleanup.")
        #expect(
            remainingSession?.phase == .failed,
            "Reconnect should preserve failed recovery state after unhealthy stale cleanup.")
        #expect(
            remainingSession?.lastEvent == "RECOVERY_REQUIRED",
            "Reconnect should mark recovery as required after unhealthy stale cleanup.")
    }

    @Test
    func preConnectCleanupDoesNotRemoveUnappliedResolvers() throws {
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-pre-connect-cleanup")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }
        let routeLedger = RemoteHostRouteLedger(
            directory: resolverDirectory.appendingPathComponent(".route-ledger", isDirectory: true)
        )

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: [])
        let shell = Shell(handler: { try mockSystem.handle($0) })
        var session = makeSessionState(
            pid: Int32.max - 12,
            profilePath: "/private/tmp/profile.ovpn",
            configFilePath: nil,
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
        session.phase = .connecting
        session.tunName = nil
        session.vpnIPv4 = nil
        session.vpnIPv6 = nil

        try FileManager.default.createDirectory(
            at: resolverDirectory, withIntermediateDirectories: true)
        let existingResolver = ResolverPaths.fileURL(for: "case.edu", in: resolverDirectory)
        try "preexisting\n".write(to: existingResolver, atomically: true, encoding: .utf8)

        let cleanupHealthy = try RouteManager(
            appliedState: session,
            shell: shell,
            resolverDirectory: resolverDirectory,
            remoteHostRouteLedger: routeLedger,
            eventLogDirectory: resolverDirectory.appendingPathComponent(
                ".event-log", isDirectory: true)
        ).cleanup(using: session)
        let directCleanupHealthy = try makeRouteManager(
            splitTunnelPolicy: .fixed,
            shell: shell,
            resolverDirectory: resolverDirectory
        )
        .cleanup(using: session)

        #expect(
            cleanupHealthy,
            "Pre-connect cleanup without an applied tunnel should still finish healthy.")
        #expect(
            directCleanupHealthy,
            "Direct cleanup with a fixed split policy should still finish healthy without applied split state."
        )
        #expect(
            FileManager.default.fileExists(atPath: existingResolver.path),
            "Pre-connect cleanup should not remove resolver files that this session never applied.")
        #expect(
            !mockSystem.recordedCommands.contains("/bin/rm -f \(existingResolver.path)"),
            "Pre-connect cleanup should not issue resolver removal for unapplied fixed CWRU policy."
        )
    }

    @Test
    func cleanupDetectsManagedDefaultRouteResidue() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        let session = makeSessionState(
            pid: 1024,
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
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            ignoredRouteDeletes: ["0.0.0.0/1", "128.0.0.0/1"],
            initialRoutes: [
                MockSystem.RouteRecord(
                    destination: "0.0.0.0/1",
                    gateway: "link#1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "link#1",
                    interfaceName: "utun7"),
            ])

        let cleanupHealthy = try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
        }

        #expect(
            !cleanupHealthy,
            "Cleanup should stay unhealthy when managed /1 tunnel routes remain after deletion.")
    }

    @Test
    func cleanupDetectsGatewayDefaultRouteResidueWithoutLedger() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        let session = makeSessionState(
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
            tunnelMode: .full,
            cleanupNeeded: true
        )
        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            ignoredRouteDeletes: ["0.0.0.0/1", "128.0.0.0/1"],
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

        let cleanupHealthy = try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
        }

        #expect(
            !cleanupHealthy,
            "Cleanup should detect gateway-shaped tunnel default routes even without a captured ledger."
        )
    }

    @Test
    func cleanupRemovesCapturedFullTunnelGatewayRoutes() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        var session = makeSessionState(
            pid: 1027,
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
        session.fullTunnelDefaultRoutes = [
            ManagedIPv4Route(
                destination: "0.0.0.0/1",
                nextHopKind: .gateway,
                nextHopValue: "10.8.0.1",
                interfaceName: "utun7",
                isInterfaceScoped: false),
            ManagedIPv4Route(
                destination: "128.0.0.0/1",
                nextHopKind: .gateway,
                nextHopValue: "10.8.0.1",
                interfaceName: "utun7",
                isInterfaceScoped: false),
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
                    destination: "0.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "128.0.0.0/1",
                    gateway: "10.8.0.1",
                    interfaceName: "utun7"),
            ])

        let cleanupHealthy = try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
        }

        #expect(
            cleanupHealthy,
            "Cleanup should remove captured gateway-shaped full-tunnel default routes.")
        #expect(
            mockSystem.recordedCommands.contains("/sbin/route -n delete -net 0.0.0.0/1 10.8.0.1"),
            "Cleanup should delete the captured lower-half route by exact gateway and interface.")
        #expect(
            mockSystem.recordedCommands.contains("/sbin/route -n delete -net 128.0.0.0/1 10.8.0.1"),
            "Cleanup should delete the captured upper-half route by exact gateway and interface.")
    }

    @Test
    func cleanupDetectsOpenVPNIPv6DefaultRouteResidue() throws {
        let configuration = SplitTunnelPolicy(
            ipv4Routes: [],
            dnsDomains: [],
            dnsServers: [],
        )
        let session = makeSessionState(
            pid: 1026,
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
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"],
            ignoredRouteDeletes: ["::/1", "8000::/1"],
            initialIPv6RouteRecords: [
                MockSystem.RouteRecord(
                    destination: "::/1",
                    gateway: "link#1",
                    interfaceName: "utun7"),
                MockSystem.RouteRecord(
                    destination: "8000::/1",
                    gateway: "link#1",
                    interfaceName: "utun7"),
            ])

        let cleanupHealthy = try Shell.withCommandHandler({ try mockSystem.handle($0) }) {
            try RouteManager(splitTunnelPolicy: configuration).cleanup(using: session)
        }

        #expect(
            !cleanupHealthy,
            "Cleanup should stay unhealthy when OpenVPN IPv6 /1 tunnel routes remain after deletion."
        )
    }

    @Test
    func cleanupWatchdogValidation() throws {
        #expect(
            !CleanupWatchdog.shouldFinishMonitoring(parentExists: true, sessionExists: true),
            "Cleanup watchdog should keep monitoring while its parent and recovery ledger exist.")
        #expect(
            CleanupWatchdog.shouldFinishMonitoring(parentExists: false, sessionExists: true),
            "Cleanup watchdog should finish when its parent exits.")
        #expect(
            CleanupWatchdog.shouldFinishMonitoring(parentExists: true, sessionExists: false),
            "Cleanup watchdog should finish when cleanup removes the recovery ledger.")

        let stateDirectory = temporaryDirectory(named: "cwru-ovpn-watchdog-state")
        defer { try? FileManager.default.removeItem(at: stateDirectory) }
        let resolverDirectory = stateDirectory.appendingPathComponent(
            "resolvers", isDirectory: true)
        let eventLogDirectory = stateDirectory.appendingPathComponent("events", isDirectory: true)
        let sessionStore = StateDirectory(
            directory: stateDirectory.appendingPathComponent("session", isDirectory: true))
        let routeLedger = RemoteHostRouteLedger(
            directory: stateDirectory.appendingPathComponent("route-ledger", isDirectory: true)
        )
        let profileURL = stateDirectory.appendingPathComponent("profile.ovpn")
        let configURL = stateDirectory.appendingPathComponent("config.json")
        try FileManager.default.createDirectory(
            at: stateDirectory, withIntermediateDirectories: true)
        try #"{"tunnelMode":"split","preventSleep":true}"#.write(
            to: configURL,
            atomically: true,
            encoding: .utf8)

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
        session.executablePath = try ExecutionIdentity.currentExecutablePath()

        #expect(
            CleanupWatchdog.sessionMatchesParent(
                session,
                parentPID: session.pid,
                parentStartTime: session.processStartTime,
                watchdogExecutablePath: session.executablePath
            ), "Cleanup watchdog should accept a complete matching parent identity.")
        #expect(
            !CleanupWatchdog.sessionMatchesParent(
                session,
                parentPID: session.pid + 1,
                parentStartTime: session.processStartTime,
                watchdogExecutablePath: session.executablePath
            ), "Cleanup watchdog should reject a mismatched parent PID.")
        #expect(
            !CleanupWatchdog.sessionMatchesParent(
                session,
                parentPID: session.pid,
                parentStartTime: ProcessStartTime(
                    seconds: session.processStartTime.seconds + 1,
                    microseconds: session.processStartTime.microseconds),
                watchdogExecutablePath: session.executablePath
            ), "Cleanup watchdog should reject a mismatched parent start time.")
        #expect(
            !CleanupWatchdog.sessionMatchesParent(
                session,
                parentPID: session.pid,
                parentStartTime: session.processStartTime,
                watchdogExecutablePath: "/tmp/different-cwru-ovpn"
            ), "Cleanup watchdog should reject a mismatched executable path.")
        try session.save(to: sessionStore)

        var alerts: [String] = []
        CleanupWatchdog.performCleanup(
            parentPID: session.pid,
            parentStartTime: session.processStartTime,
            sessionStore: sessionStore,
            shell: Shell(handler: { _ in ShellResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }),
            resolverDirectory: resolverDirectory,
            remoteHostRouteLedger: routeLedger,
            eventLogDirectory: eventLogDirectory,
            showCriticalAlert: { alerts.append($0) }
        )

        let reloaded = SessionState.load(from: sessionStore)
        #expect(
            reloaded?.phase == .failed,
            "Cleanup watchdog should preserve recovery state when validation rejects session data.")
        #expect(
            reloaded?.cleanupNeeded == true,
            "Cleanup watchdog should keep cleanupNeeded enabled after a failed cleanup attempt.")
        #expect(
            reloaded?.lastInfo?.contains("Cleanup watchdog failed") == true,
            "Cleanup watchdog should record the validation failure message.")
        #expect(
            alerts.count == 1,
            "Cleanup watchdog should surface one critical alert after a failed cleanup attempt.")
    }

    @Test(arguments: [false, true])
    func staleRecoveryRespectsControllerLock(watchdog: Bool) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-recovery-lock")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory)
        var session = makeSessionState(
            pid: Int32.max - 17, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalServiceName: "Wi-Fi", originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: [], originalIPv6Mode: "Automatic", tunName: "utun7",
            tunnelMode: .split, cleanupNeeded: true)
        session.executablePath = try ExecutionIdentity.currentExecutablePath()
        try session.save(to: store)
        var lock: ControllerLock? = try ControllerLock(at: directory.appendingPathComponent("controller.lock"))
        defer { withExtendedLifetime(lock) {} }
        let system = MockSystem(serviceName: "Wi-Fi", physicalGateway: "192.168.1.1",
                                physicalInterface: "en0", physicalDNSServers: ["1.1.1.1"],
                                physicalSearchDomains: [], ipv6Mode: "Automatic", tunnelInterfaces: [])
        let shell = Shell(handler: system.handle)
        let resolverDirectory = directory.appendingPathComponent("resolver")
        let ledger = RemoteHostRouteLedger(directory: directory.appendingPathComponent("routes"))
        let logDirectory = directory.appendingPathComponent("logs")
        if watchdog {
            let finished = CleanupWatchdog.performCleanup(parentPID: session.pid, parentStartTime: session.processStartTime,
                                                          sessionStore: store, shell: shell, resolverDirectory: resolverDirectory,
                                                          remoteHostRouteLedger: ledger, eventLogDirectory: logDirectory,
                                                          showCriticalAlert: { _ in })
            #expect(!finished)
        } else {
            #expect(throws: (any Error).self) {
                try SessionControl.disconnectExistingSession(force: false, sessionStore: store,
                                                            shell: shell, resolverDirectory: resolverDirectory,
                                                            remoteHostRouteLedger: ledger,
                                                            eventLogDirectory: logDirectory)
            }
        }
        #expect(system.recordedCommands.isEmpty)
        #expect(SessionState.load(from: store)?.pid == session.pid)
        if watchdog {
            lock = nil
            let finished = CleanupWatchdog.performCleanup(parentPID: session.pid, parentStartTime: session.processStartTime,
                                                          sessionStore: store, shell: shell, resolverDirectory: resolverDirectory,
                                                          remoteHostRouteLedger: ledger, eventLogDirectory: logDirectory,
                                                          showCriticalAlert: { message in Issue.record("\(message)") })
            #expect(finished)
            #expect(SessionState.load(from: store) == nil)
        }
    }

}
