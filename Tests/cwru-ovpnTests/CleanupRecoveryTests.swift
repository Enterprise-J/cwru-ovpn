import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct CleanupRecoveryTests {
    @Test(arguments: ["link#21", "10.9.0.1"])
    func cleanupPreservesRoutesOnAReusedTunnelInterface(gateway: String) throws {
        var state = makeSessionState(
            pid: 1207, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .full, cleanupNeeded: true)
        state.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        state.appliedSplitIPv6Routes = ["2606:ea00::/32"]
        let ipv4Destinations = ["0.0.0.0/1", "128.0.0.0/1", "129.22.0.0/16"]
        let ipv6Destinations = ["::/1", "8000::/1", "2606:ea00::/32"]
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: state.physicalGateway, physicalInterface: state.physicalInterface,
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: ["utun7"],
            initialRoutes: ipv4Destinations.map {
                .init(destination: $0, gateway: gateway, interfaceName: "utun7", flags: "USc")
            },
            initialIPv6RouteRecords: ipv6Destinations.map {
                .init(destination: $0, gateway: "link#21", interfaceName: "utun7", flags: "USc")
            })
        try CommandRunner.withCommandHandler(system.handle) {
            let manager = RouteManager(splitTunnelPolicy: .fixed)
            #expect(try manager.cleanup(using: state))
            let ipv4Entries = try manager.ipv4RoutingTableEntries()
            let ipv6Entries = try manager.ipv6RoutingTableEntries()
            #expect(ipv4Destinations.allSatisfy { manager.ipv4RouteExists($0, on: "utun7", in: ipv4Entries) })
            #expect(ipv6Destinations.allSatisfy { manager.ipv6RouteExists($0, on: "utun7", in: ipv6Entries) })
            #expect(system.recordedCommands.allSatisfy {
                !$0.hasPrefix("/sbin/route -n delete") || !$0.contains("utun7")
            })
        }
    }

    @Test
    func staleRecoveryPreservesReplacementSession() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-replacement-session")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory.appendingPathComponent("state"))
        let expected = makeSessionState(
            pid: 1201, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Automatic",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        var replacement = expected
        replacement.pid = 1202
        try replacement.save(in: store)
        var commands: [String] = []
        let manager = RouteManager(dynamicDNSLookup: { _, _ in [] }, commandRunner: CommandRunner(handler: { invocation in
            commands.append(invocation.launchPath)
            throw MockSystemError.unexpectedCommand(invocation.launchPath)
        }))
        #expect(throws: VPNControllerError.self) {
            try SessionControl.recoverStaleSession(expected, force: false, sessionStore: store, routeManager: manager)
        }
        #expect(commands.isEmpty)
        #expect(SessionState.load(from: store)?.pid == replacement.pid)
    }

    @Test(arguments: ["utun7", "utun9", "ppp0", "en1"])
    func cleanupPreservesAnotherDefaultRoute(interfaceName: String) throws {
        let state = SessionState(pid: getpid(), executablePath: "/tmp/cwru-ovpn",
                                 processStartTime: ProcessStartTime(seconds: 1, microseconds: 0),
                                 phase: .disconnected, profilePath: "/tmp/profile.ovpn", startedAt: Date(),
                                 physicalGateway: "192.0.2.1", physicalInterface: "en0", tunnelName: "utun7",
                                 tunnelMode: .split, cleanupNeeded: true)
        var mutations: [CommandInvocation] = []
        let manager = RouteManager(dynamicDNSLookup: { _, _ in [] }, commandRunner: CommandRunner(handler: { invocation in
            if invocation.launchPath == "/usr/sbin/netstat" {
                return CommandResult(exitCode: 0, stdout: "default 198.51.100.1 UGSc \(interfaceName)\n", stderr: "")
            }
            if invocation.arguments == ["-n", "get", "default"] {
                return CommandResult(exitCode: 0, stdout: "gateway: 198.51.100.1\ninterface: \(interfaceName)\n", stderr: "")
            }
            if invocation.arguments == ["-n", "get", "192.0.2.1"] {
                return CommandResult(exitCode: 0, stdout: "interface: en0\n", stderr: "")
            }
            mutations.append(invocation)
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        }))
        try manager.restoreDefaultRouteIfNecessary(using: state)
        #expect(mutations.isEmpty)
        #expect(try manager.cleanupDefaultRouteLooksHealthy(using: state))
    }

    @Test(arguments: [false, true])
    func cleanupPreservesAnUnselectedDefaultRoute(scoped: Bool) throws {
        let state = makeSessionState(
            pid: 1205, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: state.physicalGateway, physicalInterface: state.physicalInterface,
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: ["utun7"],
            initialRoutes: [.init(destination: "default", gateway: "10.8.0.1", interfaceName: "utun7",
                                  flags: scoped ? "UGSI" : "UGS")])
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: .fixed)
            #expect(try manager.cleanup(using: state))
            #expect(try manager.ipv4RoutingTableEntries().contains {
                $0.destination == "default" && $0.interfaceName == "utun7" && $0.isInterfaceScoped == scoped
            })
        }
    }

    @Test(arguments: ["utun7", "utun9", "en1"])
    func cleanupPreservesIPv6Defaults(interfaceName: String) throws {
        let state = makeSessionState(
            pid: 1206, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: state.physicalGateway, physicalInterface: state.physicalInterface,
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: ["utun7"],
            initialIPv6Routes: ["default": interfaceName])
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: .fixed)
            #expect(try manager.cleanup(using: state))
            #expect(try manager.ipv6RoutingTableEntries().contains {
                $0.destination == "default" && $0.interfaceName == interfaceName
            })
            #expect(system.recordedCommands.allSatisfy { !$0.contains(" add ") && !$0.contains(" delete ") })
        }
    }

    @Test
    func offlineCleanupHealthMessaging() throws {
        let onlineMessages = SessionControl.unhealthyCleanupMessage(networkOffline: false)
        #expect(
            onlineMessages.contains("--force"),
            "Online unhealthy cleanup should keep pointing at disconnect --force.")
        #expect(
            onlineMessages.contains("Cleanup ran"),
            "Online unhealthy cleanup recovery text should describe the cleanup outcome.")

        let offlineMessages = SessionControl.unhealthyCleanupMessage(networkOffline: true)
        #expect(
            offlineMessages.contains("captive portal"),
            "Offline unhealthy cleanup should explain the captive-portal or offline cause.")
        #expect(
            offlineMessages.contains("Cleanup ran"),
            "Offline unhealthy cleanup recovery text should still surface via the reconnect path.")

        let configuration = SplitTunnelPolicy(
            ipv4Routes: ["129.22.0.0/16"],
            dnsDomains: ["case.edu"],
            dnsServers: ["129.22.4.32"],
        )
        let manager = RouteManager(splitTunnelPolicy: configuration)

        let present = try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/sbin/route",
                invocation.arguments == ["-n", "get", "default"]
            {
                return CommandResult(
                    exitCode: 0,
                    stdout: "   route to: default\n    gateway: 192.168.1.1\n  interface: en0\n",
                    stderr: "")
            }
            return CommandResult(exitCode: 1, stdout: "", stderr: "unexpected")
        }) {
            try manager.routeLookup(for: "default") != nil
        }
        #expect(
            present, "A default route via en0 should count as a present physical default route.")

        let absent = try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/sbin/route",
                invocation.arguments == ["-n", "get", "default"]
            {
                return CommandResult(
                    exitCode: 2, stdout: "",
                    stderr: "route: writing to routing socket: not in table")
            }
            return CommandResult(exitCode: 1, stdout: "", stderr: "unexpected")
        }) {
            try manager.routeLookup(for: "default") != nil
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
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )

        let offlineHealthy = try CommandRunner.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/route" else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            return CommandResult(
                exitCode: 2, stdout: "", stderr: "route: writing to routing socket: not in table")
        }) {
            try manager.cleanupDefaultRouteLooksHealthy(using: session)
        }
        #expect(
            offlineHealthy,
            "A missing default route with an unreachable physical gateway is an offline Mac, not a failed cleanup."
        )

        let strandedHealthy = try CommandRunner.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/route" else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            if invocation.arguments == ["-n", "get", "172.30.1.1"] {
                return CommandResult(
                    exitCode: 0,
                    stdout: "   route to: 172.30.1.1\n  interface: en0\n",
                    stderr: "")
            }
            return CommandResult(
                exitCode: 2, stdout: "", stderr: "route: writing to routing socket: not in table")
        }) {
            try manager.cleanupDefaultRouteLooksHealthy(using: session)
        }
        #expect(
            !strandedHealthy,
            "A missing default route on a reachable physical gateway should still count as an unhealthy cleanup."
        )

        let replacementDefaultHealthy = try CommandRunner.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/route",
                invocation.arguments == ["-n", "get", "default"]
            else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            return CommandResult(
                exitCode: 0,
                stdout: "   route to: default\n    gateway: 10.8.0.1\n  interface: utun7\n",
                stderr: "")
        }) {
            try manager.cleanupDefaultRouteLooksHealthy(using: session)
        }
        #expect(
            replacementDefaultHealthy,
            "An existing default route on a reused interface must be preserved.")

        let replacedRoute = ManagedIPv4Route(
            destination: "207.182.159.132/32",
            nextHopKind: .gateway,
            nextHopValue: "172.30.1.1",
            interfaceName: "en0",
            isInterfaceScoped: false)
        let restorableOnSameNetwork = try CommandRunner.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/route",
                invocation.arguments == ["-n", "get", "172.30.1.1"]
            else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            return CommandResult(
                exitCode: 0,
                stdout: "   route to: 172.30.1.1\n  interface: en0\n",
                stderr: "")
        }) {
            try manager.replacedRemoteHostRouteIsRestorable(replacedRoute)
        }
        #expect(
            restorableOnSameNetwork,
            "A replaced host route should still be required while its gateway stays directly reachable."
        )

        let restorableAfterWiFiChange = try CommandRunner.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/route",
                invocation.arguments == ["-n", "get", "172.30.1.1"]
            else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            return CommandResult(
                exitCode: 0,
                stdout: "   route to: 172.30.1.1\n    gateway: 192.168.5.1\n  interface: en0\n",
                stderr: "")
        }) {
            try manager.replacedRemoteHostRouteIsRestorable(replacedRoute)
        }
        #expect(
            !restorableAfterWiFiChange,
            "A replaced host route is unrestorable once its gateway is only reachable through another router."
        )

        let restorableWhileOffline = try CommandRunner.withCommandHandler({ _ in
            CommandResult(
                exitCode: 2, stdout: "", stderr: "route: writing to routing socket: not in table")
        }) {
            try manager.replacedRemoteHostRouteIsRestorable(replacedRoute)
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
        let addressedInterface = try CommandRunner.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/ifconfig", invocation.arguments == ["en0"] else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            return CommandResult(
                exitCode: 0,
                stdout: "en0: flags=8863<UP,BROADCAST>\n\tinet 172.30.1.24 netmask 0xffffff00\n",
                stderr: "")
        }) {
            try manager.replacedRemoteHostRouteIsRestorable(interfaceRoute)
        }
        #expect(
            addressedInterface,
            "An interface-scoped replaced route should still be required while that interface holds an IPv4 address."
        )

        let strippedInterface = try CommandRunner.withCommandHandler({ invocation in
            guard invocation.launchPath == "/sbin/ifconfig", invocation.arguments == ["en0"] else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "unexpected")
            }
            return CommandResult(
                exitCode: 0,
                stdout: "en0: flags=8863<UP,BROADCAST>\n\tinet6 fe80::1%en0 prefixlen 64\n",
                stderr: "")
        }) {
            try manager.replacedRemoteHostRouteIsRestorable(interfaceRoute)
        }
        #expect(
            !strippedInterface,
            "An interface without an IPv4 address cannot carry a restored host route.")
    }

    @Test(arguments: [false, true], ["healthy", "network", "ledger", "withdrawal"])
    func cleanupCompletionRequiresNetworkAndLedger(disconnectingAfterWake: Bool, scenario: String) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-cleanup-completion")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory.appendingPathComponent("state"))
        var state = makeSessionState(
            pid: 1200, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: ["home"], originalIPv6Mode: "Automatic",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.managedIPv6Routes = [ManagedIPv6Route(blocking: "::/1")]
        try state.save(in: store)
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: state.physicalGateway, physicalInterface: state.physicalInterface,
            physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: ["home"], ipv6Mode: "Automatic",
            tunnelInterfaces: [], ignoredRouteDeletes: scenario == "network" ? ["::/1"] : [],
            initialIPv6Routes: ["::/1": "lo0"])
        let manager = makeRouteManager(
            commandRunner: CommandRunner(handler: { try system.handle($0) }), resolverDirectory: directory.appendingPathComponent("resolver"),
            remoteHostRouteLedger: RemoteHostRouteLedger(store: StateDirectory(directory: directory.appendingPathComponent("route-ledger"))),
            eventLogDirectory: directory.appendingPathComponent("events"))
        if scenario == "ledger" {
            try FileManager.default.setAttributes([.posixPermissions: 0o644],
                                                 ofItemAtPath: store.url.appendingPathComponent(SessionState.lockName).path)
        }

        do {
            try VPNController.restoreNetworkConfiguration(using: state, routeManager: manager, sessionStore: store,
                                                           dnsWithdrawalFailure: scenario == "withdrawal" ? POSIXError(.ETIMEDOUT) : nil,
                                                           disconnectingAfterWake: disconnectingAfterWake)
            #expect(scenario == "healthy")
        } catch {
            #expect(scenario != "healthy")
            if scenario == "network" {
                #expect(error.localizedDescription.contains("after wake") == disconnectingAfterWake)
            }
        }
        if scenario == "healthy" {
            #expect(SessionState.load(from: store) == nil)
        } else {
            #expect(SessionState.load(from: store)?.cleanupNeeded == true)
        }
        #expect(try manager.validateCleanupState(using: state) == (scenario != "network"))
    }

    @Test(arguments: [false, true], ["persistent", "transient"])
    func cleanupRequiresRemoteRouteLedgerRetirement(restoringReplacedRoute: Bool, failure: String) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-remote-ledger-retirement")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory.appendingPathComponent("state"))
        let ledgerDirectory = directory.appendingPathComponent("routes")
        let ledger = RemoteHostRouteLedger(store: StateDirectory(directory: ledgerDirectory))
        let ownedRoute = ManagedIPv4Route(destination: "207.182.159.133/32", nextHopKind: .gateway,
                                          nextHopValue: "192.168.1.1", interfaceName: "en0", isInterfaceScoped: false)
        let replacedRoute = ManagedIPv4Route(destination: ownedRoute.destination, nextHopKind: .gateway,
                                             nextHopValue: ownedRoute.nextHopValue, interfaceName: "en0", isInterfaceScoped: true)
        var state = makeSessionState(
            pid: 1203, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        state.managedRemoteIPv4Routes = [ownedRoute]
        state.replacedRemoteIPv4Routes = restoringReplacedRoute ? [replacedRoute] : nil
        try state.save(in: store)
        try ledger.recordOwnedRoutes([ownedRoute], pid: state.pid, processStartTime: state.processStartTime,
                                      executablePath: state.executablePath)
        let lockFile = ledgerDirectory.appendingPathComponent(RemoteHostRouteLedger.lockName)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: lockFile.path)
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: state.physicalGateway, physicalInterface: state.physicalInterface,
            physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: [], ipv6Mode: "Off",
            tunnelInterfaces: ["utun7"], initialRoutes: [
                .init(destination: ownedRoute.destination, gateway: ownedRoute.nextHopValue,
                      interfaceName: ownedRoute.interfaceName, flags: "UGHS")])
        var validations = 0
        let manager = makeRouteManager(
            commandRunner: CommandRunner(handler: { invocation in
                if invocation.launchPath == "/sbin/route", invocation.arguments == ["-n", "get", "default"] {
                    validations += 1
                    if failure == "transient", validations == 2 {
                        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: lockFile.path)
                    }
                }
                return try system.handle(invocation)
            }), resolverDirectory: directory.appendingPathComponent("resolvers"),
            remoteHostRouteLedger: ledger, eventLogDirectory: directory.appendingPathComponent("events"))
        if failure == "persistent" {
            #expect(throws: Error.self) {
                try VPNController.restoreNetworkConfiguration(using: state, routeManager: manager, sessionStore: store,
                                                               disconnectingAfterWake: false)
            }
            #expect(SessionState.load(from: store)?.cleanupNeeded == true)
            #expect(try manager.validateCleanupState(using: state))
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: lockFile.path)
            #expect(try ledger.entries().map(\.route) == [ownedRoute])
        }
        try VPNController.restoreNetworkConfiguration(using: state, routeManager: manager, sessionStore: store,
                                                       disconnectingAfterWake: false)
        #expect(SessionState.load(from: store) == nil)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: lockFile.path)
        #expect(try ledger.entries().isEmpty)
        #expect(manager.ownedManagedIPv4RouteExists(replacedRoute, in: try manager.ipv4RoutingTableEntries(),
                                                    requiresHostFlag: true) == restoringReplacedRoute)
    }

    @Test(arguments: [false, true], ["selected", "moved", "parallel"])
    func remoteRouteRestorationRespectsItsPhysicalInterface(scoped: Bool, network: String) throws {
        let route = ManagedIPv4Route(destination: "207.182.159.133/32", nextHopKind: .gateway,
                                     nextHopValue: "192.168.1.1", interfaceName: "en0", isInterfaceScoped: scoped)
        let globalInterface = network == "selected" ? "en0" : "en1"
        let system = MockSystem(
            serviceName: "Ethernet", physicalGateway: route.nextHopValue, physicalInterface: globalInterface,
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: [])
        var routeAdds: [CommandInvocation] = []
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/sbin/route", invocation.arguments.contains("get"),
               invocation.arguments.contains(route.nextHopValue) {
                if invocation.arguments.contains("-ifscope"), network == "moved" {
                    return CommandResult(exitCode: 2, stdout: "", stderr: "route: writing to routing socket: not in table")
                }
                let interfaceName = invocation.arguments.contains("-ifscope") ? "en0" : globalInterface
                return CommandResult(exitCode: 0, stdout: "gateway: link#1\ninterface: \(interfaceName)\n", stderr: "")
            }
            if invocation.launchPath == "/sbin/route", invocation.arguments.contains("add") {
                routeAdds.append(invocation)
                if scoped, network == "moved" {
                    return CommandResult(exitCode: 1, stdout: "", stderr: "route: writing to routing socket: Network is unreachable")
                }
            }
            return try system.handle(invocation)
        }) {
            let manager = RouteManager(splitTunnelPolicy: .fixed)
            let shouldRestore = network == "selected" || (scoped && network == "parallel")
            try manager.restoreManagedIPv4RouteIfMissing(route)
            #expect(routeAdds.isEmpty == !shouldRestore)
            #expect(try manager.replacedRemoteHostRouteIsRestorable(route) == shouldRestore)
            let entries = try manager.ipv4RoutingTableEntries()
            #expect(manager.ownedManagedIPv4RouteExists(route, in: entries, requiresHostFlag: true) == shouldRestore)
            #expect(!entries.contains { $0.destination == route.destination && $0.interfaceName != route.interfaceName })
        }
    }

    @Test(arguments: ["removed", "present", "failed"])
    func scopedRouteRestorationRequiresConfirmedInterfaceRemoval(interfaceState: String) throws {
        let route = ManagedIPv4Route(destination: "207.182.159.133/32", nextHopKind: .gateway,
                                     nextHopValue: "192.168.1.1", interfaceName: "en0", isInterfaceScoped: true)
        let system = MockSystem(
            serviceName: "Ethernet", physicalGateway: route.nextHopValue, physicalInterface: "en1",
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: [])
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/sbin/route", invocation.arguments.contains("get"),
               invocation.arguments.contains("-ifscope") {
                return CommandResult(exitCode: 1, stdout: "", stderr: "route: bad interface name\n")
            }
            if invocation.launchPath == "/sbin/ifconfig", invocation.arguments == ["en0"] {
                switch interfaceState {
                case "removed":
                    return CommandResult(exitCode: 1, stdout: "", stderr: "ifconfig: interface en0 does not exist\n")
                case "present":
                    return CommandResult(exitCode: 0, stdout: "en0: flags=8863<UP,BROADCAST>\n", stderr: "")
                default:
                    throw POSIXError(.EIO)
                }
            }
            return try system.handle(invocation)
        }) {
            let manager = RouteManager(splitTunnelPolicy: .fixed)
            if interfaceState == "removed" {
                try manager.restoreManagedIPv4RouteIfMissing(route)
            } else {
                #expect(throws: Error.self) { try manager.restoreManagedIPv4RouteIfMissing(route) }
            }
            #expect(system.recordedCommands.allSatisfy { !$0.contains(" add ") && !$0.contains(" delete ") })
        }
    }

    @Test(arguments: ["offline", "offline-zero", "nonzero", "timeout", "missing-fields", "zero-error", "mixed-error"],
          ["cleanup-default", "restore-default", "replaced-gateway", "replaced-gateway-scoped", "replaced-interface", "full-support"])
    func recoveryDistinguishesOfflineFromFailedInspection(scenario: String, operation: String) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-recovery-inspection")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory.appendingPathComponent("state"))
        var state = makeSessionState(
            pid: 1204, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .split, cleanupNeeded: true)
        if operation.hasPrefix("replaced-") {
            let interfaceRoute = operation == "replaced-interface"
            state.replacedRemoteIPv4Routes = [ManagedIPv4Route(
                destination: "207.182.159.133/32", nextHopKind: interfaceRoute ? .interface : .gateway,
                nextHopValue: interfaceRoute ? "en1" : "172.30.1.1", interfaceName: interfaceRoute ? "en1" : "en0",
                isInterfaceScoped: operation == "replaced-gateway-scoped")]
        }
        let ledger = RemoteHostRouteLedger(store: StateDirectory(directory: directory.appendingPathComponent("routes")))
        let ownedRoute = ManagedIPv4Route(destination: "207.182.159.134/32", nextHopKind: .gateway,
                                          nextHopValue: state.physicalGateway, interfaceName: "en0", isInterfaceScoped: false)
        state.managedRemoteIPv4Routes = [ownedRoute]
        try ledger.recordOwnedRoutes([ownedRoute], pid: state.pid, processStartTime: state.processStartTime,
                                      executablePath: state.executablePath)
        try state.save(in: store)
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: state.physicalGateway, physicalInterface: state.physicalInterface,
            physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: ["utun7"])
        let commandRunner = CommandRunner(handler: { invocation in
            let checkingDefault = operation.hasSuffix("default")
            if checkingDefault, invocation.launchPath == "/usr/sbin/netstat", invocation.arguments == ["-nrf", "inet"] {
                return CommandResult(exitCode: 0, stdout: "Routing tables\nInternet:\nDestination Gateway Flags Netif\n", stderr: "")
            }
            if invocation.launchPath == "/sbin/route", invocation.arguments.contains("add"),
               invocation.arguments.contains("207.182.159.133") {
                return CommandResult(exitCode: 1, stdout: "", stderr: "route: writing to routing socket: Network is unreachable")
            }
            let routeQuery = invocation.launchPath == "/sbin/route" && invocation.arguments.contains("get")
                && (checkingDefault || invocation.arguments.contains("172.30.1.1"))
            let interfaceQuery = invocation.launchPath == "/sbin/ifconfig"
                && ((operation == "replaced-interface" && invocation.arguments == ["en1"])
                    || (operation == "full-support" && invocation.arguments == ["en0"]))
            if routeQuery || interfaceQuery {
                switch scenario {
                case "offline", "offline-zero":
                    return interfaceQuery
                        ? CommandResult(exitCode: 0, stdout: "\(invocation.arguments[0]): flags=8863<UP,BROADCAST>\n", stderr: "")
                        : CommandResult(exitCode: scenario == "offline-zero" ? 0 : 2, stdout: "",
                                        stderr: "route: writing to routing socket: not in table\n")
                case "zero-error", "mixed-error":
                    return CommandResult(exitCode: 0, stdout: "", stderr:
                        (scenario == "mixed-error" ? "route: writing to routing socket: not in table\n" : "")
                            + "route: socket: Operation not permitted\n")
                case "timeout":
                    throw CommandError.timedOut(invocation.launchPath, 30, "")
                case "missing-fields":
                    return CommandResult(exitCode: 0, stdout: "", stderr: "")
                default:
                    return CommandResult(exitCode: 71, stdout: "", stderr: "route: socket: Operation not permitted")
                }
            }
            return try system.handle(invocation)
        })
        let manager = makeRouteManager(
            commandRunner: commandRunner, resolverDirectory: directory.appendingPathComponent("resolvers"),
            remoteHostRouteLedger: ledger,
            eventLogDirectory: directory.appendingPathComponent("events"))
        let recover = {
            if operation == "restore-default" {
                try manager.restoreDefaultRouteIfNecessary(using: state)
            } else if operation == "full-support" {
                try manager.assertFullTunnelSupported(physicalInterface: state.physicalInterface, ipv6Mode: state.originalIPv6Mode)
            } else {
                try VPNController.restoreNetworkConfiguration(using: state, routeManager: manager, sessionStore: store,
                                                               disconnectingAfterWake: false)
            }
        }
        if scenario.hasPrefix("offline") {
            try recover()
            if operation != "restore-default", operation != "full-support" {
                #expect(SessionState.load(from: store) == nil)
                #expect(try ledger.entries().isEmpty)
                #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("routes/remote-host-routes.json").path))
            }
        } else {
            #expect(throws: Error.self, performing: recover)
            #expect(SessionState.load(from: store)?.cleanupNeeded == true)
            #expect(try ledger.entries().map(\.route) == [ownedRoute])
        }
    }

    @Test
    func mockedStaleStateRecovery() throws {
        let stateDirectory = temporaryDirectory(named: "cwru-ovpn-recovery-state")
        defer { try? FileManager.default.removeItem(at: stateDirectory) }
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-recovery")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }
        let sessionStore = StateDirectory(directory: stateDirectory)
        let routeLedger = RemoteHostRouteLedger(store: StateDirectory(directory: stateDirectory.appendingPathComponent("route-ledger", isDirectory: true)))

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])
        let commandRunner = CommandRunner(handler: { try mockSystem.handle($0) })
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
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        session.appliedDNSDomains = ["case.edu", "22.129.in-addr.arpa"]
        try session.save(in: sessionStore)

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
            routeManager: makeRouteManager(
                commandRunner: commandRunner,
                resolverDirectory: resolverDirectory,
                remoteHostRouteLedger: routeLedger,
                eventLogDirectory: stateDirectory.appendingPathComponent("event-log", isDirectory: true))
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
        let routeLedger = RemoteHostRouteLedger(store: StateDirectory(directory: stateDirectory.appendingPathComponent("route-ledger", isDirectory: true)))

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])
        let commandRunner = CommandRunner(handler: { try mockSystem.handle($0) })
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
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        session.appliedDNSDomains = ["case.edu", "22.129.in-addr.arpa"]
        try session.save(in: sessionStore)

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
            routeManager: makeRouteManager(
                commandRunner: commandRunner,
                resolverDirectory: resolverDirectory,
                remoteHostRouteLedger: routeLedger,
                eventLogDirectory: stateDirectory.appendingPathComponent("event-log", isDirectory: true))
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
        let routeLedger = RemoteHostRouteLedger(store: StateDirectory(directory: stateDirectory.appendingPathComponent("route-ledger", isDirectory: true)))

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"])
        let commandRunner = CommandRunner(handler: { try mockSystem.handle($0) })
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
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.appliedSplitIPv4Routes = ["129.22.0.0/16"]
        try session.save(in: sessionStore)

        try SessionControl.disconnectExistingSession(
            force: true,
            sessionStore: sessionStore,
            routeManager: makeRouteManager(
                commandRunner: commandRunner,
                resolverDirectory: resolverDirectory,
                remoteHostRouteLedger: routeLedger,
                eventLogDirectory: stateDirectory.appendingPathComponent("event-log", isDirectory: true))
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

    @Test(arguments: ["connect", "disconnect"])
    func commandsRejectUnhealthyStaleRecoveryState(command: String) throws {
        let stateDirectory = temporaryDirectory(named: "cwru-ovpn-state-unhealthy-reconnect")
        defer { try? FileManager.default.removeItem(at: stateDirectory) }
        let resolverDirectory = temporaryDirectory(named: "cwru-ovpn-resolver-unhealthy-reconnect")
        defer { try? FileManager.default.removeItem(at: resolverDirectory) }
        let sessionStore = StateDirectory(directory: stateDirectory)
        let routeLedger = RemoteHostRouteLedger(store: StateDirectory(directory: stateDirectory.appendingPathComponent("route-ledger", isDirectory: true)))

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: [],
            ignoredRouteDeletes: ["::/1"],
            initialIPv6Routes: ["::/1": "lo0"])
        let commandRunner = CommandRunner(handler: { try mockSystem.handle($0) })
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
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.managedIPv6Routes = [ManagedIPv6Route(blocking: "::/1")]
        try session.save(in: sessionStore)

        let manager = makeRouteManager(commandRunner: commandRunner,
                                       resolverDirectory: resolverDirectory,
                                       remoteHostRouteLedger: routeLedger,
                                       eventLogDirectory: stateDirectory.appendingPathComponent("event-log", isDirectory: true))
        do {
            if command == "connect" {
                _ = try SessionControl.handleConnectRequestForActiveSession(
                    targetMode: .split, configFilePath: nil,
                    sessionStore: sessionStore, routeManager: manager)
            } else {
                try SessionControl.disconnectExistingSession(
                    force: false, sessionStore: sessionStore, routeManager: manager)
            }
            Issue.record("The command must fail when cleanup leaves unhealthy recovery state.")
        } catch {
            let message = error.localizedDescription
            #expect(
                message.contains("Cleanup ran"),
                "The command should surface the stale cleanup recovery failure.")
            #expect(
                message.contains("disconnect --force"),
                "Recovery guidance should name the explicit forced-disconnect command.")
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
        let routeLedger = RemoteHostRouteLedger(store: StateDirectory(directory: resolverDirectory.appendingPathComponent(".route-ledger", isDirectory: true)))

        let mockSystem = MockSystem(
            serviceName: "Wi-Fi",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"],
            physicalSearchDomains: ["home"],
            ipv6Mode: "Automatic",
            tunnelInterfaces: [])
        let commandRunner = CommandRunner(handler: { try mockSystem.handle($0) })
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
            tunnelName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.phase = .connecting
        session.tunnelName = nil
        session.vpnIPv4 = nil
        session.vpnIPv6 = nil

        try FileManager.default.createDirectory(
            at: resolverDirectory, withIntermediateDirectories: true)
        let existingResolver = ResolverPaths.fileURL(for: "case.edu", in: resolverDirectory)
        try "preexisting\n".write(to: existingResolver, atomically: true, encoding: .utf8)

        let cleanupHealthy = try RouteManager(
            dynamicDNSLookup: { _, _ in [] },
            commandRunner: commandRunner,
            resolverDirectory: resolverDirectory,
            remoteHostRouteLedger: routeLedger,
            eventLogDirectory: resolverDirectory.appendingPathComponent(
                ".event-log", isDirectory: true)
        ).cleanup(using: session)
        let directCleanupHealthy = try makeRouteManager(
            splitTunnelPolicy: .fixed,
            commandRunner: commandRunner,
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
    }

    @Test
    func cleanupDetectsManagedIPv6RouteResidue() throws {
        var state = makeSessionState(
            pid: 1024, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: [], originalSearchDomains: [], originalIPv6Mode: "Off",
            tunnelName: "utun7", tunnelMode: .full, cleanupNeeded: true)
        state.managedIPv6Routes = [ManagedIPv6Route(blocking: "::/1")]
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: state.physicalGateway, physicalInterface: state.physicalInterface,
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: [],
            ignoredRouteDeletes: ["::/1"],
            initialIPv6Routes: ["::/1": "lo0"])
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: .fixed)
            #expect(try !manager.cleanup(using: state))
            #expect(try !manager.validateCleanupState(using: state))
            #expect(try manager.cleanupPhysicalDNSLooksHealthy(using: state))
            #expect(try manager.cleanupPhysicalIPv6LooksHealthy(using: state))
        }
    }

    @Test(arguments: ["interface", "gateway", "ipv6"])
    func activeTunnelDefaultRemovalVerifiesDeletion(family: String) throws {
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: [], physicalSearchDomains: [], ipv6Mode: "Off", tunnelInterfaces: ["utun7"],
            ignoredRouteDeletes: ["0.0.0.0/1", "::/1"],
            initialRoutes: family == "ipv6" ? [] : [
                .init(destination: "0.0.0.0/1", gateway: family == "gateway" ? "10.8.0.1" : "link#9",
                      interfaceName: "utun7")],
            initialIPv6Routes: family == "ipv6" ? ["::/1": "utun7"] : [:])
        try CommandRunner.withCommandHandler(system.handle) {
            #expect(throws: RouteManagerError.self) {
                try RouteManager(splitTunnelPolicy: .fixed).removeTunnelDefaultRoutes(tunnelName: "utun7")
            }
            #expect(system.recordedCommands.contains { $0.hasPrefix("/sbin/route -n delete") })
        }
    }

    @Test
    @MainActor
    func cleanupWatchdogValidation() throws {
        let stateDirectory = temporaryDirectory(named: "cwru-ovpn-watchdog-state")
        defer { try? FileManager.default.removeItem(at: stateDirectory) }
        let resolverDirectory = stateDirectory.appendingPathComponent(
            "resolvers", isDirectory: true)
        let eventLogDirectory = stateDirectory.appendingPathComponent("events", isDirectory: true)
        let sessionStore = StateDirectory(
            directory: stateDirectory.appendingPathComponent("session", isDirectory: true))
        let routeLedger = RemoteHostRouteLedger(store: StateDirectory(directory: stateDirectory.appendingPathComponent("route-ledger", isDirectory: true)))
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
            tunnelName: "utun7",
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
        try session.save(in: sessionStore)

        let failedOutcome = CleanupWatchdog.performCleanup(
            parentPID: session.pid,
            parentStartTime: session.processStartTime,
            sessionStore: sessionStore,
            routeManager: makeRouteManager(
                commandRunner: CommandRunner(handler: { _ in CommandResult(exitCode: 1, stdout: "", stderr: "unexpected") }),
                resolverDirectory: resolverDirectory,
                remoteHostRouteLedger: routeLedger,
                eventLogDirectory: eventLogDirectory)
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
        guard case .finished(criticalAlert: _?) = failedOutcome else {
            Issue.record("Cleanup watchdog should report one critical alert after a failed cleanup attempt.")
            return
        }
        #expect(
            (try? ControllerLock(in: sessionStore)) != nil,
            "Cleanup watchdog must release the lifecycle lock before its alert is presented.")

        let repeatedOutcome = CleanupWatchdog.performCleanup(
            parentPID: session.pid,
            parentStartTime: session.processStartTime,
            sessionStore: sessionStore,
            routeManager: makeRouteManager(
                commandRunner: CommandRunner(handler: { _ in CommandResult(exitCode: 1, stdout: "", stderr: "unexpected") }),
                resolverDirectory: resolverDirectory,
                remoteHostRouteLedger: routeLedger,
                eventLogDirectory: eventLogDirectory)
        )
        #expect(
            SessionState.load(from: sessionStore)?.lastEvent == "RECOVERY_REQUIRED",
            "A repeated cleanup attempt should keep the recovery marker.")
        #expect(
            repeatedOutcome == .finished(criticalAlert: nil),
            "A cleanup attempt on a ledger already marked for recovery must not alert the user again.")
    }

    @Test(arguments: [false, true])
    @MainActor
    func staleRecoveryRespectsControllerLock(watchdog: Bool) throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-recovery-lock")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory)
        var session = makeSessionState(
            pid: Int32.max - 17, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalServiceName: "Wi-Fi", originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: [], originalIPv6Mode: "Automatic", tunnelName: "utun7",
            tunnelMode: .split, cleanupNeeded: true)
        session.executablePath = try ExecutionIdentity.currentExecutablePath()
        try session.save(in: store)
        var lock: ControllerLock? = try controllerLock(at: directory.appendingPathComponent("controller.lock"))
        defer { withExtendedLifetime(lock) {} }
        let system = MockSystem(serviceName: "Wi-Fi", physicalGateway: "192.168.1.1",
                                physicalInterface: "en0", physicalDNSServers: ["1.1.1.1"],
                                physicalSearchDomains: [], ipv6Mode: "Automatic", tunnelInterfaces: [])
        let routeManager = makeRouteManager(
            commandRunner: CommandRunner(handler: system.handle),
            resolverDirectory: directory.appendingPathComponent("resolver"),
            remoteHostRouteLedger: RemoteHostRouteLedger(store: StateDirectory(directory: directory.appendingPathComponent("routes"))),
            eventLogDirectory: directory.appendingPathComponent("logs"))
        if watchdog {
            #expect(CleanupWatchdog.performCleanup(parentPID: session.pid, parentStartTime: session.processStartTime,
                                                   sessionStore: store, routeManager: routeManager) == .lockBusy)
        } else {
            #expect(throws: (any Error).self) {
                try SessionControl.disconnectExistingSession(force: false, sessionStore: store, routeManager: routeManager)
            }
        }
        #expect(system.recordedCommands.isEmpty)
        #expect(SessionState.load(from: store)?.pid == session.pid)
        if watchdog {
            lock = nil
            let deadline = Date().addingTimeInterval(5)
            var outcome = CleanupWatchdog.CleanupOutcome.lockBusy
            while outcome == .lockBusy, Date() < deadline {
                outcome = CleanupWatchdog.performCleanup(parentPID: session.pid, parentStartTime: session.processStartTime,
                                                         sessionStore: store, routeManager: routeManager)
                if outcome == .lockBusy {
                    usleep(10_000)
                }
            }
            #expect(outcome == .finished(criticalAlert: nil))
            #expect(SessionState.load(from: store) == nil)
        }
    }

    @Test @MainActor
    func watchdogDoesNotRecreateRemovedStateDirectory() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-watchdog-removed-state")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory.appendingPathComponent("state"))
        #expect(CleanupWatchdog.performCleanup(
            parentPID: Int32.max - 20,
            parentStartTime: ProcessStartTime(seconds: 1, microseconds: 0),
            sessionStore: store) == .finished(criticalAlert: nil))
        #expect(!FileManager.default.fileExists(atPath: store.url.path))
    }

    @Test
    func watchdogLeavesLedgersItDoesNotOwnToTheirController() throws {
        let directory = temporaryDirectory(named: "cwru-ovpn-watchdog-ledger-owner")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = StateDirectory(directory: directory)
        let session = makeSessionState(
            pid: Int32.max - 23, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalServiceName: "Wi-Fi", originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: [], originalIPv6Mode: "Automatic", tunnelName: "utun7",
            tunnelMode: .split, cleanupNeeded: true)
        #expect(
            !CleanupWatchdog.ledgerAwaitsCleanup(in: store, parentPID: session.pid,
                                                 parentStartTime: session.processStartTime),
            "A missing ledger means the parent finished its own cleanup.")
        try session.save(in: store)
        #expect(
            CleanupWatchdog.ledgerAwaitsCleanup(in: store, parentPID: session.pid,
                                                parentStartTime: session.processStartTime),
            "A ledger naming the parent keeps the watchdog armed.")
        #expect(
            !CleanupWatchdog.ledgerAwaitsCleanup(in: store, parentPID: session.pid + 1,
                                                 parentStartTime: session.processStartTime),
            "A ledger written by a later controller is not this watchdog's to clean.")
        #expect(
            !CleanupWatchdog.ledgerAwaitsCleanup(
                in: store, parentPID: session.pid,
                parentStartTime: ProcessStartTime(seconds: session.processStartTime.seconds + 1,
                                                  microseconds: session.processStartTime.microseconds)),
            "A reused process identifier with a different start time is not the parent.")
        var reportedFailure = session
        reportedFailure.markRecoveryRequired(message: "Cleanup failed: route restoration was refused.")
        try reportedFailure.save(in: store)
        #expect(
            !CleanupWatchdog.ledgerAwaitsCleanup(in: store, parentPID: session.pid,
                                                 parentStartTime: session.processStartTime),
            "A failure the controller already reported is left for explicit recovery without taking the lifecycle lock.")
    }
}
