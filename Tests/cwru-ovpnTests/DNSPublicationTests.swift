import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct DNSPublicationTests {
    private let policy = SplitTunnelPolicy(ipv4Routes: ["129.22.0.0/16"],
                                           dnsDomains: ["case.edu"], dnsServers: ["129.22.4.32"])

    private func fixture(baseline: [String] = ["1.1.1.1"],
                         publicationDelayReads: Int? = nil,
                         supplementalPublicationDelayReads: Int? = 0,
                         vpnDNSServer: String = "129.22.4.32") -> (SessionState, MockSystem) {
        var state = makeSessionState(
            pid: 1088, profilePath: "/tmp/profile.ovpn", configFilePath: nil,
            physicalGateway: "192.168.1.1", physicalInterface: "en0", physicalServiceName: "Wi-Fi",
            originalDNSServers: baseline, originalSearchDomains: [], originalIPv6Mode: "Automatic",
            tunnelName: "utun7", tunnelMode: .full, cleanupNeeded: true)
        state.fullTunnelDNSServers = [vpnDNSServer]
        state.appliedDNSDomains = ["case.edu"]
        state.managedIPv6Routes = ["::/1", "8000::/1"].map { ManagedIPv6Route(blocking: $0) }
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: [vpnDNSServer], physicalSearchDomains: [], ipv6Mode: "Off",
            activeDefaultDNSServers: [vpnDNSServer], tunnelInterfaces: ["utun7"],
            activeResolverPublicationDelayReads: publicationDelayReads,
            supplementalResolverPublicationDelayReads: supplementalPublicationDelayReads,
            initialRoutes: ["0.0.0.0/1", "128.0.0.0/1"].map {
                MockSystem.RouteRecord(destination: $0, gateway: "link#9", interfaceName: "utun7")
            }, initialIPv6Routes: ["::/1": "lo0", "8000::/1": "lo0"])
        return (state, system)
    }

    @Test
    func cleanupCannotReportSuccessWhileVPNDNSRemainsPublished() throws {
        let (state, system) = fixture()
        system.releaseTunnelInterface(named: "utun7")
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            try manager.installResolverFiles(forDomains: ["case.edu"], nameServers: ["129.22.4.32"])
            #expect(try !manager.cleanup(using: state))
            #expect(try manager.activeDefaultResolverLeakState(using: state).usesVPNNameServers)
            #expect(try !manager.validateCleanupState(using: state))
            #expect(try manager.cleanupPhysicalDNSLooksHealthy(using: state))
            #expect(try manager.cleanupPhysicalIPv6LooksHealthy(using: state))
            #expect(try manager.publicIPv4RouteState(for: "129.22.4.32", tunnelName: "utun7") == .physical)
        }
    }

    @Test(arguments: ["/usr/bin/dscacheutil", "/usr/bin/killall"])
    func failedDNSCacheFlushDoesNotFailWithdrawal(failingCommand: String) throws {
        let (state, system) = fixture()
        let flushCommands = ["/usr/bin/dscacheutil", "/usr/bin/killall"]
        var attemptedFlushCommands: [String] = []
        try CommandRunner.withCommandHandler({ invocation in
            if flushCommands.contains(invocation.launchPath) {
                attemptedFlushCommands.append(invocation.launchPath)
                if invocation.launchPath == failingCommand {
                    return CommandResult(exitCode: 1, stdout: "", stderr: "flush failed")
                }
            }
            return try system.handle(invocation)
        }) {
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            #expect(
                throws: Never.self,
                "A cache flush that exits non-zero must not turn DNS withdrawal into a thrown failure."
            ) {
                _ = try manager.withdrawVPNDNS(using: state)
            }
            #expect(
                attemptedFlushCommands == flushCommands,
                "Both flush commands must run even when one of them fails.")
        }
    }

    @Test
    func failedSwitchPreservesTunnelCoverageUntilRollback() throws {
        var (state, system) = fixture()
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            #expect(throws: RouteManagerError.self) {
                try manager.applySplitTunnel(using: &state, persistPreparedState: persistPreparedState)
            }
            #expect(try manager.activeDefaultResolverLeakState(using: state).usesVPNNameServers)
            #expect(try manager.publicIPv4RouteState(for: "129.22.4.32", tunnelName: "utun7") == .tunnel)
            #expect(try manager.fullTunnelIPv4LooksSafe(tunnelName: "utun7", using: state))
            #expect(manager.assessFullTunnelIPv6Safety(tunnelName: "utun7").isSafe)
            #expect(!system.recordedCommands.contains { $0.contains("-setv6automatic") })
            try manager.switchToFullTunnel(using: &state, persistPreparedState: persistPreparedState)
            #expect(try manager.fullTunnelIPv4LooksSafe(tunnelName: "utun7", using: state))
        }
    }

    @Test(arguments: [false, true])
    func splitCoverageWaitsForTargetResolverPublication(monitoring: Bool) throws {
        var (state, system) = fixture(publicationDelayReads: 0, supplementalPublicationDelayReads: nil)
        state.tunnelMode = monitoring ? .split : .full
        state.appliedSplitIPv4Routes = policy.ipv4Routes
        state.appliedDNSDomains = policy.resolverDomains(forIPv4Routes: policy.ipv4Routes, ipv6Routes: [])
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            #expect(throws: RouteManagerError.self) {
                if monitoring {
                    _ = try manager.monitorSplitTunnel(using: state)
                } else {
                    try manager.applySplitTunnel(using: &state, persistPreparedState: persistPreparedState)
                }
            }
            #expect(try !manager.activeDefaultResolverLeakState(using: state).needsRepair)
            #expect(try manager.fullTunnelIPv4LooksSafe(tunnelName: "utun7", using: state))
            #expect(!system.recordedCommands.contains {
                $0.hasPrefix("/sbin/route -n delete") || $0.contains("-setv6automatic")
            })
        }
    }

    @Test(arguments: ["absent", "partial", "empty", "wrong", "scoped", "service-specific", "conflicting"])
    func splitPublicationRequiresEveryTargetResolver(scenario: String) throws {
        let (state, system) = fixture()
        let domains = policy.resolverDomains(forIPv4Routes: policy.ipv4Routes, ipv6Routes: [])
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/usr/sbin/scutil" {
                let publishedDomains = scenario == "absent" ? [] : scenario == "partial" ? [domains[0]] : domains
                var output = "DNS configuration\nresolver #1\nnameserver[0] : 1.1.1.1\n"
                if scenario == "scoped" || scenario == "service-specific" {
                    output += "DNS configuration (for \(scenario) queries)\n"
                }
                for (index, domain) in publishedDomains.enumerated() {
                    output += "resolver #\(index + 2)\ndomain : \(domain)\n"
                    if scenario != "empty" {
                        output += "nameserver[0] : \(scenario == "wrong" ? "9.9.9.9" : "129.22.4.32")\n"
                    }
                }
                if scenario == "conflicting" {
                    output += "resolver #9\ndomain : \(domains[0])\nnameserver[0] : 9.9.9.9\n"
                }
                return CommandResult(exitCode: 0, stdout: output, stderr: "")
            }
            return try system.handle(invocation)
        }) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            try manager.installResolverFiles(forDomains: domains, nameServers: policy.dnsServers)
            #expect(try !manager.waitForVPNDNSWithdrawal(using: state, retainingResolverDomains: domains))
        }
    }

    @Test(arguments: ["absent", "scoped", "service-specific", "conflicting"])
    func splitSettlingRequiresPublishedTargetResolvers(scenario: String) throws {
        var (state, _) = fixture()
        state.tunnelMode = .split
        state.appliedSplitIPv4Routes = policy.ipv4Routes
        let domains = policy.resolverDomains(forIPv4Routes: policy.ipv4Routes, ipv6Routes: [])
        state.appliedDNSDomains = domains
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: ["1.1.1.1"], physicalSearchDomains: [], ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"], initialRoutes: policy.ipv4Routes.map {
                MockSystem.RouteRecord(destination: $0, gateway: "link#9", interfaceName: "utun7")
            })
        var repaired = false
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/usr/sbin/scutil" {
                var output = "DNS configuration\nresolver #1\nnameserver[0] : 1.1.1.1\n"
                if !repaired, scenario == "scoped" || scenario == "service-specific" {
                    output += "DNS configuration (for \(scenario) queries)\n"
                }
                if repaired || scenario != "absent" {
                    for (index, domain) in domains.enumerated() {
                        output += "resolver #\(index + 2)\ndomain : \(domain)\nnameserver[0] : 129.22.4.32\n"
                    }
                }
                if !repaired, scenario == "conflicting" {
                    output += "resolver #9\ndomain : \(domains[0])\nnameserver[0] : 9.9.9.9\n"
                }
                return CommandResult(exitCode: 0, stdout: output, stderr: "")
            }
            return try system.handle(invocation)
        }) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            try manager.installResolverFiles(forDomains: domains, nameServers: policy.dnsServers)
            #expect(throws: RouteManagerError.self) { try manager.validateNetworkSafetyWhileSettling(using: state) }
            repaired = true
            try manager.validateNetworkSafetyWhileSettling(using: state)
        }
    }

    @Test
    func splitPublicationAcceptsSystemNameserverLimit() throws {
        let (state, system) = fixture(publicationDelayReads: 0, supplementalPublicationDelayReads: 2)
        let policy = SplitTunnelPolicy.fixed
        let domains = policy.resolverDomains(forIPv4Routes: policy.ipv4Routes, ipv6Routes: policy.ipv6Routes)
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .seconds(1))
            try manager.installResolverFiles(forDomains: domains, nameServers: policy.dnsServers)
            #expect(try manager.restorePhysicalDNSConfigurationIfNeeded(using: state))
            #expect(try manager.waitForVPNDNSWithdrawal(using: state, retainingResolverDomains: domains))
            let published = try manager.parseActiveDNSResolvers(
                manager.commandRunner.run("/usr/sbin/scutil", arguments: ["--dns"]).stdout)
            #expect(Set(published.compactMap(\.domain)) == Set(domains))
            #expect(published.filter { $0.domain != nil }.allSatisfy {
                $0.nameServers == Array(policy.dnsServers.prefix(3))
            })
        }
    }

    @Test
    func splitMonitorPreservesTunnelCoverageUntilDNSWithdrawal() throws {
        var (state, system) = fixture()
        state.tunnelMode = .split
        state.appliedSplitIPv4Routes = policy.ipv4Routes
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            #expect(throws: RouteManagerError.self) { try manager.monitorSplitTunnel(using: state) }
            #expect(try manager.publicIPv4RouteState(for: "8.8.8.8", tunnelName: "utun7") == .tunnel)
            #expect(!system.recordedCommands.contains { $0.hasPrefix("/sbin/route -n delete") })
        }
    }

    @Test
    func splitTransitionPreservesCoverageUntilSearchDomainsWithdraw() throws {
        var (state, system) = fixture()
        state.fullTunnelSearchDomains = ["vpn.example"]
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/usr/sbin/scutil" {
                return CommandResult(exitCode: 0,
                                     stdout: "DNS configuration\nresolver #1\nsearch domain[0] : vpn.example\nnameserver[0] : 1.1.1.1\n",
                                     stderr: "")
            }
            return try system.handle(invocation)
        }) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            #expect(throws: RouteManagerError.self) {
                try manager.applySplitTunnel(using: &state, persistPreparedState: persistPreparedState)
            }
            #expect(try manager.fullTunnelIPv4LooksSafe(tunnelName: "utun7", using: state))
            #expect(manager.assessFullTunnelIPv6Safety(tunnelName: "utun7").isSafe)
        }
    }

    @Test(arguments: ["ipv4", "ipv6"], [false, true])
    func splitRoutingRequiresCoverageBeforeReleasingDefaults(family: String, monitoring: Bool) throws {
        var (state, system) = fixture(publicationDelayReads: 0)
        let policy = SplitTunnelPolicy(ipv4Routes: ["129.22.0.0/16"], ipv6Routes: ["2606:ea00::/32"],
                                       dnsDomains: ["case.edu"], dnsServers: ["129.22.4.32"])
        let missingRoute = family == "ipv4" ? policy.ipv4Routes[0] : policy.ipv6Routes[0]
        state.tunnelMode = monitoring ? .split : .full
        state.appliedSplitIPv4Routes = policy.ipv4Routes
        state.appliedSplitIPv6Routes = policy.ipv6Routes
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/sbin/route", invocation.arguments.contains("add"),
               invocation.arguments.contains(missingRoute) {
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }
            return try system.handle(invocation)
        }) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            #expect(throws: RouteManagerError.self) {
                if monitoring {
                    _ = try manager.monitorSplitTunnel(using: state)
                } else {
                    try manager.applySplitTunnel(using: &state, persistPreparedState: persistPreparedState)
                }
            }
            #expect(try manager.publicIPv4RouteState(for: "8.8.8.8", tunnelName: "utun7") == .tunnel)
            #expect(!system.recordedCommands.contains { $0.hasPrefix("/sbin/route -n delete") })
        }
    }

    @Test(arguments: ["scoped", "supplemental"])
    func withdrawalRequiresEveryManagedResolverToLeavePublication(kind: String) throws {
        let (state, system) = fixture()
        var published = true
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/usr/sbin/scutil" {
                let old = published ? "nameserver[0] : 129.22.4.32\n" : ""
                let section = kind == "scoped"
                    ? "DNS configuration (for scoped queries)\nresolver #1\n"
                    : "resolver #2\ndomain : case.edu\n"
                return CommandResult(exitCode: 0,
                                     stdout: "DNS configuration\nresolver #1\nnameserver[0] : 1.1.1.1\n" + section + old,
                                     stderr: "")
            }
            return try system.handle(invocation)
        }) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            #expect(try !manager.withdrawVPNDNS(using: state))
            #expect(try manager.cleanupResolversRemoved(using: state))
            #expect(try !manager.validateCleanupState(using: state))
            published = false
            #expect(try manager.cleanup(using: state))
        }
    }

    @Test(arguments: ["", "domain : case.edu\n"])
    func withdrawalRecognizesEquivalentIPv6Addresses(domain: String) throws {
        var (state, system) = fixture()
        state.fullTunnelDNSServers = ["2001:0DB8:0000:0000:0000:0000:0000:0053"]
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/usr/sbin/scutil" {
                return CommandResult(exitCode: 0,
                                     stdout: "DNS configuration\nresolver #1\n\(domain)nameserver[0] : 2001:db8::53\n",
                                     stderr: "")
            }
            return try system.handle(invocation)
        }) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            #expect(try !manager.withdrawVPNDNS(using: state))
            if domain.isEmpty {
                #expect(try manager.activeDefaultResolverLeakState(using: state).usesVPNNameServers)
            }
        }
    }

    @Test(arguments: [false, true])
    func withdrawalAccountsForResolverOwnership(unmanaged: Bool) throws {
        let (state, system) = fixture()
        let domain = unmanaged ? "case.edu" : "openvpn.com"
        let server = unmanaged ? "129.22.4.32" : "9.9.9.9"
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/usr/sbin/scutil" {
                return CommandResult(exitCode: 0,
                                     stdout: "DNS configuration\nresolver #1\nnameserver[0] : 1.1.1.1\nresolver #2\ndomain : \(domain)\nnameserver[0] : \(server)\n",
                                     stderr: "")
            }
            return try system.handle(invocation)
        }) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            try FileManager.default.createDirectory(at: manager.resolverDirectory, withIntermediateDirectories: true)
            if unmanaged {
                try "nameserver \(server)\ndomain \(domain)\n".write(
                    to: manager.resolverFileURL(for: domain), atomically: true, encoding: .utf8)
            } else {
                try manager.installResolverFiles(forDomains: [domain], nameServers: [server])
            }
            #expect(try manager.withdrawVPNDNS(using: state) == unmanaged)
            #expect(try manager.cleanup(using: state) == unmanaged)
            #expect(try manager.validateCleanupState(using: state) == unmanaged)
            #expect(FileManager.default.fileExists(atPath: manager.resolverFileURL(for: domain).path) == unmanaged)
        }
    }

    @Test
    func equivalentDNSAddressesDoNotTriggerNetworkWrites() throws {
        var (state, _) = fixture(baseline: ["2001:0DB8:0000:0000:0000:0000:0000:0053"])
        state.pushedDNSServers = state.originalDNSServers
        state.pushedSearchDomains = ["home"]
        state.originalSearchDomains = ["home"]
        let system = MockSystem(
            serviceName: "Wi-Fi", physicalGateway: "192.168.1.1", physicalInterface: "en0",
            physicalDNSServers: ["2001:db8::53"], physicalSearchDomains: ["home"], ipv6Mode: "Automatic",
            tunnelInterfaces: ["utun7"], initialIPv6Routes: ["2001:db8::/64": "utun7"])
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            try manager.installResolverFiles(forDomains: manager.fullTunnelScopedDNSDomains(), nameServers: ["2001:db8::53"])
            #expect(try manager.applyFullTunnelDNSConfiguration(using: &state, persistPreparedState: persistPreparedState) == ["2001:db8::53"])
            #expect(try !manager.restorePhysicalDNSConfigurationIfNeeded(using: state))
            #expect(try manager.cleanupPhysicalDNSLooksHealthy(using: state))
            #expect(!system.recordedCommands.contains {
                $0.contains("networksetup -set") || $0.contains("-flushcache") || $0.contains("-HUP")
            })
        }
    }

    @Test(arguments: [false, true])
    func fullDNSReconfigurationRetainsWithdrawalOwnership(failingWrite: Bool) throws {
        var (state, system) = fixture(vpnDNSServer: "8.8.4.4")
        state.pushedDNSServers = ["10.8.0.53"]
        var injectFailure = failingWrite
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/usr/sbin/networksetup", invocation.arguments.first == "-setdnsservers" {
                let store = try #require(TestDependencies.sessionStore)
                let saved = try #require(SessionState.load(from: store))
                #expect(Set(saved.fullTunnelDNSServers ?? []) == ["8.8.4.4", "10.8.0.53"])
            }
            if injectFailure, invocation.launchPath == "/usr/sbin/networksetup",
               invocation.arguments.first == "-setsearchdomains" {
                injectFailure = false
                throw POSIXError(.EIO)
            }
            return try system.handle(invocation)
        }) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            if failingWrite {
                #expect(throws: POSIXError.self) {
                    try manager.applyFullTunnelDNSConfiguration(using: &state, persistPreparedState: persistPreparedState)
                }
            } else {
                #expect(try manager.applyFullTunnelDNSConfiguration(using: &state, persistPreparedState: persistPreparedState) == ["10.8.0.53"])
            }
            let store = try #require(TestDependencies.sessionStore)
            let saved = try #require(SessionState.load(from: store))
            #expect(try manager.currentDNSSettings(using: saved)?.dnsServers == ["10.8.0.53"])
            #expect(try !manager.withdrawVPNDNS(using: saved))
            state.pushedDNSServers = nil
            #expect(try manager.effectiveFullTunnelDNSServers(using: state) == policy.dnsServers)
        }
    }

    @Test
    func fullDNSRequiresDurableOwnershipBeforeMutation() throws {
        var (state, system) = fixture()
        state.pushedDNSServers = ["10.8.0.53"]
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy)
            #expect(throws: POSIXError.self) {
                try manager.applyFullTunnelDNSConfiguration(using: &state, persistPreparedState: { _ in
                    throw POSIXError(.EIO)
                })
            }
            #expect(!FileManager.default.fileExists(atPath: manager.resolverDirectory.path))
            #expect(!system.recordedCommands.contains {
                $0.contains("networksetup -set") || $0.contains("-flushcache") || $0.contains("-HUP")
            })
        }
    }

    @Test
    func unmanagedResolverReplacementMustBePublished() throws {
        let (state, system) = fixture()
        var publishedServer = "129.22.4.32"
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/usr/sbin/scutil" {
                return CommandResult(exitCode: 0,
                                     stdout: "DNS configuration\nresolver #1\ndomain : case.edu\nnameserver[0] : \(publishedServer)\n",
                                     stderr: "")
            }
            return try system.handle(invocation)
        }) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            try FileManager.default.createDirectory(at: manager.resolverDirectory, withIntermediateDirectories: true)
            let file = manager.resolverFileURL(for: "case.edu")
            let content = "nameserver 9.9.9.9\ndomain case.edu\n"
            try content.write(to: file, atomically: true, encoding: .utf8)
            #expect(try !manager.withdrawVPNDNS(using: state))
            publishedServer = "9.9.9.9"
            #expect(try manager.withdrawVPNDNS(using: state))
            #expect(try String(contentsOf: file, encoding: .utf8) == content)
        }
    }

    @Test(arguments: [false, true])
    func withdrawalPreservesPhysicalCampusDNS(dhcp: Bool) throws {
        let (state, system) = fixture(baseline: dhcp ? [] : ["129.22.4.32"])
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero,
                                       dynamicDNSLookup: { _, _ in
                guard dhcp else {
                    throw POSIXError(.EIO)
                }
                return ["129.22.4.32"]
            })
            #expect(try manager.withdrawVPNDNS(using: state))
            #expect(try manager.cleanup(using: state))
            #expect(try !manager.activeDefaultResolverLeakState(using: state).usesVPNNameServers)
        }
    }

    @Test(arguments: [false, true])
    func dynamicDNSBaselineDistinguishesPhysicalIPv6FromVPNOverride(sharedServer: Bool) throws {
        let (state, system) = fixture(baseline: [], vpnDNSServer: "2001:0DB8:0000:0000:0000:0000:0000:0053")
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero,
                                       dynamicDNSLookup: { interfaceName, serviceName in
                #expect(interfaceName == "en0")
                #expect(serviceName == "Wi-Fi")
                return ["192.168.1.1", sharedServer ? "2001:db8::53" : "2001:db8::54", "fe80::1%en0"]
            })
            #expect(try manager.withdrawVPNDNS(using: state) == sharedServer)
            #expect(try manager.cleanup(using: state) == sharedServer)
            #expect(try manager.activeDefaultResolverLeakState(using: state).usesVPNNameServers == !sharedServer)
        }
    }

    @Test
    func dynamicDNSInspectionFailureCannotCompleteCleanup() throws {
        let (state, system) = fixture(baseline: [])
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero,
                                       dynamicDNSLookup: { _, _ in throw POSIXError(.EACCES) })
            #expect(throws: POSIXError.self) { try manager.withdrawVPNDNS(using: state) }
            #expect(throws: POSIXError.self) { try manager.cleanup(using: state) }
        }
    }

    @Test
    func dynamicDNSStatePreservesScopedAddressesAndRejectsMalformedData() throws {
        let servers = ["192.168.1.1", "2001:db8::53", "fe80::1%en0"]
        #expect(try RouteManager.dynamicDNSServers(in: ["ServerAddresses": servers]) == servers)
        #expect(try RouteManager.dynamicDNSServers(in: nil).isEmpty)
        #expect(try RouteManager.dynamicDNSServers(in: [:] as [String: Any]).isEmpty)
        #expect(try RouteManager.dynamicDNSServers(in: ["ServerAddresses": [] as [String]]).isEmpty)
        let malformedValues: [Any] = [7, ["ServerAddresses": "192.168.1.1"], ["ServerAddresses": [7]]]
        for malformed in malformedValues {
            #expect(throws: RouteManagerError.self) { try RouteManager.dynamicDNSServers(in: malformed) }
        }
    }

    @Test(arguments: [false, true], ["vpn", "configured", "effective"])
    func withdrawalRequiresPublishedSearchDomainsToMatchBaseline(scoped: Bool, source: String) throws {
        var (state, system) = fixture()
        state.fullTunnelSearchDomains = ["vpn.example"]
        if source == "configured" {
            state.originalSearchDomains = ["vpn.example"]
        } else if source == "effective" {
            state.originalDefaultSearchDomains = ["vpn.example"]
        }
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/usr/sbin/scutil" {
                let section = scoped ? "DNS configuration (for scoped queries)" : "DNS configuration"
                return CommandResult(exitCode: 0,
                                     stdout: "\(section)\nresolver #1\nsearch domain[0] : VPN.EXAMPLE\nnameserver[0] : 1.1.1.1\n",
                                     stderr: "")
            }
            return try system.handle(invocation)
        }) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            #expect(try manager.withdrawVPNDNS(using: state) == (source != "vpn"))
            #expect(try manager.cleanup(using: state) == (source != "vpn"))
            #expect(try manager.validateCleanupState(using: state) == (source != "vpn"))
            if !scoped {
                #expect(try manager.activeDefaultResolverLeakState(using: state).overlapsVPNSearchDomains == (source == "vpn"))
            }
        }
    }

    @Test
    func partialDNSWriteFailureFlushesAndCannotCompleteCleanup() throws {
        let (state, system) = fixture()
        try CommandRunner.withCommandHandler({ invocation in
            if invocation.launchPath == "/usr/sbin/networksetup", invocation.arguments.first == "-setsearchdomains" {
                return CommandResult(exitCode: 1, stdout: "", stderr: "injected search-domain write failure")
            }
            return try system.handle(invocation)
        }) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            #expect(throws: RouteManagerError.self) { try manager.withdrawVPNDNS(using: state) }
            #expect(system.recordedCommands.contains("/usr/bin/dscacheutil -flushcache"))
            #expect(try manager.currentDNSSettings(using: state)?.dnsServers == ["1.1.1.1"])
            #expect(try !manager.cleanup(using: state))
        }
    }

    @Test
    func partialResolverRemovalFailureFlushesAndPreservesUnremovedFiles() throws {
        let (state, system) = fixture()
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            try manager.installResolverFiles(forDomains: ["case.edu", "cwru.edu"], nameServers: ["129.22.4.32"])
            let invalid = manager.resolverFileURL(for: "cwru.edu")
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: invalid.path)
            #expect(throws: RouteManagerError.self) { try manager.withdrawVPNDNS(using: state) }
            #expect(!FileManager.default.fileExists(atPath: manager.resolverFileURL(for: "case.edu").path))
            #expect(FileManager.default.fileExists(atPath: invalid.path))
            #expect(system.recordedCommands.contains("/usr/bin/dscacheutil -flushcache"))
        }
    }

    @Test(arguments: [false, true])
    func staleRecoveryRetainsUnpublishedDNSUnlessExplicitlyForced(force: Bool) throws {
        let (state, system) = fixture()
        try CommandRunner.withCommandHandler(system.handle) { () throws -> Void in
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            let store = try #require(TestDependencies.sessionStore)
            try state.save(in: store)
            if force {
                try SessionControl.recoverStaleSession(state, force: true, sessionStore: store, routeManager: manager)
                #expect(SessionState.load(from: store) == nil)
            } else {
                #expect(throws: VPNControllerError.self) {
                    try SessionControl.recoverStaleSession(state, force: false, sessionStore: store, routeManager: manager)
                }
                #expect(SessionState.load(from: store)?.lastEvent == "RECOVERY_REQUIRED")
            }
        }
    }

    @Test @MainActor
    func watchdogPreservesReportedFailureUntilExplicitRecovery() throws {
        var (state, system) = fixture(baseline: ["129.22.4.32"])
        state.executablePath = try ExecutionIdentity.currentExecutablePath()
        state.markRecoveryRequired(message: "DNS withdrawal failed before tunnel teardown.")
        try CommandRunner.withCommandHandler(system.handle) {
            let manager = RouteManager(splitTunnelPolicy: policy, dnsPublicationTimeout: .zero)
            let store = try #require(TestDependencies.sessionStore)
            try state.save(in: store)
            #expect(CleanupWatchdog.performCleanup(
                parentPID: state.pid, parentStartTime: state.processStartTime,
                sessionStore: store, routeManager: manager) == .finished(criticalAlert: nil))
            #expect(system.recordedCommands.isEmpty)
            #expect(SessionState.load(from: store)?.lastInfo == state.lastInfo)
            try SessionControl.recoverStaleSession(state, force: false, sessionStore: store, routeManager: manager)
            #expect(SessionState.load(from: store) == nil)
        }
    }
}
