import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

enum TestDependencies {
    @TaskLocal static var shell = Shell()
    @TaskLocal static var resolverDirectory: URL?
    @TaskLocal static var remoteHostRouteLedger: RemoteHostRouteLedger?
    @TaskLocal static var sessionStore: StateDirectory?
    @TaskLocal static var eventLogDirectory: URL?
}

func taskScopedCommandShell() -> Shell {
    Shell(handler: { invocation in
        try TestDependencies.shell.run(
            invocation.launchPath,
            arguments: invocation.arguments,
            input: invocation.input,
            allowNonZero: invocation.allowNonZero,
            requirePrivileges: invocation.requirePrivileges,
            environmentOverrides: invocation.environment)
    })
}

extension Shell {
    static func withCommandHandler<T>(
        _ handler: @escaping Handler,
        perform body: () throws -> T
    ) rethrows -> T {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(
                "cwru-ovpn-command-environment-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let resolverDirectory =
            TestDependencies.resolverDirectory
            ?? root.appendingPathComponent("resolvers", isDirectory: true)
        let ledger = RemoteHostRouteLedger(
            directory: root.appendingPathComponent("ledger", isDirectory: true))
        let sessionStore = StateDirectory(
            directory: root.appendingPathComponent("session-state", isDirectory: true))
        let eventLogDirectory = root.appendingPathComponent("event-log", isDirectory: true)
        return try TestDependencies.$shell.withValue(Shell(handler: handler)) {
            try TestDependencies.$resolverDirectory.withValue(resolverDirectory) {
                try TestDependencies.$remoteHostRouteLedger.withValue(ledger) {
                    try TestDependencies.$sessionStore.withValue(sessionStore) {
                        try TestDependencies.$eventLogDirectory.withValue(
                            eventLogDirectory, operation: body)
                    }
                }
            }
        }
    }
}

func withResolverDirectory<T>(
    _ directory: URL,
    body: () throws -> T
) rethrows -> T {
    let standardizedDirectory = directory.standardizedFileURL
    return try TestDependencies.$resolverDirectory.withValue(standardizedDirectory) {
        try TestDependencies.$eventLogDirectory.withValue(
            standardizedDirectory.appendingPathComponent(".event-log", isDirectory: true),
            operation: body)
    }
}

func testResolverFileURL(for domain: String) -> URL {
    guard let directory = TestDependencies.resolverDirectory else {
        preconditionFailure("Resolver fixture is not active")
    }
    return ResolverPaths.fileURL(for: domain, in: directory)
}

func persistPreparedState(_ state: SessionState) throws {
    let store = try #require(
        TestDependencies.sessionStore,
        "Session persistence fixture is unavailable.")
    try state.save(to: store)
}

extension RouteManager {
    init(
        splitTunnelPolicy: SplitTunnelPolicy,
        dnsBootstrapServers: [String] = [],
        fullTunnelIPv6SafetyTimeout: Duration = .milliseconds(2500)
    ) {
        self.init(
            splitTunnelPolicy: splitTunnelPolicy,
            dnsBootstrapServers: dnsBootstrapServers,
            fullTunnelIPv6SafetyTimeout: fullTunnelIPv6SafetyTimeout,
            shell: taskScopedCommandShell(),
            resolverDirectory: TestDependencies.resolverDirectory ?? ResolverPaths.directory,
            resolverFileOwnership: (getuid(), getgid()),
            remoteHostRouteLedger: TestDependencies.remoteHostRouteLedger
                ?? RemoteHostRouteLedger(),
            eventLogDirectory: TestDependencies.eventLogDirectory
        )
    }
}

func makeRouteManager(dnsBootstrapServers: [String] = []) -> RouteManager {
    RouteManager(
        dnsBootstrapServers: dnsBootstrapServers,
        shell: taskScopedCommandShell(),
        resolverDirectory: TestDependencies.resolverDirectory ?? ResolverPaths.directory,
        resolverFileOwnership: (getuid(), getgid()),
        remoteHostRouteLedger: TestDependencies.remoteHostRouteLedger ?? RemoteHostRouteLedger(),
        eventLogDirectory: TestDependencies.eventLogDirectory)
}

func makeRouteManager(appliedState: SessionState) -> RouteManager {
    RouteManager(
        appliedState: appliedState,
        shell: taskScopedCommandShell(),
        resolverDirectory: TestDependencies.resolverDirectory ?? ResolverPaths.directory,
        resolverFileOwnership: (getuid(), getgid()),
        remoteHostRouteLedger: TestDependencies.remoteHostRouteLedger ?? RemoteHostRouteLedger(),
        eventLogDirectory: TestDependencies.eventLogDirectory)
}

func makeRouteManager(
    splitTunnelPolicy: SplitTunnelPolicy,
    dnsBootstrapServers: [String] = [],
    shell: Shell,
    resolverDirectory: URL
) -> RouteManager {
    RouteManager(
        splitTunnelPolicy: splitTunnelPolicy,
        dnsBootstrapServers: dnsBootstrapServers,
        shell: shell,
        resolverDirectory: resolverDirectory,
        resolverFileOwnership: (getuid(), getgid()),
        remoteHostRouteLedger: RemoteHostRouteLedger(
            directory: resolverDirectory.appendingPathComponent(".route-ledger", isDirectory: true)
        ),
        eventLogDirectory: TestDependencies.eventLogDirectory
            ?? resolverDirectory.appendingPathComponent(".event-log", isDirectory: true))
}
