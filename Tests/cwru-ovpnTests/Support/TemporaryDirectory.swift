import Darwin
import Foundation
import Testing

func withEnvironmentVariable<T>(
    _ name: String,
    value: String,
    body: () throws -> T
) throws -> T {
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

func withCurrentDirectory<T>(
    _ path: String,
    body: () throws -> T
) throws -> T {
    let previousPath = FileManager.default.currentDirectoryPath
    guard FileManager.default.changeCurrentDirectoryPath(path) else {
        Issue.record("Failed to change the current directory for a test fixture.")
        throw POSIXError(.ENOENT)
    }
    defer { _ = FileManager.default.changeCurrentDirectoryPath(previousPath) }
    return try body()
}

func temporaryDirectory(named prefix: String) -> URL {
    let url = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
    try? FileManager.default.createDirectory(
        at: url,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
    try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    return url
}
