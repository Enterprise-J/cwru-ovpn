import Foundation

enum AppIdentity {
    static let executableName = "cwru-ovpn"
    static let bundleIdentifier = "io.github.enterprise-j.cwru-ovpn"
    static let bundleName = "CWRU OpenVPN"
    static let version = "1.0.0"
    static let displayName = "\(bundleName) \(version)"
    static let reportedClientVersion = "\(executableName) \(version)"
    static let stateDirectoryName = ".cwru-ovpn"

    static func applicationDirectory(for executable: URL) -> URL {
        executable.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    static func validateBundleInfo(_ data: Data) throws {
        guard let info = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              info["CFBundleIdentifier"] as? String == AppIdentity.bundleIdentifier,
              info["CFBundleExecutable"] as? String == AppIdentity.executableName,
              info["CFBundleName"] as? String == AppIdentity.bundleName,
              info["CFBundleVersion"] as? String == AppIdentity.version,
              info["CFBundleShortVersionString"] as? String == AppIdentity.version,
              info["CFBundlePackageType"] as? String == "APPL",
              info["LSUIElement"] as? Bool == true else {
            throw SetupError.installFailed("The application bundle identity does not match this executable.")
        }
    }

    static func verifyBundleSignature(at directory: URL) throws {
        _ = try CommandRunner().run("/usr/bin/codesign",
                                    arguments: ["--verify", "--deep", "--strict", directory.path])
    }
}
