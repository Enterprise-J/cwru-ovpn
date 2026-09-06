import Foundation

enum AppIdentity {
    static let executableName = "cwru-ovpn"
    static let bundleName = "CWRU OpenVPN"
    static let version = "0.11.0"
    static let displayName = "\(bundleName) \(version)"
    static let reportedClientVersion = "\(executableName) \(version)"
    static let stateDirectoryName = ".cwru-ovpn"
}
