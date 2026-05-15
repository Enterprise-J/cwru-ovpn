import Foundation

enum AppIdentity {
    static let executableName = "cwru-ovpn"
    static let bundleName = "CWRU OpenVPN"
    static let version = "0.5.3"
    static let reportedClientVersion = "\(bundleName) \(version)"
    static let stateDirectoryName = ".cwru-ovpn"
    static let defaultConfigFileName = "cwru-ovpn.config.json"
}
