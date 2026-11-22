import Foundation
import Security

enum AppIdentity {
    static let executableName = "cwru-ovpn"
    static let bundleIdentifier = "io.github.enterprise-j.cwru-ovpn"
    static let bundleName = "CWRU OpenVPN"
    static let version = "1.1.0"
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
        var code: SecStaticCode?
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode)
        guard SecStaticCodeCreateWithPath(directory as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess else {
            throw SetupError.installFailed("The application signature is invalid.")
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let signing = info as? [String: Any],
              let flags = signing[kSecCodeInfoFlags as String] as? UInt32,
              flags & SecCodeSignatureFlags.runtime.rawValue != 0,
              signing[kSecCodeInfoIdentifier as String] as? String == bundleIdentifier,
              (signing[kSecCodeInfoEntitlementsDict as String] as? NSDictionary)?.count ?? 0 == 0 else {
            throw SetupError.installFailed("The application signing identifier, runtime flags or entitlements are unexpected.")
        }
    }

    static func verifyApplication(at directory: URL) throws {
        try verifyBundleSignature(at: directory)
        let contents = directory.appendingPathComponent("Contents")
        try validateBundleInfo(SecureFile.readRegularFile(at: contents.appendingPathComponent("Info.plist"), maximumBytes: 65536, context: "application identity"))
        try ExecutableTrust.validate(SecureFile.readRegularFile(at: contents.appendingPathComponent("MacOS/" + executableName),
                                                               maximumBytes: 64 * 1024 * 1024, context: "application executable"))
    }
}
