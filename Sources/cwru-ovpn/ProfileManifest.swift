import Foundation
import Darwin
import CryptoKit

enum ProfileManifestError: LocalizedError {
    case identityUnavailable
    case notApproved

    var errorDescription: String? {
        switch self {
        case .identityUnavailable:
            return "Could not determine the current executable identity, so profile approval cannot be verified safely."
        case .notApproved:
            return "The VPN profile was not approved by setup, or it changed since setup. Run 'sudo cwru-ovpn setup --profile /path/to/profile.ovpn' to approve the current profile."
        }
    }
}

enum ProfileManifest {
    static let maxProfileBytes = 262_144
    private static let maxApprovedDigestBytes = 1024

    static func digest(of data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func readProfileData(at url: URL, expectedUserID: uid_t? = nil) throws -> Data {
        try SecureFile.readRegularFile(at: url,
                                       maximumBytes: maxProfileBytes,
                                       context: "VPN profile \(url.path)",
                                       expectedUserID: expectedUserID)
    }

    static func approvedDigest() -> String? {
        guard let data = try? SecureFile.readRegularFile(
            at: RuntimePaths.approvedProfileManifest,
            maximumBytes: maxApprovedDigestBytes,
            context: "approved profile manifest \(RuntimePaths.approvedProfileManifest.path)"
        ) else {
            return nil
        }
        let value = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    static func enforcementApplies() throws -> Bool {
        try enforcementApplies(executablePathResolver: ExecutionIdentity.currentExecutablePath,
                               isPrivileged: geteuid() == 0)
    }

    static func enforcementApplies(executablePathResolver: () throws -> String,
                                   isPrivileged: Bool) throws -> Bool {
        let executablePath: String
        do {
            executablePath = try executablePathResolver()
        } catch {
            if isPrivileged {
                throw ProfileManifestError.identityUnavailable
            }
            return false
        }

        return isPrivileged
            || URL(fileURLWithPath: executablePath).standardized.path
            == RuntimePaths.privilegedExecutable.standardized.path
    }

    static func matches(profileData: Data, approvedDigest: String?) -> Bool {
        guard let approvedDigest else {
            return false
        }
        return digest(of: profileData) == approvedDigest
    }

    static func verifyApprovedIfEnforced(profileData: Data) throws {
        guard try enforcementApplies() else {
            return
        }
        guard matches(profileData: profileData, approvedDigest: approvedDigest()) else {
            throw ProfileManifestError.notApproved
        }
    }

}
