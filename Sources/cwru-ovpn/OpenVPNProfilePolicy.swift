import Foundation

enum OpenVPNProfilePolicyError: LocalizedError {
    case unsupportedDirective(String)

    var errorDescription: String? {
        switch self {
        case .unsupportedDirective(let directive):
            return "OpenVPN profile directive '\(directive)' is not supported by \(AppIdentity.executableName)."
        }
    }
}

enum OpenVPNProfilePolicy {
    private static let supportedDirectives: Set<String> = [
        "allow-compression",
        "auth",
        "auth-nocache",
        "auth-retry",
        "auth-token",
        "auth-token-user",
        "auth-user-pass",
        "cipher",
        "client",
        "comp-lzo",
        "comp-noadapt",
        "compress",
        "connect-retry",
        "connect-retry-max",
        "connect-timeout",
        "data-ciphers",
        "data-ciphers-fallback",
        "dev",
        "dev-type",
        "explicit-exit-notify",
        "float",
        "fragment",
        "hand-window",
        "inactive",
        "key-direction",
        "keepalive",
        "link-mtu",
        "mssfix",
        "mute",
        "mute-replay-warnings",
        "ncp-ciphers",
        "nobind",
        "ns-cert-type",
        "persist-key",
        "persist-remote-ip",
        "persist-tun",
        "ping",
        "ping-exit",
        "ping-restart",
        "pull",
        "pull-filter",
        "proto",
        "proto-force",
        "push-peer-info",
        "rcvbuf",
        "remote",
        "remote-cert-eku",
        "remote-cert-ku",
        "remote-cert-tls",
        "remote-random",
        "remote-random-hostname",
        "reneg-sec",
        "replay-window",
        "resolv-retry",
        "route-nopull",
        "server-poll-timeout",
        "sndbuf",
        "socket-flags",
        "static-challenge",
        "tls-cipher",
        "tls-ciphersuites",
        "tls-client",
        "tls-remote",
        "tls-version-max",
        "tls-version-min",
        "topology",
        "tran-window",
        "tun-mtu",
        "tun-mtu-extra",
        "verify-hash",
        "verify-x509-name",
        "verb",
    ]

    private static let literalBlocks: Set<String> = [
        "ca",
        "cert",
        "extra-certs",
        "http-proxy-user-pass",
        "key",
        "pkcs12",
        "secret",
        "tls-auth",
        "tls-crypt",
        "tls-crypt-v2",
    ]

    private static let supportedSetenvNames: Set<String> = [
        "CLIENT_CERT",
        "IV_GUI_VER",
        "USERNAME",
        "UV_ASCLI_VER",
        "UV_ID",
        "UV_NAME",
        "UV_PLAT",
        "UV_PLAT_REL",
    ]

    private static let supportedAccessServerMetadata: Set<String> = [
        "AUTOLOGIN",
        "CLI_PREF_ALLOW_WEB_IMPORT",
        "CLI_PREF_BASIC_CLIENT",
        "CLI_PREF_ENABLE_CONNECT",
        "CLI_PREF_ENABLE_XD_PROXY",
        "FRIENDLY_NAME",
        "HOST_LIST",
        "IS_OPENVPN_WEB_CA",
        "NO_WEB",
        "ORGANIZATION",
        "PROFILE",
        "USERNAME",
        "WEB_CA_BUNDLE",
        "WSHOST",
    ]

    static func validate(_ profile: OpenVPNProfile) throws {
        try validate(profile.options)
    }

    private static func validate(_ options: [OpenVPNProfile.Option]) throws {
        for option in options {
            switch option {
            case .directive(let arguments):
                try validateDirective(arguments)
            case .block(let name):
                guard literalBlocks.contains(name) else {
                    throw OpenVPNProfilePolicyError.unsupportedDirective(name)
                }
            case .connectionBlock(let connectionOptions):
                try validate(connectionOptions)
            case .accessServerMetadata(let name):
                guard supportedAccessServerMetadata.contains(name) else {
                    throw OpenVPNProfilePolicyError.unsupportedDirective("OVPN_ACCESS_SERVER_\(name)")
                }
            }
        }
    }

    private static func validateDirective(_ arguments: [String]) throws {
        let directive = arguments[0]
        if directive == "setenv" {
            guard arguments.count >= 2, supportedSetenvNames.contains(arguments[1]) else {
                throw OpenVPNProfilePolicyError.unsupportedDirective(directive)
            }
            return
        }
        guard supportedDirectives.contains(directive) else {
            throw OpenVPNProfilePolicyError.unsupportedDirective(directive)
        }
        if directive == "auth-user-pass", arguments.count > 1 {
            throw OpenVPNProfilePolicyError.unsupportedDirective(directive)
        }
    }
}
