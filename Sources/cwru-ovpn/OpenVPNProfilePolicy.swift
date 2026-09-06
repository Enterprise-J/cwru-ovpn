import Foundation

enum OpenVPNProfilePolicyError: LocalizedError {
    case unsupportedDirective(String, Int)
    case unterminatedLiteralBlock(String)
    case excessiveInlineNesting(Int)

    var errorDescription: String? {
        switch self {
        case .unsupportedDirective(let directive, let line):
            return "OpenVPN profile directive '\(directive)' on line \(line) is not supported by \(AppIdentity.executableName)."
        case .unterminatedLiteralBlock(let block):
            return "OpenVPN profile literal block '<\(block)>' is not closed."
        case .excessiveInlineNesting(let line):
            return "OpenVPN profile line \(line) contains too many nested inline directives."
        }
    }
}

enum OpenVPNProfilePolicy {
    private static let unsupportedSideEffectDirectives: Set<String> = [
        "askpass",
        "auth-user-pass-verify",
        "block-ipv4",
        "block-ipv6",
        "client-connect",
        "client-disconnect",
        "config",
        "down",
        "down-pre",
        "ipchange",
        "learn-address",
        "log",
        "log-append",
        "management",
        "management-client-auth",
        "plugin",
        "replay-persist",
        "redirect-gateway",
        "route",
        "route-ipv6",
        "route-pre-down",
        "route-up",
        "script-security",
        "status",
        "tls-export-cert",
        "tls-verify",
        "up",
        "writepid",
    ]

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

    private static let supportedBlockTags = literalBlocks.union(["connection"])

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

    private static let accessServerMetaPrefix = "# OVPN_ACCESS_SERVER_"
    private static let supportedAccessServerMetaDirectives: Set<String> = [
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

    static func validate(configContent: String) throws {
        let profileContents = configContent.replacingOccurrences(of: "\u{FEFF}", with: "")
        var literalBlock: String?

        for (index, rawLine) in profileContents.split(omittingEmptySubsequences: false,
                                                       whereSeparator: \.isNewline).enumerated() {
            let lineNumber = index + 1
            try validateAccessServerMetaDirectiveIfPresent(String(rawLine),
                                                            lineNumber: lineNumber)
            let trimmed = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty,
                  !trimmed.hasPrefix("#"),
                  !trimmed.hasPrefix(";") else {
                continue
            }

            if let block = literalBlock {
                if let tag = closingTag(in: trimmed), tag.name == block {
                    literalBlock = nil
                    try rejectUnsupportedDirective(in: tag.trailingContent, lineNumber: lineNumber)
                }
                continue
            }

            if let tag = openingTag(in: trimmed) {
                guard supportedBlockTags.contains(tag.name) else {
                    throw OpenVPNProfilePolicyError.unsupportedDirective(tag.name, lineNumber)
                }
                if unsupportedSideEffectDirectives.contains(tag.name) {
                    throw OpenVPNProfilePolicyError.unsupportedDirective(tag.name, lineNumber)
                }
                if literalBlocks.contains(tag.name) {
                    if let trailingContent = contentAfterClosingTag(in: tag.trailingContent, for: tag.name) {
                        try rejectUnsupportedDirective(in: trailingContent, lineNumber: lineNumber)
                    } else {
                        literalBlock = tag.name
                    }
                    continue
                }
                try rejectUnsupportedDirective(in: tag.trailingContent, lineNumber: lineNumber)
                continue
            }
            if let tag = closingTag(in: trimmed) {
                guard supportedBlockTags.contains(tag.name) else {
                    throw OpenVPNProfilePolicyError.unsupportedDirective(tag.name, lineNumber)
                }
                try rejectUnsupportedDirective(in: tag.trailingContent, lineNumber: lineNumber)
                continue
            }

            try rejectUnsupportedDirective(in: trimmed, lineNumber: lineNumber)
        }

        if let literalBlock {
            throw OpenVPNProfilePolicyError.unterminatedLiteralBlock(literalBlock)
        }
    }

    private static func validateAccessServerMetaDirectiveIfPresent(_ line: String,
                                                                   lineNumber: Int) throws {
        guard line.hasPrefix(accessServerMetaPrefix) else {
            return
        }

        let payload = line.dropFirst(accessServerMetaPrefix.count)
        let encodedName = payload.split(separator: "=", maxSplits: 1,
                                        omittingEmptySubsequences: false).first.map(String.init) ?? ""
        let name: String
        if encodedName.hasSuffix("_START") {
            name = String(encodedName.dropLast("_START".count))
        } else if encodedName.hasSuffix("_STOP") {
            name = String(encodedName.dropLast("_STOP".count))
        } else {
            name = encodedName
        }

        guard supportedAccessServerMetaDirectives.contains(name) else {
            let directive = name.isEmpty ? "OVPN_ACCESS_SERVER" : "OVPN_ACCESS_SERVER_\(name)"
            throw OpenVPNProfilePolicyError.unsupportedDirective(directive, lineNumber)
        }
    }

    private static func rejectUnsupportedDirective(in line: String, lineNumber: Int) throws {
        var remaining = line[...]
        for _ in 0..<32 {
            remaining = remaining.drop(while: \.isWhitespace)
            guard !remaining.isEmpty else {
                return
            }
            if remaining.hasPrefix("<"), let end = remaining.firstIndex(of: ">") {
                let name = remaining.dropFirst(remaining.hasPrefix("</") ? 2 : 1)[..<end]
                    .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                guard supportedBlockTags.contains(name) else {
                    throw OpenVPNProfilePolicyError.unsupportedDirective(name, lineNumber)
                }
                remaining = remaining[remaining.index(after: end)...]
                continue
            }
            let tokens = remaining.split(maxSplits: 2, whereSeparator: \.isWhitespace)
            let directive = normalizedDirectiveToken(tokens[0])
            if directive == "setenv" {
                guard tokens.count >= 2 else {
                    throw OpenVPNProfilePolicyError.unsupportedDirective(directive, lineNumber)
                }
                if normalizedDirectiveToken(tokens[1]) == "opt", tokens.count == 3 {
                    remaining = tokens[2]
                    continue
                }
                guard supportedSetenvNames.contains(String(tokens[1])) else {
                    throw OpenVPNProfilePolicyError.unsupportedDirective(directive, lineNumber)
                }
                return
            }
            if unsupportedSideEffectDirectives.contains(directive)
                || literalBlocks.contains(directive)
                || !supportedDirectives.contains(directive) {
                throw OpenVPNProfilePolicyError.unsupportedDirective(directive, lineNumber)
            }
            if directive == "auth-user-pass", tokens.count > 1 {
                throw OpenVPNProfilePolicyError.unsupportedDirective(directive, lineNumber)
            }
            return
        }
        throw OpenVPNProfilePolicyError.excessiveInlineNesting(lineNumber)
    }

    private static func normalizedDirectiveToken(_ token: some StringProtocol) -> String {
        String(token).trimmingCharacters(in: CharacterSet(charactersIn: "-")).lowercased()
    }

    private static func openingTag(in line: String) -> (name: String, trailingContent: String)? {
        guard line.hasPrefix("<"), !line.hasPrefix("</"),
              let end = line.firstIndex(of: ">") else {
            return nil
        }
        let name = line[line.index(after: line.startIndex)..<end]
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard !name.isEmpty else {
            return nil
        }
        let trailingContent = line[line.index(after: end)...]
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return (name, trailingContent)
    }

    private static func closingTag(in line: String) -> (name: String, trailingContent: String)? {
        guard line.hasPrefix("</"),
              let end = line.firstIndex(of: ">") else {
            return nil
        }
        let nameStart = line.index(line.startIndex, offsetBy: 2)
        let name = line[nameStart..<end]
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard !name.isEmpty else {
            return nil
        }
        let trailingContent = line[line.index(after: end)...]
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return (name, trailingContent)
    }

    private static func contentAfterClosingTag(in line: String, for block: String) -> String? {
        guard let range = line.range(of: "</\(block)>", options: .caseInsensitive) else {
            return nil
        }
        return line[range.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
