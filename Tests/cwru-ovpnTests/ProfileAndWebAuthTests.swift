import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

private func parseWebAuth(info: String) -> WebAuthRequest? {
    guard case .request(let request) = WebAuthRequest.parseResult(info: info) else {
        return nil
    }
    return request
}

@Suite
struct ProfileAndWebAuthTests {
    @Test
    func profilePolicyBoundsInlineNesting() throws {
        for input in [String(repeating: "</ca>", count: 50_000),
                      String(repeating: "setenv opt ", count: 20_000) + "client",
                      String(repeating: "<connection>", count: 20_000)] {
            #expect(throws: OpenVPNProfilePolicyError.self) {
                try OpenVPNProfilePolicy.validate(configContent: input)
            }
        }
        try OpenVPNProfilePolicy.validate(configContent: "setenv opt client\n<connection>remote vpn.case.edu 1194</connection>\n<ca>inline</ca>\n")
    }

    @Test
    func profileManifestApproval() throws {
        let profile = Data("client\nremote vpn.case.edu 443 tcp\n".utf8)
        let digest = ProfileManifest.digest(of: profile)

        #expect(
            ProfileManifest.digest(of: profile) == digest,
            "Profile digest must be deterministic for identical content.")
        #expect(
            ProfileManifest.matches(profileData: profile, approvedDigest: digest),
            "A profile must match its own pinned digest.")
        #expect(
            !ProfileManifest.matches(
                profileData: Data("client\nremote evil.example 443 tcp\n".utf8),
                approvedDigest: digest),
            "A changed profile must not match the pinned digest.")
        #expect(
            !ProfileManifest.matches(profileData: profile, approvedDigest: nil),
            "With no pinned digest (profile never approved by setup), nothing matches.")
        let currentExecutableEnforcementApplies = try ProfileManifest.enforcementApplies()
        #expect(
            !currentExecutableEnforcementApplies,
            "Digest enforcement must be inert outside the installed privileged binary, so dev/foreground runs are unaffected."
        )
        try ProfileManifest.verifyApprovedIfEnforced(profileData: profile)

        let installedEnforcementApplies = try ProfileManifest.enforcementApplies(
            executablePathResolver: { RuntimePaths.privilegedExecutable.path },
            isPrivileged: true
        )
        #expect(
            installedEnforcementApplies,
            "Digest enforcement should apply to the installed privileged executable.")
        let privilegedNonInstalledEnforcementApplies = try ProfileManifest.enforcementApplies(
            executablePathResolver: { "/tmp/cwru-ovpn" },
            isPrivileged: true
        )
        #expect(
            privilegedNonInstalledEnforcementApplies,
            "Privileged executions should require digest enforcement even outside the installed helper path."
        )
        let nonPrivilegedInstalledPathEnforcementApplies = try ProfileManifest.enforcementApplies(
            executablePathResolver: { RuntimePaths.privilegedExecutable.path },
            isPrivileged: false
        )
        #expect(
            nonPrivilegedInstalledPathEnforcementApplies,
            "The installed helper path should still require digest enforcement even when simulated as non-root."
        )
        do {
            _ = try ProfileManifest.enforcementApplies(
                executablePathResolver: { throw POSIXError(.EIO) },
                isPrivileged: true
            )
            try #require(
                Bool(false),
                "Privileged profile enforcement must fail closed when executable identity cannot be resolved."
            )
        } catch ProfileManifestError.identityUnavailable {
        }
        let nonPrivilegedIdentityFailureApplies = try ProfileManifest.enforcementApplies(
            executablePathResolver: { throw POSIXError(.EIO) },
            isPrivileged: false
        )
        #expect(
            !nonPrivilegedIdentityFailureApplies,
            "Foreground non-privileged development runs may skip digest enforcement when identity cannot be resolved."
        )

        try Setup.validateProfileForApproval(
            profileData: Data("client\nremote vpn.case.edu 1194 udp\n".utf8))
        #expect(
            throws: (any Error).self,
            "Setup should reject unsafe profiles before pinning an approved digest."
        ) {
            try Setup.validateProfileForApproval(profileData: Data("client\nup /tmp/run.sh\n".utf8))
        }
    }

    @Test
    func webAuthRequestValidation() throws {
        let embeddedRequest = parseWebAuth(
            info: "WEB_AUTH::https://cwru.openvpn.com/connect")
        #expect(
            embeddedRequest?.url.host == "cwru.openvpn.com",
            "WebAuth should accept the expected OpenVPN host.")
        #expect(
            embeddedRequest?.requiresExternalBrowser == false,
            "Flexible WebAuth requests should not require an external browser.")
        #expect(
            embeddedRequest?.presentationURL(usesSystemSession: false)
                .absoluteString.contains("embedded=true") == false,
            "Default-browser WebAuth should preserve the original URL.")
        #expect(
            embeddedRequest?.presentationURL(usesSystemSession: true)
                .absoluteString.contains("embedded=true") == true,
            "System-session WebAuth should append embedded=true to the query string.")
        let serverEmbeddedRequest = parseWebAuth(
            info: "WEB_AUTH::https://cwru.openvpn.com/connect?embedded=true&state=opaque"
        )
        #expect(
            serverEmbeddedRequest?.presentationURL(usesSystemSession: false)
                == serverEmbeddedRequest?.url,
            "Default-browser WebAuth should not rewrite the server-provided URL.")
        let systemSessionURL = serverEmbeddedRequest?.presentationURL(
            usesSystemSession: true
        )
        let embeddedItems = systemSessionURL.flatMap {
            URLComponents(url: $0, resolvingAgainstBaseURL: false)?
                .queryItems?
                .filter { $0.name == "embedded" }
        }
        #expect(
            embeddedItems?.count == 1 && embeddedItems?.first?.value == "true",
            "System-session WebAuth should normalize embedded to one true value.")
        let externalFlagRequest = parseWebAuth(
            info: "WEB_AUTH:external:https://cwru.openvpn.com/connect"
        )
        #expect(
            externalFlagRequest?.requiresExternalBrowser == true,
            "WebAuth should preserve the server external flag for presentation diagnostics.")
        #expect(
            externalFlagRequest?.presentationURL(usesSystemSession: true)
                .absoluteString.contains("embedded=true") == true,
            "System mode should prepare external WebAuth requests for an embedded session.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::http://cwru.openvpn.com/connect") == nil,
            "WebAuth should reject non-HTTPS URLs.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://evil.example/connect") == nil,
            "WebAuth should reject unexpected hosts.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://case.edu/connect") == nil,
            "WebAuth should reject the case.edu apex now that only the OpenVPN entry point is an entry point."
        )
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://cwru.edu/connect") == nil,
            "WebAuth should reject the cwru.edu apex now that only the OpenVPN entry point is an entry point."
        )
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://login.case.edu/sso") == nil,
            "WebAuth should reject campus SSO hosts; they are reached by in-browser redirect, not as an entry point."
        )
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://cwru.openvpn.com.evil.example/connect")
                == nil,
            "WebAuth should reject hosts that only contain the allowed host as a prefix.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://evil.cwru.openvpn.com/connect") == nil,
            "WebAuth should reject subdomains of the allowed host.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://cwru.openvpn.com./connect") == nil,
            "WebAuth should reject trailing-dot host variants.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://evil.example@cwru.openvpn.com/connect")
                == nil,
            "WebAuth should reject URLs with userinfo even when the host is allowed.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://cwru.openvpn.com%2eevil.example/connect")
                == nil,
            "WebAuth should reject percent-encoded host boundary tricks.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://cwru.openvpn%2ecom/connect") == nil,
            "WebAuth should reject a percent-encoded host even when it decodes to the allowed host, because the browser is handed the undecoded URL."
        )
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://xn--wru-3ed.openvpn.com/connect") == nil,
            "WebAuth should reject punycode homograph hosts.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://cwru.openvpn.com:8443/connect") == nil,
            "WebAuth should reject non-HTTPS ports on the allowed host.")
        #expect(
            parseWebAuth(
                info: "WEB_AUTH::https://cwru.openvpn.com:9999999999999999999999/connect") == nil,
            "WebAuth should reject a port too large to parse, which Foundation reports as no port at all."
        )
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://cwru.openvpn.com:/connect") == nil,
            "WebAuth should reject an empty explicit port, which Foundation also reports as no port at all."
        )
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://cwru.openvpn.com:0443/connect") == nil,
            "WebAuth should reject a zero-padded port that Foundation parses as 443 but hands to the browser unchanged."
        )
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://cwru.openvpn.com:0/connect") == nil,
            "WebAuth should reject port zero on the allowed host.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://cwru.openvpn.com:65536/connect") == nil,
            "WebAuth should reject an out-of-range port on the allowed host.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https:/a://cwru.openvpn.com/x") == nil,
            "WebAuth should reject a hostless URL that only carries the allowed host inside its path."
        )
        #expect(
            parseWebAuth(
                info: "WEB_AUTH::https:%2f%2fevil.example/https://cwru.openvpn.com")
                == nil,
            "WebAuth should reject an encoded authority that hides the real host ahead of the allowed one."
        )
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://user:pw@cwru.openvpn.com/connect") == nil,
            "WebAuth should reject a password in the authority even when the host is allowed.")
        #expect(
            parseWebAuth(
                info: "WEB_AUTH::https://cwru.openvpn.com:443@evil.example/connect")
                == nil,
            "WebAuth should reject an authority whose allowed host and port are only userinfo for another host."
        )
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://CWRU.OpenVPN.COM/connect")?.url.host?
                .lowercased()
                == "cwru.openvpn.com",
            "WebAuth host matching should stay case-insensitive.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://cwru.openvpn.com:443/connect") != nil,
            "WebAuth should accept an explicit HTTPS port on the allowed host.")
        #expect(
            parseWebAuth(info: "OPEN_URL:https://cwru.openvpn.com/connect") == nil,
            "Deprecated OPEN_URL should not be accepted.")
        guard case .invalid = WebAuthRequest.parseResult(info: "WEB_AUTH:not-a-valid-request")
        else {
            Issue.record("Malformed WebAuth input should be classified as invalid.")
            return
        }
        guard case .unrelated = WebAuthRequest.parseResult(info: "INFO:connected") else {
            Issue.record("Unrelated informational events should remain unrelated.")
            return
        }
    }

    @Test
    func openVPNProfilePolicy() throws {
        try OpenVPNProfilePolicy.validate(
            configContent: """
                setenv USERNAME "cwru/example"
                client
                remote vpn.case.edu 1194 udp
                # up /tmp/commented.sh
                # harmless comment with <up> inside
                ; log /tmp/commented.log
                <ca>
                -----BEGIN CERTIFICATE-----
                up should-not-be-parsed-inside-ca-block
                -----END CERTIFICATE-----
                </ca>
                <connection>
                remote backup.case.edu 1194 udp
                </connection>
                <connection>remote backup.case.edu 1194 udp</connection>
                <cert>inline-cert</cert>
                # OVPN_ACCESS_SERVER_USERNAME=cwru/example
                # OVPN_ACCESS_SERVER_WEB_CA_BUNDLE_START
                # -----BEGIN CERTIFICATE-----
                # -----END CERTIFICATE-----
                # OVPN_ACCESS_SERVER_WEB_CA_BUNDLE_STOP
                """)
        try OpenVPNProfilePolicy.validate(
            configContent: "client\r\nremote vpn.case.edu 1194 udp\r\n")
        do {
            try OpenVPNProfilePolicy.validate(configContent: "client\r\nup /tmp/run.sh\r\n")
            try #require(
                Bool(false), "OpenVPN profile policy should reject CRLF side-effect directives.")
        } catch OpenVPNProfilePolicyError.unsupportedDirective {
        }

        let rejectedDirectives = [
            "# OVPN_ACCESS_SERVER_route=203.0.113.7",
            "# OVPN_ACCESS_SERVER_redirect-gateway",
            "# OVPN_ACCESS_SERVER_route_START",
            "# OVPN_ACCESS_SERVER_AAA=BBB",
            "<ca>\n# OVPN_ACCESS_SERVER_route=203.0.113.7\n</ca>",
            "<ca></ca>\nup /tmp/run.sh",
            "<ca></ca>up /tmp/run.sh",
            "<ca></ca><up>/tmp/run.sh</up>",
            "<ca> </CA>up /tmp/run.sh",
            "<ca>\nplaceholder\n</ca>up /tmp/run.sh",
            "\u{FEFF}up /tmp/run.sh",
            "<up>/tmp/run.sh</up>",
            "<connection>up /tmp/run.sh</connection>",
            "<connection><up>/tmp/run.sh</up></connection>",
            "connection",
            "script-security 2",
            "UP /tmp/run.sh",
            "up /tmp/run.sh",
            "  up /tmp/run.sh",
            "\tup /tmp/run.sh",
            "--down /tmp/down.sh",
            "log /tmp/cwru-ovpn.log",
            "log-append /tmp/cwru-ovpn.log",
            "plugin /tmp/plugin.so",
            "setenv opt up /tmp/run.sh",
            "setenv opt plugin /tmp/x.so",
            "setenv opt script-security 2",
            "--setenv opt --down /tmp/down.sh",
            "setenv opt <up>/tmp/run.sh</up>",
            "status /tmp/status",
            "tls-export-cert /tmp",
            "tls-verify /tmp/check.sh",
            "writepid /tmp/pid",
            "ca /etc/hosts",
            "cert /tmp/cert.pem",
            "key /tmp/key.pem",
            "auth-user-pass /tmp/creds",
            "http-proxy proxy.example 8080 /tmp/creds",
            "http-proxy-option CUSTOM-HEADER X-Auth /tmp/secret",
            "http-proxy-user-pass /tmp/creds",
            "dev-node /dev/tun0",
            "management 127.0.0.1 7505",
            "route 10.0.0.0 255.0.0.0",
            "redirect-gateway def1",
            "block-ipv4",
            "block-ipv6",
            "replay-persist /tmp/replay",
            "unknown-but-valid-openvpn-option yes",
            "setenv DYLD_INSERT_LIBRARIES /tmp/inject.dylib",
            "setenv opt http-proxy proxy.example 8080 /tmp/creds",
        ]
        for line in rejectedDirectives {
            do {
                try OpenVPNProfilePolicy.validate(configContent: "client\n\(line)\n")
                try #require(
                    Bool(false),
                    "OpenVPN profile policy should reject side-effect directive: \(line)")
            } catch OpenVPNProfilePolicyError.unsupportedDirective {
            } catch {
                throw error
            }
        }

        do {
            try OpenVPNProfilePolicy.validate(configContent: "client\n<ca>\nscript-security 2\n")
            try #require(
                Bool(false), "OpenVPN profile policy should reject unterminated literal blocks.")
        } catch OpenVPNProfilePolicyError.unterminatedLiteralBlock(let block) {
            #expect(
                block == "ca",
                "Unterminated literal block errors should identify the open block.")
        }

        do {
            try OpenVPNProfilePolicy.validate(
                configContent: "client\n<ca>inline</ca> script-security 2\n")
            try #require(
                Bool(false),
                "OpenVPN profile policy should reject side-effect directives after inline literal blocks."
            )
        } catch OpenVPNProfilePolicyError.unsupportedDirective {
        }
    }

    @Test
    func splitOpenVPNConfigFiltersServerPushedNetworkPolicy() throws {
        let profile = """
            client
            pull-filter accept dns
            pull-filter accept route
            pull-filter accept redirect-gateway
            pull-filter accept redirect-private
            pull-filter accept dhcp-option
            pull-filter accept block-ipv4
            pull-filter accept block-ipv6
            remote vpn.case.edu 1194 udp
            remote vpn.case.edu 443 tcp
            remote vpn.case.edu 1194 udp
            """
        let splitProfile = VPNController.openVPNConfigContent(profile, for: .split)
        let expectedPrefix =
            "route-nopull\npull-filter ignore \"route ''\"\npull-filter ignore \"route-ipv6 ''\"\npull-filter ignore redirect-gateway\npull-filter ignore redirect-private\npull-filter ignore dns\npull-filter ignore dhcp-option\npull-filter ignore block-ipv4\npull-filter ignore block-ipv6\n"
        #expect(
            splitProfile.hasPrefix(expectedPrefix),
            "Split mode should prepend route, redirect, DNS, and block filters before profile-provided pull-filter rules."
        )
        #expect(
            splitProfile.contains("pull-filter accept dns"),
            "Split mode should preserve the original profile content after prepending safety filters."
        )
        let expectedRemoteOrder = [
            "remote vpn.case.edu 1194 udp",
            "remote vpn.case.edu 443 tcp",
            "remote vpn.case.edu 1194 udp",
        ]
        let splitRemoteLines = splitProfile.components(separatedBy: "\n").filter {
            VPNController.openVPNDirectiveFields($0).first == "remote"
        }
        #expect(
            splitRemoteLines == expectedRemoteOrder,
            "Split mode must preserve the profile's remote ordering and not reorder TCP 443 ahead of UDP."
        )
        let fullProfile = VPNController.openVPNConfigContent(profile, for: .full)
        let fullExpectedPrefix =
            "pull-filter ignore \"route ''\"\npull-filter ignore \"route-ipv6 ''\"\npull-filter ignore redirect-gateway\npull-filter ignore redirect-private\npull-filter ignore block-ipv4\npull-filter ignore block-ipv6\n"
        #expect(
            fullProfile.hasPrefix(fullExpectedPrefix),
            "Full mode should reject server-pushed IPv4 and redirect routes before profile-provided filters."
        )
        let applicationFilterIndex = try #require(
            fullProfile.range(of: "pull-filter ignore \"route ''\"")?.lowerBound
        )
        let profileFilterIndex = try #require(
            fullProfile.range(of: "pull-filter accept route")?.lowerBound,
            "Full mode should retain both application and profile route filters."
        )
        #expect(
            applicationFilterIndex < profileFilterIndex,
            "Application route filters should precede profile filters so later accepts cannot bypass them."
        )
        let fullRemoteLines = fullProfile.components(separatedBy: "\n").filter {
            VPNController.openVPNDirectiveFields($0).first == "remote"
        }
        #expect(
            fullRemoteLines == expectedRemoteOrder,
            "Full mode must preserve the profile's remote ordering.")
    }

    @Test
    func openVPNAddressFamilyPolicyByMode() throws {
        #expect(
            VPNController.openVPNAllowUnusedAddrFamilies(for: .split) == "yes",
            "Split mode should let RouteManager own unused address-family blocking instead of letting OpenVPN mutate system routes."
        )
        #expect(
            VPNController.openVPNAllowUnusedAddrFamilies(for: .full) == "no",
            "Full mode should keep OpenVPN's unused address-family fail-closed behavior.")
    }
}
