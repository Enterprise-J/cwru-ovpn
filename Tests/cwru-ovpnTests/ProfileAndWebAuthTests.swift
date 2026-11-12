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
    func profileParserBoundsProfileSize() throws {
        for input in [String(repeating: "client\n", count: 40_000),
                      "client\n" + String(repeating: "a", count: 600) + "\n",
                      String(repeating: "a", count: 100) + " yes\n"] {
            #expect(throws: OpenVPNProfileError.self) {
                try OpenVPNProfile(content: input)
            }
        }
    }

    @Test
    func profileParserMatchesOpenVPNGrammar() throws {
        let profile = try OpenVPNProfile(
            content: """
                client
                  # remote commented.example 1194
                ; remote commented.example 1194
                "remote" quoted.example 1194 udp
                setenv opt tls-version-min 1.2
                setenv opt
                <ca>
                remote inside-ca.example 1194
                </ca>
                <connection>
                setenv opt remote unwrapped-only-at-top-level.example 443
                remote block.example 443 tcp
                </connection>
                # OVPN_ACCESS_SERVER_USERNAME=cwru/example
                # OVPN_ACCESS_SERVER_WEB_CA_BUNDLE_START
                # -----BEGIN CERTIFICATE-----
                # OVPN_ACCESS_SERVER_WEB_CA_BUNDLE_STOP
                """)
        #expect(
            profile.options == [
                .directive(["client"]),
                .directive(["remote", "quoted.example", "1194", "udp"]),
                .directive(["tls-version-min", "1.2"]),
                .directive(["setenv", "opt"]),
                .block("ca"),
                .connectionBlock([
                    .directive(["setenv", "opt", "remote", "unwrapped-only-at-top-level.example", "443"]),
                    .directive(["remote", "block.example", "443", "tcp"]),
                ]),
                .accessServerMetadata("USERNAME"),
                .accessServerMetadata("WEB_CA_BUNDLE"),
            ],
            "Profile options must be exactly the options OpenVPN 3 itself parses.")
        #expect(
            profile.firstRemoteHost == "quoted.example",
            "The gateway host should come from the first remote option OpenVPN 3 parses.")
        #expect(
            try OpenVPNProfile(content: "client\r\n<connection>\r\nremote crlf.example 1194\r\n</connection>\r\n")
                .firstRemoteHost == "crlf.example",
            "Remote options inside connection blocks should be found in CRLF profiles.")
        #expect(
            try OpenVPNProfile(content: "client\ndev tun\n").firstRemoteHost == nil,
            "A profile without a remote option has no gateway host.")
        #expect(
            try OpenVPNProfile(
                content: "<connection>\nremote block.example 443\n</connection>\nremote top-level.example 1194\n"
            ).firstRemoteHost == "top-level.example",
            "OpenVPN 3 lists top-level remotes ahead of connection blocks.")
        #expect(
            try OpenVPNProfile(
                content: "<connection>\nsetenv opt remote decoy.example 443\nremote real.example 443\n</connection>\n"
            ).firstRemoteHost == "real.example",
            "OpenVPN 3 does not unwrap setenv opt inside connection blocks.")

        let oversizedConnectionBlock = "<connection>\n"
            + String(repeating: "remote padding.example 1194\n", count: 200)
            + "</connection>\n"
        #expect(throws: OpenVPNProfileError.self, "Connection blocks share the core's 4096-byte limit.") {
            try OpenVPNProfile(content: oversizedConnectionBlock)
        }

        for (content, expected) in [
            ("< ca >\nroute 0.0.0.0 0.0.0.0\n</ca>\n",
             [OpenVPNProfile.Option.directive(["<", "ca", ">"]),
              .directive(["route", "0.0.0.0", "0.0.0.0"]),
              .directive(["</ca>"])]),
            ("<ca >\nroute 0.0.0.0 0.0.0.0\n</ca>\n",
             [.directive(["<ca", ">"]),
              .directive(["route", "0.0.0.0", "0.0.0.0"]),
              .directive(["</ca>"])]),
            ("<ca>x\nup /tmp/run.sh\n</ca>\n",
             [.directive(["<ca>x"]),
              .directive(["up", "/tmp/run.sh"]),
              .directive(["</ca>"])]),
            ("\u{00A0}<ca>\nroute 1.2.3.4\n</ca>\n",
             [.directive(["\u{00A0}<ca>"]),
              .directive(["route", "1.2.3.4"]),
              .directive(["</ca>"])]),
        ] {
            #expect(
                try OpenVPNProfile(content: content).options == expected,
                "Lines OpenVPN 3 does not treat as block tags must surface as live directives.")
        }

        #expect(
            try OpenVPNProfile(content: "<ca>\nplaceholder\n</ca> up /tmp/run.sh\n</ca>\n").options == [.block("ca")],
            "A line OpenVPN 3 does not treat as the closing tag stays inert block content.")

        for malformed in ["<ca>\nscript-security 2\n",
                          "<ca>inline</ca>\n",
                          "# OVPN_ACCESS_SERVER_WEB_CA_BUNDLE_START\n# unterminated\n"] {
            #expect(throws: OpenVPNProfileError.self, "OpenVPN 3 rejects the unterminated block in: \(malformed)") {
                try OpenVPNProfile(content: malformed)
            }
        }
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
        #expect(
            throws: ProfileManifestError.self,
            "Privileged connect must refuse a profile whose digest setup never pinned."
        ) {
            try ProfileManifest.verifyApproved(profileData: profile)
        }

        try Setup.validateProfileForApproval(
            profileData: Data("client\nremote vpn.case.edu 1194 udp\n".utf8))
        var acceptedLineCount = 1
        var rejectedLineCount = 40_000
        while rejectedLineCount - acceptedLineCount > 1 {
            let lineCount = (acceptedLineCount + rejectedLineCount) / 2
            if (try? OpenVPNProfile(content: String(repeating: "client\n", count: lineCount))) == nil {
                rejectedLineCount = lineCount
            } else {
                acceptedLineCount = lineCount
            }
        }
        let largestParsableProfile = String(repeating: "client\n", count: acceptedLineCount)
        _ = try OpenVPNProfile(content: largestParsableProfile)
        #expect(
            throws: OpenVPNProfileError.self,
            "Setup must size-check the content handed to OpenVPN 3, which includes the application's pull filters."
        ) {
            try Setup.validateProfileForApproval(profileData: Data(largestParsableProfile.utf8))
        }
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
            embeddedRequest?.presentationURL.absoluteString.contains("embedded=true") == true,
            "System-session WebAuth should append embedded=true to the query string.")
        let serverEmbeddedRequest = parseWebAuth(
            info: "WEB_AUTH::https://cwru.openvpn.com/connect?embedded=true&state=opaque"
        )
        let systemSessionURL = serverEmbeddedRequest?.presentationURL
        let embeddedItems = systemSessionURL.flatMap {
            URLComponents(url: $0, resolvingAgainstBaseURL: false)?
                .queryItems?
                .filter { $0.name == "embedded" }
        }
        #expect(
            embeddedItems?.count == 1 && embeddedItems?.first?.value == "true",
            "System-session WebAuth should normalize embedded to one true value.")
        #expect(
            parseWebAuth(info: "WEB_AUTH:external:https://cwru.openvpn.com/connect")?
                .presentationURL.absoluteString.contains("embedded=true") == true,
            "Server external-browser requests should still open in the embedded system session.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::http://cwru.openvpn.com/connect") == nil,
            "WebAuth should reject non-HTTPS URLs.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://evil.example/connect") == nil,
            "WebAuth should reject unexpected hosts.")
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://case.edu/connect") == nil,
            "WebAuth should reject the case.edu apex because only the OpenVPN host is an entry point."
        )
        #expect(
            parseWebAuth(info: "WEB_AUTH::https://cwru.edu/connect") == nil,
            "WebAuth should reject the cwru.edu apex because only the OpenVPN host is an entry point."
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
            "OPEN_URL should not be accepted as a WebAuth request.")
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
            OpenVPNProfile(content: """
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
                <cert>
                inline-cert
                </cert>
                setenv opt tls-version-min 1.2
                # OVPN_ACCESS_SERVER_USERNAME=cwru/example
                # OVPN_ACCESS_SERVER_WEB_CA_BUNDLE_START
                # -----BEGIN CERTIFICATE-----
                # -----END CERTIFICATE-----
                # OVPN_ACCESS_SERVER_WEB_CA_BUNDLE_STOP
                """))
        try OpenVPNProfilePolicy.validate(
            OpenVPNProfile(content: "client\r\nremote vpn.case.edu 1194 udp\r\n"))
        do {
            try OpenVPNProfilePolicy.validate(OpenVPNProfile(content: "client\r\nup /tmp/run.sh\r\n"))
            try #require(
                Bool(false), "OpenVPN profile policy should reject CRLF side-effect directives.")
        } catch OpenVPNProfilePolicyError.unsupportedDirective {
        }

        let rejectedDirectives = [
            "# OVPN_ACCESS_SERVER_route=203.0.113.7",
            "# OVPN_ACCESS_SERVER_redirect-gateway",
            "# OVPN_ACCESS_SERVER_route_START\n# 203.0.113.7\n# OVPN_ACCESS_SERVER_route_STOP",
            "<connection>remote vpn.case.edu 1194</connection>",
            "# OVPN_ACCESS_SERVER_AAA=BBB",
            "<ca>\n# OVPN_ACCESS_SERVER_route=203.0.113.7\n</ca>",
            "<ca>\nplaceholder\n</ca>\nup /tmp/run.sh",
            "<CA>\nplaceholder\n</CA>",
            "< ca >\nignore-unknown-option < </ca>\nroute 0.0.0.0 0.0.0.0\n</ca>",
            "<ca >\nroute 0.0.0.0 0.0.0.0\n</ca>",
            "<ca>x\nscript-security 2\n</ca>",
            "\u{00A0}<ca>\nroute 1.2.3.4\n</ca>",
            "\u{00A0}# comment",
            "\u{FEFF}client",
            "\u{FEFF}up /tmp/run.sh",
            "<up>\n/tmp/run.sh\n</up>",
            "<connection>\nup /tmp/run.sh\n</connection>",
            "<connection>\n<up>\n/tmp/run.sh\n</up>\n</connection>",
            "<connection>\nsetenv opt route 10.0.0.0 255.0.0.0\n</connection>",
            "connection",
            "ignore-unknown-option route",
            "Remote vpn.case.edu 1194",
            "--remote vpn.case.edu 1194",
            "\"up\" /tmp/run.sh",
            "setenv opt",
            "setenv",
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
            "setenv opt setenv opt client",
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
                try OpenVPNProfilePolicy.validate(OpenVPNProfile(content: "client\n\(line)\n"))
                try #require(
                    Bool(false),
                    "OpenVPN profile policy should reject side-effect directive: \(line)")
            } catch OpenVPNProfilePolicyError.unsupportedDirective {
            } catch {
                throw error
            }
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
        let splitProfile = OpenVPNProfile.connectContent(profile, for: .split)
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
            $0.hasPrefix("remote ")
        }
        #expect(
            splitRemoteLines == expectedRemoteOrder,
            "Split mode must preserve the profile's remote ordering and not reorder TCP 443 ahead of UDP."
        )
        let fullProfile = OpenVPNProfile.connectContent(profile, for: .full)
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
            $0.hasPrefix("remote ")
        }
        #expect(
            fullRemoteLines == expectedRemoteOrder,
            "Full mode must preserve the profile's remote ordering.")
    }
}
