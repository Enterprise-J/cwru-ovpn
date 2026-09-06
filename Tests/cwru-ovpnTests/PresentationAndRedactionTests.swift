import COpenVPN3Wrapper
import Darwin
import Foundation
import Testing

@testable import cwru_ovpn

@Suite
struct PresentationAndRedactionTests {
    @Test
    func statusIndicators() throws {
        #expect(
            SessionPresentation.statusIndicator(for: .connected, tunnelMode: .split) == "◐",
            "Connected split tunnel should use the half-filled circle.")
        #expect(
            SessionPresentation.statusIndicator(for: .connected, tunnelMode: .full) == "●",
            "Connected full tunnel should use the filled circle.")
        #expect(
            SessionPresentation.statusIndicator(for: .connecting, tunnelMode: .split) == "○",
            "Non-connected states should use the hollow circle.")
    }

    @Test
    func statusTextLabels() throws {
        let activeCases: [(SessionState.Phase, String)] = [
            (.connecting, "Status: Connecting"),
            (.authPending, "Status: Sign-In Required"),
            (.connected, "Status: Connected"),
            (.disconnecting, "Status: Disconnecting"),
            (.disconnected, "Status: Disconnected"),
            (.failed, "Status: Failed"),
        ]

        for (phase, expected) in activeCases {
            #expect(
                SessionPresentation.statusLine(for: phase, stale: false, recoveryNeeded: false)
                    == expected,
                "Status output should label \(phase.rawValue) as '\(expected)'.")
        }

        #expect(
            SessionPresentation.statusLine(for: .connected, stale: true, recoveryNeeded: false)
                == "Status: Stale",
            "Stale status output should keep the Status label.")
        #expect(
            SessionPresentation.statusLine(for: .failed, stale: true, recoveryNeeded: true)
                == "Status: Recovery Needed",
            "Recovery-needed status output should keep the Status label.")
        #expect(
            SessionPresentation.gatewayLine(for: "vpn.example.edu") == "Gateway: vpn.example.edu",
            "Status gateway output should use the Gateway label.")
        #expect(
            SessionPresentation.gatewayLine(for: "   ") == nil,
            "Status gateway output should hide blank gateways.")

        let reconnectingSession = SessionState(
            pid: 4321,
            executablePath: "/tmp/cwru-ovpn",
            processStartTime: ProcessStartTime(seconds: 1, microseconds: 0),
            phase: .connected,
            profilePath: "/tmp/profile.ovpn",
            startedAt: Date(timeIntervalSince1970: 0),
            lastEvent: "RECONNECTING",
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        let presentationCases: [(ProcessIdentityAssessment, String, String, String, String)] = [
            (
                .matched,
                "Reconnecting",
                "Controller PID: 4321",
                "Session alive: yes",
                "Session identity: verified"
            ),
            (
                .unavailable,
                "Reconnecting (identity unavailable)",
                "Controller PID: 4321 (identity unavailable)",
                "Session alive: unknown (process exists; identity unavailable)",
                "Session identity: unavailable"
            ),
            (
                .mismatched,
                "Recovery Needed",
                "Controller PID: 4321 (identity mismatch)",
                "Session alive: no",
                "Session identity: mismatch"
            ),
            (
                .notRunning,
                "Recovery Needed",
                "Controller PID: 4321 (not running)",
                "Session alive: no",
                "Session identity: process absent"
            ),
        ]
        for (assessment, title, pidLine, aliveLine, identityLine) in presentationCases {
            #expect(
                SessionPresentation.readOnlyStatusTitle(
                    for: reconnectingSession,
                    identityAssessment: assessment) == title,
                "Read-only status titles should preserve transport state while accurately qualifying process identity."
            )
            #expect(
                SessionPresentation.readOnlyControllerPIDLine(
                    pid: reconnectingSession.pid,
                    identityAssessment: assessment) == pidLine,
                "Read-only PID output should distinguish every process identity state.")
            #expect(
                SessionPresentation.readOnlySessionAliveLine(identityAssessment: assessment)
                    == aliveLine,
                "Doctor liveness output should distinguish verified, unknown, mismatched, and absent controllers."
            )
            #expect(
                SessionPresentation.readOnlySessionIdentityLine(identityAssessment: assessment)
                    == identityLine,
                "Doctor identity output should distinguish every process identity state.")
        }
    }

    @Test
    func menuBarTextCompaction() throws {
        #expect(
            MenuBarText.status("Sign-In Required") == "Sign in required",
            "Menu bar auth status should avoid title-case command wording.")
        #expect(
            MenuBarText.statusRowTitle("Connected") == "Status: Connected",
            "Menu bar status row should include an explicit status label.")
    }

    @Test
    func fatalDisconnectMessages() throws {
        #expect(
            VPNController.userFacingFatalDisconnectMessage(name: "SESSION_EXPIRED", info: "")
                == "VPN disconnected because the server-side session expired. Reconnect to sign in again.",
            "SESSION_EXPIRED should produce a clear reauthentication message.")
        #expect(
            VPNController.userFacingFatalDisconnectMessage(name: "AUTH_FAILED", info: "")
                == "VPN disconnected because authentication failed. Reconnect to sign in again.",
            "AUTH_FAILED should produce a clear authentication message.")

        let genericMessage = VPNController.userFacingFatalDisconnectMessage(
            name: "TLS_ALERT_MISC",
            info: "OPEN_URL:https://login.example/callback?token=secret"
        )
        #expect(
            genericMessage.contains("TLS_ALERT_MISC"),
            "Generic fatal messages should include the event name.")
        #expect(
            !genericMessage.contains("secret"),
            "Generic fatal messages should redact sensitive event details.")
        #expect(
            VPNController.userFacingFatalDisconnectMessage(name: "CORE_EXIT", info: "")
                == "VPN disconnected because the OpenVPN worker stopped unexpectedly. Reconnect to try again.",
            "Unexpected clean worker exit should produce a clear reconnect message.")
    }

    @Test
    func estimatedSessionCountdownText() throws {
        var session = makeSessionState(
            pid: 100,
            profilePath: "/tmp/profile.ovpn",
            configFilePath: nil,
            physicalGateway: "192.168.1.1",
            physicalInterface: "en0",
            physicalServiceName: "Wi-Fi",
            originalDNSServers: ["1.1.1.1"],
            originalSearchDomains: [],
            originalIPv6Mode: "Automatic",
            tunName: "utun7",
            tunnelMode: .split,
            cleanupNeeded: true
        )
        session.startedAt = Date(timeIntervalSince1970: 0)
        session.connectedAt = Date(timeIntervalSince1970: 10)

        #expect(
            SessionPresentation.estimatedSessionCountdownText(
                for: session,
                countdownInterval: 43_140,
                now: Date(timeIntervalSince1970: 10))
                == "Estimated session: 11h59m left",
            "Countdown should start from the configured duration at CONNECTED time using compact hour/minute text."
        )
        #expect(
            SessionPresentation.estimatedSessionCountdownText(
                for: session,
                countdownInterval: 43_140,
                now: Date(timeIntervalSince1970: 39_600))
                == "Estimated session: 59m left",
            "Countdown without seconds should omit the hour when under one hour remains.")
        #expect(
            SessionPresentation.estimatedSessionCountdownText(
                for: session,
                countdownInterval: 43_140,
                now: Date(timeIntervalSince1970: 43_100))
                == "Estimated session: <1m left",
            "Menu-bar countdown should avoid second-level precision under one minute.")
        #expect(
            SessionPresentation.estimatedSessionCountdownText(
                for: session,
                countdownInterval: 43_140,
                now: Date(timeIntervalSince1970: 43_151))
                == "Estimated session: limit reached",
            "Countdown should clamp at a limit-reached state after zero.")
        session.phase = .disconnecting
        #expect(
            SessionPresentation.estimatedSessionCountdownText(
                for: session,
                countdownInterval: 43_140,
                now: Date(timeIntervalSince1970: 10)) == nil,
            "Countdown should only render for connected sessions.")
    }

    @Test
    func fatalDisconnectAlwaysAlerts() throws {
        for name in ["SESSION_EXPIRED", "AUTH_FAILED", "CORE_EXIT", "TRANSPORT_ERROR"] {
            let record = try #require(
                VPNController.fatalDisconnectRecord(
                    name: name,
                    info: "",
                    isFatal: true),
                "A fatal \(name) disconnect should alert the user before the process exits.")
            #expect(
                record.event == name,
                "A fatal disconnect should record the originating event name.")
            #expect(
                !record.alertMessage.isEmpty,
                "A fatal disconnect should carry a user-facing explanation.")
        }

        #expect(
            VPNController.fatalDisconnectRecord(name: "SESSION_EXPIRED", info: "", isFatal: true)?
                .alertMessage.contains("session expired") == true,
            "The twelve-hour session expiry should tell the user why the VPN disconnected.")
        #expect(
            VPNController.fatalDisconnectRecord(name: "DISCONNECTED", info: "", isFatal: true)
                == nil,
            "The terminal DISCONNECTED event should not raise its own alert.")
        #expect(
            VPNController.fatalDisconnectRecord(name: "SESSION_EXPIRED", info: "", isFatal: false)
                == nil,
            "A non-fatal event should not raise a disconnect alert.")
    }

    @Test
    @MainActor
    func pendingAlertGateHoldsTermination() {
        let gate = PendingAlertGate()
        let terminations = TerminationCounter()

        gate.whenIdle { terminations.count += 1 }
        #expect(
            terminations.count == 1,
            "Termination should run immediately when no alert is on screen.")

        terminations.count = 0
        gate.enter()
        #expect(
            gate.hasPendingAlerts,
            "A presented alert should register as pending.")
        gate.whenIdle { terminations.count += 1 }
        #expect(
            terminations.count == 0,
            "The process must not exit while a critical alert is still on screen.")

        gate.enter()
        gate.leave()
        #expect(
            terminations.count == 0,
            "Dismissing a stacked alert should not exit while the first alert remains.")

        gate.leave()
        #expect(
            terminations.count == 1,
            "Termination should run once the last alert is dismissed.")
        #expect(
            !gate.hasPendingAlerts,
            "The gate should be idle after every alert is dismissed.")

        gate.leave()
        #expect(
            terminations.count == 1,
            "An unbalanced dismissal should not run termination twice.")
    }

    @Test
    func urlRedaction() throws {
        let rendered = redactSensitiveText(
            "Open https://login.example/callback#token=secret?state=abc now")
        #expect(
            rendered == "Open https://login.example/callback#[redacted] now",
            "URL redaction should redact fragments that appear before query markers.")

        let tokens = redactSensitiveText(
            "access_token=abc id_token:def SAMLResponse=ghi Bearer raw-token")
        #expect(
            !tokens.contains("abc"),
            "Redaction should suppress access_token values outside URLs.")
        #expect(
            !tokens.contains("def"),
            "Redaction should suppress id_token values outside URLs.")
        #expect(
            !tokens.contains("ghi"),
            "Redaction should suppress SAMLResponse values outside URLs.")
        #expect(
            !tokens.contains("raw-token"),
            "Redaction should suppress bearer token values outside URLs.")
        let multilineAuthHeader = redactSensitiveText(
            "first\nAuthorization: Bearer header-secret\nlast")
        #expect(
            !multilineAuthHeader.contains("header-secret"),
            "Redaction should suppress bearer tokens in multi-line Authorization headers.")
        let basicAuthHeader = redactSensitiveText("first\nAuthorization: Basic dXNlcjpwYXNz\nlast")
        #expect(
            !basicAuthHeader.contains("dXNlcjpwYXNz"),
            "Redaction should suppress basic auth credentials in multi-line Authorization headers.")
        let jsonish = redactSensitiveText(#"access_token=abc,"foo":"bar""#)
        #expect(
            !jsonish.contains("abc"),
            "Redaction should suppress token-like values before JSON-style separators.")
        #expect(
            jsonish.contains(#""foo":"bar""#),
            "Redaction should avoid swallowing the next JSON-shaped field.")

        let quotedTokens = redactSensitiveText(
            #"access_token:"abc","refresh_token":"xyz","foo":"bar""#)
        #expect(
            !quotedTokens.contains("abc"),
            "Redaction should suppress quoted token-like values.")
        #expect(
            !quotedTokens.contains("xyz"),
            "Redaction should suppress JSON-style quoted token values.")
        #expect(
            quotedTokens.contains(#""foo":"bar""#),
            "Redaction should preserve unrelated JSON-style fields after quoted token values.")

        let credentials = redactSensitiveText(
            #"password=hunter2 otp=123456 client_secret:"shh","foo":"bar""#)
        #expect(
            !credentials.contains("hunter2"),
            "Redaction should suppress password-like values.")
        #expect(
            !credentials.contains("123456"),
            "Redaction should suppress OTP-like values.")
        #expect(
            !credentials.contains("shh"),
            "Redaction should suppress client_secret values.")
        #expect(
            credentials.contains(#""foo":"bar""#),
            "Redaction should preserve unrelated fields after credential-like values.")

        let urlUserInfo = redactSensitiveText(
            "Proxy https://user:pass@login.example/path?state=abc")
        #expect(
            urlUserInfo == "Proxy https://[redacted]@login.example/path?[redacted]",
            "URL redaction should suppress user-info credentials before query redaction.")

        let bridgedWebAuth = redactSensitiveText(
            "openvpn.auth:WEB_AUTH:https://login.case.edu/private/path?token=secret")
        #expect(
            bridgedWebAuth == "openvpn.auth:WEB_AUTH:[redacted]",
            "Protocol-prefixed WebAuth messages should redact the entire authentication payload, including URL paths."
        )
        let bridgedChallenge = redactSensitiveText("openvpn.auth:CR_TEXT:challenge-secret")
        #expect(
            bridgedChallenge == "openvpn.auth:CR_TEXT:[redacted]",
            "Protocol-prefixed interactive challenges should redact the entire payload.")
    }

    @Test
    func escapedQuotesDoNotExposeSecretSuffixes() {
        for input in [#"{"password":"before\"sensitive-suffix"}"#, #"password="before\"sensitive-suffix""#] {
            #expect(!redactSensitiveText(input).contains("sensitive-suffix"))
        }
    }

}
