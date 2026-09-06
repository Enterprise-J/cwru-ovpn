import Foundation

enum SessionPresentation {
    static let estimatedSessionCountdownInterval: TimeInterval = 43_140

    static func recoveryDetail(for session: SessionState, stale: Bool) -> String? {
        guard stale, session.cleanupNeeded else {
            return nil
        }

        if let message = session.lastInfo, !message.isEmpty {
            return "\(message) Run ovpnd again to retry restoring routes and DNS."
        }

        return "Previous cleanup did not finish. Run ovpnd again to retry restoring routes and DNS."
    }

    static func estimatedSessionCountdownText(for session: SessionState,
                                               countdownInterval: TimeInterval? = estimatedSessionCountdownInterval,
                                               now: Date = Date()) -> String? {
        guard let remaining = estimatedSessionCountdownRemaining(for: session,
                                                                 countdownInterval: countdownInterval,
                                                                 now: now) else {
            return nil
        }

        if remaining <= 0 {
            return "Estimated session: limit reached"
        }
        return "Estimated session: \(formatCountdownDurationWithoutSeconds(remaining)) left"
    }

    static func estimatedSessionCountdownRemaining(for session: SessionState,
                                                    countdownInterval: TimeInterval? = estimatedSessionCountdownInterval,
                                                    now: Date = Date()) -> TimeInterval? {
        guard session.phase == .connected,
              let countdownInterval,
              countdownInterval > 0 else {
            return nil
        }

        let connectedAt = session.connectedAt ?? session.startedAt
        return connectedAt.addingTimeInterval(countdownInterval).timeIntervalSince(now)
    }

    static func formatCountdownDurationWithoutSeconds(_ interval: TimeInterval) -> String {
        let totalSeconds = max(0, Int(ceil(interval)))
        guard totalSeconds >= 60 else {
            return "<1m"
        }

        let totalMinutes = totalSeconds / 60
        let hours = totalMinutes / 60
        let minutes = totalMinutes % 60
        if hours > 0 {
            return "\(hours)h\(minutes)m"
        }

        return "\(minutes)m"
    }

    static func statusIndicator(for phase: SessionState.Phase, tunnelMode: AppTunnelMode) -> String {
        guard phase == .connected else {
            return "○"
        }

        switch tunnelMode {
        case .split:
            return "◐"
        case .full:
            return "●"
        }
    }

    static func statusTitle(for phase: SessionState.Phase, stale: Bool, recoveryNeeded: Bool) -> String {
        if recoveryNeeded {
            return "Recovery Needed"
        }
        if stale {
            return "Stale"
        }

        switch phase {
        case .connecting:
            return "Connecting"
        case .authPending:
            return "Sign-In Required"
        case .connected:
            return "Connected"
        case .disconnecting:
            return "Disconnecting"
        case .disconnected:
            return "Disconnected"
        case .failed:
            return "Failed"
        }
    }

    static func transportStatusTitle(for session: SessionState) -> String? {
        guard session.phase == .connected else {
            return nil
        }
        switch session.lastEvent {
        case "RECONNECTING":
            return "Reconnecting"
        case "DATA_PATH_DEGRADED":
            return "Degraded"
        case "TRANSPORT_RECOVERY_STABILIZING":
            return "Stabilizing"
        default:
            return nil
        }
    }

    static func statusTitle(for session: SessionState, stale: Bool, recoveryNeeded: Bool) -> String {
        if recoveryNeeded || stale {
            return statusTitle(for: session.phase, stale: stale, recoveryNeeded: recoveryNeeded)
        }
        return transportStatusTitle(for: session)
            ?? statusTitle(for: session.phase, stale: false, recoveryNeeded: false)
    }

    static func readOnlyStatusTitle(for session: SessionState,
                                    identityAssessment: ProcessIdentityAssessment) -> String {
        let sessionMayBeActive = identityAssessment.permitsReadOnlyStatus
        let title = statusTitle(for: session,
                                stale: !sessionMayBeActive,
                                recoveryNeeded: !sessionMayBeActive && session.cleanupNeeded)
        if identityAssessment == .unavailable {
            return "\(title) (identity unavailable)"
        }
        return title
    }

    static func readOnlyControllerPIDLine(pid: Int32,
                                          identityAssessment: ProcessIdentityAssessment) -> String {
        let suffix: String
        switch identityAssessment {
        case .matched:
            suffix = ""
        case .mismatched:
            suffix = " (identity mismatch)"
        case .unavailable:
            suffix = " (identity unavailable)"
        case .notRunning:
            suffix = " (not running)"
        }
        return "Controller PID: \(pid)\(suffix)"
    }

    static func readOnlySessionAliveLine(identityAssessment: ProcessIdentityAssessment) -> String {
        switch identityAssessment {
        case .matched:
            return "Session alive: yes"
        case .unavailable:
            return "Session alive: unknown (process exists; identity unavailable)"
        case .mismatched, .notRunning:
            return "Session alive: no"
        }
    }

    static func readOnlySessionIdentityLine(identityAssessment: ProcessIdentityAssessment) -> String {
        switch identityAssessment {
        case .matched:
            return "Session identity: verified"
        case .mismatched:
            return "Session identity: mismatch"
        case .unavailable:
            return "Session identity: unavailable"
        case .notRunning:
            return "Session identity: process absent"
        }
    }

    static func statusLine(for phase: SessionState.Phase, stale: Bool, recoveryNeeded: Bool) -> String {
        statusLine(title: statusTitle(for: phase, stale: stale, recoveryNeeded: recoveryNeeded))
    }

    static func statusLine(title: String) -> String {
        let trimmed = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return "Status"
        }

        return "Status: \(trimmed)"
    }

    static func gatewayLine(for serverHost: String?) -> String? {
        guard let serverHost,
              !serverHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return nil
        }

        return "Gateway: \(serverHost)"
    }
}
