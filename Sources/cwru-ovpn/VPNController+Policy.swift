import Darwin
import Foundation

nonisolated extension VPNController {
    static let maximumPushedDNSServerCount = 16
    static let maximumPushedSearchDomainCount = 128
    static let connectingDeadlineSeconds = 60
    static let dnsBootstrapRetryDeadlineSeconds = 3
    static let dnsBootstrapResolveTimeoutSeconds = 1
    static let localTransportFailureWindowSeconds: TimeInterval = 60
    static let localTransportOpenVPNReconnectSeconds: TimeInterval = 3
    static let localTransportManagedReconnectSeconds: TimeInterval = 20
    static let localTransportOpenVPNReconnectMinimumCount = 2
    static let localTransportManagedReconnectMinimumCount = 5
    static let openVPNTransportReconnectThrottleSeconds: TimeInterval = 10
    static let reachabilityFailureSurfaceThrottleSeconds: TimeInterval = 300
    static let reachabilityRetrySeconds: TimeInterval = 30
    static let transportRecoveryDeadlineSeconds: TimeInterval = 10 * 60
    static let stableTransportResetSeconds: TimeInterval = 60
    static let routeHealthCheckLogCoalesceSeconds: TimeInterval = 300
    static let reconnectLifecycleEventLogWindowSeconds: TimeInterval = 60
    static let duplicateLogLineSuppressionSeconds: TimeInterval = 1
    static let fullTunnelControlChannelSettleMaxRetries = 3
    static let postConnectConfigurationSettleMaxRetries = 3
    static let postConnectConfigurationSettleDelaySeconds = 3
    static let supportedSSOMethods = "webauth"

    enum DeadlineKind {
        case connecting
        case authPending
        case transportRecovery
    }

    enum DeadlineClock {
        case wall
        case monotonic
    }

    enum WorkspaceSleepEvent {
        case willSleep
        case didWake
    }

    struct WorkspaceSleepTransition: Equatable {
        let systemAsleep: Bool
        let shouldDisconnect: Bool
    }

    static func deadlineClock(for kind: DeadlineKind) -> DeadlineClock {
        switch kind {
        case .connecting, .authPending:
            return .wall
        case .transportRecovery:
            return .monotonic
        }
    }

    static func workspaceSleepTransition(event: WorkspaceSleepEvent,
                                         phase: SessionState.Phase,
                                         requestedStop: Bool,
                                         cleanupComplete: Bool) -> WorkspaceSleepTransition {
        switch event {
        case .willSleep:
            return WorkspaceSleepTransition(systemAsleep: true, shouldDisconnect: false)
        case .didWake:
            return WorkspaceSleepTransition(systemAsleep: false,
                                            shouldDisconnect: phase == .connected
                                                && !requestedStop
                                                && !cleanupComplete)
        }
    }

    static func shouldShowEstimatedSessionCountdownAlert(phase: SessionState.Phase,
                                                         requestedStop: Bool,
                                                         cleanupComplete: Bool,
                                                         systemAsleep: Bool,
                                                         disconnectingAfterWake: Bool,
                                                         alertShown: Bool,
                                                         remaining: TimeInterval?) -> Bool {
        phase == .connected
            && !requestedStop
            && !cleanupComplete
            && !systemAsleep
            && !disconnectingAfterWake
            && !alertShown
            && remaining.map { $0 <= 0 } == true
    }

    static let startupConnectTimeoutMessage = "The VPN did not finish connecting in time. On public Wi-Fi, finish any captive-portal sign-in and wait for the network to stabilize, then try again."

    static func shouldPreResolveGateway(host: String, bootstrapServers: [String]) -> Bool {
        !bootstrapServers.isEmpty && !NetworkValidation.isValidIPAddress(host)
    }

    struct LocalTransportFailureWindow: Equatable {
        var startedAt: Date?
        var count: Int
    }

    enum TransportRecoveryAction {
        case none
        case reconnect
        case restart
    }

    struct ReconnectLifecycleEventLogWindow: Equatable {
        var startedAt: Date?
        var eventNames: Set<String>
    }

    static func evaluateLocalTransportFailure(window: LocalTransportFailureWindow,
                                              now: Date,
                                              systemAsleep: Bool)
        -> (window: LocalTransportFailureWindow, action: TransportRecoveryAction) {
        var updated = window
        if let startedAt = window.startedAt,
           now.timeIntervalSince(startedAt) <= localTransportFailureWindowSeconds {
            updated.count += 1
        } else {
            updated.startedAt = now
            updated.count = 1
        }

        let elapsed = updated.startedAt.map { now.timeIntervalSince($0) } ?? 0
        if !systemAsleep,
           updated.count >= localTransportManagedReconnectMinimumCount,
           elapsed >= localTransportManagedReconnectSeconds {
            return (updated, .restart)
        }
        if updated.count >= localTransportOpenVPNReconnectMinimumCount,
           elapsed >= localTransportOpenVPNReconnectSeconds {
            return (updated, .reconnect)
        }
        return (updated, .none)
    }

    static func evaluateReconnectLifecycleEventLog(window: ReconnectLifecycleEventLogWindow,
                                                   eventName: String,
                                                   now: Date)
        -> (window: ReconnectLifecycleEventLogWindow, shouldLog: Bool) {
        var updated = window
        if let startedAt = window.startedAt,
           now >= startedAt,
           now.timeIntervalSince(startedAt) < reconnectLifecycleEventLogWindowSeconds {
            let inserted = updated.eventNames.insert(eventName).inserted
            return (updated, inserted)
        }

        updated.startedAt = now
        updated.eventNames = [eventName]
        return (updated, true)
    }

    static func isDuplicateLogLine(_ info: String, previous: (info: String, at: Date)?, now: Date) -> Bool {
        guard let previous, previous.info == info else {
            return false
        }
        return now.timeIntervalSince(previous.at) < duplicateLogLineSuppressionSeconds
    }

    static func transportRecoveryDeadlineDelay(degradedAt: Date, now: Date) -> TimeInterval {
        max(0, degradedAt.addingTimeInterval(transportRecoveryDeadlineSeconds).timeIntervalSince(now))
    }

    static func shouldEnforceTransportRecoveryDeadline(degradedAt: Date?,
                                                       phase: SessionState.Phase,
                                                       requestedStop: Bool,
                                                       cleanupComplete: Bool) -> Bool {
        degradedAt != nil
            && (phase == .connected || phase == .authPending)
            && !requestedStop
            && !cleanupComplete
    }

    static func reachabilityDegradationStateNeedsUpdate(lastEvent: String?,
                                                        lastInfo: String?,
                                                        detail: String) -> Bool {
        lastEvent != "RECONNECTING"
            && (lastEvent != "DATA_PATH_DEGRADED" || lastInfo != detail)
    }

    static func managedReconnectTunnelMode(persistedState: SessionState?,
                                           controllerPID: Int32,
                                           controllerExecutablePath: String,
                                           controllerStartTime: ProcessStartTime,
                                           currentMode: AppTunnelMode) -> AppTunnelMode {
        guard let persistedState,
              persistedState.pid == controllerPID,
              persistedState.executablePath == controllerExecutablePath,
              persistedState.processStartTime == controllerStartTime,
              let requestedTunnelMode = persistedState.requestedTunnelMode else {
            return currentMode
        }
        return requestedTunnelMode
    }

    static func routeHealthCheckSchedule(existingDeadline: Date?, now: Date) -> Date? {
        guard existingDeadline == nil else {
            return nil
        }
        return now.addingTimeInterval(3)
    }

    struct RouteHealthCheckLogPlan: Equatable {
        var shouldLog: Bool
        var suppressedCount: Int
    }

    static func routeHealthCheckLogPlan(reason: String,
                                        lastReason: String?,
                                        lastLoggedAt: Date?,
                                        suppressedCount: Int,
                                        now: Date) -> RouteHealthCheckLogPlan {
        if reason == lastReason,
           let lastLoggedAt,
           now.timeIntervalSince(lastLoggedAt) < routeHealthCheckLogCoalesceSeconds {
            return RouteHealthCheckLogPlan(shouldLog: false, suppressedCount: suppressedCount + 1)
        }
        return RouteHealthCheckLogPlan(shouldLog: true, suppressedCount: suppressedCount)
    }

    static func routeHealthCheckLogNote(reason: String, suppressedCount: Int) -> String {
        guard suppressedCount > 0 else {
            return "Network path monitor noticed: \(reason)"
        }
        let plural = suppressedCount == 1 ? "" : "s"
        return "Network path monitor noticed: \(reason) (\(suppressedCount) preceding duplicate update\(plural) not logged)"
    }

    static func signalName(_ signalNumber: Int32) -> String {
        switch signalNumber {
        case SIGINT:
            return "SIGINT"
        case SIGTERM:
            return "SIGTERM"
        case SIGHUP:
            return "SIGHUP"
        default:
            return String(signalNumber)
        }
    }

    static func completeReachabilityProbe(payloadGeneration: Int,
                                          currentGeneration: Int,
                                          tunnelMode: AppTunnelMode,
                                          phase: SessionState.Phase,
                                          inFlight: inout Bool) -> Bool {
        guard payloadGeneration == currentGeneration else {
            return false
        }
        inFlight = false
        return tunnelMode == .split && phase == .connected
    }

    static func splitDNSRepairFailureRequiresFlush(_ error: Error) -> Bool {
        (error as? RouteManagerError)?.mayHaveMutatedDNS ?? false
    }

    static func sessionStateForSave(currentState: SessionState,
                                    persistedState: SessionState?) -> SessionState {
        guard currentState.phase == .connected || currentState.phase == .connecting || currentState.phase == .authPending,
              let persistedState,
              persistedState.pid == currentState.pid,
              persistedState.executablePath == currentState.executablePath,
              persistedState.processStartTime == currentState.processStartTime else {
            return currentState
        }

        var mergedState = currentState
        let requestChanged = mergedState.requestedTunnelMode != persistedState.requestedTunnelMode
        mergedState.requestedTunnelMode = persistedState.requestedTunnelMode
        if mergedState.lastEvent == "MODE_SWITCH_DEFERRED",
           requestChanged
            || persistedState.requestedTunnelMode == nil {
            mergedState.lastEvent = nil
            mergedState.lastInfo = nil
        }
        return mergedState
    }

    static func sessionStateAfterConsumingModeRequest(currentState: SessionState,
                                                      persistedState: SessionState?,
                                                      consumedMode: AppTunnelMode) -> SessionState {
        var updatedState = currentState
        updatedState.requestedTunnelMode = nil
        if updatedState.lastEvent == "MODE_SWITCH_DEFERRED" {
            updatedState.lastEvent = nil
            updatedState.lastInfo = nil
        }

        guard currentState.phase == .connected || currentState.phase == .connecting || currentState.phase == .authPending,
              let persistedState,
              persistedState.pid == currentState.pid,
              persistedState.executablePath == currentState.executablePath,
              persistedState.processStartTime == currentState.processStartTime else {
            return updatedState
        }

        let pendingMode = persistedState.requestedTunnelMode
        guard let pendingMode,
              pendingMode != consumedMode else {
            return updatedState
        }

        updatedState.requestedTunnelMode = pendingMode
        return updatedState
    }

    static func sessionStateForPhysicalNetworkChange(currentState: SessionState,
                                                     physicalNetwork: PhysicalNetwork,
                                                     physicalDNSConfiguration: PhysicalDNSConfiguration,
                                                     activeDefaultSearchDomains: [String]) -> (state: SessionState, changed: Bool, shouldRestorePreviousService: Bool, transportAffecting: Bool) {
        let serviceChanged = currentState.physicalServiceName != nil
            && currentState.physicalServiceName != physicalDNSConfiguration.serviceName
        let transportAffecting = currentState.physicalGateway != physicalNetwork.gateway
            || currentState.physicalInterface != physicalNetwork.interfaceName

        let fullTunnelSameService = currentState.tunnelMode == .full && !serviceChanged
        let capturedDNSServers: [String]? = fullTunnelSameService
            ? currentState.originalDNSServers
            : physicalDNSConfiguration.dnsServers
        let capturedSearchDomains: [String]? = fullTunnelSameService
            ? currentState.originalSearchDomains
            : physicalDNSConfiguration.searchDomains
        let capturedDefaultSearchDomains: [String]? = fullTunnelSameService
            ? (transportAffecting ? nil : currentState.originalDefaultSearchDomains)
            : activeDefaultSearchDomains
        let capturedIPv6Mode = fullTunnelSameService
            ? currentState.originalIPv6Mode ?? physicalDNSConfiguration.ipv6Mode
            : physicalDNSConfiguration.ipv6Mode

        let configurationChanged = currentState.originalDNSServers != capturedDNSServers
            || currentState.originalSearchDomains != capturedSearchDomains
            || currentState.originalDefaultSearchDomains != capturedDefaultSearchDomains
            || currentState.originalIPv6Mode != capturedIPv6Mode
        let changed = transportAffecting
            || currentState.physicalServiceName != physicalDNSConfiguration.serviceName
            || configurationChanged

        guard changed else {
            return (currentState, false, false, false)
        }

        var updated = currentState
        updated.physicalGateway = physicalNetwork.gateway
        updated.physicalInterface = physicalNetwork.interfaceName
        updated.physicalServiceName = physicalDNSConfiguration.serviceName
        updated.originalDNSServers = capturedDNSServers
        updated.originalSearchDomains = capturedSearchDomains
        updated.originalDefaultSearchDomains = capturedDefaultSearchDomains
        updated.originalIPv6Mode = capturedIPv6Mode
        return (updated, true, serviceChanged, transportAffecting)
    }

    static func isOpenVPNNetworkLifecycleLog(_ info: String) -> Bool {
        info.contains("MacLifeCycle NET_IFACE")
            || info.contains("MacLifeCycle NET_STATE")
            || info.contains("MacLifeCycle ACTION")
    }

    static func isLocalTransportFailureLog(_ info: String) -> Bool {
        let normalized = info.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else {
            return false
        }

        if normalized.contains("route_gateway_error") {
            return true
        }
        let socketFailure = normalized.hasPrefix("udp send exception:")
            || normalized.hasPrefix("transport error: udp connect error on ")
            || normalized.hasPrefix("transport error: tcpv4 connect error on ")
            || normalized.hasPrefix("transport error: tcpv6 connect error on ")
        let localErrors = [
            "can't assign requested address", "no buffer space available", "network is down",
            "network is unreachable", "no route to host",
        ]
        return socketFailure && localErrors.contains { normalized.hasSuffix(": \($0)") }
    }

    static func isOpenVPNGatewayProgressEvent(_ name: String) -> Bool {
        switch name {
        case "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES", "CONNECTED":
            return true
        default:
            return false
        }
    }

    static func restoreNetworkConfiguration(using state: SessionState,
                                            routeManager: RouteManager,
                                            sessionStore: StateDirectory = StateDirectory(),
                                            dnsWithdrawalFailure: Error? = nil,
                                            disconnectingAfterWake: Bool) throws {
        if state.cleanupNeeded, try !routeManager.cleanup(using: state) {
            let context = disconnectingAfterWake ? " after wake" : ""
            throw VPNControllerError.cleanupFailed("Cleanup completed\(context), but the network still looks unhealthy.")
        }
        if let dnsWithdrawalFailure {
            throw dnsWithdrawalFailure
        }
        try SessionState.remove(from: sessionStore)
    }

    static func fatalDisconnectRecord(name: String,
                                      info: String,
                                      isFatal: Bool) -> (event: String, alertMessage: String)? {
        guard isFatal, name != "DISCONNECTED" else {
            return nil
        }

        return (name, userFacingFatalDisconnectMessage(name: name, info: info))
    }

    static func userFacingFatalDisconnectMessage(name: String, info: String) -> String {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        switch name {
        case "SESSION_EXPIRED":
            return "VPN disconnected because the server-side session expired. Reconnect to sign in again."
        case "AUTH_FAILED":
            return "VPN disconnected because authentication failed. Reconnect to sign in again."
        case "CORE_EXIT":
            return "VPN disconnected because the OpenVPN worker stopped unexpectedly. Reconnect to try again."
        default:
            let detail = redactSensitiveText(info).trimmingCharacters(in: .whitespacesAndNewlines)
            let eventDescription = name.isEmpty ? "a fatal OpenVPN event" : "fatal OpenVPN event \(name)"
            if detail.isEmpty {
                return "VPN disconnected after \(eventDescription)."
            }
            return "VPN disconnected after \(eventDescription): \(detail)"
        }
    }

    struct ParsedPushedDNSOptions: Equatable {
        let isAuthoritativeSnapshot: Bool
        let dnsServers: [String]
        let searchDomains: [String]
    }

    private enum CapturedDNSSection {
        case none
        case serverAddresses
        case searchDomains
    }

    static func parsePushedDNSOptions(_ info: String) -> ParsedPushedDNSOptions? {
        if info.contains("CAPTURED OPTIONS:") {
            var sawSession = false
            var sawExcludeRoutes = false
            var insideDNSServers = false
            var section = CapturedDNSSection.none
            var dnsServers: [String] = []
            var searchDomains: [String] = []

            for rawLine in info.components(separatedBy: .newlines) {
                let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                if line.hasPrefix("Session Name:") {
                    sawSession = true
                }
                if line == "Exclude Routes:" {
                    sawExcludeRoutes = true
                }

                switch line {
                case "DNS Servers:":
                    insideDNSServers = true
                    section = .none
                case "DNS Search Domains:":
                    insideDNSServers = false
                    section = .searchDomains
                case "Addresses:" where insideDNSServers:
                    section = .serverAddresses
                case "Domains:" where insideDNSServers:
                    section = .none
                default:
                    if line.hasPrefix("Priority:")
                        || line.hasPrefix("DNSSEC:")
                        || line.hasPrefix("Transport:")
                        || line.hasPrefix("SNI:") {
                        section = .none
                        continue
                    }
                    if rawLine.first?.isWhitespace != true {
                        insideDNSServers = false
                        section = .none
                        continue
                    }
                    switch section {
                    case .serverAddresses:
                        if let address = capturedDNSAddress(line) {
                            dnsServers.append(address)
                        }
                    case .searchDomains:
                        if NetworkValidation.isValidDomainName(line) {
                            searchDomains.append(line)
                        }
                    case .none:
                        break
                    }
                }
            }

            guard sawSession, sawExcludeRoutes else {
                return nil
            }
            return ParsedPushedDNSOptions(isAuthoritativeSnapshot: true,
                                          dnsServers: dnsServers,
                                          searchDomains: searchDomains)
        }

        guard info.contains("OPTIONS:") else {
            return nil
        }
        var dnsServers: [String] = []
        var searchDomains: [String] = []
        for rawLine in info.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.contains("[dhcp-option] [DNS] ["),
               let value = bracketFields(in: line).last {
                let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                if NetworkValidation.isValidIPAddress(trimmed) {
                    dnsServers.append(trimmed)
                }
            } else if line.contains("[dhcp-option] [DOMAIN-SEARCH] ["),
                      let value = bracketFields(in: line).last {
                searchDomains.append(contentsOf: value
                    .split(separator: ",")
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter(NetworkValidation.isValidDomainName))
            }
        }
        guard !dnsServers.isEmpty || !searchDomains.isEmpty else {
            return nil
        }
        return ParsedPushedDNSOptions(isAuthoritativeSnapshot: false,
                                      dnsServers: dnsServers,
                                      searchDomains: searchDomains)
    }

    static func updatedPushedOptionValues(existing: [String]?,
                                          parsed: [String],
                                          isAuthoritativeSnapshot: Bool) -> [String]? {
        if isAuthoritativeSnapshot {
            return parsed.isEmpty ? nil : parsed
        }
        return parsed.isEmpty ? existing : parsed
    }

    private static func capturedDNSAddress(_ value: String) -> String? {
        if NetworkValidation.isValidIPAddress(value) {
            return value
        }
        if value.hasPrefix("["),
           let closingBracket = value.firstIndex(of: "]") {
            let start = value.index(after: value.startIndex)
            let address = String(value[start..<closingBracket])
            return NetworkValidation.isValidIPv6Address(address) ? address : nil
        }
        if let separator = value.lastIndex(of: ":") {
            let address = String(value[..<separator])
            let port = value[value.index(after: separator)...]
            if !port.isEmpty,
               port.allSatisfy(\.isNumber),
               NetworkValidation.isValidIPv4Address(address) {
                return address
            }
        }
        return nil
    }

    private static func bracketFields(in line: String) -> [String] {
        guard let regex = Self.bracketFieldRegex else {
            return []
        }
        let range = NSRange(line.startIndex..., in: line)
        return regex.matches(in: line, range: range).compactMap { match in
            guard match.numberOfRanges > 1,
                  let valueRange = Range(match.range(at: 1), in: line) else {
                return nil
            }
            return String(line[valueRange])
        }
    }

    private static let bracketFieldRegex = try? NSRegularExpression(pattern: #"\[([^\]\r\n]+)\]"#)

    static func uniqueTrimmedNonEmptyStrings(_ values: [String]) -> [String] {
        values.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }.uniqued()
    }
}
