import Foundation

extension VPNController {
    func handleInfoEvent(_ info: String) {
        if info.hasPrefix("OPEN_URL:") {
            failSession(event: "UNSUPPORTED_AUTH_METHOD",
                        message: "The VPN server requested an unsupported URL authentication method.")
            return
        }

        switch WebAuthRequest.parseResult(info: info) {
        case .request(let request):
            presentWebAuth(request)
            return
        case .invalid:
            failSession(event: "INVALID_AUTH_REQUEST",
                        message: "The VPN server sent an invalid WebAuth request.")
            return
        case .unrelated:
            break
        }

        if info.hasPrefix("CR_TEXT:") {
            failSession(event: "UNSUPPORTED_AUTH_CHALLENGE",
                        message: "The VPN server requested an unsupported interactive prompt.")
        }
    }

    private func presentWebAuth(_ request: WebAuthRequest) {
        routeMonitor.postConnectGeneration += 1
        closeAuthenticationUI()

        let generation = webAuth.presentationGeneration

        guard let host = request.url.host,
              !routeManager.dnsBootstrapServers.isEmpty else {
            startWebAuthSession(request)
            return
        }

        webAuth.pendingRequest = request
        let timeoutSeconds = Self.dnsBootstrapResolveTimeoutSeconds
        webAuth.resolveQueue.async { [weak self] in
            let sinkholed = RouteManager.systemResolverSinkholes(host: host,
                                                                 timeoutSeconds: timeoutSeconds,
                                                                 dualStack: true)
            Task { @MainActor [weak self] in
                self?.finishWebAuthDNSProbe(sinkholed: sinkholed, generation: generation)
            }
        }
    }

    private func finishWebAuthDNSProbe(sinkholed: Bool, generation: Int) {
        guard webAuth.presentationGeneration == generation else {
            return
        }

        guard let request = webAuth.pendingRequest,
              !isStopRequested,
              !isCleanupComplete else {
            webAuth.pendingRequest = nil
            return
        }
        webAuth.pendingRequest = nil

        if sinkholed {
            installWebAuthDNSOverride()
        }
        startWebAuthSession(request)
    }

    private var webAuthInFlight: Bool {
        webAuth.isPresenting || webAuth.pendingRequest != nil
    }

    private func installWebAuthDNSOverride() {
        guard !webAuth.isDNSOverrideInstalled else {
            return
        }

        do {
            try routeManager.installWebAuthBootstrapResolvers()
            try routeManager.flushDNS()
            webAuth.isDNSOverrideInstalled = true
            EventLog.append(note: "This network's resolver returned a blocked address for the sign-in host. Installed temporary scoped resolver files for the OpenVPN namespace using the configured DNS bootstrap servers during sign-in.",
                            phase: sessionState.phase)
            emit("This network blocks DNS for the sign-in page. Resolving it through the configured DNS bootstrap servers until sign-in finishes.", level: .debug)
        } catch {
            EventLog.append(note: "Could not install scoped resolver files for the sign-in host: \(error.localizedDescription)",
                            phase: sessionState.phase)
            emit("Could not work around this network's DNS block for the sign-in page: \(error.localizedDescription)", level: .debug)
            _ = try? routeManager.removeWebAuthBootstrapResolvers()
            try? routeManager.flushDNS()
        }
    }

    func removeStaleWebAuthDNSOverride() {
        do {
            guard try !routeManager.removeWebAuthBootstrapResolvers().isEmpty else {
                return
            }
            try routeManager.flushDNS()
            EventLog.append(note: "Removed scoped resolver files left behind by an interrupted sign-in.",
                            phase: sessionState.phase)
        } catch {
            EventLog.append(note: "Could not remove scoped resolver files left behind by an interrupted sign-in: \(error.localizedDescription)",
                            phase: sessionState.phase)
        }
    }

    private func removeWebAuthDNSOverrideIfNeeded() {
        guard webAuth.isDNSOverrideInstalled else {
            return
        }
        webAuth.isDNSOverrideInstalled = false

        do {
            guard try !routeManager.removeWebAuthBootstrapResolvers().isEmpty else {
                return
            }
            try routeManager.flushDNS()
            EventLog.append(note: "Removed the scoped resolver files installed for the sign-in window.",
                            phase: sessionState.phase)
        } catch {
            EventLog.append(note: "Could not remove the scoped resolver files installed for the sign-in window: \(error.localizedDescription)",
                            phase: sessionState.phase)
            emit("Could not remove the sign-in DNS workaround: \(error.localizedDescription)", level: .error)
        }
    }

    private func startWebAuthSession(_ request: WebAuthRequest) {
        let prefersEphemeralSession = webAuthSessionMode == .ephemeral
        EventLog.append(note: "Opening \(prefersEphemeralSession ? "an ephemeral" : "the shared") system authentication session for a validated CWRU WebAuth endpoint.",
                        phase: sessionState.phase)
        guard let userInterface else {
            failSession(event: "AUTH_SESSION_FAILED", message: "Sign-in requires a logged-in macOS user.")
            return
        }
        webAuth.isPresenting = true
        userInterface.send(.authenticate(request.presentationURL, ephemeral: prefersEphemeralSession, generation: webAuth.presentationGeneration))
        emit("Opening sign-in window.")
        updateMenuBar()
    }

    func prepareOpenVPNClient(profileContent: String) throws {
        let servers = routeManager.dnsBootstrapServers
        guard let host = webAuth.remoteHost,
              Self.shouldPreResolveGateway(host: host, bootstrapServers: servers) else {
            try launchOpenVPNClient(profileContent: profileContent, serverOverride: nil)
            armDNSBootstrapRetryIfNeeded()
            return
        }

        let timeoutSeconds = Self.dnsBootstrapResolveTimeoutSeconds
        webAuth.resolveQueue.async { [weak self] in
            let sinkholed = RouteManager.systemResolverSinkholes(host: host,
                                                                 timeoutSeconds: timeoutSeconds,
                                                                 dualStack: false)
            let resolvedIP = sinkholed
                ? RouteManager.resolveHostUsingBootstrap(host: host, servers: servers,
                                                         timeoutSeconds: timeoutSeconds)
                : nil
            Task { @MainActor [weak self] in
                guard let self,
                      !self.isStopRequested,
                      !self.isCleanupComplete,
                      self.sessionState.phase == .connecting,
                      self.client == nil else {
                    return
                }
                if sinkholed {
                    let detail = resolvedIP == nil
                        ? "This network blocks DNS for the VPN gateway, and the configured DNS bootstrap servers did not respond. Continuing with the system resolver."
                        : "This network blocks DNS for the VPN gateway. Connecting with the address from the configured DNS bootstrap servers."
                    EventLog.append(note: detail, phase: self.sessionState.phase)
                    self.emit(detail, level: .debug)
                }
                do {
                    try self.launchOpenVPNClient(profileContent: profileContent, serverOverride: resolvedIP)
                    self.armDNSBootstrapRetryIfNeeded()
                } catch {
                    self.failSession(event: "STARTUP_FAILED", message: error.localizedDescription)
                }
            }
        }
    }

    func armDNSBootstrapRetryIfNeeded() {
        guard !webAuth.hasAttemptedBootstrapRetry,
              !routeManager.dnsBootstrapServers.isEmpty,
              webAuth.profileContent != nil,
              sessionState.phase == .connecting,
              !isStopRequested,
              !isCleanupComplete else {
            return
        }
        webAuth.bootstrapGeneration += 1
        let generation = webAuth.bootstrapGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(Self.dnsBootstrapRetryDeadlineSeconds)) { [weak self] in
            guard let self,
                  self.webAuth.bootstrapGeneration == generation,
                  !self.webAuth.hasAttemptedBootstrapRetry,
                  !self.webAuth.hasObservedHandshake,
                  self.sessionState.phase == .connecting,
                  !self.webAuthInFlight,
                  !self.isStopRequested,
                  !self.isCleanupComplete else {
                return
            }
            self.performDNSBootstrapRetry()
        }
    }

    private func performDNSBootstrapRetry() {
        webAuth.hasAttemptedBootstrapRetry = true
        guard client != nil,
              let profileContent = webAuth.profileContent,
              let host = webAuth.remoteHost,
              !NetworkValidation.isValidIPAddress(host) else {
            return
        }

        let servers = routeManager.dnsBootstrapServers
        let timeoutSeconds = Self.dnsBootstrapResolveTimeoutSeconds
        let generation = webAuth.bootstrapGeneration
        emit("Still connecting. Re-resolving the VPN gateway through the configured DNS bootstrap servers.", level: .debug)
        webAuth.resolveQueue.async { [weak self] in
            let resolvedIP = RouteManager.resolveHostUsingBootstrap(host: host,
                                                                    servers: servers,
                                                                    timeoutSeconds: timeoutSeconds)
            Task { @MainActor [weak self] in
                self?.finishDNSBootstrapRetry(profileContent: profileContent, resolvedIP: resolvedIP, generation: generation)
            }
        }
    }

    private func finishDNSBootstrapRetry(profileContent: String, resolvedIP: String?, generation: Int) {
        guard webAuth.bootstrapGeneration == generation,
              !webAuth.hasObservedHandshake,
              sessionState.phase == .connecting,
              !webAuthInFlight,
              !isStopRequested,
              !isCleanupComplete,
              client != nil else {
            return
        }

        guard let resolvedIP else {
            EventLog.append(note: "Could not re-resolve the VPN gateway through the configured DNS bootstrap servers. Continuing with the system resolver.",
                            phase: sessionState.phase)
            emit("Could not re-resolve the VPN gateway through the configured DNS bootstrap servers.", level: .debug)
            return
        }

        EventLog.append(note: "Connection stalled before reaching the gateway. Reconnecting using the address resolved from the configured DNS bootstrap servers.",
                        phase: sessionState.phase)
        emit("Reconnecting to the VPN gateway using the address from the configured DNS bootstrap servers.", level: .debug)

        shutdownOpenVPNClient()

        do {
            try launchOpenVPNClient(profileContent: profileContent, serverOverride: resolvedIP)
        } catch {
            EventLog.append(note: "DNS bootstrap reconnect failed to start: \(error.localizedDescription)",
                            phase: sessionState.phase)
            failSession(event: "DNS_BOOTSTRAP_FAILED",
                        message: "Reconnecting with the bootstrap-resolved gateway address failed: \(error.localizedDescription)")
        }
    }

    func armAuthPendingDeadline(info: String) {
        guard sessionState.phase == .authPending,
              !isStopRequested,
              !isCleanupComplete,
              let deadline = webAuth.recovery.begin(info: info, now: .now) else {
            return
        }
        scheduleDeadline(at: deadline) { [weak self] in
            guard let self,
                  self.webAuth.recovery.deadline == deadline,
                  self.sessionState.phase == .authPending,
                  !self.isStopRequested,
                  !self.isCleanupComplete else {
                return
            }
            self.closeAuthenticationUI()
            self.failSession(event: "AUTH_TIMED_OUT",
                             message: "The sign-in request expired before the VPN connection completed. Reconnect to start a new request.")
        }
    }

    var canRetryWebAuthentication: Bool {
        sessionState.phase == .authPending
            && sessionState.connectedAt == nil
            && webAuth.recovery.canRetry
            && webAuthInFlight
            && !isStopRequested
            && !isCleanupComplete
            && !isSystemAsleep
            && client != nil
            && webAuth.profileContent != nil
    }

    func retryWebAuthentication() {
        guard canRetryWebAuthentication,
              let profileContent = webAuth.profileContent,
              webAuth.recovery.retry() else {
            return
        }

        let serverOverride = webAuth.serverOverride
        closeAuthenticationUI()
        shutdownOpenVPNClient()
        webAuth.bootstrapGeneration += 1
        webAuth.hasAttemptedBootstrapRetry = false
        webAuth.hasObservedHandshake = false
        sessionState.phase = .connecting
        sessionState.lastEventName = "AUTH_RETRY"
        sessionState.diagnosticDetail = "Retrying sign-in with a new VPN authentication request."
        sessionState.pushedDNS = nil
        EventLog.append(eventName: "AUTH_RETRY",
                        info: "user requested sign-in retry",
                        isError: false,
                        isFatal: false,
                        phase: sessionState.phase)
        emit("Retrying sign-in. Your existing browser sign-in may be reused.")

        do {
            try saveState()
            try launchOpenVPNClient(profileContent: profileContent, serverOverride: serverOverride)
            armDNSBootstrapRetryIfNeeded()
        } catch {
            failSession(event: "AUTH_RETRY_FAILED",
                        message: "Could not retry sign-in: \(error.localizedDescription)")
        }
        updateMenuBar()
    }

    func closeAuthenticationUI() {
        webAuth.presentationGeneration += 1
        userInterface?.send(.closeAuthentication)
        webAuth.isPresenting = false
        webAuth.pendingRequest = nil
        removeWebAuthDNSOverrideIfNeeded()
    }
}
