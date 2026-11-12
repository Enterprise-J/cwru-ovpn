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
                        message: "An interactive challenge was requested, but this client does not support that prompt type.")
        }
    }

    private func presentWebAuth(_ request: WebAuthRequest) {
        postConnectConfigurationGeneration += 1
        closeAuthenticationUI()

        let generation = webAuthPresentationGeneration

        guard let host = request.url.host,
              !routeManager.dnsBootstrapServers.isEmpty else {
            startWebAuthSession(request)
            return
        }

        pendingWebAuthRequest = request
        let timeoutSeconds = Self.dnsBootstrapResolveTimeoutSeconds
        let commandRunner = routeManager.commandRunner
        gatewayResolveQueue.async { [weak self] in
            let sinkholed = RouteManager.systemResolverSinkholes(host: host,
                                                                 timeoutSeconds: timeoutSeconds,
                                                                 commandRunner: commandRunner)
            Task { @MainActor [weak self] in
                self?.finishWebAuthDNSProbe(sinkholed: sinkholed, generation: generation)
            }
        }
    }

    private func finishWebAuthDNSProbe(sinkholed: Bool, generation: Int) {
        guard webAuthPresentationGeneration == generation else {
            return
        }

        guard let request = pendingWebAuthRequest,
              !requestedStop,
              !cleanupComplete else {
            pendingWebAuthRequest = nil
            return
        }
        pendingWebAuthRequest = nil

        if sinkholed {
            installWebAuthDNSOverride()
        }
        startWebAuthSession(request)
    }

    private var webAuthInFlight: Bool {
        externalWebAuthSession != nil || pendingWebAuthRequest != nil
    }

    private func installWebAuthDNSOverride() {
        guard !webAuthDNSOverrideInstalled else {
            return
        }

        do {
            try routeManager.installWebAuthBootstrapResolvers()
            try routeManager.flushDNS()
            webAuthDNSOverrideInstalled = true
            EventLog.append(note: "This network's resolver returns a blocked address for the sign-in host; installed scoped resolver files for the OpenVPN namespace pointing at the configured DNS bootstrap servers, for the sign-in window only.",
                            phase: sessionState.phase)
            emit("This network blocks DNS for the sign-in page; resolving it through the configured DNS bootstrap servers until sign-in finishes.", level: .debug)
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
        guard webAuthDNSOverrideInstalled else {
            return
        }
        webAuthDNSOverrideInstalled = false

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
        let prefersEphemeralSession = webAuthSession == .system
        EventLog.append(note: "Opening \(prefersEphemeralSession ? "an ephemeral" : "the shared") system authentication session for a validated CWRU WebAuth endpoint.",
                        phase: sessionState.phase)
        let controller = ExternalWebAuthSession(
            url: request.presentationURL,
            prefersEphemeralSession: prefersEphemeralSession
        )
        let generation = webAuthPresentationGeneration
        controller.onUserCancelled = { [weak self] in
            guard let self, self.webAuthPresentationGeneration == generation else {
                return
            }
            self.handleAuthenticationCancellation()
        }
        controller.onFailure = { [weak self] error in
            guard let self, self.webAuthPresentationGeneration == generation else {
                return
            }
            self.handleAuthenticationSessionFailure(error)
        }
        if controller.start() {
            externalWebAuthSession = controller
            emit("Opening sign-in window.")
            updateMenuBar()
        } else {
            EventLog.append(note: "Authentication session failed to start.", phase: sessionState.phase)
            failSession(event: "AUTH_SESSION_FAILED",
                        message: "The sign-in session could not be started.")
        }
    }

    private func handleAuthenticationCancellation() {
        guard !requestedStop, !cleanupComplete else {
            return
        }
        failSession(event: "AUTH_CANCELLED", message: "Sign-in was cancelled.")
    }

    private func handleAuthenticationSessionFailure(_ error: Error) {
        guard !requestedStop, !cleanupComplete else {
            return
        }

        let failure = error as NSError
        EventLog.append(eventName: "AUTH_SESSION_ERROR",
                        info: "\(failure.domain) (\(failure.code))",
                        isError: true,
                        isFatal: false,
                        phase: sessionState.phase)
        closeAuthenticationUI()
        failSession(event: "AUTH_SESSION_FAILED",
                    message: "The sign-in session ended unexpectedly. Disconnecting; reconnect to try again.")
    }

    func prepareOpenVPNClient(profileContent: String) throws {
        let servers = routeManager.dnsBootstrapServers
        guard let host = connectRemoteHost,
              Self.shouldPreResolveGateway(host: host, bootstrapServers: servers) else {
            try launchOpenVPNClient(profileContent: profileContent, serverOverride: nil)
            armDNSBootstrapRetryIfNeeded()
            return
        }

        let timeoutSeconds = Self.dnsBootstrapResolveTimeoutSeconds
        let commandRunner = routeManager.commandRunner
        gatewayResolveQueue.async { [weak self] in
            let sinkholed = RouteManager.systemResolverSinkholes(host: host,
                                                                 timeoutSeconds: timeoutSeconds,
                                                                 commandRunner: commandRunner)
            let resolvedIP = sinkholed
                ? RouteManager.resolveHostUsingBootstrap(host: host, servers: servers,
                                                         timeoutSeconds: timeoutSeconds, commandRunner: commandRunner)
                : nil
            Task { @MainActor [weak self] in
                guard let self,
                      !self.requestedStop,
                      !self.cleanupComplete,
                      self.sessionState.phase == .connecting,
                      self.client == nil else {
                    return
                }
                if sinkholed {
                    let detail = resolvedIP == nil
                        ? "This network blocks DNS for the VPN gateway and the configured DNS bootstrap servers did not answer; continuing with the system resolver."
                        : "This network blocks DNS for the VPN gateway; connecting through the configured DNS bootstrap servers."
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
        guard !dnsBootstrapRetryAttempted,
              !routeManager.dnsBootstrapServers.isEmpty,
              connectProfileContent != nil,
              sessionState.phase == .connecting,
              !requestedStop,
              !cleanupComplete else {
            return
        }
        dnsBootstrapRetryGeneration += 1
        let generation = dnsBootstrapRetryGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(Self.dnsBootstrapRetryDeadlineSeconds)) { [weak self] in
            guard let self,
                  self.dnsBootstrapRetryGeneration == generation,
                  !self.dnsBootstrapRetryAttempted,
                  !self.handshakeProgressObserved,
                  self.sessionState.phase == .connecting,
                  !self.webAuthInFlight,
                  !self.requestedStop,
                  !self.cleanupComplete else {
                return
            }
            self.performDNSBootstrapRetry()
        }
    }

    private func performDNSBootstrapRetry() {
        dnsBootstrapRetryAttempted = true
        guard client != nil,
              let profileContent = connectProfileContent,
              let host = connectRemoteHost,
              !NetworkValidation.isValidIPAddress(host) else {
            return
        }

        let servers = routeManager.dnsBootstrapServers
        let timeoutSeconds = Self.dnsBootstrapResolveTimeoutSeconds
        let generation = dnsBootstrapRetryGeneration
        let commandRunner = routeManager.commandRunner
        emit("Still connecting; re-resolving the VPN gateway through the configured DNS bootstrap servers.", level: .debug)
        gatewayResolveQueue.async { [weak self] in
            let resolvedIP = RouteManager.resolveHostUsingBootstrap(host: host,
                                                                    servers: servers,
                                                                    timeoutSeconds: timeoutSeconds,
                                                                    commandRunner: commandRunner)
            Task { @MainActor [weak self] in
                self?.finishDNSBootstrapRetry(profileContent: profileContent, resolvedIP: resolvedIP, generation: generation)
            }
        }
    }

    private func finishDNSBootstrapRetry(profileContent: String, resolvedIP: String?, generation: Int) {
        guard dnsBootstrapRetryGeneration == generation,
              !handshakeProgressObserved,
              sessionState.phase == .connecting,
              !webAuthInFlight,
              !requestedStop,
              !cleanupComplete,
              client != nil else {
            return
        }

        guard let resolvedIP else {
            EventLog.append(note: "Could not re-resolve the VPN gateway through the configured DNS bootstrap servers; continuing with the system resolver.",
                            phase: sessionState.phase)
            emit("Could not re-resolve the VPN gateway through the configured DNS bootstrap servers.", level: .debug)
            return
        }

        EventLog.append(note: "Connection stalled before reaching the gateway; re-resolved it through the configured DNS bootstrap servers and reconnecting to the resolved address.",
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
              !requestedStop,
              !cleanupComplete,
              let deadline = webAuthRecovery.begin(info: info, now: Date()) else {
            return
        }
        scheduleDeadline(.authPending, after: max(0, deadline.timeIntervalSinceNow)) { [weak self] in
            guard let self,
                  self.webAuthRecovery.deadline == deadline,
                  self.sessionState.phase == .authPending,
                  !self.requestedStop,
                  !self.cleanupComplete else {
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
            && webAuthRecovery.canRetry
            && webAuthInFlight
            && !requestedStop
            && !cleanupComplete
            && !systemAsleep
            && client != nil
            && connectProfileContent != nil
    }

    func retryWebAuthentication() {
        guard canRetryWebAuthentication,
              let profileContent = connectProfileContent,
              webAuthRecovery.retry() else {
            return
        }

        let serverOverride = connectServerOverride
        closeAuthenticationUI()
        shutdownOpenVPNClient()
        dnsBootstrapRetryGeneration += 1
        dnsBootstrapRetryAttempted = false
        handshakeProgressObserved = false
        sessionState.phase = .connecting
        sessionState.lastEvent = "AUTH_RETRY"
        sessionState.lastInfo = "Retrying sign-in with a new VPN authentication request."
        sessionState.pushedDNSServers = nil
        sessionState.pushedSearchDomains = nil
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
                        message: "The sign-in retry could not be started: \(error.localizedDescription)")
        }
        updateMenuBar()
    }

    func closeAuthenticationUI() {
        webAuthPresentationGeneration += 1
        externalWebAuthSession?.close()
        externalWebAuthSession = nil
        pendingWebAuthRequest = nil
        removeWebAuthDNSOverrideIfNeeded()
    }
}
