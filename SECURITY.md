# Security Model

`cwru-ovpn` is a native macOS command-line and menu-bar OpenVPN client for Case Western Reserve University profiles. Setup installs a root-owned executable at `/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn.app/Contents/MacOS/cwru-ovpn`, user state under `~/.cwru-ovpn`, and a sudoers rule covering a fixed list of connect and disconnect invocations. Each connection starts a session controller and a cleanup watchdog to restore the network when the session ends. Neither is registered as a launch daemon or login item.

This document describes what that process protects, what it does not, and the assumptions it relies on.

## Trust Boundaries

**Local user to root** is the primary boundary. Passwordless sudo must not become arbitrary root execution, arbitrary config or profile selection, or persistent network compromise.

**VPN server to client** covers everything the server can influence: profile content, pushed DNS and search domains, control-channel messages, gateway DNS answers, and OpenVPN 3 parsing all run through privileged code.

**Network privacy** differs by mode. In full tunnel, the IPv4 default route, more-specific public-unicast IPv4 routes, and the VPN control channel are enforced fail-closed; DNS uses VPN servers subject to macOS resolver limitations, and IPv6 is best-effort within macOS constraints. In split tunnel, CWRU traffic is scoped to CWRU routes and DNS, and everything else is kept off the CWRU tunnel. The exceptions appear under [Routing and DNS](#routing-and-dns) and [Known Limitations](#known-limitations).

## Privileged Controls

Setup installs the executable root-owned and writes sudoers entries pinned to the installed binary's SHA-256 digest. Passwordless sudo covers exactly five invocations:

```
connect
connect --mode full
connect --mode split
disconnect
disconnect --force
```

Before replacing the installed executable, setup validates the root-owned staged copy as a native Apple Silicon Mach-O executable. It rejects third-party dynamic dependencies, unsafe loader search paths, and embedded loader environment settings. Installable builds link third-party libraries statically. OpenSSL configuration loading is disabled before constructing the VPN client, and packaged OpenSSL also disables automatic configuration and dynamic module loading.

The executable runs inside a signed application bundle with its own macOS identity. Setup admits only the bundle's executable, identity plist, signature resources, and containing directories from the archive; links and additional paths are rejected. Extraction discards archive ownership, ACLs, extended attributes, and file flags. The installed bundle is owned by root, and its signature is verified after installation. A failed verification restores the previous executable, metadata, profile approval, and sudoers rule together.

Setup itself, `--config`, `--verbosity`, `--foreground`, and the internal `--background-child` flag are all outside the passwordless set. `setup` and `uninstall` require an interactive `sudo`. Explicit config selection with `--config` stays an interactive debugging path.

`connect` and `disconnect` refuse to run without root; the client never escalates individual commands through `sudo`. Network changes run through validated argument vectors, never interpolated shell strings. Resolver file names, DNS domains, interface names, service names, IP addresses, and CIDRs are validated before privileged use. The Swift command runner gives system commands their own process groups, deadlines, and an 8 MiB limit per output stream; exceeding the limit stops the command and fails the operation. It supplies a fixed `PATH` with `LANG` and `LC_ALL` set to `C` instead of the caller's environment. Detached controller and watchdog processes inherit that same minimal environment plus a sudo identity validated against the passwd database, which is what lets root find the invoking user's state directory.

Physical DNS inspection runs in a temporary read-only subprocess under the same deadline and output limits as network commands. It reads the active physical service's dynamic DNS state through SystemConfiguration, so an unresponsive system service cannot leave this query waiting indefinitely.

## Configuration and Profile Trust

The config schema is strict and rejects unknown keys. It exposes only `tunnelMode`, `privacyMode`, `preventSleep`, `webAuthSession`, and `dnsBootstrapServers`. User configuration cannot select a profile, server, route, scoped DNS domain, scoped DNS server, or health-check endpoint.

Native event delivery bounds individual strings and queues at most 256 ordinary events or 8 MiB of payloads. Exceeding either limit produces one fatal event and triggers cleanup. Authentication and DNS metadata are never silently truncated to fit the queue.

Split mode uses a fixed CWRU policy:

- IPv4 routes: `129.22.0.0/16`, `192.5.109.0/24` through `192.5.113.0/24`
- IPv6 routes: `2606:ea00::/32`
- DNS domains: `case.edu`, `cwru.edu`
- Scoped DNS servers: `129.22.4.32`, `129.22.104.132`, `129.22.4.31`, `129.22.104.25`
- Data-path probes: `129.22.4.32` and `129.22.104.132` over TCP 53

The OpenVPN profile is read from `~/.cwru-ovpn/profile.ovpn`. `setup`, which needs interactive `sudo`, validates the profile given with `--profile`, or the one already in `~/.cwru-ovpn` when the option is omitted, and records its SHA-256 digest at `/Library/PrivilegedHelperTools/cwru-ovpn/approved-profile.sha256`. Privileged `connect` requires this file to be owned by root:wheel with mode `0644`, hashes the profile, and refuses to start unless it matches.

Profile policy is allow-list based and is applied to the option list that OpenVPN 3's own profile parser produces, so the policy and the core cannot disagree about what is a directive, a comment, or an inline block. The parsed text is the content handed to the core, which is the profile with the application's pull filters prepended, under the core's profile size limits; setup checks it for both tunnel modes. A line the core does not treat as a block tag is a directive and is checked as one. Top-level `setenv opt` wrappers are unwrapped as the core unwraps them, and `<connection>` blocks are parsed with the core's 4096-byte block limit and checked without unwrapping, as the core reads them. The policy rejects external certificate, key, and credential file references, management sockets, script and plugin hooks, route and redirect-gateway directives, logging, status, and writepid directives, unrecognized `setenv` names, unrecognized Access Server metadata, and any option it does not know, all before OpenVPN starts. Directive names are matched exactly as the core spells them. Certificates and keys are accepted only as inline blocks. Only autologin certificate profiles are supported; a profile that requires typed credentials is refused.

Server-pushed network policy is filtered at pull time in both modes: pushed `route`, `route-ipv6`, `redirect-gateway`, `redirect-private`, `block-ipv4`, and `block-ipv6` options are ignored. Split mode additionally sets `route-nopull` and ignores pushed `dns` and `dhcp-option`, so scoped DNS comes from the fixed policy rather than the server.

## Filesystem Protections

Profile, config, session, resolver, and shell-integration reads are bounded and reject non-regular files, hardlinks, and a final path component that is a symlink. Session state, the home mirror, and shell-integration files are additionally opened relative to a validated directory descriptor, so a swapped parent directory cannot redirect them; profile and config reads resolve their parent directories by path. Authoritative session state and managed resolvers also enforce their required ownership and modes; shell-integration edits validate ownership and reject group- or world-writable files. Profile approval is enforced by its root-owned digest, while configuration follows the strict allowlisted schema. Startup reads the profile once, verifies the digest, and reuses that content for route preparation, so a later path change cannot swap the data underneath privileged setup.

Scoped resolver files carry a managed marker on their first line. Install refuses to overwrite active resolver files without it, and cleanup preserves resolver files a user wrote by hand. Managed files are written root-owned, mode `0644`, and installed, replaced, and removed atomically. Interrupted writes are reclaimed only when the UUID filename, ownership, mode, and complete or partial managed marker match the writer's format. Cleanup and its final verification cover every fixed resolver domain even when a write stopped before its domain was recorded; an unreadable file in that set prevents a successful cleanup result.

Shell integration refuses to edit a shell configuration file that is group- or world-writable, and names the file plus the `chmod go-w` fix.

## Recovery State

The authoritative recovery ledger lives at `/var/db/cwru-ovpn/session.json` with root-only permissions. A copy under `~/.cwru-ovpn` exists so `status` and `doctor` can run without root, and is never trusted as a root recovery source. Writes are size-bounded and serialized with a lock shared by the controller and CLI processes, and an unreadable or malformed ledger blocks reconnecting or discarding state until it is repaired. Identical file contents retain the existing file after ownership and path identity checks; changed contents are synchronized before replacement. The controller, stale-session recovery, cleanup watchdog, and installer also share an exclusive lifecycle lock. Recovery reloads the ledger after acquiring that lock, and a new controller cannot overwrite an existing recovery ledger.

The controller acquires the lifecycle lock before capturing the original network configuration. Lock acquisition verifies that the locked file is still the file in the state directory. Locks are explicitly released when their owning scope ends, including when a spawned process temporarily holds a copy of the descriptor. Stale recovery stays bound to the session identity that prompted it and refuses to act on a replacement session. The watchdog takes the lifecycle lock only when its controller has exited and the ledger cannot be read or still names that controller without a reported cleanup failure; a missing ledger, one written by a later controller, or one already marked for recovery ends the watchdog without touching the lock. It retries temporary lock contention without creating a missing state directory, and logging never waits for another process to release the event-log lock. Critical alerts are shown by a separate short-lived process, so neither the controller nor the watchdog waits on a dialog: after a failed cleanup they release the lifecycle lock and exit while the alert stays on screen, and a running session keeps monitoring and responding to `disconnect` while an alert is open. Uninstall removes other recognized state files before retiring the lifecycle lock and removing the empty state directory; unrecognized files are preserved and reported. Uninstall removes the shell helper and, as its last step with `--purge`, the home state directory relative to validated directory descriptors, unlinking symlinks instead of following them. That removal holds one descriptor per directory level, so a tree nested deeper than the process descriptor limit makes this final step fail with an error, after everything else has been removed, and can leave part of the tree behind.

Session cleanup validates persisted state before restoring routes, DNS, IPv6 mode, or resolver files, so root cleanup never acts on arbitrary paths or malformed routes. Cleanup attempts DNS withdrawal before restoring routes and restores the IPv6 mode last. It flushes the resolver cache after a DNS change or a failure that may have partially changed DNS. The core owns the tunnel descriptor; macOS detaches the interface and removes its routes after that descriptor closes. Persistent cleanup restores physical-network overrides and owned reject routes without treating a reusable tunnel name as ownership. Route cleanup requires exact gateway and interface matches. Replaced host routes are restored only while their next hop remains usable on the recorded interface; scoped routes are checked within that interface's scope. Default-route restoration preserves an existing route, including one belonging to another VPN.

Startup failure and normal disconnect share the same cleanup completion path. Success requires verified network restoration, retirement of remote-route ownership records, and removal of the session recovery ledger. Failed route or interface inspection cannot establish that the physical network is offline or that a replaced route no longer needs restoration. A failure retains recovery evidence, prevents automatic reconnect, and produces a nonzero disconnect exit status.

A watchdog process, spawned at startup and pinned to the controller's PID, executable path, and start time, restores the pre-connection configuration if the controller exits unexpectedly. When it cannot, it marks the ledger as needing recovery and raises a critical alert. A ledger already marked for recovery remains available for explicit recovery; the watchdog does not erase a reported cleanup failure.

## Routing and DNS

Physical network handling follows the active macOS default route and network service rather than assuming Wi-Fi. The control-channel exception is a single exact host route for the endpoint currently being attempted, or the established peer when no attempt is pending. The pinned OpenVPN 3 patch keeps the tunnel across reconnects without generating bypass routes for cached remote lists; server-pushed routes and generic excluded-route output are not trusted as physical-routing exceptions.

Before either UDP or TCP connects, the core's socket-protection callback requests preparation of its actual endpoint. The worker waits for the controller to record route ownership, replace the prior endpoint's managed route, and verify egress on the selected physical interface. Only a matching live request can release that socket; rejection, a ten-second preparation timeout, or cancellation prevents connection. Shutdown wakes pending requests before joining the worker, and callbacks from an old client cannot change the replacement session. The pending endpoint is recorded separately from the established server address and clears at CONNECTED. A candidate list never becomes a set of permanent bypass routes.

Physical-interface IPv4 notifications trigger refresh of the application's ledgered physical host routes even when the interface name, gateway and address return unchanged, so each route is deleted and reinstalled against the interface's current address rather than one recorded before the change. Refresh checks ownership before removal and reinstalls through the same host-route securing step as setup and route repair, so one rule decides which existing routes are preserved, replaced and recorded for restoration, or refused. It verifies reinstallation and leaves recovery records available if it fails. Observer cancellation also suppresses queued notifications during shutdown.

The same patch disables native DNS and proxy publication so reconnects cannot override application DNS policy after a mode switch. The OpenVPN core configures tunnel addresses without adding address-family block routes. The application owns full-tunnel IPv6 blocking and persists each route's ownership before installation, so recovery does not depend on receiving a connection event. Both modes require a captured physical DNS service before startup. When physical-network migration is deferred, read-only route and DNS checks must still establish safety; otherwise the controller disconnects and cleans up. A default resolver that macOS has emptied because the physical service lost its address passes the DNS check, so an offline full tunnel keeps its fail-closed routes and waits under the OpenVPN reconnect lifecycle instead of disconnecting.

The physical service's VPN DNS is applied after tunnel default coverage is in place. Each DNS change records its servers, search domains, and resolver files in the recovery ledger before writing system configuration. DNS selection follows the current server push or the fixed policy; cleanup retains ownership of servers that can remain published across reconfiguration. A switch to split mode restores the physical DNS configuration and waits for default and interface-scoped publication to drop the VPN override before removing tunnel defaults. It retains the target split resolvers and their verified tunnel routes. Failed preparation preserves recorded resources for the controller to roll back or stop; it does not restore ordinary networking inside the mode transition.

Controlled shutdown restores the captured DNS settings, removes managed resolver files, and waits for VPN server addresses and search domains to leave published default, supplemental, and interface-scoped resolvers before asking OpenVPN to stop. Publication checks include temporary sign-in resolvers and preserve independently managed resolver files. DNS addresses are compared in canonical form, so equivalent IPv6 spellings neither hide published VPN servers nor trigger redundant configuration writes. Physical DNS servers from the captured static configuration or the current DHCP lease are legitimate baseline DNS even when they also belong to CWRU. Search-domain checks preserve both the captured effective default domains and the original service configuration. If withdrawal fails or exceeds its deadline, shutdown still restores ordinary networking, reports failure, retains the recovery ledger, and cancels managed reconnect. A later successful cleanup observation cannot erase the earlier teardown failure; an explicit recovery command can retry.

The OpenVPN transport is forced to IPv4 with `protoVersionOverride=4`, because full tunnel may disable restorable physical-service IPv6 while securing the route table, and an IPv6 control channel would then cut its own transport.

While physical-network detection is deferred, route monitoring waits for the core's network lifecycle instead of forcing a reconnect that would resume a paused core. Local address, buffer, and reachability failures from UDP sends and UDP/TCP connects share the existing bounded recovery policy. Remote refusal and polling timeouts alone do not trigger local-failure escalation. A managed process restart still requires a new connection and may require sign-in again.

### Full tunnel

- Verifies fail-closed IPv4 default coverage (`0.0.0.0/1` and `128.0.0.0/1`) through the VPN, and rejects more-specific physical public-unicast IPv4 routes. Coverage and exceptions are evaluated from the same routing-table snapshot. The only exceptions are exact host routes to the VPN server's control-channel address, the physical gateway's own host route, and the current directly attached subnet, which must be an exact match and no wider than `/16`.
- Installs scoped resolvers for `case.edu` and `cwru.edu` and points the physical service's default DNS at servers the current VPN session supplied, falling back to the fixed CWRU servers. Whichever set is used must be provably routed through the tunnel, or the full tunnel fails closed. Cleanup restores the captured DNS wherever the service still differs from it. `disconnect --force` discards the ledger even when that restoration failed; it then only renews the interface's DHCP lease, so service DNS that could not be restored stays as it was until it is reset by hand.
- Preserves the captured service-level DNS and search-domain configuration while full tunnel manages the same service, including across gateway changes, so cleanup restores the user's settings and the managed override is never recorded as the original configuration. A physical-network change discards only the prior effective default search-domain snapshot.
- Installs owned IPv6 reject routes for `::/1` and `8000::/1` and disables restorable physical-service IPv6, including when the tunnel has an IPv6 address. More-specific routes may carry IPv6 through the VPN; public IPv6 must use the VPN or be blocked. Full tunnel refuses interfaces using CLAT or advertising a NAT64 prefix before applying its network policy, because a physical transit exception would weaken those guarantees. Manual and other physical IPv6 modes are rejected because they cannot be restored from the captured mode string.
- Treats Apple Private Relay, Limit IP Address Tracking, and other non-VPN tunnels carrying public IPv6 as unsafe unless managed reject routes block that traffic first.
- Leaves non-public, link-local, and multicast IPv4 routes under macOS control. Full tunnel is not a LAN-isolation firewall.

### Split tunnel

- Routes only the fixed CWRU IPv4 and IPv6 prefixes through the VPN, and skips the IPv6 route entirely on an IPv4-only tunnel.
- Connection setup, route repair, and checks during network migration require the expected routes to be present and refuse a global default route over the CWRU tunnel. Route repair waits for DNS isolation, installs the required CWRU routes, then removes excess tunnel coverage. A successful route command alone does not establish coverage. Read-only diagnostics inspect both IP routing tables, including IPv6 when the tunnel has no assigned IPv6 address.
- Adds no physical default or half-default route during setup or operation. Public traffic outside the CWRU prefixes, other than the control-channel endpoint, follows the system's own routing, so resolving the physical gateway never depends on a route this application owns.
- Rejects more-specific physical routes that override a protected CWRU prefix. The sole routing exception is an unscoped static host route to the current control-channel endpoint through the selected physical gateway and interface. An existing route that meets those conditions is preserved without being claimed for cleanup.
- Leaves non-CWRU public IPv6 on the physical network or another system-managed tunnel, and preserves the physical service's IPv6 setting. If public IPv6 is still routed over the CWRU tunnel after repair, the session fails closed.
- Refreshes the physical DNS and IPv6 baseline when the active service or its settings change while split mode is running. Full mode preserves the baseline for the service whose settings it manages, so mode switches and cleanup restore the appropriate configuration.
- Ignores kernel-managed interface-scoped routes (link-local, multicast, broadcast, loopback) when auditing the tunnel for unexpected routes.
- Installs scoped resolver files only for the fixed CWRU domains and the reverse zones of the fixed CWRU routes.
- Restores physical DNS for the default resolver and fails closed if the default resolver still carries VPN DNS servers or VPN-added search domains. The physical DNS baseline uses configured servers or the active network service's dynamic IPv4 and IPv6 DNS state. If service settings already match the baseline but publication still carries a VPN override, repair reapplies the baseline before releasing tunnel coverage. Captured effective and configured search domains count as physical-network baseline.
- Probes the two fixed CWRU DNS endpoints over TCP 53, so reachability reflects the CWRU data path rather than an unrelated public endpoint.

### Monitoring

A network path monitor schedules a health check after each path change. Health checks rewrite routes, DNS, or resolver files only where the applied state has drifted; a healthy check performs no network writes, so monitoring cannot feed back into the notifications that schedule it. A check that cannot re-establish its mode's guarantees stops the session and restores the previous configuration. While the physical network or its DNS service cannot be captured, the check defers repair after fresh read-only checks establish that the tunnel interface is present, IPv4 and IPv6 are covered or blocked, and every published default name server routes through the tunnel; full-tunnel setup and monitoring permit the same bounded wait for a settling control channel. Deferring physical-network repair arms the transport outage deadline while preserving the core's pause and reconnect lifecycle. Persistent transport failures can escalate to the budgeted managed reconnect; a subsequent stop request cancels that pending reconnect. Other configuration failures stop the session.

An established session's transport outage has a ten-minute deadline that also covers sign-in requested during recovery. Initial sign-in has its own authentication deadline.

### Mode switches

In-place switches keep CWRU routes that already use the active tunnel, prepare the target route set before removing superseded default coverage, replace retained scoped resolver files atomically, and drop obsolete resolver domains only once the target state is installed. Mode requests remain queued while the tunnel or physical network is recovering. Physical-network deferral verifies the current mode's safety before waiting, and health checks or core connection events retry the pending request without consuming it or beginning rollback. A switch to split mode verifies that VPN default DNS overrides have left publication and every split domain has a resolver available to ordinary queries before removing the tunnel default routes. Split monitoring and deferred network recovery require the same resolver publication; correct files alone are insufficient. macOS may publish only a subset of configured DNS servers, but every published server for a managed split domain must belong to the fixed policy. Pending mode requests are serialized with controller state saves. Requesting the mode that is already active records it as the desired final state until the controller acknowledges the cancellation. Completion or rollback clears only the target it satisfied or consumed, so a newer queued target survives and is processed next.

### DNS bootstrap

`dnsBootstrapServers` is separate from split scoped DNS and stays off unless configured; the setup template configures public fallback resolvers so that filtering, captive, or sinkholing networks can still connect. Gateway resolution always tries the system resolver first, so a healthy connection discloses no hostname to the bootstrap servers. Initial DNS checks run off the UI thread, remain subject to the connection deadline, and cannot start a client after cancellation.

Two situations send the client to them, and both ask only for the gateway hostname:

- At connect time, if every address the system resolver returns for the gateway is unusable (all-zero or loopback, the sinkhole signature), the client asks the bootstrap servers immediately and connects pinned to the answer rather than stalling on a dead address.
- If no control-channel handshake happens within a few seconds, which also covers stalls that are not DNS at all, it re-resolves through the bootstrap servers and reconnects pinned.

Reconnecting pinned fixes the tunnel transport but not the browser, which resolves the sign-in host through the system resolver. Before opening the sign-in window the client probes that host through the system resolver, and only when every answer is unusable does it install scoped `/etc/resolver` files for `openvpn.com` and `openvpn.net` pointing at the bootstrap servers. An empty, failed, or ambiguous answer is never read as a sinkhole, so a healthy or merely offline network is never written to. Those files carry the same managed marker as split-tunnel scoped resolvers, are removed when sign-in ends, and are reclaimed by every existing sweep, including the post-connect stale-resolver prune, session cleanup, uninstall, and a startup sweep, so an interrupted sign-in cannot leave them behind.

Outside that window the feature changes no system DNS configuration. Disclosure is bounded to the gateway hostname on a sinkholed or stalled connect, plus the OpenVPN namespace while a sinkholed network's sign-in window is open, and it never authorizes CWRU scoped DNS for non-CWRU traffic. The lookup runs `dig` only after the gateway hostname validates as a domain name, so profile content cannot inject `dig` options, and it runs with `HOME` pointed at an empty directory so a user-writable `~/.digrc` cannot steer the privileged lookup.

## Authentication

External web authentication accepts exactly one entry point: `https://cwru.openvpn.com` on the default HTTPS port. No other host, subdomain, port, or campus domain is accepted as a starting URL. Campus SSO hosts are reached by in-browser redirect during sign-in and are never handed to the client as an entry point.

Validation reads the serialized authority exactly as the browser will receive it, and requires it to be the allowed host alone or the allowed host with port 443. Any authority carrying userinfo or a percent-encoded host is rejected, including one that merely decodes to the allowed host.

Session modes:

- `systemShared` (default) uses a macOS authentication session that shares the default browser's cookie store, so an existing campus SSO session completes sign-in without a fresh credential prompt. Sign-in state the flow leaves behind lives in the browser's store rather than being discarded with the window.
- `system` runs the same in-app session with an ephemeral cookie store destroyed when the window closes, at the cost of a full sign-in on every connect.

Both modes keep sign-in inside the authentication session, including for server requests marked `external`, so the root process never launches the user-selected HTTPS handler.

Only `WEB_AUTH` is advertised and supported. Other URL authentication methods and interactive challenges fail the session, and authentication payloads are redacted rather than displayed.

An authentication page, its URL, and its cookies never establish VPN success. The client closes the system sign-in window when the VPN reports `ASSIGN_IP` or completes connection setup. During initial authentication, **Retry sign-in** explicitly replaces a pending request once, preserving the approved profile and network recovery baseline. There is no automatic retry for slow authentication, expired requests, cancellation, or server rejection. Each request uses the server-advertised timeout, capped at 900 seconds, or 300 seconds if no valid timeout is available; repeated pending events do not extend it. The launcher has a fixed upper bound covering both requests and connection setup. Events and callbacks from the replaced request cannot act on the new attempt.

## Logging

Privacy mode is on by default. Event records keep their timestamp, phase, event name, and error flags, while profile paths, state directory paths, VPN event detail, and free-form notes are replaced with placeholders.

With privacy mode off, records are sanitized rather than suppressed: URL user-info credentials, query strings, fragments, bearer and basic auth headers, session tokens, and password-, secret-, and token-like fields are redacted, as are web-auth payloads. Redaction removes terminal control characters before matching sensitive fields, preserving tabs and newlines. The event log is size-bounded and compacts itself while retaining failure evidence.

## Known Limitations

- DNS egress is not strictly confined to the tunnel. During physical-network recovery, macOS can send queries to VPN DNS over the physical interface even while the full session and tunnel routes remain active. Cached or in-flight queries can also use the physical interface during controlled shutdown despite successful resolver withdrawal checks. Queried names, query types, and timing can therefore be exposed outside VPN encryption. Route and publication checks do not establish the actual interface used by every query.
- Applications using their own resolver or DNS-over-HTTPS do not follow macOS split DNS selection. Users who need split DNS behavior must configure those applications to use the system resolver.
- macOS resolver behavior is not identical to `dig` or `curl`. `scutil --dns`, mDNSResponder caching, and per-application DNS can each resolve differently from scoped resolver files.
- Setting the physical service's DNS persists until cleanup. Use `disconnect` to recover an interrupted session and `doctor` to inspect the remaining state.
- Full tunnel is unavailable on detected CLAT/NAT64 networks; split mode retains physical IPv6 connectivity.
- The split-tunnel IPv6 route applies only when the tunnel receives an IPv6 address.
- Only the active default network service is managed. Multi-interface combinations, such as wired plus Wi-Fi plus Apple Private Relay, are not governed as a single global policy.
- An uncontrolled controller exit or a DNS-withdrawal failure can leave published VPN resolvers after the tunnel is gone. Queries in that interval can use the physical interface. Resolver publication checks also cannot recall already dispatched queries or application-held resolver state; disconnect is not a persistent kill switch.
- Cleanup verifies restoration of the physical service's IPv6 mode. Address configuration, source-address selection, routes, and application paths can converge later; their reachability is separate from configuration restoration.
- Remote and transport ordering in the profile is preserved as written. The client does not reorder remotes, for example to prefer TCP 443.
- The installation serves one user per Mac. The sudoers rule and the approved-profile digest are machine-wide files bound to the user who last ran setup; a second user running setup replaces both, and the first user must run setup again.
- A mode switch requested from the command line is reported for a few seconds. If the controller is still applying it after that, the command says so and exits successfully; `ovpnstatus` shows the outcome.

## Remaining Risk

The OpenVPN 3 C++ core and its profile parser remain the highest-value attack surface, because they process profile and server-controlled data inside a privileged process. The profile policy depends on that parser too: `setup` runs the core's option tokenizer as root over the profile it is given or finds in the state directory before the allow-list is applied, so a profile the policy would reject still reaches that tokenizer. Connect verifies the pinned digest first, so only approved content reaches it there. That process is not privilege-separated: the OpenVPN core, the menu-bar and web-authentication UI, and every route, DNS, and IPv6 mutation run together as root. A memory-safety bug anywhere in that surface is a root compromise.

Process-group timeout cleanup is bounded by signaling semantics: a descendant that escapes the group or forks concurrently with the final group signal can survive. When termination cannot be delivered, `CommandRunner.run` can outlive its configured timeout while waiting for the direct child to exit. Call sites invoke fixed system tools or the internal read-only DNS inspection command with validated arguments. The OpenVPN core executes native `ifconfig` and `route` commands synchronously during tunnel setup and teardown; their duration and output are not bounded by the Swift command runner. Kernel interface detachment and network reachability can settle after persistent configuration has been restored.

Release builds depend on local OpenVPN 3, Asio, OpenSSL, LZ4, and fmt source snapshots, so third-party notices and dependency build metadata should be reviewed before publishing artifacts. Packaging builds from a clean git tree, ignoring only its own `.build` output directory, allows a dirty tree only for explicitly ad-hoc artifacts, and uses Developer ID signing when configured; the installer additionally requires an independently pinned publisher TeamIdentifier and fails closed until that trust root is set. Ad-hoc release signing and ad-hoc installs each require an explicit local-artifact override. `dist/build-info.json` records the app version, source commit and dirty state, toolchain, dependency commits and patch hash, artifact hashes, deployment targets, and third-party prefix hashes, and is never treated as its own publisher trust root. The published `dist/` artifacts are ad-hoc signed and were built from the working tree committed together with them, so their `build-info.json` records `gitDirty: true` and no commit.
