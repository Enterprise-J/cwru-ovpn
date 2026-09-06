# Security Model

`cwru-ovpn` is a native macOS command-line and menu-bar OpenVPN client for Case Western Reserve University profiles. Setup installs a root-owned executable at `/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn`, user state under `~/.cwru-ovpn`, and a sudoers rule covering a fixed list of connect and disconnect invocations. Nothing is registered as a launch daemon or login item: a connect starts one process that lives for the session and restores the network when it ends.

This document describes what that process protects, what it does not, and the assumptions it relies on.

## Trust Boundaries

**Local user to root** is the primary boundary. Passwordless sudo must not become arbitrary root execution, arbitrary config or profile selection, or persistent network compromise.

**VPN server to client** covers everything the server can influence: profile content, pushed DNS and search domains, control-channel messages, gateway DNS answers, and OpenVPN 3 parsing all run through privileged code.

**Network privacy** differs by mode. In full tunnel, the IPv4 default route, more-specific public-unicast IPv4 routes, and the VPN control channel are enforced fail-closed; DNS is routed through the VPN, and IPv6 is best-effort within macOS constraints. In split tunnel, CWRU traffic is scoped to CWRU routes and DNS, and everything else is kept off the CWRU tunnel. The exceptions appear under [Routing and DNS](#routing-and-dns) and [Known Limitations](#known-limitations).

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

Setup itself, `--config`, `--verbosity`, `--foreground`, and the internal `--background-child` and `--startup-status-file` flags are all outside the passwordless set, and setup fails if its generated rules would grant any of them. `setup` and `uninstall` require an interactive `sudo`. Canonical privileged connect ignores `CWRU_OVPN_CONFIG`; explicit config selection stays an interactive debugging path.

Network changes run through validated argument vectors, never interpolated shell strings. Resolver file names, DNS domains, interface names, service names, IP addresses, and CIDRs are validated before privileged use. Bounded subprocesses run in their own process groups so a timeout signals descendants as well, and privileged ones get a fixed `PATH` with `LANG` and `LC_ALL` set to `C`. The detached controller process inherits that same minimal environment plus a sudo identity validated against the passwd database, which is what lets root find the invoking user's state directory.

## Configuration and Profile Trust

The config schema is strict and rejects unknown keys. It exposes only `tunnelMode`, `privacyMode`, `preventSleep`, `webAuthSession`, and `dnsBootstrapServers`. User configuration cannot select a profile, server, route, scoped DNS domain, scoped DNS server, or health-check endpoint.

Native event delivery bounds individual strings and queues at most 256 ordinary events or 8 MiB of payloads. Exceeding either limit produces one fatal event and triggers cleanup. Authentication and DNS metadata are never silently truncated to fit the queue.

Split mode uses a fixed CWRU policy:

- IPv4 routes: `129.22.0.0/16`, `192.5.109.0/24` through `192.5.113.0/24`
- IPv6 routes: `2606:ea00::/32`
- DNS domains: `case.edu`, `cwru.edu`
- Scoped DNS servers: `129.22.4.32`, `129.22.104.132`, `129.22.4.31`, `129.22.104.25`
- Data-path probes: `129.22.4.32` and `129.22.104.132` over TCP 53

The OpenVPN profile is read from `~/.cwru-ovpn/profile.ovpn`. `setup --profile`, which needs interactive `sudo`, records a root-owned SHA-256 digest at `/Library/PrivilegedHelperTools/cwru-ovpn/approved-profile.sha256`. Privileged `connect` hashes the profile and refuses to start unless it matches.

Profile policy is allow-list based. It rejects external certificate, key, and credential file references, management sockets, script and plugin hooks, route and redirect-gateway directives, logging, status, and writepid directives, unrecognized `setenv` names, and any option it does not know, all before OpenVPN starts. Certificates and keys are accepted only as inline blocks. Only autologin certificate profiles are supported; a profile that requires typed credentials is refused.

Server-pushed network policy is filtered at pull time in both modes: pushed `route`, `route-ipv6`, `redirect-gateway`, `redirect-private`, `block-ipv4`, and `block-ipv6` options are ignored. Split mode additionally sets `route-nopull` and ignores pushed `dns` and `dhcp-option`, so scoped DNS comes from the fixed policy rather than the server.

## Filesystem Protections

Profile, config, session, startup-status, resolver, and shell-integration reads are bounded and reject non-regular files, symlinks, and hardlinks. Authoritative session state and managed resolvers also enforce their required ownership and modes; shell-integration edits validate ownership and reject group- or world-writable files. Profile approval is enforced by its root-owned digest, while configuration follows the strict allowlisted schema. Startup reads the profile once, verifies the digest, and reuses that content for route preparation, so a later path change cannot swap the data underneath privileged setup.

Scoped resolver files carry a managed marker on their first line. Install refuses to overwrite, and cleanup refuses to delete, any `/etc/resolver` file without it, so resolver files a user wrote by hand are left alone. Managed files are written root-owned, mode `0644`, and replaced atomically.

Shell integration refuses to edit a shell configuration file that is group- or world-writable, and names the file plus the `chmod go-w` fix.

## Recovery State

The authoritative recovery ledger lives at `/var/db/cwru-ovpn/session.json` with root-only permissions. A copy under `~/.cwru-ovpn` exists for status and menu-bar display and is never trusted as a root recovery source. Writes are size-bounded and serialized with a lock shared by the controller and CLI processes, and an unreadable or malformed ledger blocks reconnecting or discarding state until it is repaired. The controller, stale-session recovery, cleanup watchdog, and installer also share an exclusive lifecycle lock. Recovery reloads the ledger after acquiring that lock, and a new controller cannot overwrite an existing recovery ledger.

The controller acquires the lifecycle lock before capturing the original network configuration. The watchdog retries temporary lock contention, and logging never waits for another process to release the event-log lock.

Session cleanup validates persisted state before restoring routes, DNS, IPv6 mode, or resolver files, so root cleanup never acts on arbitrary paths or malformed routes. Route cleanup records exact gateway and interface ownership, restores host routes it replaced, and does not delete an unrelated route merely because the destination matches.

A watchdog process, spawned at startup and pinned to the controller's PID, executable path, and start time, restores the pre-connection configuration if the controller exits unexpectedly. When it cannot, it marks the ledger as needing recovery and raises a critical alert pointing at `cwru-ovpn doctor`.

## Routing and DNS

Physical network handling follows the active macOS default route and network service rather than assuming Wi-Fi. The control-channel exception is an exact host route for the server address reported by the established OpenVPN connection. The pinned OpenVPN 3 patch keeps the tunnel across reconnects without generating bypass routes for cached alternate remotes; profile-resolved alternates, server-pushed routes, and generic excluded-route output are never trusted as physical-routing exceptions.

The same patch disables native DNS and proxy publication so reconnects cannot override application DNS policy after a mode switch. Both modes require a captured physical DNS service before startup. When physical-network migration is deferred, read-only route and DNS checks must still establish safety; otherwise the controller disconnects and cleans up.

The OpenVPN transport is forced to IPv4 with `protoVersionOverride=4`, because full tunnel may disable restorable physical-service IPv6 while securing the route table, and an IPv6 control channel would then cut its own transport.

### Full tunnel

- Verifies fail-closed IPv4 default coverage (`0.0.0.0/1` and `128.0.0.0/1`) through the VPN, and rejects more-specific physical public-unicast IPv4 routes. The only exceptions are exact host routes to the VPN server's control-channel address, the physical gateway's own host route, and the current directly attached subnet, which must be an exact match and no wider than `/16`.
- Installs scoped resolvers for `case.edu` and `cwru.edu` and points the physical service's default DNS at servers the current VPN session supplied, falling back to the fixed CWRU servers. Whichever set is used must be provably routed through the tunnel, or the full tunnel fails closed. Cleanup restores the captured DNS, or reverts the service to DHCP when the ledger was discarded.
- Preserves the captured service-level DNS and search-domain configuration while full tunnel manages the same service, including across gateway changes, so cleanup restores the user's settings and the managed override is never recorded as the original configuration. A physical-network change discards only the prior effective default search-domain snapshot.
- Disables restorable physical-service IPv6 and accepts public IPv6 only when it is routed through the VPN or blocked. Full tunnel refuses interfaces using CLAT or advertising a NAT64 prefix before applying its network policy, because a physical transit exception would weaken those guarantees. Manual and other physical IPv6 modes are rejected because they cannot be restored from the captured mode string.
- Treats Apple Private Relay, Limit IP Address Tracking, and other non-VPN tunnels carrying public IPv6 as unsafe unless managed reject routes block that traffic first.
- Leaves non-public, link-local, and multicast IPv4 routes under macOS control. Full tunnel is not a LAN-isolation firewall.

### Split tunnel

- Routes only the fixed CWRU IPv4 and IPv6 prefixes through the VPN, and skips the IPv6 route entirely on an IPv4-only tunnel.
- Rejects more-specific physical routes that override a protected CWRU prefix. The sole routing exception is the current server's exact, app-owned control-channel host route.
- Leaves non-CWRU public IPv6 on the physical network or another system-managed tunnel, and leaves physical-service IPv6 enabled. If public IPv6 is still routed over the CWRU tunnel after repair, the session fails closed.
- Ignores kernel-managed interface-scoped routes (link-local, multicast, broadcast, loopback) when auditing the tunnel for unexpected routes.
- Installs scoped resolver files only for the fixed CWRU domains and the reverse zones of the fixed CWRU routes.
- Restores physical DNS for the default resolver and fails closed if the default resolver still carries CWRU scoped DNS servers or VPN-added CWRU search domains. CWRU search domains already present before connecting count as physical-network baseline.
- Probes the two fixed CWRU DNS endpoints over TCP 53, so reachability reflects the CWRU data path rather than an unrelated public endpoint.

### Monitoring

A network path monitor schedules a health check after each path change. Health checks rewrite routes, DNS, or resolver files only where the applied state has drifted; a healthy check performs no network writes, so monitoring cannot feed back into the notifications that schedule it. A check that cannot re-establish its mode's guarantees stops the session and restores the previous configuration. When only the control channel is still settling right after a physical-network change, the monitor reconnects and retries a bounded number of times, with fail-closed IPv4 coverage held in place throughout.

### Mode switches

In-place switches keep CWRU routes that already use the active tunnel, prepare the target route set before removing superseded default coverage, replace retained scoped resolver files atomically, and drop obsolete resolver domains only once the target state is installed. Pending mode requests are serialized with controller state saves. Requesting the mode that is already active records it as the desired final state until the controller acknowledges the cancellation. Completion or rollback clears only the target it satisfied or consumed, so a newer queued target survives and is processed next.

### DNS bootstrap

`dnsBootstrapServers` is separate from split scoped DNS and stays off unless configured; the setup template configures public fallback resolvers so that filtering, captive, or sinkholing networks can still connect. Gateway resolution always tries the system resolver first, so a healthy connection discloses no hostname to the bootstrap servers.

Two situations send the client to them, and both ask only for the gateway hostname:

- At connect time, if every address the system resolver returns for the gateway is unusable (all-zero or loopback, the sinkhole signature), the client asks the bootstrap servers immediately and connects pinned to the answer rather than stalling on a dead address.
- If no control-channel handshake happens within a few seconds, which also covers stalls that are not DNS at all, it re-resolves through the bootstrap servers and reconnects pinned.

Reconnecting pinned fixes the tunnel transport but not the browser, which resolves the sign-in host through the system resolver. Before opening the sign-in window the client probes that host through the system resolver, and only when every answer is unusable does it install scoped `/etc/resolver` files for `openvpn.com` and `openvpn.net` pointing at the bootstrap servers. An empty, failed, or ambiguous answer is never read as a sinkhole, so a healthy or merely offline network is never written to. Those files carry the same managed marker as split-tunnel scoped resolvers, are removed when sign-in ends, and are reclaimed by every existing sweep, including the post-connect stale-resolver prune, session cleanup, uninstall, and a startup sweep, so an interrupted sign-in cannot leave them behind.

Outside that window the feature changes no system DNS configuration. Disclosure is bounded to the gateway hostname on a sinkholed or stalled connect, plus the OpenVPN namespace while a sinkholed network's sign-in window is open, and it never authorizes CWRU scoped DNS for non-CWRU traffic. The lookup runs `dig` only after the gateway hostname validates as a domain name, so profile content cannot inject `dig` options, and it runs with `HOME` pointed at an empty directory so a user-writable `~/.digrc` cannot steer the privileged lookup.

## Authentication

External web authentication accepts exactly one entry point: `https://cwru.openvpn.com` on the default HTTPS port. No other host, subdomain, port, or campus domain is accepted as a starting URL. Campus SSO hosts are reached by in-browser redirect during sign-in and are never handed to the client as an entry point.

Validation reads the serialized authority exactly as the browser will receive it, and requires it to be the allowed host alone or the allowed host with port 443. Any authority carrying userinfo or a percent-encoded host is rejected, including one that merely decodes to the allowed host.

Session modes:

- `systemShared` (default) uses a macOS authentication session that shares the default browser's cookie store, so an existing campus SSO session completes sign-in without a fresh credential prompt. Sign-in state the flow leaves behind lives in the browser's store rather than being discarded with the window. This mode overrides server requests marked `external`.
- `system` runs the same in-app session with an ephemeral cookie store destroyed when the window closes, at the cost of a full sign-in on every connect.
- `browser` hands the URL to the default browser, and only in non-privileged sessions. A privileged connect always forces a system authentication session, so the root process never launches the user-selected HTTPS handler.

Only `WEB_AUTH` is advertised and supported. The deprecated `OPEN_URL` method and interactive challenges are rejected, and their payloads are redacted rather than displayed.

An authentication page, its URL, and its cookies never establish VPN success. The client closes the system sign-in window when the VPN reports `ASSIGN_IP` or completes connection setup. During initial authentication, **Retry sign-in** explicitly replaces a pending request once, preserving the approved profile and network recovery baseline. There is no automatic retry for slow authentication, expired requests, cancellation, or server rejection. Each request uses the server-advertised timeout, capped at 900 seconds, or 300 seconds if no valid timeout is available; repeated pending events do not extend it. The launcher has a fixed upper bound covering both requests and connection setup. Events and callbacks from the replaced request cannot act on the new attempt.

## Logging

Privacy mode is on by default. Event records keep their timestamp, phase, event name, and error flags, while profile paths, state directory paths, VPN event detail, and free-form notes are replaced with placeholders.

With privacy mode off, records are sanitized rather than suppressed: URL user-info credentials, query strings, fragments, bearer and basic auth headers, session tokens, and password-, secret-, and token-like fields are redacted, as are web-auth payloads. The event log is size-bounded and compacts itself while retaining failure evidence.

## Known Limitations

- Full-tunnel DNS is routed through the VPN but is not an absolute boundary. Browsers using DNS-over-HTTPS and applications that resolve on their own bypass macOS resolvers entirely. Users who need split DNS behavior must turn off DoH for the relevant browser profile.
- macOS resolver behavior is not identical to `dig` or `curl`. `scutil --dns`, mDNSResponder caching, and per-application DNS can each resolve differently from scoped resolver files.
- Setting the physical service's DNS persists until cleanup, so an interrupted session is recovered by `disconnect` or `doctor`.
- Full tunnel is unavailable on detected CLAT/NAT64 networks; split mode retains physical IPv6 connectivity.
- The split-tunnel IPv6 route applies only when the tunnel receives an IPv6 address.
- Only the active default network service is managed. Multi-interface combinations, such as wired plus Wi-Fi plus Apple Private Relay, are not governed as a single global policy.
- Remote and transport ordering in the profile is preserved as written. The client does not reorder remotes, for example to prefer TCP 443.

## Remaining Risk

The OpenVPN 3 C++ core and its profile parser remain the highest-value attack surface, because they process profile and server-controlled data inside a privileged process. That process is not privilege-separated: the OpenVPN core, the menu-bar and web-authentication UI, and every route, DNS, and IPv6 mutation run together as root. A memory-safety bug anywhere in that surface is a root compromise.

Process-group timeout cleanup is bounded by operating-system permissions and signaling semantics. An unprivileged controller cannot guarantee `SIGKILL` delivery to a root descendant launched beneath `sudo`, and a descendant that escapes the group or forks concurrently with the final group signal can survive. When termination cannot be delivered, `Shell.run` can outlive its configured timeout while waiting for the direct child to exit, and a blocked stdin writer stays pending until every surviving reader closes. Production call sites invoke fixed leaf system tools rather than shells or fork loops.

Release builds depend on local OpenVPN 3, Asio, OpenSSL, LZ4, and fmt source snapshots, so third-party notices and dependency build metadata should be reviewed before publishing artifacts. Packaging requires a clean git tree and uses Developer ID signing when configured; the installer additionally requires an independently pinned publisher TeamIdentifier and fails closed until that trust root is set. Ad-hoc release signing and ad-hoc installs each require an explicit local-artifact override. `dist/build-info.json` records the app version, artifact hashes, deployment targets, and active macOS SDK version, and is never treated as its own publisher trust root.
