# Security

## Trust and Privileges

Setup selects the packaged `arm64` app for the host’s macOS major version from `dist/ad-hoc`. It verifies the checksum, release manifest, archive contents, executable architecture, and ad-hoc signature before requesting administrator access. The root-owned bundle in `/Library/PrivilegedHelperTools/cwru-ovpn` uses the hardened runtime, has no entitlements, and loads only system libraries. The signature verifies integrity. Publisher trust depends on where the release was obtained. To build from reviewed source, run `./scripts/setup.sh --build`.

No launch daemon or login item is installed. Sessions pair a root controller and cleanup watchdog with a user-session helper over a private socket. Sudoers is pinned to one numeric user ID and binary digest for `connect`, `connect --mode full`, `connect --mode split`, `disconnect`, and `disconnect --force`, while `setup` and `uninstall` require administrative authentication. Running setup from another account replaces the machine-wide sudoers rule and the approved profile digest.

## Profile and Execution

Setup parses an inline autologin certificate profile as root against an allowlist, rejecting unrecognized directives, hooks, plugins, and external key or credential files. Connect hashes `~/.cwru-ovpn/profile.ovpn` against `approved-profile.sha256` before the core parses it. Users can configure bootstrap DNS servers. The approved profile and campus routing and DNS rules are fixed. Anchored file operations verify ownership and type without following symlinks. The Swift command runner limits output and applies deadlines. A child process can outlast its deadline. OpenVPN 3 invokes `ifconfig` and `route` as root outside those limits.

## Routing and DNS

Both modes manage one physical network service and one verified host route to the VPN gateway, with no persistent kill switch or LAN isolation. Split mode tunnels `129.22.0.0/16` and `192.5.109.0/24` through `192.5.113.0/24`, adds `2606:ea00::/32` when tunnel IPv6 exists, directs `case.edu`, `cwru.edu`, and campus reverse zones to campus DNS, and preserves the physical service’s DNS and IPv6 settings in a split-only session.

Full mode verifies IPv4 half-default and overriding public routes, allowing physical route exclusions only for the peer host, local gateway host, and the directly attached subnet when `/16` or narrower. It tunnels or blocks public IPv6, refuses CLAT or NAT64 networks, applies VPN or campus fallback DNS to the physical service, and records the original settings for restoration. Route checks do not guarantee packet-level DNS confidentiality. During link recovery or shutdown, macOS can send cached or in-flight VPN DNS over the physical interface despite full-tunnel routes, exposing names, types, and timing. Custom resolvers or DNS-over-HTTPS bypass system DNS, and crashes or failed withdrawal can leave stale VPN resolvers.

## Sign-In and Bootstrap DNS

`WEB_AUTH` sign-in must start at `https://cwru.openvpn.com` on port 443. User information and encoded hostnames in the URL are rejected. Campus SSO redirects run in the system sign-in window. The default `systemShared` setting reuses browser sign-in state, and `system` requests an ephemeral session. Closing the window cancels the attempt. A pending attempt can be retried once.

Optional bootstrap DNS servers can see the gateway hostname when local DNS returns only loopback or all-zero addresses, or when a handshake stalls. If the sign-in host also resolves only to unusable addresses, temporary resolver settings can send `openvpn.com` and `openvpn.net` queries to those servers.

## Recovery and Diagnostics

During a session, the root controller saves the routes, DNS settings, and IPv6 settings it changes in `/private/var/db/cwru-ovpn/session.json`. A separate user-readable copy supports diagnostics. On disconnect, the controller withdraws VPN DNS before closing the tunnel. If withdrawal fails, it still attempts to restore networking. The watchdog attempts recovery if the controller exits unexpectedly. Cleanup preserves independent settings and removes resolver files marked as belonging to the app.

If restoration cannot be confirmed, the saved settings remain available. Retry with `ovpnd`. During stale-session recovery, `sudo "$CWRU_OVPN_BIN" disconnect --force` can renew DHCP. A mode change requested during recovery can remain pending after the command times out. Restored IPv6 settings can take time to become reachable.

Read-only `ovpnstatus` and `"$CWRU_OVPN_BIN" doctor` show saved session information and can inspect live routes and DNS on a connected session. `"$CWRU_OVPN_BIN" logs` shows local events. Privacy mode hides free-form details by default, while credential filtering strips passwords, keys, tokens, cookies, authentication headers, and web sign-in payloads even when `privacyMode` is `false`.
