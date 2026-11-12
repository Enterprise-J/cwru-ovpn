# cwru-ovpn

Native macOS OpenVPN client for Case Western Reserve University profiles, built on OpenVPN 3. Version `1.0.0`, Apple Silicon, macOS 15 or later.

A session is one controller process plus its cleanup watchdog; there is no launch daemon and no login item. Two modes: full tunnel, or a CWRU-only split tunnel.

## Install

Download a `.ovpn` profile from `https://cwru.openvpn.com/`, then run setup as your normal user:

```bash
./scripts/setup.sh --allow-ad-hoc-release-artifact --profile /path/to/profile.ovpn
```

With exactly one `.ovpn` file at the repository root, `--profile` can be omitted. Setup uses `sudo` only for the privileged steps and installs:

- App: `/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn.app`
- Binary: `/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn.app/Contents/MacOS/cwru-ovpn`
- Config, profile, and logs: `~/.cwru-ovpn`
- Shell shortcuts: your `zsh` or `bash` rc file

Only autologin certificate profiles, which is what the CWRU portal issues, are accepted. Setup uses a signed `.app.tar.gz` for the host macOS version. Ad-hoc artifacts require `--allow-ad-hoc-release-artifact`; local builds require `--allow-local-build-install`. Disconnect before upgrading. [`SECURITY.md`](SECURITY.md) describes how artifacts are verified.

To uninstall and remove `~/.cwru-ovpn`:

```bash
sudo /Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn.app/Contents/MacOS/cwru-ovpn uninstall --purge
```

## Use

| Shortcut | Action |
| --- | --- |
| `ovpn` | Connect in the configured mode |
| `ovpnfull` | Connect or switch to full tunnel |
| `ovpnsplit` | Connect or switch to split tunnel |
| `ovpnstatus` | Print status |
| `ovpnd` | Disconnect |

A menu bar item shows status, mode, gateway, and an estimated session countdown, and offers the same mode switch and disconnect. If the sign-in page completes but the VPN still reports sign-in required, choose **Retry sign-in** there. Closing the sign-in window cancels the connection.

Mode changes requested while the tunnel or physical network is recovering stay queued and apply when the connection is ready. A switch that is still being applied when the command returns is reported as in progress; `ovpnstatus` shows the result. Requesting the current mode cancels the queued change; disconnecting cancels recovery and any queued mode change.

`status`, `logs --tail N`, and `doctor` need no `sudo`. Foreground debugging:

```bash
sudo /Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn.app/Contents/MacOS/cwru-ovpn connect --verbosity debug --foreground
```

Event logs default to privacy mode, which keeps timestamps, phases, and event names but replaces details with placeholders.

Reconnect requests use the active session's configuration. To select a different config file, disconnect first. `disconnect` returns a nonzero exit status if cleanup cannot be confirmed. `disconnect --force` can discard a stale recovery ledger after cleanup fails; its completion does not establish that the network is healthy.

## Config

`~/.cwru-ovpn/config.json`, created from [`examples/cwru-ovpn.config.example.json`](examples/cwru-ovpn.config.example.json) on first install. Every key is optional; unknown keys are rejected.

| Key | Description |
| --- | --- |
| `tunnelMode` | `split` (default) or `full` |
| `privacyMode` | Redact details from logs; default `true` |
| `preventSleep` | Keep the Mac awake while connected; default `true` |
| `webAuthSession` | `systemShared` (default) reuses the browser's SSO state; `system` signs in with an ephemeral cookie jar |
| `dnsBootstrapServers` | Resolvers used only when the network's DNS sinkholes the gateway or a connect stalls; empty disables them |

Split mode routes only the fixed CWRU prefixes and scopes `case.edu` and `cwru.edu` to CWRU DNS; all other traffic except the connection to the VPN server keeps the Mac's own routes. Full mode routes IPv4 through the VPN, uses the VPN's DNS, and keeps public IPv6 on the VPN or blocks it; it refuses CLAT and NAT64 networks. DNS queries can escape the tunnel during network recovery or shutdown. Routing, DNS, authentication, recovery, and known limitations are specified in [`SECURITY.md`](SECURITY.md).

## Build

```bash
brew install openssl@4 lz4 fmt
git clone https://github.com/OpenVPN/openvpn3 ../openvpn3
git -C ../openvpn3 checkout 7f572f4fe647a36f5a1094cbeb261a5bcdae5047
git -C ../openvpn3 apply "$PWD/scripts/patches/openvpn3-cwru-policy.patch"
git clone https://github.com/chriskohlhoff/asio ../asio
git -C ../asio checkout 8806a6803cde7054c3049d3666d3ec36786568c5
./scripts/test.sh
```

Local installs and release packaging also require CMake (`brew install cmake`) and link checksum-pinned dependencies statically. See [dependency build options](THIRD_PARTY_NOTICES.md#build-overrides) and the [release trust model](SECURITY.md#remaining-risk). Package release artifacts with `./scripts/build-release-binaries.sh`.

## License

MIT. See [`LICENSE`](LICENSE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

This is an unofficial community tool, not affiliated with or endorsed by Case Western Reserve University. Use is subject to the CWRU Acceptable Use Policy.
