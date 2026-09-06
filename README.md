# cwru-ovpn

Native macOS client for Case Western Reserve University OpenVPN profiles, built on OpenVPN 3.

- Version: `0.11.0`
- Platforms: Apple Silicon on macOS 15 or later
- Modes: full tunnel, or a CWRU-only split tunnel
- Process model: one process per session, with no launch daemon and no login item

## Install

Download a `.ovpn` profile from `https://cwru.openvpn.com/`, then run setup as your normal user:

```bash
./scripts/setup.sh --allow-ad-hoc-release-artifact --profile /path/to/profile.ovpn
```

On a first install, if exactly one `.ovpn` file sits at the repository root, setup imports it without `--profile`:

```bash
./scripts/setup.sh --allow-ad-hoc-release-artifact
```

Setup uses `sudo` only for the privileged steps. It installs:

- Binary: `/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn`
- Config, profile, and logs: `~/.cwru-ovpn`
- Shell shortcuts: your `zsh` or `bash` rc file

The client accepts autologin certificate profiles, which is what the CWRU portal issues. A profile that asks for a typed username and password is rejected before the tunnel starts.

The included release artifacts are ad-hoc signed and require `--allow-ad-hoc-release-artifact`. A local developer build requires `--allow-local-build-install` instead. See [`SECURITY.md`](SECURITY.md) for how artifacts are verified.

Disconnect before upgrading. Setup refuses to replace the installed binary unless `status` reports `Disconnected`.

## Use

| Shortcut | Action |
| --- | --- |
| `ovpn` | Connect using the default mode from `config.json` |
| `ovpnfull` | Connect or switch to full tunnel |
| `ovpnsplit` | Connect or switch to split tunnel |
| `ovpnstatus` | Print status |
| `ovpnd` | Disconnect |

While a session is up, a menu bar item shows status, mode, gateway, and an estimated session countdown, and offers the same mode switch and disconnect.

If the sign-in page reaches the configuration portal but the VPN still says sign-in is required, choose **Retry sign-in** from the menu bar. This starts one fresh authentication request and may reuse the browser's existing SSO session. Waiting alone never triggers a retry. The client honors the server's authentication timeout up to 15 minutes, using five minutes when no valid timeout is supplied; closing the sign-in window still cancels the connection.

Mode switches reuse the active tunnel and are make-before-break: new routes and scoped resolvers go in before the old ones come out. A switch requested mid-reconnect applies once the tunnel returns, and a newer request replaces a pending one.

Read-only checks do not need `sudo`:

```bash
/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn status
/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn logs --tail 100
/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn doctor
```

Foreground debug:

```bash
sudo /Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn connect --config ~/.cwru-ovpn/config.json --verbosity debug --foreground
```

Event logs default to privacy mode, which stores the timestamp, phase, and event name but replaces profile paths, VPN event detail, and free-form notes with placeholders. Treat logs as sensitive when `"privacyMode": false`.

The binary takes `connect`, `disconnect`, `status`, `logs`, `doctor`, `setup`, `uninstall`, `version`, and `help`. Setup and uninstall require interactive `sudo`.

## Config

Default config: `~/.cwru-ovpn/config.json`

Template: [`examples/cwru-ovpn.config.example.json`](examples/cwru-ovpn.config.example.json)

Every key is optional, and any key outside this table is rejected:

| Key | Description |
| --- | --- |
| `tunnelMode` | `split` (default) or `full` |
| `privacyMode` | Redact sensitive details from logs; default `true` |
| `preventSleep` | Keep the Mac awake while connected; default `true` |
| `webAuthSession` | `systemShared` (default), `system` (ephemeral), or `browser` |
| `dnsBootstrapServers` | Fallback resolvers, used only when the network's DNS is sinkholed or a connect stalls |

The default `systemShared` session and the non-privileged `browser` session share browser sign-in state, so a live campus SSO session usually gets you in without retyping credentials or approving another push. Privileged connects always use a system authentication session, so the root process never launches the default HTTPS handler. `system` opens the same window with an ephemeral cookie jar: it keeps nothing, at the cost of a full sign-in every time. Use it, or Safari Private Browsing, if a regular Safari profile shows a blank sign-in page.

Split mode follows a fixed, non-configurable CWRU policy: routes `129.22.0.0/16`, `192.5.109.0/24` through `192.5.113.0/24`, and `2606:ea00::/32`; scoped domains `case.edu` and `cwru.edu`; DNS servers `129.22.4.32`, `129.22.104.132`, `129.22.4.31`, and `129.22.104.25`. Data-path checks use the first two over TCP 53. The IPv6 route applies only when the tunnel provides IPv6.

`dnsBootstrapServers` is empty by default, and the setup template fills it in so that networks which sinkhole DNS can still reach the gateway. The client asks these servers for the gateway hostname only, and only when the system resolver returns a blocked address or a connect stalls. Such networks usually block the sign-in page too, so scoped `/etc/resolver` files for `openvpn.com` and `openvpn.net` point at these servers for the duration of the sign-in window. That is the one case where the client changes system DNS outside a tunnel mode's own policy. An empty list disables both behaviors; see [`SECURITY.md`](SECURITY.md).

Full mode routes IPv4 through the VPN, uses DNS learned from the current VPN session with the fixed CWRU servers as fallback, and blocks public IPv6. It refuses physical interfaces with CLAT or a detected NAT64 prefix because it cannot enforce the same full-tunnel guarantees on those networks; use split mode there.

## Limitations

- Only the active default network service is managed. Multi-interface setups, such as wired plus Wi-Fi plus Apple Private Relay, are not governed as one policy.
- Browsers using DNS-over-HTTPS resolve outside macOS resolvers, so scoped resolver files do not reach them.
- Full tunnel is not a LAN-isolation firewall. Private, link-local, and multicast IPv4 routes stay under macOS control.
- Remote and transport selection belongs to the profile. The client preserves the order it finds and does not reorder remotes.

[`SECURITY.md`](SECURITY.md) covers the full security model, including routing, DNS, and recovery behavior.

## Build

Prerequisites, with the OpenVPN 3 and Asio checkouts next to this repository:

```bash
brew install openssl@4 lz4 fmt
git clone https://github.com/OpenVPN/openvpn3 ../openvpn3
git -C ../openvpn3 checkout 7f572f4fe647a36f5a1094cbeb261a5bcdae5047
git -C ../openvpn3 apply "$PWD/scripts/patches/openvpn3-cwru-policy.patch"
git clone https://github.com/chriskohlhoff/asio ../asio
git -C ../asio checkout 8806a6803cde7054c3049d3666d3ec36786568c5
```

`OPENVPN3_DIR` and `ASIO_DIR` point the build at checkouts kept elsewhere. An `openvpn3` checkout inside this repository takes precedence over a sibling checkout. Apply the single project policy patch to the pinned upstream revision; it fixes utun allocation and disables native DNS, proxy, and remote bypass actions. The application manages DNS and the control-channel host route; proxy configuration is unsupported.

Validation and release build:

```bash
./scripts/test.sh
brew fetch --build-from-source lz4 fmt
./scripts/build-release-binaries.sh
```

Release builds require both checkouts to contain the pinned commits, compile from archives of exactly those commits, and record the commits in `dist/build-info.json`.

Other overrides: `HOMEBREW_PREFIX`, `OPENSSL_PREFIX`, `LZ4_PREFIX`, and `FMT_PREFIX`.

Development builds may use Homebrew dynamic libraries. Passwordless installation requires statically linked third-party libraries; `scripts/setup.sh --allow-local-build-install` builds and verifies those dependencies before compiling the local executable.

The release script requires a clean git tree, builds macOS 15, 26, and 27 artifacts, and writes `dist/SHA256SUMS` alongside `dist/build-info.json`. Set `CWRU_OVPN_CODESIGN_IDENTITY` for Developer ID signing, or `CWRU_OVPN_ALLOW_ADHOC_RELEASE=1` for ad-hoc artifacts. Developer ID installs also need the publisher TeamIdentifier pinned in `scripts/setup.sh`; see [`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE), [`SECURITY.md`](SECURITY.md), and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

This is an unofficial community tool, not affiliated with or endorsed by Case Western Reserve University. Use is subject to the CWRU Acceptable Use Policy.
