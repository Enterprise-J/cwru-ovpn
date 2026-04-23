# cwru-ovpn

Native macOS client for Case Western Reserve University OpenVPN profiles, built on OpenVPN 3.

- **Version:** 0.4.0
- **Last Updated:** 2026-04-23
- **Requires:** Apple Silicon Macs with macOS 14 or later

## Features

- Browser-based authentication against OpenVPN CloudConnexa and CWRU SSO.
- Full- and split-tunnel modes, switchable in place without dropping the session.
- Scoped split-tunnel DNS, with IPv6 leak protection for split- and full-tunnel modes.
- Lightweight implementation. No launch daemons, no login items.

## Installation

For Intel Macs, see [Build](#build).

1. Sign in at `https://cwru.openvpn.com/` and download a `.ovpn` profile.
2. Put a single profile at the repository root so `./scripts/setup.sh` can import it automatically, or pass `--profile /path/to/profile.ovpn`.
3. Run as your normal user:

   ```bash
   ./scripts/setup.sh
   ```

`setup.sh` uses `sudo` only for the privileged install steps. It installs the binary at `/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn`, writes the shell helper to `~/.cwru-ovpn/cwru-ovpn.zsh`, and updates the current user's `zsh` or `bash` rc file.

## Usage

| Command | Action |
| --- | --- |
| `ovpn` | Connect in the default mode configured in `config.json` |
| `ovpnfull` \| `ovpnsplit` | Connect in full- or split-tunnel mode, or switch mode in place |
| `ovpnstatus` | Print the current connection status |
| `ovpnd` | Disconnect the current session |

By default, `cwru-ovpn` tries to prevent idle sleep while connected. Pass `--allow-sleep`, or set `allowSleep` to `true` in `config.json`, to let the Mac idle sleep instead.

## Advanced

Use the installed binary directly for foreground mode, debug logging, explicit config files, or profile imports. The command comes immediately after the binary, and options belong to that command; there are no global options.

```bash
sudo /Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn <command> [that-command's-options]
```

| Command | Purpose |
| --- | --- |
| `connect` | Connect using the default mode from `config.json` |
| `disconnect` | Disconnect the current session |
| `status` | Print the current connection status |
| `logs` | Print recent event log entries |
| `doctor` | Print diagnostic information about config, session state, and resolver files |
| `setup` | Install sudoers rules for passwordless operation |
| `uninstall` | Remove the sudoers rule, shell shortcuts, and scoped resolver files |
| `version` | Print the version number |
| `help` | Show the built-in help text |

| Command | Option | Purpose |
| --- | --- |
| `connect` | `--config PATH` | Use a specific config JSON file |
| `connect` | `--verbosity silent\|daily\|debug` | Override the configured log level |
| `connect` | `--mode full\|split` | Override the configured tunnel mode; `--tunnel-mode` is also accepted |
| `connect` | `--allow-sleep` | Allow the Mac to idle sleep for this run |
| `connect` | `--foreground` | Keep the controller attached to the terminal |
| `disconnect` | `--force` or `-f` | Drop stale state even if cleanup still reports the network as unhealthy; `ovpnd` intentionally does not forward this flag |
| `logs` | `--tail COUNT` | Show the last `COUNT` event log entries; defaults to `40` |
| `setup` | `--profile PATH` | Copy a profile to `~/.cwru-ovpn/profile.ovpn` before installing sudoers |
| `uninstall` | `--purge` | Also remove `~/.cwru-ovpn` after uninstalling shell integration |

Read-only commands such as `status`, `logs`, `doctor`, `version`, and `help` can run without `sudo`.

Passwordless `sudo` is order-sensitive. It covers `connect`, `connect --mode full`, `connect --mode split`, those same forms with `--verbosity debug` or `--verbosity debug --foreground`, and any of those forms with trailing `--allow-sleep`. It also covers `disconnect`, `disconnect -f`, `disconnect --force`, and plain `setup`. `connect --config PATH ...`, `connect --foreground` without `--verbosity debug`, and non-canonical argument orders may still prompt for an admin password.

Foreground debug:

```bash
sudo /Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn connect --config ~/.cwru-ovpn/config.json --verbosity debug --foreground
tail -n 100 ~/.cwru-ovpn/events.ndjson
```

`events.ndjson` may contain connection metadata; treat it as sensitive.

Troubleshooting:

```bash
/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn doctor
/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn logs --tail 100
```

`doctor` lists live `utun*` interfaces, which can help explain interrupted cleanup.

## Configuration

The config file lives at `~/.cwru-ovpn/config.json`. A template is provided at [`examples/cwru-ovpn.config.example.json`](examples/cwru-ovpn.config.example.json).

| Key | Description |
| --- | --- |
| `profilePath` | Default `.ovpn` profile path |
| `tunnelMode` | Default mode (`full` or `split`) |
| `allowSleep` | `true` to allow idle sleep while connected; defaults to `false` |
| `verbosity` | `silent`, `daily`, or `debug` |
| `splitTunnel.includedRoutes` | IPv4 CIDR blocks routed through the VPN |
| `splitTunnel.reachabilityProbeHosts` | Public IPs or hostnames probed during health checks; omit for defaults, `[]` to disable |
| `splitTunnel.resolverDomains` | Domains written to `/etc/resolver`; reverse (`in-addr.arpa`) zones for `includedRoutes` are added automatically |
| `splitTunnel.resolverNameServers` | Fallback DNS servers for scoped resolver files |

## Build

### Prerequisites

```bash
brew install openssl@3 lz4 fmt
git clone https://github.com/OpenVPN/openvpn3 ~/openvpn3
git clone https://github.com/chriskohlhoff/asio ~/asio
git clone https://github.com/Enterprise-J/cwru-ovpn.git ~/cwru-ovpn
cd ~/cwru-ovpn
```

If you plan to run `./scripts/build-release-binaries.sh`, fetch the source archives once:

```bash
brew fetch --build-from-source openssl@3 lz4 fmt
```

### Path Overrides

```bash
export OPENVPN3_DIR=/path/to/openvpn3
export ASIO_DIR=/path/to/asio
export HOMEBREW_PREFIX=/opt/homebrew
export OPENSSL_PREFIX=/opt/homebrew/opt/openssl@3
export LZ4_PREFIX=/opt/homebrew/opt/lz4
export FMT_PREFIX=/opt/homebrew/opt/fmt
```

Optional build knobs:

```bash
export CWRU_OVPN_ENABLE_LEGACY_ALGORITHMS=1
export CWRU_OVPN_ENABLE_NON_PREFERRED_DC_ALGORITHMS=1
export CWRU_OVPN_CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
```

### Common Builds

```bash
swift build --disable-sandbox
swift build -c release --disable-sandbox
./scripts/test.sh
```

`swift build` targets the current macOS major version and links against Homebrew dynamic libraries. Override it with `CWRU_OVPN_MACOS_DEPLOYMENT_TARGET`.

Intel is not a supported install target. If you build on Intel anyway, only the local `./.build/release/cwru-ovpn` output exists.

### Release Artifacts

```bash
./scripts/build-release-binaries.sh
```

Run that script from a native Apple Silicon shell. It rebuilds target-specific static OpenSSL, LZ4, and fmt libraries under `.build/third-party`, emits `dist/cwru-ovpn-macos<major>-arm64`, updates `dist/SHA256SUMS`, and signs the binaries if `CWRU_OVPN_CODESIGN_IDENTITY` is set.

### Which Output `setup.sh` Uses

- Apple Silicon: `setup.sh` installs `dist/cwru-ovpn-macos<major>-arm64` when it is present and passes host, checksum, and signature checks. Otherwise it falls back to `./.build/release/cwru-ovpn`.
- Unsupported hosts: `setup.sh` uses `./.build/release/cwru-ovpn` only.

## License

This repository is distributed under the MIT License; see [`LICENSE`](LICENSE). Third-party dependency references are documented in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

---

**Disclaimer:** This is an unofficial community tool and is not affiliated with or endorsed by Case Western Reserve University. Use is subject to the CWRU Acceptable Use Policy.
