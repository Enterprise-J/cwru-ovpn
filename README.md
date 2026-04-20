# cwru-ovpn

A native macOS client for Case Western Reserve University OpenVPN profiles, built on the OpenVPN 3 core.

- **Version:** 0.2.0
- **Requires:** macOS 14 or later

## Features

- Browser-based authentication against OpenVPN CloudConnexa and CWRU SSO.
- Full-tunnel and split-tunnel modes, switchable in place without restarting the session.
- Scoped DNS resolvers and IPv6 leak prevention in split-tunnel mode.
- Lightweight implementation, no launch daemons or login items.

## Installation

1. Sign in at `https://cwru.openvpn.com/` and download a `.ovpn` profile.
2. Place a single profile at the repository root so `./scripts/setup.sh` can import it automatically, or pass it explicitly with `--profile /path/to/profile.ovpn`.
3. Run the installer:

   ```bash
   ./scripts/setup.sh
   ```

`setup.sh` installs shell shortcuts into the current user's `zsh` or `bash` rc file, and `uninstall` removes that managed block automatically.

`./scripts/setup.sh` installs the matching prebuilt binary from `dist/cwru-ovpn-macos<major>` for the current Mac. If that artifact is missing, it falls back to a local `swift build -c release` on the current machine.

## Usage

These shell helpers are installed by `setup.sh` and wrap the passwordless `sudo` commands configured by `setup`.

| Command | Action |
| --- | --- |
| `ovpn` | Connect in the default mode configured in `config.json` |
| `ovpnfull` \| `ovpnsplit` | Connect in full- or split-tunnel mode, or switch mode in place |
| `ovpnstatus` | Print the current connection status |
| `ovpnd` | Disconnect the current session |

## Advanced

Use the binary directly for foreground operation, debug logging, explicit config files, or profile imports. The shell helpers above are thin wrappers around the same command surface.

For commands that change VPN or install state:

```bash
sudo ~/.cwru-ovpn/bin/cwru-ovpn [command] [options]
```

Read-only commands such as `status`, `logs`, `doctor`, `version`, and `help` can also be run directly without `sudo`.

Commands:

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

`connect` options:

| Parameter | Purpose |
| --- | --- |
| `--config PATH` | Use a specific config JSON file |
| `--verbosity silent\|daily\|debug` | Override the configured log level |
| `--mode full\|split` | Override the configured tunnel mode |
| `--allow-sleep` | Allow the Mac to idle sleep |
| `--foreground` | Keep the controller attached to the terminal |

Other command options:

| Parameter | Purpose |
| --- | --- |
| `disconnect --force` | Drop stale state even if cleanup still reports the network as unhealthy; `ovpnd` intentionally does not forward this flag |
| `logs --tail COUNT` | Show the last `COUNT` event log entries; defaults to `40` |
| `setup --profile PATH` | Copy a profile to `~/.cwru-ovpn/profile.ovpn` before installing sudoers |
| `uninstall --purge` | Also remove `~/.cwru-ovpn` after uninstalling shell integration |

When using passwordless `sudo` installed by `setup`, keep argument order in the canonical form shown here.

Foreground debug example:

```bash
sudo ~/.cwru-ovpn/bin/cwru-ovpn connect --config ~/.cwru-ovpn/config.json --verbosity debug --foreground
tail -n 100 ~/.cwru-ovpn/events.ndjson
```
Note: `events.ndjson` may contain connection metadata and should be treated as sensitive.

For a concise troubleshooting snapshot:

```bash
~/.cwru-ovpn/bin/cwru-ovpn doctor
~/.cwru-ovpn/bin/cwru-ovpn logs --tail 60
```

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

Install dependencies:

```bash
brew install openssl@3 lz4 fmt
```

Clone the repositories under `~`:

```bash
git clone https://github.com/OpenVPN/openvpn3 ~/openvpn3
git clone https://github.com/chriskohlhoff/asio ~/asio
git clone https://github.com/Enterprise-J/cwru-ovpn.git ~/cwru-ovpn
cd ~/cwru-ovpn
```

Override locations if needed:

```bash
export OPENVPN3_DIR=~/openvpn3
export ASIO_DIR=~/asio
# Optional: allow legacy or non-preferred OpenVPN data-channel algorithms
export CWRU_OVPN_ENABLE_LEGACY_ALGORITHMS=1
export CWRU_OVPN_ENABLE_NON_PREFERRED_DC_ALGORITHMS=1
```

Build from the repository root:

```bash
swift build --disable-sandbox                  # debug
swift build -c release --disable-sandbox       # release
```

Local `swift build` links against the Homebrew-installed dynamic libraries on the current Mac.

To produce versioned release binaries and `dist/SHA256SUMS` for distribution:

```bash
./scripts/build-release-binaries.sh
```

If the source archives are missing, fetch them once with:

```bash
brew fetch --build-from-source openssl@3 lz4 fmt
```

Run the repository's validation workflow:

```bash
./scripts/test.sh
```

## License

This repository is distributed under the MIT License; see [`LICENSE`](LICENSE). Third-party dependency references are documented in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

---

**Disclaimer:** This is an unofficial community tool and is not affiliated with or endorsed by Case Western Reserve University. Use is subject to the CWRU Acceptable Use Policy.
