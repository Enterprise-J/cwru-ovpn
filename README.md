# cwru-ovpn

Native macOS client for Case Western Reserve University OpenVPN profiles, built on OpenVPN 3.

- Version: `0.4.2`
- Requires: Apple Silicon and macOS 14 or later for prebuilt installs
- Modes: full tunnel and split tunnel, switchable while connected
- Scope: no launch daemon and no login item

## Install

1. Download a `.ovpn` profile from `https://cwru.openvpn.com/`.
2. Run setup as your normal user:

   ```bash
   ./scripts/setup.sh --profile /path/to/profile.ovpn
   ```

   If exactly one `.ovpn` file is at the repository root, setup imports it automatically:

   ```bash
   ./scripts/setup.sh
   ```

The script uses `sudo` only for privileged install steps. It installs:

- Binary: `/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn`
- Config/profile/logs: `~/.cwru-ovpn`
- Shell shortcuts: current user's `zsh` or `bash` rc file

Prebuilt installs are Apple Silicon only. Intel Macs must run a local release build before setup.

## Use

| Shortcut | Action |
| --- | --- |
| `ovpn` | Connect using the default mode from `config.json` |
| `ovpnfull` | Connect or switch to full tunnel |
| `ovpnsplit` | Connect or switch to split tunnel |
| `ovpnstatus` | Print status |
| `ovpnd` | Disconnect |

By default, the client prevents system sleep while connected, including on battery. Use `connect --allow-sleep` or set `"preventSleep": false` to allow sleep.

Read-only commands can run without `sudo`:

```bash
/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn status
/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn logs --tail 100
/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn doctor
```

For foreground debug:

```bash
sudo /Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn connect --config ~/.cwru-ovpn/config.json --verbosity debug --foreground
```

`events.ndjson` may include connection metadata. Treat it as sensitive.

## Commands

```bash
sudo /Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn <command> [options]
```

| Command | Purpose |
| --- | --- |
| `connect` | Connect using config defaults |
| `disconnect` | Disconnect; add `--force` only to drop stuck recovery state |
| `status` | Print status |
| `logs` | Print recent events; `--tail COUNT` defaults to `40` |
| `doctor` | Print config, session, resolver, and live `utun*` diagnostics |
| `setup` | Install sudoers rules; `--profile PATH` imports a profile |
| `uninstall` | Remove sudoers, shell shortcuts, and resolver files; `--purge` also removes `~/.cwru-ovpn` |
| `version` | Print version |
| `help` | Print built-in help |

`connect` accepts `--config PATH`, `--verbosity silent|daily|debug`, `--mode full|split` (`--tunnel-mode` also works), `--allow-sleep`, and `--foreground`.

Passwordless `sudo` is intentionally narrow and order-sensitive. It covers canonical `connect`, `connect --mode full|split`, the same forms with `--verbosity debug`, optional debug `--foreground`, optional trailing `--allow-sleep`, `disconnect`, `disconnect -f`, `disconnect --force`, and plain `setup`.

## Config

The default config is `~/.cwru-ovpn/config.json`. A template lives at [`examples/cwru-ovpn.config.example.json`](examples/cwru-ovpn.config.example.json).

| Key | Meaning |
| --- | --- |
| `profilePath` | `.ovpn` profile path |
| `tunnelMode` | `split` or `full` |
| `preventSleep` | `true` by default |
| `verbosity` | `silent`, `daily`, or `debug` |
| `splitTunnel.includedRoutes` | IPv4 CIDRs routed through VPN |
| `splitTunnel.resolverDomains` | Domains written to scoped `/etc/resolver` files |
| `splitTunnel.resolverNameServers` | Fallback scoped DNS servers |
| `splitTunnel.reachabilityProbeHosts` | Optional health-check hosts; `[]` disables probes |

Reverse DNS zones for included routes are derived automatically.

## Build

Prerequisites:

```bash
brew install openssl@3 lz4 fmt
git clone https://github.com/OpenVPN/openvpn3 ~/openvpn3
git clone https://github.com/chriskohlhoff/asio ~/asio
```

Local validation:

```bash
swift build --disable-sandbox
swift build -c release --disable-sandbox
./scripts/test.sh
```

Path overrides:

```bash
export OPENVPN3_DIR=/path/to/openvpn3
export ASIO_DIR=/path/to/asio
export HOMEBREW_PREFIX=/opt/homebrew
export OPENSSL_PREFIX=/opt/homebrew/opt/openssl@3
export LZ4_PREFIX=/opt/homebrew/opt/lz4
export FMT_PREFIX=/opt/homebrew/opt/fmt
```

Release artifacts require cached Homebrew source archives:

```bash
brew fetch --build-from-source openssl@3 lz4 fmt
./scripts/build-release-binaries.sh
```

Release artifacts are Apple Silicon only. The release script writes `dist/cwru-ovpn-macos<major>-arm64`, updates `dist/SHA256SUMS`, and signs binaries when `CWRU_OVPN_CODESIGN_IDENTITY` is set.

On Apple Silicon, `setup.sh` installs a matching verified `dist` binary. If it is missing or wrong-architecture, setup falls back to a local release build.

## License

MIT. See [`LICENSE`](LICENSE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

This is an unofficial community tool and is not affiliated with or endorsed by Case Western Reserve University. Use is subject to the CWRU Acceptable Use Policy.
