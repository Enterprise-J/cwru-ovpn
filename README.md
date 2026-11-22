# cwru-ovpn

`cwru-ovpn` 1.1.0 is an unofficial OpenVPN 3 client for Case Western Reserve University on Apple Silicon Macs (macOS 15, 26, or 27). Campus network use follows the CWRU Acceptable Use Policy.

## Installation

Download and extract a trusted copy of this repository, or open an existing checkout. Download an autologin certificate profile from the [CWRU OpenVPN portal](https://cwru.openvpn.com/), then run setup from the project root as your login user.

```bash
./scripts/setup.sh --profile /path/to/profile.ovpn
```

Setup installs the prebuilt app for the Mac’s operating system. The three [release archives](dist/ad-hoc/) are Release-optimized, ad-hoc-signed development builds for Apple Silicon with minimum macOS versions of 15, 26, and 27. Setup verifies the package before requesting administrator access. To check all published digests, run `(cd dist/ad-hoc && shasum -a 256 -c SHA256SUMS)`.

To upgrade, run `ovpnd` and rerun `./scripts/setup.sh` from the new copy to reuse your profile.

## Usage

Open a new `zsh` or `bash` shell after installation to load `CWRU_OVPN_BIN` and five shortcuts, then run `ovpn` and complete browser sign-in.

- `ovpn` connects using `tunnelMode` (`split` by default).
- `ovpnfull` connects or switches to `full` mode.
- `ovpnsplit` connects or switches to `split` mode.
- `ovpnstatus` shows status without `sudo`.
- `ovpnd` disconnects the session.

The menu bar item switches modes, disconnects, or retries sign-in, and closing the sign-in window cancels connecting. Check health with `"$CWRU_OVPN_BIN" doctor` and logs with `"$CWRU_OVPN_BIN" logs`. After failed cleanup, `sudo "$CWRU_OVPN_BIN" disconnect --force` retries recovery and can renew DHCP.

## Configuration

Setup creates `~/.cwru-ovpn/config.json` from the [example configuration](examples/cwru-ovpn.config.example.json) on first install. All five keys are optional.

- `tunnelMode` accepts `"split"` (default) or `"full"`.
- `privacyMode` (`true` default) hides free-form log details, keeping credential filtering when `false`.
- `preventSleep` defaults to `true` and prevents idle system sleep while connected.
- `webAuthSession` defaults to `"systemShared"` cookies and accepts `"system"` for ephemeral sign-in.
- `dnsBootstrapServers` sets `["1.1.1.1", "8.8.8.8"]` in the example. Omit it or set `[]` to disable fallback DNS.

Split mode tunnels campus traffic and DNS only. Full mode tunnels public IPv4 and tunnels or blocks public IPv6. During recovery or shutdown, macOS can [send DNS queries over the physical network](SECURITY.md#routing-and-dns).

## Optional Build from Source

Source builds require a clean Git checkout, Swift 6.2 or later, and CMake. Prepare pinned sibling checkouts before testing or building archives into `.build/local-artifacts`. Tests require `openvpn3-cwru-policy.patch` in `../openvpn3`, and packaging exports clean pinned sources and applies the patch itself.

```bash
source scripts/dependency-pins.env
git clone https://github.com/OpenVPN/openvpn3 ../openvpn3
git -C ../openvpn3 checkout "$OPENVPN3_PINNED_COMMIT"
git -C ../openvpn3 apply "$PWD/scripts/patches/openvpn3-cwru-policy.patch"
git clone https://github.com/chriskohlhoff/asio ../asio
git -C ../asio checkout "$ASIO_PINNED_COMMIT"
./scripts/test.sh
./scripts/build-release-binaries.sh
```

Install a local host build with `./scripts/setup.sh --build --profile /path/to/profile.ovpn`, omitting `--profile` on upgrades.

## Uninstallation

Run `sudo "$CWRU_OVPN_BIN" uninstall` to remove the system helper, or run `sudo "$CWRU_OVPN_BIN" uninstall --purge` to also delete `~/.cwru-ovpn`.

Project-authored code uses the [MIT License](LICENSE), with third-party terms in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
