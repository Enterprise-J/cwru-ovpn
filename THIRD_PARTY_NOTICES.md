# Third-Party Notices

`cwru-ovpn` source builds compile against local OpenVPN 3 and Asio checkouts. This repository also vendors a small OpenVPN 3 compatibility slice, and packaged release builds statically link OpenSSL, LZ4, and fmt.

## OpenVPN 3 Core

- Upstream project: OpenVPN 3
- Upstream repository: https://github.com/OpenVPN/openvpn3
- Default source lookup: `OPENVPN3_DIR`, `./openvpn3`, `../openvpn3`
- Integration snapshot: commit `7f572f4fe647a36f5a1094cbeb261a5bcdae5047`
- Upstream files mirrored here: `client/ovpncli.hpp`, `client/ovpncli.cpp`, and `openvpn/crypto/data_epoch.cpp`
- Upstream usage reference: `test/ovpncli/cli.cpp`
- Upstream SPDX on vendored files: `MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception`
- The repository vendors these upstream-derived OpenVPN 3 files:
  - [Sources/COpenVPN3/include/ovpncli.hpp](Sources/COpenVPN3/include/ovpncli.hpp)
  - [Sources/COpenVPN3/ovpncli.cpp](Sources/COpenVPN3/ovpncli.cpp)
  - [Sources/COpenVPN3/data_epoch.cpp](Sources/COpenVPN3/data_epoch.cpp)
- The vendored files retain their upstream licensing terms.
- The rest of the OpenVPN 3 core is consumed from the local checkout at build time and retains its upstream license there.
- Release builds apply [`scripts/patches/openvpn3-cwru-policy.patch`](scripts/patches/openvpn3-cwru-policy.patch) to the OpenVPN 3 source before compiling, and record the patch file's SHA-256 in `dist/build-info.json`. The patch fixes utun allocation and disables native DNS, proxy, and remote bypass actions. The application manages DNS and the control-channel host route; proxy configuration is unsupported.
- [Sources/COpenVPN3Wrapper/openvpn3_wrapper.cpp](Sources/COpenVPN3Wrapper/openvpn3_wrapper.cpp) and [Sources/COpenVPN3Wrapper/include/cwru_openvpn3_wrapper.h](Sources/COpenVPN3Wrapper/include/cwru_openvpn3_wrapper.h) are project-authored bridge code and fall under this repository's top-level MIT license.
- Maintenance note: keep local changes concentrated in [Sources/COpenVPN3Wrapper/openvpn3_wrapper.cpp](Sources/COpenVPN3Wrapper/openvpn3_wrapper.cpp), and diff the vendored files against their upstream copies when rebasing.

## Asio

- Upstream project: Asio
- Upstream repository: https://github.com/chriskohlhoff/asio
- Default source lookup: `ASIO_DIR`, `../asio`, `../asio/asio`, `./asio`, `./asio/asio`
- Integration snapshot: commit `8806a6803cde7054c3049d3666d3ec36786568c5` (asio-1-38-2)
- Upstream license: Boost Software License 1.0, in `LICENSE_1_0.txt`

## Release Libraries

- `scripts/build-third-party-libs.sh` builds static OpenSSL, LZ4, and fmt libraries for packaged release binaries. OpenSSL is fetched from the upstream release tarball with SHA-256 verification; LZ4 and fmt use Homebrew-fetched source archives, also SHA-256 verified.
- OpenSSL packaging applies [`scripts/patches/openssl-4.0.2-build-compatibility.patch`](scripts/patches/openssl-4.0.2-build-compatibility.patch) before compilation. The patch supplies omitted installation variables and removes build-time debug output that remain in the upstream release.
- Per-target build metadata records:
  - OpenSSL 4.0.2 - Apache-2.0 - https://github.com/openssl/openssl
  - LZ4 1.10.0 - BSD-2-Clause - https://github.com/lz4/lz4
  - fmt 12.2.0 - MIT - https://github.com/fmtlib/fmt
- `dist/build-info.json` records each release target's third-party prefix and build-metadata hashes.
- Local source builds can instead link Homebrew-provided dynamic libraries through `Package.swift`.

## Build Overrides

Development and packaging tools recognize these environment variables:

- `OPENVPN3_DIR`
- `ASIO_DIR`
- `HOMEBREW_PREFIX`
- `OPENSSL_PREFIX`
- `LZ4_PREFIX`
- `FMT_PREFIX`
- `CWRU_OVPN_THIRD_PARTY_PREFIX`
- `CWRU_OVPN_THIRD_PARTY_BUILD_ROOT`
- `CWRU_OVPN_THIRD_PARTY_SOURCE_CACHE`
- `CWRU_OVPN_FORCE_THIRD_PARTY_REBUILD`
- `CWRU_OVPN_STATIC_THIRD_PARTY`
- `CWRU_OVPN_MACOS_DEPLOYMENT_TARGET`
- `CWRU_OVPN_CODESIGN_IDENTITY`

Packaged release builds ignore the individual OpenSSL, LZ4, and fmt prefix overrides and rebuild each target-specific static prefix from checksum-pinned archives inside an isolated build path.
