# Third-Party Notices

`cwru-ovpn` source builds use local OpenVPN 3 and Asio checkouts. This repository also vendors a small OpenVPN 3 compatibility slice, and packaged release builds statically link OpenSSL, LZ4, and fmt.

## OpenVPN 3 Core

- Upstream project: OpenVPN 3
- Upstream repository: https://github.com/OpenVPN/openvpn3
- Default source lookup: `OPENVPN3_DIR`, `../openvpn3`, `./openvpn3`
- Integration snapshot: commit `9c2e0a21ccf8ea44523f900f881afb0b5d84172f`
- Upstream files mirrored here: `client/ovpncli.hpp`, `client/ovpncli.cpp`, and `openvpn/crypto/data_epoch.cpp`
- Upstream usage reference: `test/ovpncli/cli.cpp`
- Upstream SPDX on vendored files: `MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception`
- The repository vendors these upstream-derived OpenVPN 3 files:
  - [Sources/COpenVPN3Wrapper/ovpncli.hpp](Sources/COpenVPN3Wrapper/ovpncli.hpp)
  - [Sources/COpenVPN3Wrapper/ovpncli.cpp](Sources/COpenVPN3Wrapper/ovpncli.cpp)
  - [Sources/COpenVPN3Wrapper/data_epoch.cpp](Sources/COpenVPN3Wrapper/data_epoch.cpp)
- The vendored files retain their upstream licensing terms.
- The rest of the OpenVPN 3 core is consumed from the local checkout at build time and retains its upstream license there.
- [Sources/COpenVPN3Wrapper/openvpn3_wrapper.cpp](Sources/COpenVPN3Wrapper/openvpn3_wrapper.cpp) and [Sources/COpenVPN3Wrapper/include/cwru_openvpn3_wrapper.h](Sources/COpenVPN3Wrapper/include/cwru_openvpn3_wrapper.h) are project-authored bridge code and fall under this repository's top-level MIT license.
- Maintenance note: keep local changes concentrated in [Sources/COpenVPN3Wrapper/openvpn3_wrapper.cpp](Sources/COpenVPN3Wrapper/openvpn3_wrapper.cpp), and diff the vendored files against their upstream copies when rebasing.

## Asio

- Upstream project: Asio
- Upstream repository: https://github.com/chriskohlhoff/asio
- Default source lookup: `ASIO_DIR`, `../asio`, `../asio/asio`, `./asio`, `./asio/asio`
- Integration snapshot: commit `bd500f0a018db9a845ebaaed5c0318343ae9f497`
- Upstream license: Boost Software License 1.0, in `LICENSE_1_0.txt`

## Release Libraries

- `scripts/build-third-party-libs.sh` builds static OpenSSL, LZ4, and fmt libraries from Homebrew-fetched source archives for packaged release binaries.
- Current build metadata under `.build/third-party/*/build-metadata.txt` records:
  - OpenSSL 3.6.2 - Apache-2.0 - https://github.com/openssl/openssl
  - LZ4 1.10.0 - BSD-2-Clause - https://github.com/lz4/lz4
  - fmt 12.1.0 - MIT - https://github.com/fmtlib/fmt
- Local source builds can instead link Homebrew-provided dynamic libraries through `Package.swift`.

## Build Overrides

`Package.swift` and the build scripts honor these environment variables:

- `OPENVPN3_DIR`
- `ASIO_DIR`
- `HOMEBREW_PREFIX`
- `OPENSSL_PREFIX`
- `LZ4_PREFIX`
- `FMT_PREFIX`
- `CWRU_OVPN_THIRD_PARTY_PREFIX`
- `CWRU_OVPN_STATIC_THIRD_PARTY`
