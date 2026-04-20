# Third-Party Notices

`cwru-ovpn` depends directly on upstream third-party source trees that are checked out beside this repository during local development.

## OpenVPN 3 Core

- Upstream project: OpenVPN 3
- Upstream repository: https://github.com/OpenVPN/openvpn3
- Local checkout expected by default at: `~/openvpn3`
- Local checkout used for this integration snapshot: commit `9c2e0a21ccf8ea44523f900f881afb0b5d84172f`
- Primary API referenced by this project: `client/ovpncli.hpp`
- Closest upstream usage example: `test/ovpncli/cli.cpp`
- Upstream license summary: AGPL-3.0-only or MPL-2.0, as described in `openvpn3/LICENSE.md`

License scope in this repository:

- No OpenVPN 3 source files are vendored into this repository. The OpenVPN 3 core is consumed from the sibling checkout at build time; its files retain their upstream license.
- [Sources/COpenVPN3Wrapper/openvpn3_wrapper.cpp](Sources/COpenVPN3Wrapper/openvpn3_wrapper.cpp) and [Sources/COpenVPN3Wrapper/include/cwru_openvpn3_wrapper.h](Sources/COpenVPN3Wrapper/include/cwru_openvpn3_wrapper.h) are project-authored bridge code and fall under this repository's top-level MIT license.

Maintenance notes:

- The OpenVPN 3 integration surface is intentionally concentrated in [Sources/COpenVPN3Wrapper/openvpn3_wrapper.cpp](Sources/COpenVPN3Wrapper/openvpn3_wrapper.cpp).
- If OpenVPN 3 changes its API, start by diffing `client/ovpncli.hpp` in the updated upstream checkout.
- Reconcile any behavior changes against the upstream CLI example in `test/ovpncli/cli.cpp`.
- If your checkout is not in the default sibling location, build with `OPENVPN3_DIR=/path/to/openvpn3`.

## Asio

- Upstream project: Asio
- Upstream repository: https://github.com/chriskohlhoff/asio
- Local checkout expected by default at: `~/asio`
- Local checkout used for this integration snapshot: commit `bd500f0a018db9a845ebaaed5c0318343ae9f497`
- Upstream license: Boost Software License 1.0, in `LICENSE_1_0.txt`

Maintenance notes:

- If Asio moves in your workspace, build with `ASIO_DIR=/path/to/asio`.
- `Package.swift` resolves either `<asio>/include` or `<asio>/asio/include` so the package can tolerate the common checkout layouts.

## Local Build Overrides

`Package.swift` supports these environment variables to make upstream dependency maintenance less brittle:

- `OPENVPN3_DIR`
- `ASIO_DIR`
- `HOMEBREW_PREFIX`
- `OPENSSL_PREFIX`
