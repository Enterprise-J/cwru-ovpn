#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/scripts/common.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/cwru-ovpn-tests.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

if ! command -v sw_vers >/dev/null 2>&1; then
  echo "${SCRIPT_NAME}: macOS is required." >&2
  exit 78
fi

HOST_MACOS_MAJOR_VERSION="$(sw_vers -productVersion | cut -d '.' -f1)"
DEPLOYMENT_TARGET="${CWRU_OVPN_MACOS_DEPLOYMENT_TARGET:-${HOST_MACOS_MAJOR_VERSION}.0}"

source "$ROOT/scripts/dependency-pins.env"
OPENVPN3_DIR="${OPENVPN3_DIR:-$ROOT/../openvpn3}"
ASIO_DIR="${ASIO_DIR:-$ROOT/../asio}"
export OPENVPN3_DIR ASIO_DIR
[[ "$(git -C "$OPENVPN3_DIR" rev-parse HEAD)" == "$OPENVPN3_PINNED_COMMIT" ]]
[[ "$(git -C "$ASIO_DIR" rev-parse HEAD)" == "$ASIO_PINNED_COMMIT" ]]
[[ "$(python3 "$ROOT/scripts/tree-sha256.py" "$OPENVPN3_DIR" .git)" == "$OPENVPN3_TREE_SHA256" ]]
[[ "$(python3 "$ROOT/scripts/tree-sha256.py" "$ASIO_DIR" .git)" == "$ASIO_TREE_SHA256" ]]
export CWRU_OVPN_THIRD_PARTY_BUILD_ROOT="$TMP_ROOT/third-party"
"$ROOT/scripts/build-third-party-libs.sh" "${DEPLOYMENT_TARGET%%.*}"
export CWRU_OVPN_THIRD_PARTY_PREFIX="$TMP_ROOT/third-party/macos${DEPLOYMENT_TARGET%%.*}/prefix"
mkdir -p \
  "${TMP_ROOT}/home" \
  "${TMP_ROOT}/swiftpm-module-cache" \
  "${TMP_ROOT}/swiftpm-cache" \
  "${TMP_ROOT}/swiftpm-config" \
  "${TMP_ROOT}/swiftpm-security" \
  "${TMP_ROOT}/clang-module-cache"

run_swift() {
  local subcommand="$1"
  shift

  env HOME="${TMP_ROOT}/home" \
    SWIFTPM_MODULECACHE_OVERRIDE="${TMP_ROOT}/swiftpm-module-cache" \
    CLANG_MODULE_CACHE_PATH="${TMP_ROOT}/clang-module-cache" \
    CWRU_OVPN_MACOS_DEPLOYMENT_TARGET="${DEPLOYMENT_TARGET}" \
    CWRU_OVPN_STATIC_THIRD_PARTY=1 \
    swift "${subcommand}" \
      --cache-path "${TMP_ROOT}/swiftpm-cache" \
      --config-path "${TMP_ROOT}/swiftpm-config" \
      --security-path "${TMP_ROOT}/swiftpm-security" \
      --scratch-path "$TMP_ROOT/build" \
      --manifest-cache local \
      "$@"
}

SWIFT_TESTING_ARGUMENTS=()
DEVELOPER_DIRECTORY="$(xcode-select -p)"
TESTING_MACRO_PLUGIN="${DEVELOPER_DIRECTORY}/usr/lib/swift/host/plugins/testing/libTestingMacros.dylib"
TESTING_FRAMEWORK_DIRECTORY="${DEVELOPER_DIRECTORY}/Library/Developer/Frameworks"
TESTING_INTEROP_DIRECTORY="${DEVELOPER_DIRECTORY}/Library/Developer/usr/lib"
if [[ -f "${TESTING_MACRO_PLUGIN}" && -d "${TESTING_FRAMEWORK_DIRECTORY}" && -d "${TESTING_INTEROP_DIRECTORY}" ]]; then
  SWIFT_TESTING_ARGUMENTS=(
    -Xswiftc -load-plugin-library
    -Xswiftc "${TESTING_MACRO_PLUGIN}"
    -Xlinker -rpath
    -Xlinker "${TESTING_FRAMEWORK_DIRECTORY}"
    -Xlinker -rpath
    -Xlinker "${TESTING_INTEROP_DIRECTORY}"
  )
fi

xcrun clang++ -std=c++20 -DASIO_STANDALONE -DUSE_ASIO -D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST \
  -isystem "$OPENVPN3_DIR" -isystem "$ASIO_DIR/include" -isystem "$CWRU_OVPN_THIRD_PARTY_PREFIX/include" \
  "$ROOT/Tests/Native/CertificateUsage.cpp" "$CWRU_OVPN_THIRD_PARTY_PREFIX/lib/libfmt.a" -o "$TMP_ROOT/certificate-usage"
"$TMP_ROOT/certificate-usage"

run_swift build --disable-sandbox --package-path "${ROOT}"
if [[ "${#SWIFT_TESTING_ARGUMENTS[@]}" -eq 0 ]]; then
  run_swift test --disable-sandbox --package-path "${ROOT}"
else
  run_swift test --disable-sandbox --package-path "${ROOT}" "${SWIFT_TESTING_ARGUMENTS[@]}"
fi
run_swift build --disable-sandbox --package-path "${ROOT}" -c release

echo "Validation passed."
