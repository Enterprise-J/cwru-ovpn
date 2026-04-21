#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${TMPDIR:-/tmp}/cwru-ovpn-swift"
HOST_MACOS_MAJOR_VERSION="$(sw_vers -productVersion | cut -d '.' -f1)"

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
    CWRU_OVPN_MACOS_DEPLOYMENT_TARGET="${HOST_MACOS_MAJOR_VERSION}.0" \
    CWRU_OVPN_STATIC_THIRD_PARTY=0 \
    swift "${subcommand}" \
      --cache-path "${TMP_ROOT}/swiftpm-cache" \
      --config-path "${TMP_ROOT}/swiftpm-config" \
      --security-path "${TMP_ROOT}/swiftpm-security" \
      --manifest-cache local \
      "$@"
}

run_swift build --disable-sandbox --package-path "${ROOT}"
run_swift run --disable-sandbox --package-path "${ROOT}" cwru-ovpn self-test

echo "Validation passed."
