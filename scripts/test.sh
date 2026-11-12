#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/scripts/common.sh"
TMP_ROOT="${TMPDIR:-/tmp}/cwru-ovpn-swift"

if ! command -v sw_vers >/dev/null 2>&1; then
  echo "${SCRIPT_NAME}: macOS is required." >&2
  exit 78
fi

HOST_MACOS_MAJOR_VERSION="$(sw_vers -productVersion | cut -d '.' -f1)"
DEPLOYMENT_TARGET="${CWRU_OVPN_MACOS_DEPLOYMENT_TARGET:-${HOST_MACOS_MAJOR_VERSION}.0}"

ensure_private_tmp_root "${TMP_ROOT}"
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
    CWRU_OVPN_STATIC_THIRD_PARTY=0 \
    swift "${subcommand}" \
      --cache-path "${TMP_ROOT}/swiftpm-cache" \
      --config-path "${TMP_ROOT}/swiftpm-config" \
      --security-path "${TMP_ROOT}/swiftpm-security" \
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

run_swift build --disable-sandbox --package-path "${ROOT}"
if [[ "${#SWIFT_TESTING_ARGUMENTS[@]}" -eq 0 ]]; then
  run_swift test --disable-sandbox --package-path "${ROOT}"
else
  run_swift test --disable-sandbox --package-path "${ROOT}" "${SWIFT_TESTING_ARGUMENTS[@]}"
fi
run_swift build --disable-sandbox --package-path "${ROOT}" -c release

echo "Validation passed."
