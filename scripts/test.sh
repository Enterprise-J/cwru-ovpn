#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${TMPDIR:-/tmp}/cwru-ovpn-swift"

if ! command -v sw_vers >/dev/null 2>&1; then
  echo "scripts/test.sh requires macOS" >&2
  exit 78
fi

HOST_MACOS_MAJOR_VERSION="$(sw_vers -productVersion | cut -d '.' -f1)"
DEPLOYMENT_TARGET="${CWRU_OVPN_MACOS_DEPLOYMENT_TARGET:-${HOST_MACOS_MAJOR_VERSION}.0}"

ensure_private_tmp_root() {
  local tmp_root="$1"
  mkdir -p "${tmp_root}"
  if [[ -L "${tmp_root}" || ! -d "${tmp_root}" ]]; then
    echo "scripts/test.sh: refusing unsafe temporary build directory ${tmp_root}" >&2
    exit 1
  fi
  if [[ "$(stat -f '%u' "${tmp_root}")" != "$(id -u)" ]]; then
    echo "scripts/test.sh: temporary build directory ${tmp_root} is not owned by the current user" >&2
    exit 1
  fi
  chmod 700 "${tmp_root}"
}

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

testing_compatibility_arguments=()
selected_developer_directory="$(xcode-select -p)"
testing_macro_plugin="${selected_developer_directory}/usr/lib/swift/host/plugins/testing/libTestingMacros.dylib"
testing_framework_directory="${selected_developer_directory}/Library/Developer/Frameworks"
testing_interop_directory="${selected_developer_directory}/Library/Developer/usr/lib"
if [[ -f "${testing_macro_plugin}" && -d "${testing_framework_directory}" && -d "${testing_interop_directory}" ]]; then
  testing_compatibility_arguments=(
    -Xswiftc -load-plugin-library
    -Xswiftc "${testing_macro_plugin}"
    -Xlinker -rpath
    -Xlinker "${testing_framework_directory}"
    -Xlinker -rpath
    -Xlinker "${testing_interop_directory}"
  )
fi

run_swift build --disable-sandbox --package-path "${ROOT}"
if [[ "${#testing_compatibility_arguments[@]}" -eq 0 ]]; then
  run_swift test --disable-sandbox --package-path "${ROOT}"
else
  run_swift test --disable-sandbox --package-path "${ROOT}" "${testing_compatibility_arguments[@]}"
fi
run_swift build --disable-sandbox --package-path "${ROOT}" -c release

echo "Validation passed."
