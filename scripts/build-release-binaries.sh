#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT}/dist"
BUILD_ROOT="${ROOT}/.build"
THIRD_PARTY_ROOT="${ROOT}/.build/third-party"
TMP_ROOT="${TMPDIR:-/tmp}/cwru-ovpn-release"
TEMP_BUILD_PATHS=()
BUILT_OUTPUTS=()
CODESIGN_IDENTITY="${CWRU_OVPN_CODESIGN_IDENTITY:-}"
HOST_ARCH="$(uname -m)"

cleanup_temp_build_paths() {
  if [[ ${#TEMP_BUILD_PATHS[@]} -gt 0 ]]; then
    rm -rf "${TEMP_BUILD_PATHS[@]}"
  fi
}

sign_release_binary() {
  local output_path="$1"

  if [[ -z "${CODESIGN_IDENTITY}" ]]; then
    echo "Warning: ${output_path} is not Developer ID signed; set CWRU_OVPN_CODESIGN_IDENTITY to sign release binaries." >&2
    return
  fi

  codesign --force --options runtime --timestamp --sign "${CODESIGN_IDENTITY}" "${output_path}"
  codesign --verify --deep --strict --verbose=2 "${output_path}"
}

remove_temp_build_path() {
  local build_path="$1"
  local remaining=()
  local candidate

  for candidate in "${TEMP_BUILD_PATHS[@]}"; do
    if [[ "${candidate}" != "${build_path}" ]]; then
      remaining+=("${candidate}")
    fi
  done

  if [[ ${#remaining[@]} -gt 0 ]]; then
    TEMP_BUILD_PATHS=("${remaining[@]}")
  else
    TEMP_BUILD_PATHS=()
  fi
}

trap cleanup_temp_build_paths EXIT

if [[ "${HOST_ARCH}" != "arm64" ]]; then
  echo "build-release-binaries.sh: packaged dist artifacts are arm64-only and must be built on Apple Silicon." >&2
  exit 1
fi

if [[ $# -gt 0 ]]; then
  MACOS_VERSIONS=("$@")
else
  MACOS_VERSIONS=(14 15 26)
fi

mkdir -p "${DIST_DIR}" "${BUILD_ROOT}"
rm -f "${DIST_DIR}"/cwru-ovpn-macos* "${DIST_DIR}/SHA256SUMS"
mkdir -p \
  "${TMP_ROOT}/home" \
  "${TMP_ROOT}/swiftpm-module-cache" \
  "${TMP_ROOT}/swiftpm-cache" \
  "${TMP_ROOT}/swiftpm-config" \
  "${TMP_ROOT}/swiftpm-security" \
  "${TMP_ROOT}/clang-module-cache"

for major_version in "${MACOS_VERSIONS[@]}"; do
  deployment_target="${major_version}.0"
  legacy_build_path="${BUILD_ROOT}/release-macos${major_version}"
  build_path="$(mktemp -d "${BUILD_ROOT}/release-macos${major_version}.XXXXXX")"
  output_path="${DIST_DIR}/cwru-ovpn-macos${major_version}-arm64"
  third_party_prefix="${THIRD_PARTY_ROOT}/macos${major_version}/prefix"
  TEMP_BUILD_PATHS+=("${build_path}")

  rm -rf "${legacy_build_path}"

  echo "Building release binary for macOS ${deployment_target}"
  "${ROOT}/scripts/build-third-party-libs.sh" "${major_version}"

  env HOME="${TMP_ROOT}/home" \
    SWIFTPM_MODULECACHE_OVERRIDE="${TMP_ROOT}/swiftpm-module-cache" \
    CLANG_MODULE_CACHE_PATH="${TMP_ROOT}/clang-module-cache" \
    CWRU_OVPN_MACOS_DEPLOYMENT_TARGET="${deployment_target}" \
    CWRU_OVPN_STATIC_THIRD_PARTY=1 \
    CWRU_OVPN_THIRD_PARTY_PREFIX="${third_party_prefix}" \
    swift build -c release --disable-sandbox \
    --package-path "${ROOT}" \
    --cache-path "${TMP_ROOT}/swiftpm-cache" \
    --config-path "${TMP_ROOT}/swiftpm-config" \
    --security-path "${TMP_ROOT}/swiftpm-security" \
    --manifest-cache local \
    --build-path "${build_path}"

  install -m 755 "${build_path}/release/cwru-ovpn" "${output_path}"
  BUILT_OUTPUTS+=("$(basename "${output_path}")")
  sign_release_binary "${output_path}"
  rm -rf "${build_path}"
  remove_temp_build_path "${build_path}"

  if command -v vtool >/dev/null 2>&1; then
    echo "Build metadata for ${output_path}:"
    vtool -show-build "${output_path}" | sed 's/^/  /'
  fi
done

(
  cd "${DIST_DIR}"
  shasum -a 256 "${BUILT_OUTPUTS[@]}" > SHA256SUMS
)

echo "Wrote dist/SHA256SUMS"
