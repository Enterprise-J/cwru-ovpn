#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT}/dist"
BUILD_ROOT="${ROOT}/.build"
THIRD_PARTY_ROOT="${ROOT}/.build/third-party"
TEMP_BUILD_PATHS=()

cleanup_temp_build_paths() {
  if [[ ${#TEMP_BUILD_PATHS[@]} -gt 0 ]]; then
    rm -rf "${TEMP_BUILD_PATHS[@]}"
  fi
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

if [[ $# -gt 0 ]]; then
  MACOS_VERSIONS=("$@")
else
  MACOS_VERSIONS=(14 15 26)
fi

mkdir -p "${DIST_DIR}" "${BUILD_ROOT}"

for major_version in "${MACOS_VERSIONS[@]}"; do
  deployment_target="${major_version}.0"
  legacy_build_path="${BUILD_ROOT}/release-macos${major_version}"
  build_path="$(mktemp -d "${BUILD_ROOT}/release-macos${major_version}.XXXXXX")"
  output_path="${DIST_DIR}/cwru-ovpn-macos${major_version}"
  third_party_prefix="${THIRD_PARTY_ROOT}/macos${major_version}/prefix"
  TEMP_BUILD_PATHS+=("${build_path}")

  rm -rf "${legacy_build_path}"

  echo "Building release binary for macOS ${deployment_target}"
  "${ROOT}/scripts/build-third-party-libs.sh" "${major_version}"

  env HOME=/tmp \
    SWIFTPM_MODULECACHE_OVERRIDE=/tmp/swiftpm-module-cache \
    CLANG_MODULE_CACHE_PATH=/tmp/clang-module-cache \
    CWRU_OVPN_MACOS_DEPLOYMENT_TARGET="${deployment_target}" \
    CWRU_OVPN_STATIC_THIRD_PARTY=1 \
    CWRU_OVPN_THIRD_PARTY_PREFIX="${third_party_prefix}" \
    swift build -c release --disable-sandbox \
    --package-path "${ROOT}" \
    --build-path "${build_path}"

  install -m 755 "${build_path}/release/cwru-ovpn" "${output_path}"
  rm -rf "${build_path}"
  remove_temp_build_path "${build_path}"

  if command -v vtool >/dev/null 2>&1; then
    echo "Build metadata for ${output_path}:"
    vtool -show-build "${output_path}" | sed 's/^/  /'
  fi
done

(
  cd "${DIST_DIR}"
  shasum -a 256 cwru-ovpn-macos* > SHA256SUMS
)

echo "Wrote dist/SHA256SUMS"
