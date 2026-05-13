#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${ROOT}/.build/third-party"
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
CPU_COUNT="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"
CURRENT_TARGET_ROOT=""

case "$(uname -m)" in
  arm64)
    OPENSSL_TARGET="darwin64-arm64-cc"
    ;;
  x86_64)
    OPENSSL_TARGET="darwin64-x86_64-cc"
    ;;
  *)
    echo "build-third-party-libs.sh: unsupported architecture '$(uname -m)'" >&2
    exit 1
    ;;
esac

if [[ $# -gt 0 ]]; then
  MACOS_VERSIONS=("$@")
else
  MACOS_VERSIONS=("$(sw_vers -productVersion | cut -d '.' -f1)")
fi

OPENSSL_ARCHIVE="$(brew --cache --build-from-source openssl@3)"
LZ4_ARCHIVE="$(brew --cache --build-from-source lz4)"
FMT_ARCHIVE="$(brew --cache --build-from-source fmt)"
OPENSSL_MKINSTALLVARS_PATCH="${ROOT}/scripts/patches/openssl-3.6.2-mkinstallvars-no-debug.patch"

require_archive() {
  local archive_path="$1"
  local formula_name="$2"

  if [[ ! -f "${archive_path}" ]]; then
    echo "build-third-party-libs.sh: missing source archive for ${formula_name}: ${archive_path}" >&2
    echo "Run: brew fetch --build-from-source openssl@3 lz4 fmt" >&2
    exit 1
  fi
}

extract_archive() {
  local archive_path="$1"
  local destination_root="$2"

  rm -rf "${destination_root}"
  mkdir -p "${destination_root}"

  case "${archive_path}" in
    *.tar.gz|*.tgz)
      tar -xzf "${archive_path}" -C "${destination_root}"
      ;;
    *.zip)
      unzip -q "${archive_path}" -d "${destination_root}"
      ;;
    *)
      echo "build-third-party-libs.sh: unsupported archive format: ${archive_path}" >&2
      exit 1
      ;;
  esac
}

first_directory_child() {
  local parent="$1"
  find "${parent}" -mindepth 1 -maxdepth 1 -type d | head -n 1
}

patch_checksum() {
  local patch_path="$1"
  shasum -a 256 "${patch_path}" | awk '{print $1}'
}

build_metadata() {
  local deployment_target="$1"

  cat <<EOF
deployment_target=${deployment_target}
arch=$(uname -m)
openssl_archive=$(basename "${OPENSSL_ARCHIVE}")
openssl_mkinstallvars_patch=$(patch_checksum "${OPENSSL_MKINSTALLVARS_PATCH}")
lz4_archive=$(basename "${LZ4_ARCHIVE}")
fmt_archive=$(basename "${FMT_ARCHIVE}")
EOF
}

cleanup_workdirs() {
  local target_root="$1"

  rm -rf \
    "${target_root}/openssl-src" \
    "${target_root}/lz4-src" \
    "${target_root}/fmt-src" \
    "${target_root}/fmt-build"
}

cleanup_current_workdirs() {
  if [[ -n "${CURRENT_TARGET_ROOT}" ]]; then
    cleanup_workdirs "${CURRENT_TARGET_ROOT}"
  fi
}

trap cleanup_current_workdirs EXIT

build_openssl() {
  local deployment_target="$1"
  local prefix="$2"
  local work_root="$3"
  local source_root="${work_root}/openssl-src"

  extract_archive "${OPENSSL_ARCHIVE}" "${source_root}"
  local source_dir
  source_dir="$(first_directory_child "${source_root}")"
  patch -d "${source_dir}" -p1 < "${OPENSSL_MKINSTALLVARS_PATCH}"

  pushd "${source_dir}" >/dev/null
  env \
    MACOSX_DEPLOYMENT_TARGET="${deployment_target}" \
    CC=clang \
    CXX=clang++ \
    AR=ar \
    RANLIB=ranlib \
    CFLAGS="-mmacosx-version-min=${deployment_target} -isysroot ${SDK_PATH}" \
    CXXFLAGS="-mmacosx-version-min=${deployment_target} -isysroot ${SDK_PATH}" \
    LDFLAGS="-mmacosx-version-min=${deployment_target} -isysroot ${SDK_PATH}" \
    ./Configure "${OPENSSL_TARGET}" \
      no-shared \
      no-tests \
      no-apps \
      no-docs \
      no-module \
      --prefix="${prefix}" \
      --openssldir="${prefix}/ssl"
  make -j "${CPU_COUNT}"
  make install_sw
  popd >/dev/null
}

build_lz4() {
  local deployment_target="$1"
  local prefix="$2"
  local work_root="$3"
  local source_root="${work_root}/lz4-src"

  extract_archive "${LZ4_ARCHIVE}" "${source_root}"
  local source_dir
  source_dir="$(first_directory_child "${source_root}")"

  pushd "${source_dir}/lib" >/dev/null
  make clean >/dev/null 2>&1 || true
  env \
    CC=clang \
    AR=ar \
    RANLIB=ranlib \
    CFLAGS="-O3 -mmacosx-version-min=${deployment_target} -isysroot ${SDK_PATH}" \
    make -j "${CPU_COUNT}" liblz4.a

  install -d "${prefix}/include" "${prefix}/lib"
  install -m 644 liblz4.a "${prefix}/lib/liblz4.a"
  install -m 644 lz4.h lz4frame.h lz4frame_static.h lz4hc.h "${prefix}/include/"
  popd >/dev/null
}

build_fmt() {
  local deployment_target="$1"
  local prefix="$2"
  local work_root="$3"
  local source_root="${work_root}/fmt-src"
  local build_dir="${work_root}/fmt-build"

  extract_archive "${FMT_ARCHIVE}" "${source_root}"
  local source_dir
  source_dir="$(first_directory_child "${source_root}")"

  cmake -S "${source_dir}" -B "${build_dir}" \
    --log-level=NOTICE \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${prefix}" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="${deployment_target}" \
    -DCMAKE_OSX_SYSROOT="${SDK_PATH}" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DFMT_DOC=OFF \
    -DFMT_TEST=OFF
  cmake --build "${build_dir}" --parallel "${CPU_COUNT}"
  cmake --install "${build_dir}"
}

require_archive "${OPENSSL_ARCHIVE}" "openssl@3"
require_archive "${LZ4_ARCHIVE}" "lz4"
require_archive "${FMT_ARCHIVE}" "fmt"

mkdir -p "${BUILD_ROOT}"

for major_version in "${MACOS_VERSIONS[@]}"; do
  deployment_target="${major_version}.0"
  target_root="${BUILD_ROOT}/macos${major_version}"
  prefix="${target_root}/prefix"
  metadata_file="${target_root}/build-metadata.txt"
  expected_metadata="$(build_metadata "${deployment_target}")"
  CURRENT_TARGET_ROOT="${target_root}"

  if [[ -f "${metadata_file}" ]] \
    && [[ -f "${prefix}/lib/libssl.a" ]] \
    && [[ -f "${prefix}/lib/libcrypto.a" ]] \
    && [[ -f "${prefix}/lib/liblz4.a" ]] \
    && [[ -f "${prefix}/lib/libfmt.a" ]] \
    && [[ -f "${prefix}/include/openssl/ssl.h" ]] \
    && [[ -f "${prefix}/include/lz4.h" ]] \
    && [[ -f "${prefix}/include/fmt/core.h" ]] \
    && [[ "$(cat "${metadata_file}")" == "${expected_metadata}" ]]; then
    echo "Reusing target-specific third-party libraries for macOS ${deployment_target}"
    cleanup_workdirs "${target_root}"
    continue
  fi

  echo "Building target-specific third-party libraries for macOS ${deployment_target}"
  rm -rf "${target_root}"
  mkdir -p "${target_root}"

  build_openssl "${deployment_target}" "${prefix}" "${target_root}"
  build_lz4 "${deployment_target}" "${prefix}" "${target_root}"
  build_fmt "${deployment_target}" "${prefix}" "${target_root}"

  printf "%s\n" "${expected_metadata}" > "${metadata_file}"
  cleanup_workdirs "${target_root}"
done
