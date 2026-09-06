#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${CWRU_OVPN_THIRD_PARTY_BUILD_ROOT:-${ROOT}/.build/third-party}"
SOURCE_CACHE="${CWRU_OVPN_THIRD_PARTY_SOURCE_CACHE:-${BUILD_ROOT}/sources}"
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
SDK_VERSION="$(xcrun --sdk macosx --show-sdk-version)"
SDK_BUILD_VERSION="$(xcrun --sdk macosx --show-sdk-build-version)"
CLANG_VERSION_SHA256="$(xcrun --sdk macosx clang --version | shasum -a 256 | awk '{print $1}')"
CMAKE_VERSION_SHA256="$(cmake --version | shasum -a 256 | awk '{print $1}')"
BUILD_SCRIPT_SHA256="$(shasum -a 256 "${BASH_SOURCE[0]}" | awk '{print $1}')"
CPU_COUNT="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"
CURRENT_TARGET_ROOT=""
FORCE_REBUILD="${CWRU_OVPN_FORCE_THIRD_PARTY_REBUILD:-0}"
APP_VERSION="$(awk -F'"' '/static let version/ { print $2; exit }' "${ROOT}/Sources/cwru-ovpn/AppIdentity.swift")"

if [[ "${FORCE_REBUILD}" != "0" && "${FORCE_REBUILD}" != "1" ]]; then
  echo "build-third-party-libs.sh: CWRU_OVPN_FORCE_THIRD_PARTY_REBUILD must be 0 or 1." >&2
  exit 1
fi

if [[ "$(uname -m)" != "arm64" ]]; then
  echo "build-third-party-libs.sh: Apple Silicon is required." >&2
  exit 1
fi
OPENSSL_TARGET="darwin64-arm64-cc"

if [[ $# -gt 0 ]]; then
  MACOS_VERSIONS=("$@")
else
  MACOS_VERSIONS=("$(sw_vers -productVersion | cut -d '.' -f1)")
fi

validate_macos_versions() {
  local major_version

  for major_version in "$@"; do
    if [[ ! "${major_version}" =~ ^[0-9]+$ ]]; then
      echo "build-third-party-libs.sh: invalid macOS major version '${major_version}'." >&2
      exit 1
    fi
    if [[ "${major_version}" -lt 15 ]]; then
      echo "build-third-party-libs.sh: cwru-ovpn ${APP_VERSION} supports macOS 15 or later." >&2
      exit 1
    fi
  done
}

validate_macos_versions "${MACOS_VERSIONS[@]}"

OPENSSL_VERSION="4.0.2"
OPENSSL_SHA256="736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_ARCHIVE="${SOURCE_CACHE}/openssl-${OPENSSL_VERSION}.tar.gz"
LZ4_ARCHIVE="$(brew --cache --build-from-source lz4)"
LZ4_SHA256="537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b"
FMT_ARCHIVE="$(brew --cache --build-from-source fmt)"
FMT_SHA256="a2f4a8d51178f954e4c339007f77edd76ba0cb2e36f87a48e5a5403d9be5878f"
OPENSSL_BUILD_PATCH="${ROOT}/scripts/patches/openssl-4.0.2-build-compatibility.patch"

verify_archive_sha256() {
  local archive_path="$1"
  local expected_sha256="$2"
  local label="$3"
  local actual_sha256

  actual_sha256="$(shasum -a 256 "${archive_path}" | awk '{print $1}')"
  if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
    echo "build-third-party-libs.sh: ${label} checksum mismatch" >&2
    echo "expected: ${expected_sha256}" >&2
    echo "actual:   ${actual_sha256}" >&2
    exit 1
  fi
}

ensure_downloaded_archive() {
  local archive_path="$1"
  local url="$2"
  local expected_sha256="$3"
  local label="$4"
  local tmp_path="${archive_path}.tmp.$$"

  if [[ -f "${archive_path}" ]]; then
    verify_archive_sha256 "${archive_path}" "${expected_sha256}" "${label}"
    return
  fi

  mkdir -p "$(dirname "${archive_path}")"
  curl --fail --location --show-error --output "${tmp_path}" "${url}"
  verify_archive_sha256 "${tmp_path}" "${expected_sha256}" "${label}"
  mv "${tmp_path}" "${archive_path}"
}

require_archive() {
  local archive_path="$1"
  local formula_name="$2"

  if [[ ! -f "${archive_path}" ]]; then
    echo "build-third-party-libs.sh: missing source archive for ${formula_name}: ${archive_path}" >&2
    echo "Run: brew fetch --build-from-source lz4 fmt" >&2
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
sdk_path=${SDK_PATH}
sdk_version=${SDK_VERSION}
sdk_build_version=${SDK_BUILD_VERSION}
clang_version_sha256=${CLANG_VERSION_SHA256}
cmake_version_sha256=${CMAKE_VERSION_SHA256}
build_script_sha256=${BUILD_SCRIPT_SHA256}
openssl_target=${OPENSSL_TARGET}
openssl_archive=$(basename "${OPENSSL_ARCHIVE}")
openssl_url=${OPENSSL_URL}
openssl_sha256=${OPENSSL_SHA256}
openssl_build_patch=$(patch_checksum "${OPENSSL_BUILD_PATCH}")
lz4_archive=$(basename "${LZ4_ARCHIVE}")
lz4_sha256=${LZ4_SHA256}
fmt_archive=$(basename "${FMT_ARCHIVE}")
fmt_sha256=${FMT_SHA256}
EOF
}

prefix_content_sha256() {
  local prefix="$1"

  (
    cd "${prefix}"
    find . \( -type f -o -type l \) -print \
      | LC_ALL=C sort \
      | while IFS= read -r file_path; do
          if [[ -L "${file_path}" ]]; then
            printf 'symlink %s %s\n' "${file_path}" "$(readlink "${file_path}")"
          else
            printf 'file %s %s\n' "${file_path}" "$(shasum -a 256 "${file_path}" | awk '{print $1}')"
          fi
        done \
      | shasum -a 256 \
      | awk '{print $1}'
  )
}

cached_prefix_is_valid() {
  local prefix="$1"
  local metadata_file="$2"
  local hash_file="$3"
  local expected_metadata="$4"
  local recorded_hash actual_hash

  [[ -f "${metadata_file}" ]] \
    && [[ -f "${hash_file}" ]] \
    && [[ -f "${prefix}/lib/libssl.a" ]] \
    && [[ -f "${prefix}/lib/libcrypto.a" ]] \
    && [[ -f "${prefix}/lib/liblz4.a" ]] \
    && [[ -f "${prefix}/lib/libfmt.a" ]] \
    && [[ -f "${prefix}/include/openssl/ssl.h" ]] \
    && [[ -f "${prefix}/include/lz4.h" ]] \
    && [[ -f "${prefix}/include/fmt/core.h" ]] \
    && [[ "$(cat "${metadata_file}")" == "${expected_metadata}" ]] \
    || return 1

  recorded_hash="$(cat "${hash_file}")"
  [[ "${recorded_hash}" =~ ^[0-9a-f]{64}$ ]] || return 1
  actual_hash="$(prefix_content_sha256 "${prefix}")"
  [[ "${actual_hash}" == "${recorded_hash}" ]]
}

cleanup_workdirs() {
  local target_root="$1"

  rm -rf \
    "${target_root}/openssl-src" \
    "${target_root}/lz4-src" \
    "${target_root}/fmt-src" \
    "${target_root}/fmt-build" \
    "${target_root}/archives"
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
  local archive_path="$4"
  local source_root="${work_root}/openssl-src"

  verify_archive_sha256 "${archive_path}" "${OPENSSL_SHA256}" "OpenSSL ${OPENSSL_VERSION}"
  extract_archive "${archive_path}" "${source_root}"
  local source_dir
  source_dir="$(first_directory_child "${source_root}")"
  patch -d "${source_dir}" -p1 < "${OPENSSL_BUILD_PATCH}"

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
      no-autoload-config \
      no-dso \
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
  local archive_path="$4"
  local source_root="${work_root}/lz4-src"

  verify_archive_sha256 "${archive_path}" "${LZ4_SHA256}" "lz4"
  extract_archive "${archive_path}" "${source_root}"
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
  local archive_path="$4"
  local source_root="${work_root}/fmt-src"
  local build_dir="${work_root}/fmt-build"

  verify_archive_sha256 "${archive_path}" "${FMT_SHA256}" "fmt"
  extract_archive "${archive_path}" "${source_root}"
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

ensure_downloaded_archive "${OPENSSL_ARCHIVE}" "${OPENSSL_URL}" "${OPENSSL_SHA256}" "OpenSSL ${OPENSSL_VERSION}"
require_archive "${LZ4_ARCHIVE}" "lz4"
verify_archive_sha256 "${LZ4_ARCHIVE}" "${LZ4_SHA256}" "lz4"
require_archive "${FMT_ARCHIVE}" "fmt"
verify_archive_sha256 "${FMT_ARCHIVE}" "${FMT_SHA256}" "fmt"

mkdir -p "${BUILD_ROOT}"

for major_version in "${MACOS_VERSIONS[@]}"; do
  deployment_target="${major_version}.0"
  target_root="${BUILD_ROOT}/macos${major_version}"
  prefix="${target_root}/prefix"
  metadata_file="${target_root}/build-metadata.txt"
  hash_file="${target_root}/prefix-sha256.txt"
  expected_metadata="$(build_metadata "${deployment_target}")"
  CURRENT_TARGET_ROOT="${target_root}"

  if [[ "${FORCE_REBUILD}" != "1" ]] \
    && cached_prefix_is_valid "${prefix}" "${metadata_file}" "${hash_file}" "${expected_metadata}"; then
    echo "Reusing target-specific third-party libraries for macOS ${deployment_target}"
    cleanup_workdirs "${target_root}"
    continue
  fi

  echo "Building target-specific third-party libraries for macOS ${deployment_target}"
  rm -rf "${target_root}"
  archive_root="${target_root}/archives"
  mkdir -p "${archive_root}"
  openssl_build_archive="${archive_root}/$(basename "${OPENSSL_ARCHIVE}")"
  lz4_build_archive="${archive_root}/$(basename "${LZ4_ARCHIVE}")"
  fmt_build_archive="${archive_root}/$(basename "${FMT_ARCHIVE}")"
  install -m 644 "${OPENSSL_ARCHIVE}" "${openssl_build_archive}"
  install -m 644 "${LZ4_ARCHIVE}" "${lz4_build_archive}"
  install -m 644 "${FMT_ARCHIVE}" "${fmt_build_archive}"
  verify_archive_sha256 "${openssl_build_archive}" "${OPENSSL_SHA256}" "OpenSSL ${OPENSSL_VERSION}"
  verify_archive_sha256 "${lz4_build_archive}" "${LZ4_SHA256}" "lz4"
  verify_archive_sha256 "${fmt_build_archive}" "${FMT_SHA256}" "fmt"

  build_openssl "${deployment_target}" "${prefix}" "${target_root}" "${openssl_build_archive}"
  build_lz4 "${deployment_target}" "${prefix}" "${target_root}" "${lz4_build_archive}"
  build_fmt "${deployment_target}" "${prefix}" "${target_root}" "${fmt_build_archive}"

  printf "%s\n" "${expected_metadata}" > "${metadata_file}.tmp"
  prefix_content_sha256 "${prefix}" > "${hash_file}.tmp"
  mv "${metadata_file}.tmp" "${metadata_file}"
  mv "${hash_file}.tmp" "${hash_file}"
  cleanup_workdirs "${target_root}"
done
