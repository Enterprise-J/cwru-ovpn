#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/scripts/common.sh"
FINAL_DIST_DIR="${ROOT}/.build/local-artifacts"
DIST_DIR=""
BUILD_ROOT="${ROOT}/.build"
THIRD_PARTY_SOURCE_CACHE="${CWRU_OVPN_THIRD_PARTY_SOURCE_CACHE:-${ROOT}/.build/third-party/sources}"
TMP_ROOT=""
TEMP_BUILD_PATHS=()
BUILT_OUTPUTS=()
BUILT_DEPLOYMENT_TARGETS=()
BUILT_THIRD_PARTY_HASHES=()
BUILT_THIRD_PARTY_METADATA_HASHES=()
BUILT_OUTPUT_HASHES=()
HOST_ARCH="$(uname -m)"
MACOS_SDK_VERSION="$(xcrun --sdk macosx --show-sdk-version)"
SOURCE_GIT_COMMIT=""
SOURCE_TREE_SHA256=""
SOURCE_PACKAGE_ROOT="${ROOT}"
RELEASE_OPENVPN3_DIR=""
RELEASE_ASIO_DIR=""
APP_VERSION="$(app_identity_value version "${ROOT}/Sources/cwru-ovpn/AppIdentity.swift")"
WORKSPACE_ROOT="$(cd "${ROOT}/.." && pwd)"
source "${ROOT}/scripts/dependency-pins.env"
OPENVPN3_PATCH="${ROOT}/scripts/patches/openvpn3-cwru-policy.patch"
OPENVPN3_PATCH_SHA256=""
OPENVPN3_SOURCE_DIR=""
ASIO_SOURCE_DIR=""

cleanup_temp_build_paths() {
  if [[ ${#TEMP_BUILD_PATHS[@]} -gt 0 ]]; then
    rm -rf "${TEMP_BUILD_PATHS[@]}"
  fi
}

verify_binary_target() {
  local binary_path="$1"
  local deployment_target="$2"
  local architectures minimum_version

  architectures="$(lipo -archs "${binary_path}")"
  if [[ "${architectures}" != "arm64" ]]; then
    echo "build-release-binaries.sh: ${binary_path} has unexpected architectures: ${architectures}" >&2
    exit 1
  fi
  minimum_version="$(vtool -show-build "${binary_path}" | awk '$1 == "minos" { print $2; exit }')"
  if [[ "${minimum_version}" != "${deployment_target}" ]]; then
    echo "build-release-binaries.sh: ${binary_path} targets macOS ${minimum_version:-unknown}, expected ${deployment_target}." >&2
    exit 1
  fi
}

binary_loader_paths() {
  local binary_path="$1"

  otool -l "${binary_path}" | awk '
    $1 == "cmd" && ($2 == "LC_RPATH" || $2 == "LC_LOAD_DYLINKER") {
      command = $2
      getline
      getline
      value = $0
      sub(/^[[:space:]]*(path|name)[[:space:]]+/, "", value)
      sub(/[[:space:]]+\(offset [0-9]+\)[[:space:]]*$/, "", value)
      print command "\t" value
    }
  '
}

verify_binary_load_paths() {
  local binary_path="$1"
  local load_command loader_path loader_paths dependencies

  loader_paths="$(binary_loader_paths "${binary_path}")" || return 1
  while IFS=$'\t' read -r load_command loader_path; do
    case "${load_command}:${loader_path}" in
      LC_LOAD_DYLINKER:/usr/lib/dyld)
        ;;
      *)
        echo "build-release-binaries.sh: ${binary_path} has an unsafe loader path: ${loader_path}" >&2
        exit 1
        ;;
    esac
  done <<<"${loader_paths}"

  dependencies="$(otool -L "${binary_path}" | tail -n +2 | sed -E 's/^[[:space:]]*//; s/[[:space:]]+\(compatibility version.*$//')" || return 1
  while IFS= read -r loader_path; do
    case "${loader_path}" in
      /usr/lib/*|/System/Library/*)
        ;;
      *)
        echo "build-release-binaries.sh: ${binary_path} has an unsafe dynamic dependency: ${loader_path}" >&2
        exit 1
        ;;
    esac
  done <<<"${dependencies}"
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

require_no_control_bytes() {
  if LC_ALL=C printf '%s' "$1" | grep -q '[[:cntrl:]]'; then
    echo "build-release-binaries.sh: refusing to write control bytes to build-info.json" >&2
    exit 1
  fi
}

require_clean_git_tree() {
  local changes

  if ! git -C "${ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "build-release-binaries.sh: release artifacts must be built from a git checkout." >&2
    exit 1
  fi

  SOURCE_GIT_COMMIT="$(git -C "${ROOT}" rev-parse --verify HEAD)"
  changes="$(git -C "$ROOT" status --porcelain=v1 --untracked-files=all --ignore-submodules=none)" || return 1
  if [[ -n "$changes" ]]; then
    echo "Builds require a clean Git working tree." >&2
    return 1
  fi
}

verify_prefix_hash() {
  local prefix="$1"
  local expected_hash="$2"
  local actual_hash

  actual_hash="$(python3 "$SOURCE_PACKAGE_ROOT/scripts/tree-sha256.py" "$prefix")"
  if [[ "${actual_hash}" != "${expected_hash}" ]]; then
    echo "build-release-binaries.sh: third-party prefix content changed or failed verification: ${prefix}" >&2
    exit 1
  fi
}

resolve_git_dir() {
  local override="$1"; shift
  local candidate

  if [[ -n "${override}" ]]; then
    printf '%s' "${override}"
    return 0
  fi
  for candidate in "$@"; do
    if git -C "${candidate}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

verify_pinned_dependencies() {
  local openvpn3_dir asio_dir

  openvpn3_dir="$(resolve_git_dir "${OPENVPN3_DIR:-}" "${ROOT}/openvpn3" "${WORKSPACE_ROOT}/openvpn3")" || {
    echo "build-release-binaries.sh: could not find the OpenVPN 3 source tree. Set OPENVPN3_DIR." >&2
    exit 1
  }
  asio_dir="$(resolve_git_dir "${ASIO_DIR:-}" "${WORKSPACE_ROOT}/asio" "${ROOT}/asio")" || {
    echo "build-release-binaries.sh: could not find the Asio source tree. Set ASIO_DIR." >&2
    exit 1
  }

  if ! git -C "${openvpn3_dir}" cat-file -e "${OPENVPN3_PINNED_COMMIT}^{commit}" 2>/dev/null; then
    echo "build-release-binaries.sh: openvpn3 at ${openvpn3_dir} does not contain pinned commit ${OPENVPN3_PINNED_COMMIT}." >&2
    exit 1
  fi
  if ! git -C "${asio_dir}" cat-file -e "${ASIO_PINNED_COMMIT}^{commit}" 2>/dev/null; then
    echo "build-release-binaries.sh: asio at ${asio_dir} does not contain pinned commit ${ASIO_PINNED_COMMIT}." >&2
    exit 1
  fi

  OPENVPN3_SOURCE_DIR="${openvpn3_dir}"
  ASIO_SOURCE_DIR="${asio_dir}"
}

prepare_release_sources() {
  local snapshot_root package_snapshot openvpn3_snapshot asio_snapshot

  snapshot_root="$(mktemp -d "${TMP_ROOT}/sources.XXXXXX")"
  package_snapshot="${snapshot_root}/cwru-ovpn"
  openvpn3_snapshot="${snapshot_root}/openvpn3"
  asio_snapshot="${snapshot_root}/asio"
  TEMP_BUILD_PATHS+=("${snapshot_root}")
  mkdir -p "${package_snapshot}" "${openvpn3_snapshot}" "${asio_snapshot}"

  git -C "${ROOT}" archive --format=tar "${SOURCE_GIT_COMMIT}" -- . ':(exclude)dist' \
    | tar -xf - -C "${package_snapshot}"
  git -C "${OPENVPN3_SOURCE_DIR}" archive --format=tar "${OPENVPN3_PINNED_COMMIT}" \
    | tar -xf - -C "${openvpn3_snapshot}"
  git -C "${ASIO_SOURCE_DIR}" archive --format=tar "${ASIO_PINNED_COMMIT}" \
    | tar -xf - -C "${asio_snapshot}"
  git -C "${openvpn3_snapshot}" apply "${package_snapshot}/scripts/patches/$(basename "${OPENVPN3_PATCH}")"

  [[ "$(python3 "$package_snapshot/scripts/tree-sha256.py" "$openvpn3_snapshot")" == "$OPENVPN3_TREE_SHA256" ]]
  [[ "$(python3 "$package_snapshot/scripts/tree-sha256.py" "$asio_snapshot")" == "$ASIO_TREE_SHA256" ]]
  SOURCE_TREE_SHA256="$(python3 "$package_snapshot/scripts/tree-sha256.py" "$package_snapshot" dist)"
  SOURCE_PACKAGE_ROOT="${package_snapshot}"
  RELEASE_OPENVPN3_DIR="${openvpn3_snapshot}"
  RELEASE_ASIO_DIR="${asio_snapshot}"
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

write_build_info() {
  local build_info_path="${DIST_DIR}/build-info.json"
  local temporary_build_info_path="${build_info_path}.tmp"
  local swift_version
  local index
  local output
  local hash
  local deployment_target
  local third_party_hash
  local third_party_metadata_hash
  local openvpn3_patch_name

  swift_version="$(swift --version | head -n 1)"
  openvpn3_patch_name="$(basename "${OPENVPN3_PATCH}")"

  require_no_control_bytes "${APP_VERSION}"
  require_no_control_bytes "${OPENVPN3_PINNED_COMMIT}"
  require_no_control_bytes "${ASIO_PINNED_COMMIT}"
  require_no_control_bytes "${openvpn3_patch_name}"
  require_no_control_bytes "${HOST_ARCH}"
  require_no_control_bytes "${MACOS_SDK_VERSION}"
  require_no_control_bytes "${swift_version}"
  for output in "${BUILT_OUTPUTS[@]}"; do
    require_no_control_bytes "${output}"
  done
  for deployment_target in "${BUILT_DEPLOYMENT_TARGETS[@]}"; do
    require_no_control_bytes "${deployment_target}"
  done
  for third_party_hash in "${BUILT_THIRD_PARTY_HASHES[@]}"; do
    require_no_control_bytes "${third_party_hash}"
  done
  for third_party_metadata_hash in "${BUILT_THIRD_PARTY_METADATA_HASHES[@]}"; do
    require_no_control_bytes "${third_party_metadata_hash}"
  done

  {
    printf '{\n'
    printf '  "appVersion": "%s",\n' "$(json_escape "${APP_VERSION}")"
    printf '  "configuration": "Release",\n'
    printf '  "signing": "ad-hoc",\n'
    printf '  "sourceDateEpoch": %s,\n' "$SOURCE_DATE_EPOCH"
    printf '  "sourceTreeSha256": "%s",\n' "$SOURCE_TREE_SHA256"
    printf '  "hostArch": "%s",\n' "$(json_escape "${HOST_ARCH}")"
    printf '  "macosSDKVersion": "%s",\n' "$(json_escape "${MACOS_SDK_VERSION}")"
    printf '  "swiftVersion": "%s",\n' "$(json_escape "${swift_version}")"
    printf '  "openvpn3Commit": "%s",\n' "$(json_escape "${OPENVPN3_PINNED_COMMIT}")"
    printf '  "openvpn3Patch": { "file": "%s", "sha256": "%s" },\n' "$(json_escape "${openvpn3_patch_name}")" "${OPENVPN3_PATCH_SHA256}"
    printf '  "asioCommit": "%s",\n' "$(json_escape "${ASIO_PINNED_COMMIT}")"
    printf '  "artifacts": [\n'
    for index in "${!BUILT_OUTPUTS[@]}"; do
      output="${BUILT_OUTPUTS[$index]}"
      deployment_target="${BUILT_DEPLOYMENT_TARGETS[$index]}"
      third_party_hash="${BUILT_THIRD_PARTY_HASHES[$index]}"
      third_party_metadata_hash="${BUILT_THIRD_PARTY_METADATA_HASHES[$index]}"
      hash="${BUILT_OUTPUT_HASHES[$index]}"
      printf '    { "file": "%s", "deploymentTarget": "%s", "sha256": "%s", "thirdPartyPrefixSha256": "%s", "thirdPartyBuildMetadataSha256": "%s" }' "$(json_escape "${output}")" "$(json_escape "${deployment_target}")" "${hash}" "${third_party_hash}" "${third_party_metadata_hash}"
      if [[ "${index}" -lt $((${#BUILT_OUTPUTS[@]} - 1)) ]]; then
        printf ','
      fi
      printf '\n'
    done
    printf '  ]\n'
    printf '}\n'
  } > "${temporary_build_info_path}"
  mv "${temporary_build_info_path}" "${build_info_path}"
}

trap cleanup_temp_build_paths EXIT

if [[ "${HOST_ARCH}" != "arm64" ]]; then
  echo "build-release-binaries.sh: packaged dist artifacts are arm64-only and must be built on Apple Silicon." >&2
  exit 1
fi

build_release_artifact() {
  local major_version="$1"
  local deployment_target="${major_version}.0"
  local build_path built_binary_path output_path third_party_build_root third_party_prefix
  local third_party_hash third_party_metadata_hash application_path output_hash

  build_path="$(mktemp -d "${BUILD_ROOT}/release-macos${major_version}.XXXXXX")"
  built_binary_path="${build_path}/release/cwru-ovpn"
  output_path="${DIST_DIR}/cwru-ovpn-macos${major_version}-arm64-ad-hoc.app.tar.gz"
  third_party_build_root="${build_path}/third-party"
  third_party_prefix="${third_party_build_root}/macos${major_version}/prefix"
  TEMP_BUILD_PATHS+=("${build_path}")

  echo "Building release binary for macOS ${deployment_target}"
  env CWRU_OVPN_THIRD_PARTY_BUILD_ROOT="${third_party_build_root}" \
    CWRU_OVPN_THIRD_PARTY_SOURCE_CACHE="${THIRD_PARTY_SOURCE_CACHE}" \
    CWRU_OVPN_FORCE_THIRD_PARTY_REBUILD=1 \
    "${SOURCE_PACKAGE_ROOT}/scripts/build-third-party-libs.sh" "${major_version}"

  third_party_hash="$(python3 "$SOURCE_PACKAGE_ROOT/scripts/tree-sha256.py" "$third_party_prefix")"
  third_party_metadata_hash="$(shasum -a 256 "${third_party_build_root}/macos${major_version}/build-metadata.txt" | awk '{print $1}')"

  local prefix_maps=()
  local mapping
  for mapping in "$RELEASE_OPENVPN3_DIR=/src/openvpn3" "$RELEASE_ASIO_DIR=/src/asio" "$SOURCE_PACKAGE_ROOT=/src/cwru-ovpn" "$build_path=/build"; do
    prefix_maps+=(-Xcc "-ffile-prefix-map=$mapping" -Xcxx "-ffile-prefix-map=$mapping"
                  -Xswiftc -file-prefix-map -Xswiftc "$mapping"
                  -Xswiftc -debug-prefix-map -Xswiftc "$mapping")
  done
  env -u OPENSSL_PREFIX \
    -u LZ4_PREFIX \
    -u FMT_PREFIX \
    HOME="${TMP_ROOT}/home" \
    SWIFTPM_MODULECACHE_OVERRIDE="${TMP_ROOT}/swiftpm-module-cache" \
    CLANG_MODULE_CACHE_PATH="${TMP_ROOT}/clang-module-cache" \
    OPENVPN3_DIR="${RELEASE_OPENVPN3_DIR}" \
    ASIO_DIR="${RELEASE_ASIO_DIR}" \
    CWRU_OVPN_MACOS_DEPLOYMENT_TARGET="${deployment_target}" \
    CWRU_OVPN_STATIC_THIRD_PARTY=1 \
    CWRU_OVPN_THIRD_PARTY_PREFIX="${third_party_prefix}" \
    swift build -c release -debug-info-format none --disable-sandbox \
    -Xlinker -S -Xlinker -reproducible -Xlinker -objc_stubs_small "${prefix_maps[@]}" \
    --package-path "${SOURCE_PACKAGE_ROOT}" \
    --cache-path "${TMP_ROOT}/swiftpm-cache" \
    --config-path "${TMP_ROOT}/swiftpm-config" \
    --security-path "${TMP_ROOT}/swiftpm-security" \
    --manifest-cache local \
    --build-path "${build_path}"

  verify_prefix_hash "${third_party_prefix}" "${third_party_hash}"
  python3 "$SOURCE_PACKAGE_ROOT/scripts/finalize-macho.py" "$built_binary_path"
  verify_binary_target "${built_binary_path}" "${deployment_target}"
  verify_binary_load_paths "${built_binary_path}"
  application_path="${build_path}/bundle/cwru-ovpn.app"
  /bin/bash "${SOURCE_PACKAGE_ROOT}/scripts/build-app-bundle.sh" "${built_binary_path}" "${application_path}"
  python3 "$SOURCE_PACKAGE_ROOT/scripts/archive-application.py" "$application_path" "$output_path" "$SOURCE_DATE_EPOCH"
  validate_application_archive "$output_path"
  mkdir "$build_path/verify"
  /usr/bin/tar -xzf "$output_path" -C "$build_path/verify"
  local extracted="$build_path/verify/cwru-ovpn.app"
  verify_binary_target "$extracted/Contents/MacOS/cwru-ovpn" "$deployment_target"
  verify_binary_load_paths "$extracted/Contents/MacOS/cwru-ovpn"
  verify_ad_hoc_signature "$extracted"
  "$application_path/Contents/MacOS/cwru-ovpn" verify-bundle "$extracted"
  output_hash="$(shasum -a 256 "${output_path}" | awk '{print $1}')"
  BUILT_OUTPUTS+=("$(basename "${output_path}")")
  BUILT_DEPLOYMENT_TARGETS+=("${deployment_target}")
  BUILT_THIRD_PARTY_HASHES+=("${third_party_hash}")
  BUILT_THIRD_PARTY_METADATA_HASHES+=("${third_party_metadata_hash}")
  BUILT_OUTPUT_HASHES+=("${output_hash}")
  rm -rf "${build_path}"
  remove_temp_build_path "${build_path}"
}

write_dist_checksums() (
  local index

  cd "${DIST_DIR}"
  : > SHA256SUMS.tmp
  for index in "${!BUILT_OUTPUTS[@]}"; do
    printf '%s  %s\n' "${BUILT_OUTPUT_HASHES[$index]}" "${BUILT_OUTPUTS[$index]}" >> SHA256SUMS.tmp
  done
  shasum -a 256 LICENSE THIRD_PARTY_NOTICES.md >> SHA256SUMS.tmp
  mv SHA256SUMS.tmp SHA256SUMS
)

install_dist_directory() {
  python3 - "$DIST_DIR" "$FINAL_DIST_DIR" <<'PYTHON'
import ctypes
import errno
import os
import stat
import sys

source, target = sys.argv[1:]
libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
while True:
    try:
        mode = os.lstat(target).st_mode
    except FileNotFoundError:
        try:
            os.rename(source, target)
            break
        except OSError as error:
            if error.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                raise
            continue
    if not stat.S_ISDIR(mode):
        raise RuntimeError("Invalid artifact output directory")
    if libc.renamex_np(os.fsencode(source), os.fsencode(target), 2) == 0:
        break
    error = ctypes.get_errno()
    if error != errno.ENOENT:
        raise OSError(error, os.strerror(error))
PYTHON
}

if [[ $# -gt 0 ]]; then
  MACOS_VERSIONS=("$@")
else
  MACOS_VERSIONS=(15 26 27)
fi

validate_macos_versions "${APP_VERSION}" "${MACOS_VERSIONS[@]}"
require_clean_git_tree
SOURCE_DATE_EPOCH="$(git -C "$ROOT" show -s --format=%ct "$SOURCE_GIT_COMMIT")"
export SOURCE_DATE_EPOCH
export ZERO_AR_DATE=1
verify_pinned_dependencies

mkdir -p "${BUILD_ROOT}"
DIST_DIR="$(mktemp -d "${BUILD_ROOT}/dist-stage.XXXXXX")"
TEMP_BUILD_PATHS+=("${DIST_DIR}")
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/cwru-ovpn-release.XXXXXX")"
TEMP_BUILD_PATHS+=("$TMP_ROOT")
mkdir -p \
  "${TMP_ROOT}/home" \
  "${TMP_ROOT}/swiftpm-module-cache" \
  "${TMP_ROOT}/swiftpm-cache" \
  "${TMP_ROOT}/swiftpm-config" \
  "${TMP_ROOT}/swiftpm-security" \
  "${TMP_ROOT}/clang-module-cache"
prepare_release_sources
APP_VERSION="$(app_identity_value version "${SOURCE_PACKAGE_ROOT}/Sources/cwru-ovpn/AppIdentity.swift")"
if [[ -z "${APP_VERSION}" ]]; then
  echo "build-release-binaries.sh: could not read the app version from prepared release sources." >&2
  exit 1
fi
OPENVPN3_PATCH_SHA256="$(shasum -a 256 "${SOURCE_PACKAGE_ROOT}/scripts/patches/$(basename "${OPENVPN3_PATCH}")" | awk '{ print $1 }')"
for MACOS_VERSION in "${MACOS_VERSIONS[@]}"; do
  build_release_artifact "${MACOS_VERSION}"
done

install -m 644 "${SOURCE_PACKAGE_ROOT}/LICENSE" "${SOURCE_PACKAGE_ROOT}/THIRD_PARTY_NOTICES.md" "${DIST_DIR}/"

write_dist_checksums
write_build_info
(cd "$DIST_DIR" && shasum -a 256 -c SHA256SUMS)
install_dist_directory
echo "Wrote verified artifacts to $FINAL_DIST_DIR"
