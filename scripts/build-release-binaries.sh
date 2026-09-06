#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FINAL_DIST_DIR="${ROOT}/dist"
DIST_DIR=""
BUILD_ROOT="${ROOT}/.build"
THIRD_PARTY_SOURCE_CACHE="${ROOT}/.build/third-party/sources"
TMP_ROOT="${TMPDIR:-/tmp}/cwru-ovpn-release"
TEMP_BUILD_PATHS=()
BUILT_OUTPUTS=()
BUILT_DEPLOYMENT_TARGETS=()
BUILT_TEAM_IDENTIFIERS=()
BUILT_THIRD_PARTY_HASHES=()
BUILT_THIRD_PARTY_METADATA_HASHES=()
BUILT_SIGNED_HASHES=()
CODESIGN_IDENTITY="${CWRU_OVPN_CODESIGN_IDENTITY:-}"
ALLOW_ADHOC_RELEASE="${CWRU_OVPN_ALLOW_ADHOC_RELEASE:-0}"
ALLOW_DIRTY_RELEASE="${CWRU_OVPN_ALLOW_DIRTY_RELEASE:-0}"
HOST_ARCH="$(uname -m)"
MACOS_SDK_VERSION="$(xcrun --sdk macosx --show-sdk-version)"
SOURCE_GIT_COMMIT="unknown"
SOURCE_GIT_DIRTY="unknown"
SOURCE_WORKTREE_FINGERPRINT=""
SOURCE_PACKAGE_ROOT="${ROOT}"
RELEASE_OPENVPN3_DIR=""
RELEASE_ASIO_DIR=""
APP_VERSION="$(awk -F'"' '/static let version/ { print $2; exit }' "${ROOT}/Sources/cwru-ovpn/AppIdentity.swift")"
WORKSPACE_ROOT="$(cd "${ROOT}/.." && pwd)"
OPENVPN3_PINNED_COMMIT="7f572f4fe647a36f5a1094cbeb261a5bcdae5047"
ASIO_PINNED_COMMIT="8806a6803cde7054c3049d3666d3ec36786568c5"
OPENVPN3_PATCH="${ROOT}/scripts/patches/openvpn3-cwru-policy.patch"
OPENVPN3_PATCH_SHA256=""
OPENVPN3_COMMIT="unknown"
ASIO_COMMIT="unknown"
OPENVPN3_SOURCE_DIR=""
ASIO_SOURCE_DIR=""

cleanup_temp_build_paths() {
  if [[ ${#TEMP_BUILD_PATHS[@]} -gt 0 ]]; then
    rm -rf "${TEMP_BUILD_PATHS[@]}"
  fi
}

sign_release_binary() {
  local output_path="$1"

  if [[ -z "${CODESIGN_IDENTITY}" ]]; then
    if [[ "${ALLOW_ADHOC_RELEASE}" != "1" ]]; then
      echo "build-release-binaries.sh: CWRU_OVPN_CODESIGN_IDENTITY is required for release artifacts." >&2
      echo "build-release-binaries.sh: set CWRU_OVPN_ALLOW_ADHOC_RELEASE=1 only for local test artifacts." >&2
      exit 1
    fi
    codesign --force --options runtime --sign - "${output_path}"
    codesign --verify --deep --strict --verbose=2 "${output_path}"
    echo "Ad-hoc signed ${output_path} for local testing only."
    return
  fi

  codesign --force --options runtime --timestamp --sign "${CODESIGN_IDENTITY}" "${output_path}"
  codesign --verify --deep --strict --verbose=2 "${output_path}"
}

team_identifier_for_binary() {
  local output_path="$1"
  local team_identifier

  team_identifier="$(codesign -d --verbose=4 "${output_path}" 2>&1 | awk -F= '/^TeamIdentifier=/ { print $2; exit }')"
  printf '%s' "${team_identifier:-not set}"
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

sanitize_binary_rpaths() {
  local binary_path="$1"
  local load_command loader_path loader_paths

  loader_paths="$(binary_loader_paths "${binary_path}")" || return 1
  while IFS=$'\t' read -r load_command loader_path; do
    [[ "${load_command}" == "LC_RPATH" ]] || continue
    case "${loader_path}" in
      /usr/lib/*|/System/Library/*|@loader_path|@executable_path)
        ;;
      *)
        install_name_tool -delete_rpath "${loader_path}" "${binary_path}" || return 1
        ;;
    esac
  done <<<"${loader_paths}"
}

verify_binary_load_paths() {
  local binary_path="$1"
  local load_command loader_path loader_paths dependencies

  loader_paths="$(binary_loader_paths "${binary_path}")" || return 1
  while IFS=$'\t' read -r load_command loader_path; do
    case "${load_command}:${loader_path}" in
      LC_RPATH:/usr/lib/*|LC_RPATH:/System/Library/*|LC_RPATH:@loader_path|LC_RPATH:@executable_path|LC_LOAD_DYLINKER:/usr/lib/*|LC_LOAD_DYLINKER:/System/Library/*)
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
  local untracked_files

  if ! git -C "${ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "build-release-binaries.sh: release artifacts must be built from a git checkout." >&2
    exit 1
  fi

  SOURCE_GIT_COMMIT="$(git -C "${ROOT}" rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"
  untracked_files="$(git -C "${ROOT}" ls-files --others --exclude-standard 2>/dev/null || true)"
  if git -C "${ROOT}" diff --quiet --ignore-submodules HEAD -- 2>/dev/null && [[ -z "${untracked_files}" ]]; then
    SOURCE_GIT_DIRTY="false"
    return
  fi

  if [[ "${ALLOW_DIRTY_RELEASE}" == "1" ]]; then
    if [[ -n "${CODESIGN_IDENTITY}" ]]; then
      echo "build-release-binaries.sh: dirty local builds cannot use CWRU_OVPN_CODESIGN_IDENTITY." >&2
      exit 1
    fi
    if [[ "${ALLOW_ADHOC_RELEASE}" != "1" ]]; then
      echo "build-release-binaries.sh: dirty local builds require CWRU_OVPN_ALLOW_ADHOC_RELEASE=1." >&2
      exit 1
    fi
    SOURCE_GIT_DIRTY="true"
    echo "build-release-binaries.sh: WARNING: building from a dirty tree because CWRU_OVPN_ALLOW_DIRTY_RELEASE=1." >&2
    return
  fi

  echo "build-release-binaries.sh: refusing to build release artifacts from a dirty tree." >&2
  echo "build-release-binaries.sh: commit/stash changes, or set CWRU_OVPN_ALLOW_DIRTY_RELEASE=1 for local test artifacts." >&2
  exit 1
}

source_worktree_fingerprint() {
  (
    cd "${ROOT}"
    git ls-files --cached --others --exclude-standard -z -- . ':(exclude)dist/**' \
      | while IFS= read -r -d '' file_path; do
          if [[ -L "${file_path}" ]]; then
            printf 'symlink %s %s\n' "${file_path}" "$(readlink "${file_path}")"
          elif [[ -f "${file_path}" ]]; then
            printf 'file %s %s\n' "${file_path}" "$(shasum -a 256 "${file_path}" | awk '{print $1}')"
          else
            printf 'missing %s\n' "${file_path}"
          fi
        done \
      | shasum -a 256 \
      | awk '{print $1}'
  )
}

verify_source_worktree_unchanged() {
  local current_commit current_fingerprint

  current_commit="$(git -C "${ROOT}" rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"
  current_fingerprint="$(source_worktree_fingerprint)"
  if [[ "${current_commit}" != "${SOURCE_GIT_COMMIT}" \
        || "${current_fingerprint}" != "${SOURCE_WORKTREE_FINGERPRINT}" ]]; then
    echo "build-release-binaries.sh: source inputs changed after release preparation; refusing mixed-source artifacts." >&2
    exit 1
  fi
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

verify_prefix_hash() {
  local prefix="$1"
  local expected_hash="$2"
  local actual_hash

  actual_hash="$(prefix_content_sha256 "${prefix}")"
  if [[ "${actual_hash}" != "${expected_hash}" ]]; then
    echo "build-release-binaries.sh: third-party prefix content changed or failed verification: ${prefix}" >&2
    exit 1
  fi
}

verify_built_outputs_unchanged() {
  local index output expected_hash actual_hash

  for index in "${!BUILT_OUTPUTS[@]}"; do
    output="${DIST_DIR}/${BUILT_OUTPUTS[$index]}"
    expected_hash="${BUILT_SIGNED_HASHES[$index]}"
    actual_hash="$(shasum -a 256 "${output}" | awk '{print $1}')"
    if [[ "${actual_hash}" != "${expected_hash}" ]]; then
      echo "build-release-binaries.sh: packaged output changed after signing: ${output}" >&2
      exit 1
    fi
    codesign --verify --deep --strict --verbose=2 "${output}"
  done
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

require_no_untracked_files() {
  local repo_dir="$1"
  local label="$2"
  local untracked_files

  untracked_files="$(git -C "${repo_dir}" ls-files --others 2>/dev/null || true)"
  if [[ -n "${untracked_files}" ]]; then
    echo "build-release-binaries.sh: ${label} at ${repo_dir} has untracked files; remove them before building release artifacts." >&2
    exit 1
  fi
}

verify_openvpn3_patch() (
  local repo_dir="$1"
  local temporary_dir objects_dir expected_tree actual_tree

  temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/cwru-ovpn-patch-check.XXXXXX")" || return 1
  trap 'rm -rf "${temporary_dir}"' EXIT
  objects_dir="$(git -C "${repo_dir}" rev-parse --path-format=absolute --git-path objects)" || return 1
  mkdir "${temporary_dir}/objects" || return 1
  export GIT_INDEX_FILE="${temporary_dir}/index"
  export GIT_OBJECT_DIRECTORY="${temporary_dir}/objects"
  export GIT_ALTERNATE_OBJECT_DIRECTORIES="${objects_dir}"
  git -C "${repo_dir}" read-tree "${OPENVPN3_PINNED_COMMIT}" || return 1
  git -C "${repo_dir}" apply --cached "${OPENVPN3_PATCH}" || return 1
  expected_tree="$(git -C "${repo_dir}" write-tree)" || return 1
  git -C "${repo_dir}" read-tree "${OPENVPN3_PINNED_COMMIT}" || return 1
  git -C "${repo_dir}" add -u -- . || return 1
  actual_tree="$(git -C "${repo_dir}" write-tree)" || return 1
  [[ "${actual_tree}" == "${expected_tree}" ]]
)

verify_pinned_dependencies() {
  local openvpn3_dir asio_dir actual

  openvpn3_dir="$(resolve_git_dir "${OPENVPN3_DIR:-}" "${ROOT}/openvpn3" "${WORKSPACE_ROOT}/openvpn3")" || {
    echo "build-release-binaries.sh: could not locate the OpenVPN 3 source tree; set OPENVPN3_DIR." >&2
    exit 1
  }
  asio_dir="$(resolve_git_dir "${ASIO_DIR:-}" "${WORKSPACE_ROOT}/asio" "${ROOT}/asio")" || {
    echo "build-release-binaries.sh: could not locate the Asio source tree; set ASIO_DIR." >&2
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

  if [[ "${SOURCE_GIT_DIRTY}" == "true" ]]; then
    actual="$(git -C "${openvpn3_dir}" rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"
    [[ "${actual}" == "${OPENVPN3_PINNED_COMMIT}" ]] || {
      echo "build-release-binaries.sh: dirty builds require openvpn3 HEAD ${OPENVPN3_PINNED_COMMIT}." >&2
      exit 1
    }
    require_no_untracked_files "${openvpn3_dir}" "openvpn3"
    verify_openvpn3_patch "${openvpn3_dir}" || {
      echo "build-release-binaries.sh: dirty builds require exactly the pinned OpenVPN 3 patch." >&2
      exit 1
    }
    actual="$(git -C "${asio_dir}" rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"
    [[ "${actual}" == "${ASIO_PINNED_COMMIT}" ]] || {
      echo "build-release-binaries.sh: dirty builds require asio HEAD ${ASIO_PINNED_COMMIT}." >&2
      exit 1
    }
    require_no_untracked_files "${asio_dir}" "asio"
    git -C "${asio_dir}" -c diff.external= diff --no-ext-diff --quiet HEAD || {
      echo "build-release-binaries.sh: dirty builds require a clean asio worktree." >&2
      exit 1
    }
  fi

  OPENVPN3_COMMIT="${OPENVPN3_PINNED_COMMIT}"
  ASIO_COMMIT="${ASIO_PINNED_COMMIT}"
  OPENVPN3_SOURCE_DIR="${openvpn3_dir}"
  ASIO_SOURCE_DIR="${asio_dir}"
}

prepare_release_sources() {
  local snapshot_root package_snapshot openvpn3_snapshot asio_snapshot

  if [[ "${SOURCE_GIT_DIRTY}" == "true" ]]; then
    SOURCE_PACKAGE_ROOT="${ROOT}"
    RELEASE_OPENVPN3_DIR="${OPENVPN3_SOURCE_DIR}"
    RELEASE_ASIO_DIR="${ASIO_SOURCE_DIR}"
    return
  fi

  snapshot_root="$(mktemp -d "${TMP_ROOT}/sources.XXXXXX")"
  package_snapshot="${snapshot_root}/cwru-ovpn"
  openvpn3_snapshot="${snapshot_root}/openvpn3"
  asio_snapshot="${snapshot_root}/asio"
  TEMP_BUILD_PATHS+=("${snapshot_root}")
  mkdir -p "${package_snapshot}" "${openvpn3_snapshot}" "${asio_snapshot}"

  git -C "${ROOT}" archive --format=tar "${SOURCE_GIT_COMMIT}" \
    | tar -xf - -C "${package_snapshot}"
  git -C "${OPENVPN3_SOURCE_DIR}" archive --format=tar "${OPENVPN3_PINNED_COMMIT}" \
    | tar -xf - -C "${openvpn3_snapshot}"
  git -C "${ASIO_SOURCE_DIR}" archive --format=tar "${ASIO_PINNED_COMMIT}" \
    | tar -xf - -C "${asio_snapshot}"
  git -C "${openvpn3_snapshot}" apply "${package_snapshot}/scripts/patches/$(basename "${OPENVPN3_PATCH}")"

  SOURCE_PACKAGE_ROOT="${package_snapshot}"
  RELEASE_OPENVPN3_DIR="${openvpn3_snapshot}"
  RELEASE_ASIO_DIR="${asio_snapshot}"
}

verify_live_release_inputs_unchanged() {
  verify_source_worktree_unchanged
  verify_pinned_dependencies
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

write_build_info() {
  local build_info_path="${DIST_DIR}/build-info.json"
  local temporary_build_info_path="${build_info_path}.tmp"
  local git_commit="unknown"
  local git_dirty="unknown"
  local swift_version
  local index
  local output
  local hash
  local deployment_target
  local team_identifier
  local third_party_hash
  local third_party_metadata_hash
  local openvpn3_patch_name

  git_commit="${SOURCE_GIT_COMMIT}"
  git_dirty="${SOURCE_GIT_DIRTY}"
  swift_version="$(swift --version | head -n 1)"
  openvpn3_patch_name="$(basename "${OPENVPN3_PATCH}")"

  require_no_control_bytes "${APP_VERSION}"
  require_no_control_bytes "${OPENVPN3_COMMIT}"
  require_no_control_bytes "${ASIO_COMMIT}"
  require_no_control_bytes "${openvpn3_patch_name}"
  require_no_control_bytes "${git_commit}"
  require_no_control_bytes "${HOST_ARCH}"
  require_no_control_bytes "${MACOS_SDK_VERSION}"
  require_no_control_bytes "${swift_version}"
  for output in "${BUILT_OUTPUTS[@]}"; do
    require_no_control_bytes "${output}"
  done
  for deployment_target in "${BUILT_DEPLOYMENT_TARGETS[@]}"; do
    require_no_control_bytes "${deployment_target}"
  done
  for team_identifier in "${BUILT_TEAM_IDENTIFIERS[@]}"; do
    require_no_control_bytes "${team_identifier}"
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
    printf '  "gitCommit": "%s",\n' "$(json_escape "${git_commit}")"
    printf '  "gitDirty": %s,\n' "${git_dirty}"
    printf '  "hostArch": "%s",\n' "$(json_escape "${HOST_ARCH}")"
    printf '  "macosSDKVersion": "%s",\n' "$(json_escape "${MACOS_SDK_VERSION}")"
    printf '  "swiftVersion": "%s",\n' "$(json_escape "${swift_version}")"
    printf '  "openvpn3Commit": "%s",\n' "$(json_escape "${OPENVPN3_COMMIT}")"
    printf '  "openvpn3Patch": { "file": "%s", "sha256": "%s" },\n' "$(json_escape "${openvpn3_patch_name}")" "${OPENVPN3_PATCH_SHA256}"
    printf '  "asioCommit": "%s",\n' "$(json_escape "${ASIO_COMMIT}")"
    printf '  "artifacts": [\n'
    for index in "${!BUILT_OUTPUTS[@]}"; do
      output="${BUILT_OUTPUTS[$index]}"
      deployment_target="${BUILT_DEPLOYMENT_TARGETS[$index]}"
      team_identifier="${BUILT_TEAM_IDENTIFIERS[$index]}"
      third_party_hash="${BUILT_THIRD_PARTY_HASHES[$index]}"
      third_party_metadata_hash="${BUILT_THIRD_PARTY_METADATA_HASHES[$index]}"
      hash="${BUILT_SIGNED_HASHES[$index]}"
      printf '    { "file": "%s", "deploymentTarget": "%s", "sha256": "%s", "teamIdentifier": "%s", "thirdPartyPrefixSha256": "%s", "thirdPartyBuildMetadataSha256": "%s" }' "$(json_escape "${output}")" "$(json_escape "${deployment_target}")" "${hash}" "$(json_escape "${team_identifier}")" "${third_party_hash}" "${third_party_metadata_hash}"
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

validate_macos_versions() {
  local major_version

  for major_version in "$@"; do
    if [[ ! "${major_version}" =~ ^[0-9]+$ ]]; then
      echo "build-release-binaries.sh: invalid macOS major version '${major_version}'." >&2
      exit 1
    fi
    if [[ "${major_version}" -lt 15 ]]; then
      echo "build-release-binaries.sh: cwru-ovpn ${APP_VERSION} supports macOS 15 or later." >&2
      exit 1
    fi
  done
}

ensure_private_tmp_root() {
  local tmp_root="$1"
  mkdir -p "${tmp_root}"
  if [[ -L "${tmp_root}" || ! -d "${tmp_root}" ]]; then
    echo "build-release-binaries.sh: refusing unsafe temporary build directory ${tmp_root}" >&2
    exit 1
  fi
  if [[ "$(stat -f '%u' "${tmp_root}")" != "$(id -u)" ]]; then
    echo "build-release-binaries.sh: temporary build directory ${tmp_root} is not owned by the current user" >&2
    exit 1
  fi
  chmod 700 "${tmp_root}"
}

trap cleanup_temp_build_paths EXIT

if [[ "${HOST_ARCH}" != "arm64" ]]; then
  echo "build-release-binaries.sh: packaged dist artifacts are arm64-only and must be built on Apple Silicon." >&2
  exit 1
fi

if [[ $# -gt 0 ]]; then
  MACOS_VERSIONS=("$@")
else
  MACOS_VERSIONS=(15 26 27)
fi

validate_macos_versions "${MACOS_VERSIONS[@]}"
require_clean_git_tree
verify_pinned_dependencies
if [[ "${SOURCE_GIT_DIRTY}" == "true" ]]; then
  SOURCE_WORKTREE_FINGERPRINT="$(source_worktree_fingerprint)"
fi

mkdir -p "${BUILD_ROOT}"
DIST_DIR="$(mktemp -d "${BUILD_ROOT}/dist-stage.XXXXXX")"
TEMP_BUILD_PATHS+=("${DIST_DIR}")
ensure_private_tmp_root "${TMP_ROOT}"
mkdir -p \
  "${TMP_ROOT}/home" \
  "${TMP_ROOT}/swiftpm-module-cache" \
  "${TMP_ROOT}/swiftpm-cache" \
  "${TMP_ROOT}/swiftpm-config" \
  "${TMP_ROOT}/swiftpm-security" \
  "${TMP_ROOT}/clang-module-cache"
prepare_release_sources
APP_VERSION="$(awk -F'"' '/static let version/ { print $2; exit }' "${SOURCE_PACKAGE_ROOT}/Sources/cwru-ovpn/AppIdentity.swift")"
if [[ -z "${APP_VERSION}" ]]; then
  echo "build-release-binaries.sh: could not read the app version from prepared release sources." >&2
  exit 1
fi
OPENVPN3_PATCH_SHA256="$(shasum -a 256 "${SOURCE_PACKAGE_ROOT}/scripts/patches/$(basename "${OPENVPN3_PATCH}")" | awk '{ print $1 }')"
if [[ "${SOURCE_GIT_DIRTY}" == "true" ]]; then
  verify_live_release_inputs_unchanged
fi
for major_version in "${MACOS_VERSIONS[@]}"; do
  deployment_target="${major_version}.0"
  build_path="$(mktemp -d "${BUILD_ROOT}/release-macos${major_version}.XXXXXX")"
  built_binary_path="${build_path}/release/cwru-ovpn"
  output_path="${DIST_DIR}/cwru-ovpn-macos${major_version}-arm64"
  third_party_build_root="${build_path}/third-party"
  third_party_prefix="${third_party_build_root}/macos${major_version}/prefix"
  TEMP_BUILD_PATHS+=("${build_path}")

  echo "Building release binary for macOS ${deployment_target}"
  if [[ "${SOURCE_GIT_DIRTY}" == "true" ]]; then
    verify_live_release_inputs_unchanged
  fi
  env CWRU_OVPN_THIRD_PARTY_BUILD_ROOT="${third_party_build_root}" \
    CWRU_OVPN_THIRD_PARTY_SOURCE_CACHE="${THIRD_PARTY_SOURCE_CACHE}" \
    CWRU_OVPN_FORCE_THIRD_PARTY_REBUILD=1 \
    "${SOURCE_PACKAGE_ROOT}/scripts/build-third-party-libs.sh" "${major_version}"
  if [[ "${SOURCE_GIT_DIRTY}" == "true" ]]; then
    verify_live_release_inputs_unchanged
  fi

  third_party_hash="$(prefix_content_sha256 "${third_party_prefix}")"
  third_party_metadata_hash="$(shasum -a 256 "${third_party_build_root}/macos${major_version}/build-metadata.txt" | awk '{print $1}')"

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
    swift build -c release --disable-sandbox \
    --package-path "${SOURCE_PACKAGE_ROOT}" \
    --cache-path "${TMP_ROOT}/swiftpm-cache" \
    --config-path "${TMP_ROOT}/swiftpm-config" \
    --security-path "${TMP_ROOT}/swiftpm-security" \
    --manifest-cache local \
    --build-path "${build_path}"

  verify_prefix_hash "${third_party_prefix}" "${third_party_hash}"
  if [[ "${SOURCE_GIT_DIRTY}" == "true" ]]; then
    verify_live_release_inputs_unchanged
  fi
  sanitize_binary_rpaths "${built_binary_path}"
  verify_binary_target "${built_binary_path}" "${deployment_target}"
  verify_binary_load_paths "${built_binary_path}"
  sign_release_binary "${built_binary_path}"
  team_identifier="$(team_identifier_for_binary "${built_binary_path}")"
  signed_hash="$(shasum -a 256 "${built_binary_path}" | awk '{print $1}')"
  install -m 755 "${built_binary_path}" "${output_path}"
  BUILT_OUTPUTS+=("$(basename "${output_path}")")
  BUILT_DEPLOYMENT_TARGETS+=("${deployment_target}")
  BUILT_THIRD_PARTY_HASHES+=("${third_party_hash}")
  BUILT_THIRD_PARTY_METADATA_HASHES+=("${third_party_metadata_hash}")
  BUILT_TEAM_IDENTIFIERS+=("${team_identifier}")
  BUILT_SIGNED_HASHES+=("${signed_hash}")
  verify_built_outputs_unchanged
  rm -rf "${build_path}"
  remove_temp_build_path "${build_path}"

  if command -v vtool >/dev/null 2>&1; then
    echo "Build metadata for ${output_path}:"
    vtool -show-build "${output_path}" | sed 's/^/  /'
  fi
done

if [[ "${SOURCE_GIT_DIRTY}" == "true" ]]; then
  verify_live_release_inputs_unchanged
fi
verify_built_outputs_unchanged

(
  cd "${DIST_DIR}"
  : > SHA256SUMS.tmp
  for index in "${!BUILT_OUTPUTS[@]}"; do
    printf '%s  %s\n' "${BUILT_SIGNED_HASHES[$index]}" "${BUILT_OUTPUTS[$index]}" >> SHA256SUMS.tmp
  done
  mv SHA256SUMS.tmp SHA256SUMS
)

if [[ "${SOURCE_GIT_DIRTY}" == "true" ]]; then
  verify_live_release_inputs_unchanged
fi
verify_built_outputs_unchanged
write_build_info
verify_built_outputs_unchanged
backup_dist_dir="${BUILD_ROOT}/dist-backup.$$"
rm -rf "${backup_dist_dir}"
if [[ -e "${FINAL_DIST_DIR}" ]]; then
  mv "${FINAL_DIST_DIR}" "${backup_dist_dir}"
fi
if ! mv "${DIST_DIR}" "${FINAL_DIST_DIR}"; then
  if [[ -e "${backup_dist_dir}" ]]; then
    mv "${backup_dist_dir}" "${FINAL_DIST_DIR}"
  fi
  exit 1
fi
remove_temp_build_path "${DIST_DIR}"
DIST_DIR="${FINAL_DIST_DIR}"
rm -rf "${backup_dist_dir}"
verify_built_outputs_unchanged
echo "Wrote dist/SHA256SUMS"
echo "Wrote dist/build-info.json"
