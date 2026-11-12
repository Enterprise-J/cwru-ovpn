#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/scripts/common.sh"

if [[ ${EUID} -eq 0 ]]; then
  cat >&2 <<EOF
setup.sh: run this script as your normal user, not via sudo.
It uses sudo only for the privileged install steps so your config, profile, and shell integration stay in your account.
EOF
  exit 1
fi

STATE_DIR="${HOME}/.cwru-ovpn"
CONFIG_PATH="${STATE_DIR}/config.json"
PROFILE_PATH="${STATE_DIR}/profile.ovpn"
PRIVILEGED_INSTALL_DIR="/Library/PrivilegedHelperTools/cwru-ovpn"
PRIVILEGED_INSTALL_BIN="${PRIVILEGED_INSTALL_DIR}/cwru-ovpn.app/Contents/MacOS/cwru-ovpn"
DIST_DIR="${ROOT}/dist"
EXAMPLE_CONFIG="${ROOT}/examples/cwru-ovpn.config.example.json"
LOCAL_RELEASE_BIN="${ROOT}/.build/release/cwru-ovpn"
ALIASES_SRC="${ROOT}/scripts/cwru-ovpn.zsh"
ALIASES_INSTALLED="${STATE_DIR}/cwru-ovpn.zsh"
EXPECTED_APP_VERSION="$(app_identity_value version "${ROOT}/Sources/cwru-ovpn/AppIdentity.swift")"

MACOS_MAJOR_VERSION="$(sw_vers -productVersion | cut -d '.' -f1)"
if [[ "${MACOS_MAJOR_VERSION}" -lt 15 ]]; then
  echo "setup.sh: cwru-ovpn ${EXPECTED_APP_VERSION} supports macOS 15 or later." >&2
  exit 1
fi

if [[ "$(uname -m)" != "arm64" ]]; then
  echo "setup.sh: Apple Silicon is required." >&2
  exit 1
fi
DIST_ARCHIVE="${DIST_DIR}/cwru-ovpn-macos${MACOS_MAJOR_VERSION}-arm64.app.tar.gz"
PROFILE_SOURCE=""
INSTALL_SOURCE_ARCHIVE="${DIST_ARCHIVE}"
INSTALL_SOURCE_BIN=""
INSTALL_SOURCE_APP=""
INSTALL_WORK_DIR=""
STAGED_INSTALL_DIR=""
INSTALL_SOURCE_IS_DIST=1
STAGED_INSTALL_BIN=""
ALLOW_QUARANTINE_REMOVAL=0
ALLOW_LOCAL_BUILD_INSTALL="${CWRU_OVPN_ALLOW_LOCAL_BUILD_INSTALL:-0}"
ALLOW_ADHOC_RELEASE="${CWRU_OVPN_ALLOW_ADHOC_RELEASE:-0}"
ADHOC_RELEASE_NOTICE_PRINTED=0
DIST_BUILD_INFO_TEAM_IDENTIFIER=""
EXPECTED_RELEASE_TEAM_IDENTIFIER=""

cleanup_staged_install() {
  if [[ -n "${STAGED_INSTALL_DIR}" && -d "${STAGED_INSTALL_DIR}" ]]; then
    sudo /bin/rm -rf "${STAGED_INSTALL_DIR}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${INSTALL_WORK_DIR}" && -d "${INSTALL_WORK_DIR}" ]]; then
    /bin/rm -rf "${INSTALL_WORK_DIR}"
  fi
}
trap cleanup_staged_install EXIT

require_local_build_install_allowed() {
  local reason="$1"

  if [[ "${ALLOW_LOCAL_BUILD_INSTALL}" == "1" ]]; then
    echo "setup.sh: ${reason}" >&2
    echo "setup.sh: using a local build because --allow-local-build-install or CWRU_OVPN_ALLOW_LOCAL_BUILD_INSTALL=1 was set" >&2
    return
  fi

  echo "setup.sh: ${reason}" >&2
  cat >&2 <<EOF
setup.sh: refusing to install a locally built privileged binary by default.
Release installs require a verified Developer ID prebuilt artifact.
For local development only, rerun with:
  ./scripts/setup.sh --allow-local-build-install
or set:
  CWRU_OVPN_ALLOW_LOCAL_BUILD_INSTALL=1
EOF
  exit 1
}

print_gatekeeper_bypass_instructions() {
  local artifact_path="$1"

  echo "setup.sh: macOS may block this artifact after a browser download." >&2
  echo "After verifying the artifact source, run once:" >&2
  printf '  xattr -d com.apple.quarantine %q\n' "${artifact_path}" >&2
  echo >&2
  echo "Alternatively rerun setup with --remove-quarantine-after-verification." >&2
}

handle_quarantine_if_present() {
  local artifact_path="$1"

  if ! command -v xattr >/dev/null 2>&1; then
    return
  fi

  if xattr -p com.apple.quarantine "${artifact_path}" >/dev/null 2>&1; then
    if [[ "${ALLOW_QUARANTINE_REMOVAL}" -ne 1 ]]; then
      echo "setup.sh: refusing to auto-remove macOS quarantine from ${artifact_path}" >&2
      print_gatekeeper_bypass_instructions "${artifact_path}"
      exit 1
    fi

    echo "setup.sh: removing macOS quarantine attribute from ${artifact_path} after explicit request"
    if ! xattr -d com.apple.quarantine "${artifact_path}"; then
      echo "setup.sh: failed to remove macOS quarantine attribute from ${artifact_path}" >&2
      exit 1
    fi
  fi
}

verify_dist_archive_file() {
  local archive_path="$1"
  local sums_path="${DIST_DIR}/SHA256SUMS"
  local archive_name expected_sha actual_sha

  if [[ ! -f "${sums_path}" ]]; then
    echo "setup.sh: missing ${sums_path}; refusing to install an unverifiable prebuilt binary" >&2
    exit 1
  fi

  archive_name="$(basename "${DIST_ARCHIVE}")"
  expected_sha="$(awk -v name="${archive_name}" '$2 == name { print $1 }' "${sums_path}")"
  if [[ -z "${expected_sha}" ]]; then
    echo "setup.sh: ${sums_path} does not contain a checksum for ${archive_name}" >&2
    exit 1
  fi

  actual_sha="$(shasum -a 256 "${archive_path}" | awk '{ print $1 }')"
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    echo "setup.sh: checksum mismatch for ${archive_path}" >&2
    echo "setup.sh: expected ${expected_sha}" >&2
    echo "setup.sh:   actual ${actual_sha}" >&2
    exit 1
  fi
}

read_dist_build_info_app_version() {
  /usr/bin/plutil -extract appVersion raw -expect string -o - "${DIST_DIR}/build-info.json" 2>/dev/null
}

read_dist_build_info_artifact_field() {
  local requested_artifact_name="$1"
  local field_name="$2"
  local build_info_path="${DIST_DIR}/build-info.json"
  local index=0 artifact_name

  while artifact_name="$(/usr/bin/plutil -extract "artifacts.${index}.file" raw -expect string -o - "${build_info_path}" 2>/dev/null)"; do
    if [[ "${artifact_name}" == "${requested_artifact_name}" ]]; then
      /usr/bin/plutil -extract "artifacts.${index}.${field_name}" raw -expect string -o - "${build_info_path}" 2>/dev/null
      return
    fi
    index=$((index + 1))
  done
  return 1
}

verify_dist_build_info_file() {
  local archive_path="$1"
  local build_info_path="${DIST_DIR}/build-info.json"
  local app_version archive_name deployment_target expected_deployment_target expected_sha actual_sha

  if [[ ! -f "${build_info_path}" ]]; then
    echo "setup.sh: missing ${build_info_path}; refusing to install an unverifiable prebuilt binary" >&2
    exit 1
  fi

  app_version="$(read_dist_build_info_app_version)" || app_version=""
  if [[ "${app_version}" != "${EXPECTED_APP_VERSION}" ]]; then
    echo "setup.sh: ${build_info_path} appVersion is ${app_version:-unknown}, expected ${EXPECTED_APP_VERSION}" >&2
    echo "setup.sh: rebuild release artifacts with ./scripts/build-release-binaries.sh" >&2
    exit 1
  fi

  archive_name="$(basename "${DIST_ARCHIVE}")"
  deployment_target="$(read_dist_build_info_artifact_field "${archive_name}" "deploymentTarget")" || deployment_target=""
  expected_deployment_target="${MACOS_MAJOR_VERSION}.0"
  if [[ "${deployment_target}" != "${expected_deployment_target}" ]]; then
    echo "setup.sh: ${build_info_path} deploymentTarget for ${archive_name} is ${deployment_target:-unknown}, expected ${expected_deployment_target}" >&2
    echo "setup.sh: rebuild release artifacts with ./scripts/build-release-binaries.sh" >&2
    exit 1
  fi

  expected_sha="$(read_dist_build_info_artifact_field "${archive_name}" "sha256")" || expected_sha=""
  if [[ -z "${expected_sha}" ]]; then
    echo "setup.sh: ${build_info_path} does not contain a sha256 for ${archive_name}" >&2
    exit 1
  fi
  actual_sha="$(shasum -a 256 "${archive_path}" | awk '{ print $1 }')"
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    echo "setup.sh: ${build_info_path} sha256 mismatch for ${archive_name}" >&2
    echo "setup.sh: expected ${expected_sha}" >&2
    echo "setup.sh:   actual ${actual_sha}" >&2
    exit 1
  fi

  DIST_BUILD_INFO_TEAM_IDENTIFIER="$(read_dist_build_info_artifact_field "${archive_name}" "teamIdentifier")" || DIST_BUILD_INFO_TEAM_IDENTIFIER=""
}

verify_dist_signature_for_release() {
  local application_path="$1"
  local signature_details team_identifier

  if ! command -v codesign >/dev/null 2>&1; then
    echo "setup.sh: codesign is unavailable; cannot verify ${application_path} as a release artifact" >&2
    return 1
  fi

  if ! signature_details="$(codesign -d --verbose=4 "${application_path}" 2>&1)"; then
    echo "setup.sh: ${application_path} is unsigned or has no readable code signature" >&2
    return 1
  fi

  if ! codesign --verify --deep --strict --verbose=2 "${application_path}" >/dev/null 2>&1; then
    echo "setup.sh: code signature verification failed for ${application_path}" >&2
    return 1
  fi

  if ! LC_ALL=C grep -q '^Authority=Developer ID Application:' <<<"${signature_details}"; then
    if [[ "${ALLOW_ADHOC_RELEASE}" == "1" ]]; then
      if [[ "${ADHOC_RELEASE_NOTICE_PRINTED}" != "1" ]]; then
        echo "setup.sh: accepting non-Developer ID signed artifact because CWRU_OVPN_ALLOW_ADHOC_RELEASE=1 is set" >&2
        echo "setup.sh: this install path is for local/ad-hoc artifacts and will not satisfy Gatekeeper release provenance" >&2
        ADHOC_RELEASE_NOTICE_PRINTED=1
      fi
      return 0
    fi
    echo "setup.sh: ${application_path} is not signed with a Developer ID Application certificate" >&2
    return 1
  fi

  team_identifier="$(awk -F= '/^TeamIdentifier=/ { print $2; exit }' <<<"${signature_details}")"
  if [[ -z "${team_identifier}" || "${team_identifier}" == "not set" ]]; then
    echo "setup.sh: ${application_path} has no Developer ID TeamIdentifier" >&2
    return 1
  fi
  if [[ -z "${EXPECTED_RELEASE_TEAM_IDENTIFIER}" ]]; then
    echo "setup.sh: no trusted Developer ID TeamIdentifier is configured in this installer" >&2
    echo "setup.sh: refusing to use dist/build-info.json as its own publisher trust root" >&2
    return 1
  fi
  if [[ "${team_identifier}" != "${EXPECTED_RELEASE_TEAM_IDENTIFIER}" ]]; then
    echo "setup.sh: untrusted Developer ID TeamIdentifier for ${application_path}" >&2
    echo "setup.sh: expected ${EXPECTED_RELEASE_TEAM_IDENTIFIER}" >&2
    echo "setup.sh:   actual ${team_identifier}" >&2
    return 1
  fi
  if [[ -z "${DIST_BUILD_INFO_TEAM_IDENTIFIER}" || "${DIST_BUILD_INFO_TEAM_IDENTIFIER}" == "not set" ]]; then
    echo "setup.sh: ${DIST_DIR}/build-info.json does not pin a Developer ID TeamIdentifier for $(basename "${DIST_ARCHIVE}")" >&2
    echo "setup.sh: rebuild release artifacts with ./scripts/build-release-binaries.sh" >&2
    return 1
  fi
  if [[ "${team_identifier}" != "${DIST_BUILD_INFO_TEAM_IDENTIFIER}" ]]; then
    echo "setup.sh: Developer ID TeamIdentifier mismatch for ${application_path}" >&2
    echo "setup.sh: expected ${DIST_BUILD_INFO_TEAM_IDENTIFIER}" >&2
    echo "setup.sh:   actual ${team_identifier}" >&2
    return 1
  fi

  if command -v spctl >/dev/null 2>&1 \
    && ! spctl -a -vv -t execute "${application_path}" >/dev/null 2>&1; then
    echo "setup.sh: Gatekeeper assessment did not accept ${application_path}" >&2
    return 1
  fi
}

verify_install_source_version() {
  local binary_path="${1:-${INSTALL_SOURCE_BIN}}"
  local version_output

  version_output="$("${binary_path}" version 2>/dev/null || true)"
  if [[ "${version_output}" != "cwru-ovpn ${EXPECTED_APP_VERSION}" ]]; then
    echo "setup.sh: ${binary_path} reports '${version_output:-unknown}', expected 'cwru-ovpn ${EXPECTED_APP_VERSION}'" >&2
    exit 1
  fi
}

binary_supports_host_architecture() {
  local binary_path="$1"
  local architectures file_output

  if command -v lipo >/dev/null 2>&1; then
    architectures="$(lipo -archs "${binary_path}" 2>/dev/null || true)"
    if [[ -n "${architectures}" ]]; then
      [[ "${architectures}" == "arm64" ]]
      return
    fi
  fi

  file_output="$(file -b "${binary_path}" 2>/dev/null || true)"
  [[ "${file_output}" == "Mach-O 64-bit executable arm64" ]]
}

build_local_release() {
  local reason="$1"
  local tmp_root="${TMPDIR:-/tmp}/cwru-ovpn-setup"
  local third_party_prefix="${CWRU_OVPN_THIRD_PARTY_BUILD_ROOT:-${ROOT}/.build/third-party}/macos${MACOS_MAJOR_VERSION}/prefix"
  local -a build_env

  require_local_build_install_allowed "${reason}"

  ensure_private_tmp_root "${tmp_root}"
  mkdir -p \
    "${tmp_root}/home" \
    "${tmp_root}/swiftpm-module-cache" \
    "${tmp_root}/swiftpm-cache" \
    "${tmp_root}/swiftpm-config" \
    "${tmp_root}/swiftpm-security" \
    "${tmp_root}/clang-module-cache"

  echo "setup.sh: building a local release binary for this machine" >&2

  "${ROOT}/scripts/build-third-party-libs.sh" "${MACOS_MAJOR_VERSION}"

  build_env=(
    HOME="${tmp_root}/home"
    SWIFTPM_MODULECACHE_OVERRIDE="${tmp_root}/swiftpm-module-cache"
    CLANG_MODULE_CACHE_PATH="${tmp_root}/clang-module-cache"
    CWRU_OVPN_MACOS_DEPLOYMENT_TARGET="${MACOS_MAJOR_VERSION}.0"
    CWRU_OVPN_STATIC_THIRD_PARTY=1
    CWRU_OVPN_THIRD_PARTY_PREFIX="${third_party_prefix}"
  )

  env "${build_env[@]}" swift build -c release --disable-sandbox \
    --package-path "${ROOT}" \
    --cache-path "${tmp_root}/swiftpm-cache" \
    --config-path "${tmp_root}/swiftpm-config" \
    --security-path "${tmp_root}/swiftpm-security" \
    --manifest-cache local

  if [[ ! -x "${LOCAL_RELEASE_BIN}" ]]; then
    echo "setup.sh: local release build did not produce ${LOCAL_RELEASE_BIN}" >&2
    exit 1
  fi

  if ! binary_supports_host_architecture "${LOCAL_RELEASE_BIN}"; then
    echo "setup.sh: local release build at ${LOCAL_RELEASE_BIN} is not an Apple Silicon binary" >&2
    exit 1
  fi

  INSTALL_SOURCE_APP="${INSTALL_WORK_DIR}/local/cwru-ovpn.app"
  /bin/bash "${ROOT}/scripts/build-app-bundle.sh" "${LOCAL_RELEASE_BIN}" "${INSTALL_SOURCE_APP}"
  INSTALL_SOURCE_ARCHIVE="${INSTALL_WORK_DIR}/local.app.tar.gz"
  COPYFILE_DISABLE=1 /usr/bin/tar -czf "${INSTALL_SOURCE_ARCHIVE}" -C "${INSTALL_WORK_DIR}/local" cwru-ovpn.app
  INSTALL_SOURCE_BIN="${INSTALL_SOURCE_APP}/Contents/MacOS/cwru-ovpn"
  INSTALL_SOURCE_IS_DIST=0
}

validate_application_archive() {
  local archive="$1"
  local member listing
  listing="$(/usr/bin/tar -tzf "${archive}")" || return 1
  while IFS= read -r member; do
    case "${member}" in
      cwru-ovpn.app/|cwru-ovpn.app/Contents/|cwru-ovpn.app/Contents/MacOS/|cwru-ovpn.app/Contents/_CodeSignature/|cwru-ovpn.app/Contents/Info.plist|cwru-ovpn.app/Contents/MacOS/cwru-ovpn|cwru-ovpn.app/Contents/_CodeSignature/CodeResources) ;;
      *) echo "setup.sh: unexpected application archive entry: ${member}" >&2; return 1 ;;
    esac
  done <<<"${listing}"
  /usr/bin/tar -tvzf "${archive}" | /usr/bin/awk 'substr($0, 1, 1) != "-" && substr($0, 1, 1) != "d" { bad = 1 } END { exit bad }'
}

select_install_source() {
  INSTALL_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cwru-ovpn-install.XXXXXX")"
  if [[ ! -f "${DIST_ARCHIVE}" ]]; then
    build_local_release "no packaged application found for macOS ${MACOS_MAJOR_VERSION} at ${DIST_ARCHIVE}"
    return
  fi
  verify_dist_archive_file "${DIST_ARCHIVE}"
  verify_dist_build_info_file "${DIST_ARCHIVE}"
  handle_quarantine_if_present "${DIST_ARCHIVE}"
  validate_application_archive "${DIST_ARCHIVE}"
  /usr/bin/tar -xzf "${DIST_ARCHIVE}" -C "${INSTALL_WORK_DIR}" --no-same-owner --no-same-permissions --no-acls --no-xattrs --no-fflags
  INSTALL_SOURCE_APP="${INSTALL_WORK_DIR}/cwru-ovpn.app"
  INSTALL_SOURCE_BIN="${INSTALL_SOURCE_APP}/Contents/MacOS/cwru-ovpn"
  if ! binary_supports_host_architecture "${INSTALL_SOURCE_BIN}"; then
    build_local_release "prebuilt application is not an Apple Silicon application"
  elif ! verify_dist_signature_for_release "${INSTALL_SOURCE_APP}"; then
    build_local_release "prebuilt application is not a verified Developer ID release artifact"
  fi
}

stage_install_source() {
  local expected_sha actual_sha staged_archive
  expected_sha="$(shasum -a 256 "${INSTALL_SOURCE_ARCHIVE}" | awk '{print $1}')"
  sudo /bin/mkdir -p "${PRIVILEGED_INSTALL_DIR}"
  sudo /usr/sbin/chown root:wheel "${PRIVILEGED_INSTALL_DIR}"
  sudo /bin/chmod 755 "${PRIVILEGED_INSTALL_DIR}"
  STAGED_INSTALL_DIR="$(sudo /usr/bin/mktemp -d "${PRIVILEGED_INSTALL_DIR}/.setup-candidate.XXXXXX")"
  sudo /bin/chmod 755 "${STAGED_INSTALL_DIR}"
  staged_archive="${STAGED_INSTALL_DIR}/application.tar.gz"
  sudo /usr/bin/install -m 644 "${INSTALL_SOURCE_ARCHIVE}" "${staged_archive}"
  actual_sha="$(shasum -a 256 "${staged_archive}" | awk '{print $1}')"
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    echo "setup.sh: application archive changed during staging" >&2
    exit 1
  fi
  if [[ "${INSTALL_SOURCE_IS_DIST}" == 1 ]]; then
    verify_dist_archive_file "${staged_archive}"
    verify_dist_build_info_file "${staged_archive}"
  fi
  validate_application_archive "${staged_archive}"
  sudo /usr/bin/tar -xzf "${staged_archive}" -C "${STAGED_INSTALL_DIR}" --no-same-owner --no-same-permissions --no-acls --no-xattrs --no-fflags
  local staged_app="${STAGED_INSTALL_DIR}/cwru-ovpn.app"
  STAGED_INSTALL_BIN="${staged_app}/Contents/MacOS/cwru-ovpn"
  sudo /usr/sbin/chown -R root:wheel "${staged_app}"
  sudo /bin/chmod 755 "${staged_app}" "${staged_app}/Contents" "${staged_app}/Contents/MacOS" "${staged_app}/Contents/_CodeSignature" "${STAGED_INSTALL_BIN}"
  sudo /bin/chmod 644 "${staged_app}/Contents/Info.plist" "${staged_app}/Contents/_CodeSignature/CodeResources"
  /usr/bin/codesign --verify --deep --strict "${staged_app}"
  verify_install_source_version "${STAGED_INSTALL_BIN}"
  if ! binary_supports_host_architecture "${STAGED_INSTALL_BIN}"; then
    echo "setup.sh: staged application is not an Apple Silicon application" >&2
    exit 1
  fi
  if [[ "${INSTALL_SOURCE_IS_DIST}" == 1 ]] && ! verify_dist_signature_for_release "${staged_app}"; then
    echo "setup.sh: staged application is not a verified release artifact" >&2
    exit 1
  fi
}

require_helper_disconnected() {
  local binary_path="$1"
  local status_output first_line
  if ! status_output="$("${binary_path}" status 2>/dev/null)"; then
    echo "setup.sh: could not verify the VPN session state" >&2
    exit 1
  fi
  first_line="${status_output%%$'\n'*}"
  if [[ "${first_line}" != "Status: Disconnected" ]]; then
    echo "setup.sh: disconnect the VPN before upgrading" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      if [[ $# -lt 2 ]]; then
        echo "setup.sh: missing value for --profile" >&2
        exit 2
      fi
      PROFILE_SOURCE="$2"
      shift 2
      ;;
    --remove-quarantine-after-verification)
      ALLOW_QUARANTINE_REMOVAL=1
      shift
      ;;
    --allow-local-build-install)
      ALLOW_LOCAL_BUILD_INSTALL=1
      shift
      ;;
    --allow-ad-hoc-release-artifact)
      ALLOW_ADHOC_RELEASE=1
      shift
      ;;
    -h|--help)
      cat <<EOF
Usage: ./scripts/setup.sh [--profile PATH] [--remove-quarantine-after-verification] [--allow-local-build-install] [--allow-ad-hoc-release-artifact]

Options:
  --profile PATH                            Copy a specific .ovpn profile into ${PROFILE_PATH}
  --remove-quarantine-after-verification    Remove com.apple.quarantine from the selected binary
  --allow-local-build-install               Allow local developer build fallback instead of a verified release artifact
  --allow-ad-hoc-release-artifact           Allow an ad-hoc/non-Developer ID signed prebuilt artifact
EOF
      exit 0
      ;;
    *)
      echo "setup.sh: unexpected argument '$1'" >&2
      echo "Usage: ./scripts/setup.sh [--profile PATH] [--remove-quarantine-after-verification] [--allow-local-build-install] [--allow-ad-hoc-release-artifact]" >&2
      exit 2
      ;;
  esac
done

if [[ -x "${PRIVILEGED_INSTALL_BIN}" ]]; then
  require_helper_disconnected "${PRIVILEGED_INSTALL_BIN}"
fi

mkdir -p "${STATE_DIR}"
chmod 700 "${STATE_DIR}"

if [[ ! -f "${CONFIG_PATH}" ]]; then
  install -m 600 "${EXAMPLE_CONFIG}" "${CONFIG_PATH}"
  echo "Created ${CONFIG_PATH}"
fi
chmod 600 "${CONFIG_PATH}"
if [[ -f "${PROFILE_PATH}" ]]; then
  chmod 600 "${PROFILE_PATH}"
fi

select_install_source

handle_quarantine_if_present "${INSTALL_SOURCE_APP}"
handle_quarantine_if_present "${INSTALL_SOURCE_BIN}"
verify_install_source_version
require_helper_disconnected "${INSTALL_SOURCE_BIN}"
stage_install_source

SETUP_ARGS=()
if [[ -n "${PROFILE_SOURCE}" ]]; then
  SETUP_ARGS=(--profile "${PROFILE_SOURCE}")
elif [[ ! -f "${PROFILE_PATH}" ]]; then
  repo_profiles=()
  for candidate in "${ROOT}"/*.ovpn; do
    if [[ -e "${candidate}" ]]; then
      repo_profiles+=("${candidate}")
    fi
  done
  if [[ ${#repo_profiles[@]} -eq 1 ]]; then
    SETUP_ARGS=(--profile "${repo_profiles[0]}")
  elif [[ ${#repo_profiles[@]} -gt 1 ]]; then
    echo "setup.sh: found multiple .ovpn profiles in ${ROOT}. Pass --profile PATH to choose one." >&2
    exit 1
  fi
fi

if [[ ${#SETUP_ARGS[@]} -gt 0 ]]; then
  sudo "${STAGED_INSTALL_BIN}" setup "${SETUP_ARGS[@]}"
else
  sudo "${STAGED_INSTALL_BIN}" setup
fi

if [[ ! -x "${PRIVILEGED_INSTALL_BIN}" ]]; then
  echo "setup.sh: setup did not install ${PRIVILEGED_INSTALL_BIN}" >&2
  exit 1
fi

INSTALLED_VERSION="$("${PRIVILEGED_INSTALL_BIN}" version)"
/usr/bin/codesign --verify --deep --strict "${PRIVILEGED_INSTALL_DIR}/cwru-ovpn.app"
if [[ "${INSTALLED_VERSION}" != "cwru-ovpn ${EXPECTED_APP_VERSION}" ]]; then
  echo "setup.sh: installed binary reports '${INSTALLED_VERSION}', expected 'cwru-ovpn ${EXPECTED_APP_VERSION}'" >&2
  exit 1
fi

install -m 644 "${ALIASES_SRC}" "${ALIASES_INSTALLED}"
SHELL_SETUP_ARGS=(install-shell-integration)
if [[ -n "${SHELL:-}" ]]; then
  SHELL_SETUP_ARGS+=(--shell "${SHELL}")
fi
"${PRIVILEGED_INSTALL_BIN}" "${SHELL_SETUP_ARGS[@]}"

cat <<EOF

Setup complete.

Version:
  ${INSTALLED_VERSION}

Installed binary:
  ${PRIVILEGED_INSTALL_BIN}

Next steps:
  1. Open a new shell so the shortcuts are loaded
  2. If needed, import your VPN profile with:
       sudo "${PRIVILEGED_INSTALL_BIN}" setup --profile /path/to/profile.ovpn
  3. Connect with:
       ovpn        # use the configured or default tunnel mode
       ovpnfull    # connect or switch to full-tunnel mode
       ovpnsplit   # connect or switch to split-tunnel mode
  4. Disconnect with:
       ovpnd
EOF
