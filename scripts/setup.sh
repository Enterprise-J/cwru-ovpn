#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/scripts/common.sh"

if [[ ${EUID} -eq 0 ]]; then
  echo "setup.sh: Run ./scripts/setup.sh as your login user. It requests administrator access when needed." >&2
  exit 1
fi

STATE_DIR="${HOME}/.cwru-ovpn"
CONFIG_PATH="${STATE_DIR}/config.json"
PROFILE_PATH="${STATE_DIR}/profile.ovpn"
PRIVILEGED_INSTALL_DIR="/Library/PrivilegedHelperTools/cwru-ovpn"
PRIVILEGED_INSTALL_BIN="${PRIVILEGED_INSTALL_DIR}/cwru-ovpn.app/Contents/MacOS/cwru-ovpn"
BUILD_FROM_SOURCE=0
EXAMPLE_CONFIG="${ROOT}/examples/cwru-ovpn.config.example.json"
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
ARCHIVE_NAME="cwru-ovpn-macos${MACOS_MAJOR_VERSION}-arm64-ad-hoc.app.tar.gz"
PROFILE_SOURCE=""
INSTALL_SOURCE_ARCHIVE=""
INSTALL_ARCHIVE_SHA256=""
INSTALL_WORK_DIR=""
STAGED_INSTALL_DIR=""
STAGED_INSTALL_BIN=""

cleanup_staged_install() {
  if [[ -n "${STAGED_INSTALL_DIR}" && -d "${STAGED_INSTALL_DIR}" ]]; then
    if [[ "$STAGED_INSTALL_DIR" == "$PRIVILEGED_INSTALL_DIR"/.setup-candidate.* && "${STAGED_INSTALL_DIR%/*}" == "$PRIVILEGED_INSTALL_DIR" ]]; then
      sudo -n /bin/rm -rf -- "$STAGED_INSTALL_DIR" || echo "Could not clean $STAGED_INSTALL_DIR" >&2
    fi
  fi
  if [[ -n "${INSTALL_WORK_DIR}" && -d "${INSTALL_WORK_DIR}" ]]; then
    /bin/rm -rf "${INSTALL_WORK_DIR}"
  fi
}
trap cleanup_staged_install EXIT

verify_archive_checksum() {
  local actual_sha
  actual_sha="$(/usr/bin/shasum -a 256 < "$1" | /usr/bin/awk '{ print $1 }')" || return 1
  if [[ "$actual_sha" != "$INSTALL_ARCHIVE_SHA256" ]]; then
    echo "setup.sh: checksum mismatch for $1" >&2
    echo "setup.sh: expected $INSTALL_ARCHIVE_SHA256" >&2
    echo "setup.sh:   actual $actual_sha" >&2
    return 1
  fi
}

verify_install_bundle() {
  local app="$1" binary="$1/Contents/MacOS/cwru-ovpn" version
  if [[ ! -x "$binary" || "$(LC_ALL=C /usr/bin/file -b "$binary")" != "Mach-O 64-bit executable arm64" ]]; then
    echo "setup.sh: expected an Apple Silicon executable at $binary" >&2
    return 1
  fi
  verify_ad_hoc_signature "$app" || return 1
  "$binary" verify-bundle "$app" || return 1
  version="$("$binary" version)" || return 1
  if [[ "$version" != "cwru-ovpn $EXPECTED_APP_VERSION" ]]; then
    echo "setup.sh: $binary reports '$version', expected 'cwru-ovpn $EXPECTED_APP_VERSION'" >&2
    return 1
  fi
}

prepare_install_source() {
  local artifact_dir="$ROOT/dist/ad-hoc"
  if [[ "$BUILD_FROM_SOURCE" == 1 ]]; then
    "$ROOT/scripts/build-release-binaries.sh" "$MACOS_MAJOR_VERSION"
    artifact_dir="$ROOT/.build/local-artifacts"
  elif [[ ! -f "$artifact_dir/$ARCHIVE_NAME" ]]; then
    echo "setup.sh: No prebuilt Release archive for macOS $MACOS_MAJOR_VERSION was found in $artifact_dir. Run ./scripts/setup.sh --build to compile from a clean checkout." >&2
    return 1
  fi
  INSTALL_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cwru-ovpn-install.XXXXXX")"
  INSTALL_SOURCE_ARCHIVE="$INSTALL_WORK_DIR/$ARCHIVE_NAME"
  /bin/cp "$artifact_dir/$ARCHIVE_NAME" "$artifact_dir/SHA256SUMS" "$artifact_dir/build-info.json" "$INSTALL_WORK_DIR/"
  INSTALL_ARCHIVE_SHA256="$(release_archive_checksum "$INSTALL_WORK_DIR" "$ARCHIVE_NAME" "$EXPECTED_APP_VERSION" "$MACOS_MAJOR_VERSION.0")" || return 1
  verify_archive_checksum "$INSTALL_SOURCE_ARCHIVE"
  validate_application_archive "${INSTALL_SOURCE_ARCHIVE}"
  /usr/bin/tar -xzf "${INSTALL_SOURCE_ARCHIVE}" -C "${INSTALL_WORK_DIR}" --no-same-owner --no-same-permissions --no-acls --no-xattrs --no-fflags
  verify_install_bundle "$INSTALL_WORK_DIR/cwru-ovpn.app"
}

stage_install_source() {
  local staged_archive
  sudo /bin/mkdir -p "${PRIVILEGED_INSTALL_DIR}"
  sudo /usr/sbin/chown root:wheel "${PRIVILEGED_INSTALL_DIR}"
  sudo /bin/chmod 755 "${PRIVILEGED_INSTALL_DIR}"
  STAGED_INSTALL_DIR="$(sudo /usr/bin/mktemp -d "${PRIVILEGED_INSTALL_DIR}/.setup-candidate.XXXXXX")"
  sudo /bin/chmod 755 "${STAGED_INSTALL_DIR}"
  staged_archive="${STAGED_INSTALL_DIR}/application.tar.gz"
  sudo /usr/bin/install -m 644 "${INSTALL_SOURCE_ARCHIVE}" "${staged_archive}"
  verify_archive_checksum "$staged_archive"
  validate_application_archive "${staged_archive}"
  sudo /usr/bin/tar -xzf "${staged_archive}" -C "${STAGED_INSTALL_DIR}" --no-same-owner --no-same-permissions --no-acls --no-xattrs --no-fflags
  local staged_app="${STAGED_INSTALL_DIR}/cwru-ovpn.app"
  STAGED_INSTALL_BIN="${staged_app}/Contents/MacOS/cwru-ovpn"
  sudo /usr/sbin/chown -R root:wheel "${staged_app}"
  sudo /bin/chmod 755 "${staged_app}" "${staged_app}/Contents" "${staged_app}/Contents/MacOS" "${staged_app}/Contents/_CodeSignature" "${STAGED_INSTALL_BIN}"
  sudo /bin/chmod 644 "${staged_app}/Contents/Info.plist" "${staged_app}/Contents/_CodeSignature/CodeResources"
  verify_install_bundle "$staged_app"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build)
      BUILD_FROM_SOURCE=1
      shift
      ;;
    --profile)
      if [[ -z "${2:-}" || "$2" == --* || "$2" == -h ]]; then
        echo "setup.sh: missing value for --profile" >&2
        exit 2
      fi
      PROFILE_SOURCE="$2"
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
Usage: ./scripts/setup.sh [--build] [--profile PATH]

Install the prebuilt cwru-ovpn app from the release for this macOS version.
The script verifies the archive before requesting administrator access.

Options:
  --profile PATH  Install and approve the .ovpn profile from PATH.
  --build         Compile and install the app from a clean source checkout.
  --help          Show this help message.
EOF
      exit 0
      ;;
    *)
      echo "setup.sh: unexpected argument '$1'" >&2
      echo "Usage: ./scripts/setup.sh [--build] [--profile PATH]" >&2
      exit 2
      ;;
  esac
done

prepare_install_source

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

SETUP_ARGS=(setup)
if [[ -n "${PROFILE_SOURCE}" ]]; then
  SETUP_ARGS+=(--profile "${PROFILE_SOURCE}")
elif [[ ! -f "${PROFILE_PATH}" ]]; then
  repo_profiles=()
  for candidate in "${ROOT}"/*.ovpn; do
    if [[ -e "${candidate}" ]]; then
      repo_profiles+=("${candidate}")
    fi
  done
  if [[ ${#repo_profiles[@]} -eq 1 ]]; then
    SETUP_ARGS+=(--profile "${repo_profiles[0]}")
  elif [[ ${#repo_profiles[@]} -gt 1 ]]; then
    echo "setup.sh: found multiple .ovpn profiles in ${ROOT}. Pass --profile PATH to choose one." >&2
    exit 1
  fi
fi

stage_install_source
sudo "$STAGED_INSTALL_BIN" "${SETUP_ARGS[@]}"
verify_install_bundle "$PRIVILEGED_INSTALL_DIR/cwru-ovpn.app"

install -m 644 "${ALIASES_SRC}" "${ALIASES_INSTALLED}"
SHELL_SETUP_ARGS=(install-shell-integration)
if [[ -n "${SHELL:-}" ]]; then
  SHELL_SETUP_ARGS+=(--shell "${SHELL}")
fi
"${PRIVILEGED_INSTALL_BIN}" "${SHELL_SETUP_ARGS[@]}"

cat <<'EOF'
Open a new shell to load the installed shortcuts.
Run ovpn to connect, ovpnstatus to check the connection, and ovpnd to disconnect.
EOF
