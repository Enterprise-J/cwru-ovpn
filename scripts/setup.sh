#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${HOME}/.cwru-ovpn"
CONFIG_PATH="${STATE_DIR}/config.json"
PROFILE_PATH="${STATE_DIR}/profile.ovpn"
BIN_DIR="${STATE_DIR}/bin"
INSTALL_BIN="${BIN_DIR}/cwru-ovpn"
DIST_DIR="${ROOT}/dist"
EXAMPLE_CONFIG="${ROOT}/examples/cwru-ovpn.config.example.json"
LOCAL_CONFIG="${ROOT}/cwru-ovpn.config.json"
ALIASES_SRC="${ROOT}/scripts/cwru-ovpn.zsh"
# The shell helper is installed to the state directory so moving or deleting
# the repository does not break the shell integration.
ALIASES_INSTALLED="${STATE_DIR}/cwru-ovpn.zsh"

MACOS_MAJOR_VERSION="$(sw_vers -productVersion | cut -d '.' -f1)"
DIST_BIN="${DIST_DIR}/cwru-ovpn-macos${MACOS_MAJOR_VERSION}"
PROFILE_SOURCE=""
INSTALL_SOURCE_BIN="${DIST_BIN}"

build_local_release() {
  local tmp_root="${TMPDIR:-/tmp}/cwru-ovpn-setup"
  local local_release_bin="${ROOT}/.build/release/cwru-ovpn"

  mkdir -p "${tmp_root}/home" "${tmp_root}/swiftpm-module-cache" "${tmp_root}/clang-module-cache"

  echo "setup.sh: no prebuilt binary found for macOS ${MACOS_MAJOR_VERSION} at ${DIST_BIN}" >&2
  echo "setup.sh: falling back to a local release build for this machine" >&2

  env HOME="${tmp_root}/home" \
    SWIFTPM_MODULECACHE_OVERRIDE="${tmp_root}/swiftpm-module-cache" \
    CLANG_MODULE_CACHE_PATH="${tmp_root}/clang-module-cache" \
    CWRU_OVPN_MACOS_DEPLOYMENT_TARGET="${MACOS_MAJOR_VERSION}.0" \
    CWRU_OVPN_STATIC_THIRD_PARTY=0 \
    swift build -c release --disable-sandbox --package-path "${ROOT}"

  if [[ ! -x "${local_release_bin}" ]]; then
    echo "setup.sh: local release build did not produce ${local_release_bin}" >&2
    exit 1
  fi

  INSTALL_SOURCE_BIN="${local_release_bin}"
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
    -h|--help)
      cat <<EOF
Usage: ./scripts/setup.sh [--profile PATH]

Options:
  --profile PATH  Copy a specific .ovpn profile into ${PROFILE_PATH}
EOF
      exit 0
      ;;
    *)
      echo "setup.sh: unexpected argument '$1'" >&2
      echo "Usage: ./scripts/setup.sh [--profile PATH]" >&2
      exit 2
      ;;
  esac
done

mkdir -p "${STATE_DIR}" "${BIN_DIR}"
chmod 700 "${STATE_DIR}" "${BIN_DIR}"

if [[ ! -f "${CONFIG_PATH}" ]]; then
  install -m 600 "${EXAMPLE_CONFIG}" "${CONFIG_PATH}"
  echo "Created ${CONFIG_PATH}"
fi
chmod 600 "${CONFIG_PATH}"

if [[ -f "${LOCAL_CONFIG}" ]]; then
  echo "Keeping your existing repo-local ${LOCAL_CONFIG} as-is."
fi

if [[ -f "${PROFILE_PATH}" ]]; then
  chmod 600 "${PROFILE_PATH}"
fi

if [[ ! -f "${DIST_BIN}" ]]; then
  build_local_release
fi

install -m 755 "${INSTALL_SOURCE_BIN}" "${INSTALL_BIN}"
INSTALLED_VERSION="$("${INSTALL_BIN}" version)"

SETUP_ARGS=()
if [[ -n "${PROFILE_SOURCE}" ]]; then
  SETUP_ARGS=(--profile "${PROFILE_SOURCE}")
elif [[ ! -f "${PROFILE_PATH}" ]]; then
  shopt -s nullglob
  repo_profiles=("${ROOT}"/*.ovpn)
  shopt -u nullglob
  if [[ ${#repo_profiles[@]} -eq 1 ]]; then
    SETUP_ARGS=(--profile "${repo_profiles[0]}")
  elif [[ ${#repo_profiles[@]} -gt 1 ]]; then
    echo "setup.sh: found multiple .ovpn profiles in ${ROOT}. Pass --profile PATH to choose one." >&2
    exit 1
  fi
fi

if [[ ${#SETUP_ARGS[@]} -gt 0 ]]; then
  sudo "${INSTALL_BIN}" setup "${SETUP_ARGS[@]}"
else
  sudo "${INSTALL_BIN}" setup
fi

# Install the shell aliases file to the state directory so it works even if
# the repository is later moved or deleted.
install -m 644 "${ALIASES_SRC}" "${ALIASES_INSTALLED}"
SHELL_SETUP_ARGS=(install-shell-integration --legacy-source "${ALIASES_SRC}")
if [[ -n "${SHELL:-}" ]]; then
  SHELL_SETUP_ARGS+=(--shell "${SHELL}")
fi
"${INSTALL_BIN}" "${SHELL_SETUP_ARGS[@]}"

cat <<EOF

Setup complete.

Version:
  ${INSTALLED_VERSION}

Installed binary:
  ${INSTALL_BIN}

Next steps:
  1. Open a new shell so the shortcuts are loaded
  2. If needed, import your VPN profile with:
       sudo "${INSTALL_BIN}" setup --profile /path/to/profile.ovpn
  3. Connect with:
       ovpn        # use the default mode from ${CONFIG_PATH}
       ovpnfull    # connect in full-tunnel mode
       ovpnsplit   # connect in split-tunnel mode
  4. Disconnect with:
       ovpnd
EOF
