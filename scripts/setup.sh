#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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
PRIVILEGED_INSTALL_BIN="/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn"
DIST_DIR="${ROOT}/dist"
EXAMPLE_CONFIG="${ROOT}/examples/cwru-ovpn.config.example.json"
LOCAL_CONFIG="${ROOT}/cwru-ovpn.config.json"
LOCAL_RELEASE_BIN="${ROOT}/.build/release/cwru-ovpn"
ALIASES_SRC="${ROOT}/scripts/cwru-ovpn.zsh"
# Keep the shell helper outside the repo so repo moves do not break the shell integration.
ALIASES_INSTALLED="${STATE_DIR}/cwru-ovpn.zsh"

MACOS_MAJOR_VERSION="$(sw_vers -productVersion | cut -d '.' -f1)"
detect_host_architecture() {
  if [[ "$(sysctl -in hw.optional.arm64 2>/dev/null || true)" == "1" ]]; then
    echo "arm64"
    return
  fi

  uname -m
}

HOST_ARCH="$(detect_host_architecture)"
DIST_BIN="${DIST_DIR}/cwru-ovpn-macos${MACOS_MAJOR_VERSION}-arm64"
PROFILE_SOURCE=""
INSTALL_SOURCE_BIN="${DIST_BIN}"

print_intel_prebuild_instructions() {
  cat >&2 <<EOF
setup.sh: packaged release binaries are Apple Silicon only:
  ${DIST_BIN}

Intel Macs must prebuild a local release binary before installation:
  swift build -c release --disable-sandbox

Then rerun:
  ./scripts/setup.sh
EOF
}

print_gatekeeper_bypass_instructions() {
  local binary_path="$1"

  echo "setup.sh: macOS may block this binary after a browser download." >&2
  echo "Run once after downloading:" >&2
  printf '  xattr -d com.apple.quarantine %q\n' "${binary_path}" >&2
  echo >&2
  echo "Alternatively: right-click the binary in Finder -> Open -> Open." >&2
}

clear_quarantine_if_present() {
  local binary_path="$1"

  if ! command -v xattr >/dev/null 2>&1; then
    return
  fi

  if xattr -p com.apple.quarantine "${binary_path}" >/dev/null 2>&1; then
    echo "setup.sh: removing macOS quarantine attribute from ${binary_path}"
    if ! xattr -d com.apple.quarantine "${binary_path}"; then
      echo "setup.sh: failed to remove macOS quarantine attribute from ${binary_path}" >&2
      print_gatekeeper_bypass_instructions "${binary_path}"
      exit 1
    fi
  fi
}

verify_dist_binary() {
  local sums_path="${DIST_DIR}/SHA256SUMS"
  local binary_name expected_sha actual_sha

  if [[ ! -f "${sums_path}" ]]; then
    echo "setup.sh: missing ${sums_path}; refusing to install an unverifiable prebuilt binary" >&2
    exit 1
  fi

  binary_name="$(basename "${DIST_BIN}")"
  expected_sha="$(awk -v name="${binary_name}" '$2 == name { print $1 }' "${sums_path}")"
  if [[ -z "${expected_sha}" ]]; then
    echo "setup.sh: ${sums_path} does not contain a checksum for ${binary_name}" >&2
    exit 1
  fi

  actual_sha="$(shasum -a 256 "${DIST_BIN}" | awk '{ print $1 }')"
  if [[ "${actual_sha}" != "${expected_sha}" ]]; then
    echo "setup.sh: checksum mismatch for ${DIST_BIN}" >&2
    echo "setup.sh: expected ${expected_sha}" >&2
    echo "setup.sh:   actual ${actual_sha}" >&2
    exit 1
  fi
}

verify_dist_signature_if_present() {
  local binary_path="$1"

  if ! command -v codesign >/dev/null 2>&1; then
    return
  fi

  if ! codesign -d --verbose=2 "${binary_path}" >/dev/null 2>&1; then
    echo "setup.sh: ${binary_path} is not signed; relying on dist/SHA256SUMS only." >&2
    return
  fi

  if ! codesign --verify --deep --strict --verbose=2 "${binary_path}" >/dev/null 2>&1; then
    echo "setup.sh: code signature verification failed for ${binary_path}" >&2
    exit 1
  fi
}

binary_supports_host_architecture() {
  local binary_path="$1"
  local architectures file_output

  if command -v lipo >/dev/null 2>&1; then
    architectures="$(lipo -archs "${binary_path}" 2>/dev/null || true)"
    if [[ -n "${architectures}" ]]; then
      for arch in ${architectures}; do
        if [[ "${arch}" == "${HOST_ARCH}" ]]; then
          return 0
        fi
      done
      return 1
    fi
  fi

  file_output="$(file -b "${binary_path}" 2>/dev/null || true)"
  case "${HOST_ARCH}" in
    arm64)
      [[ "${file_output}" == *"arm64"* ]]
      ;;
    x86_64)
      [[ "${file_output}" == *"x86_64"* ]]
      ;;
    *)
      return 1
      ;;
  esac
}

build_local_release() {
  local reason="$1"
  local tmp_root="${TMPDIR:-/tmp}/cwru-ovpn-setup"
  local third_party_prefix="${ROOT}/.build/third-party/macos${MACOS_MAJOR_VERSION}/prefix"
  local use_static_third_party=0
  local -a build_env

  mkdir -p \
    "${tmp_root}/home" \
    "${tmp_root}/swiftpm-module-cache" \
    "${tmp_root}/swiftpm-cache" \
    "${tmp_root}/swiftpm-config" \
    "${tmp_root}/swiftpm-security" \
    "${tmp_root}/clang-module-cache"

  echo "setup.sh: ${reason}" >&2
  echo "setup.sh: falling back to a local release build for this machine" >&2

  if [[ -d "${third_party_prefix}" ]]; then
    use_static_third_party=1
  fi

  build_env=(
    HOME="${tmp_root}/home"
    SWIFTPM_MODULECACHE_OVERRIDE="${tmp_root}/swiftpm-module-cache"
    CLANG_MODULE_CACHE_PATH="${tmp_root}/clang-module-cache"
    CWRU_OVPN_MACOS_DEPLOYMENT_TARGET="${MACOS_MAJOR_VERSION}.0"
    CWRU_OVPN_STATIC_THIRD_PARTY="${use_static_third_party}"
  )
  if [[ "${use_static_third_party}" -eq 1 ]]; then
    build_env+=("CWRU_OVPN_THIRD_PARTY_PREFIX=${third_party_prefix}")
  fi

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
    echo "setup.sh: local release build at ${LOCAL_RELEASE_BIN} does not support host architecture ${HOST_ARCH}" >&2
    exit 1
  fi

  INSTALL_SOURCE_BIN="${LOCAL_RELEASE_BIN}"
}

select_install_source() {
  case "${HOST_ARCH}" in
    arm64)
      if [[ ! -f "${DIST_BIN}" ]]; then
        build_local_release "no prebuilt binary found for macOS ${MACOS_MAJOR_VERSION} at ${DIST_BIN}"
      elif ! binary_supports_host_architecture "${DIST_BIN}"; then
        build_local_release "prebuilt binary at ${DIST_BIN} does not support host architecture ${HOST_ARCH}"
      else
        verify_dist_binary
        verify_dist_signature_if_present "${DIST_BIN}"
      fi
      ;;
    x86_64)
      if [[ -x "${LOCAL_RELEASE_BIN}" ]] && binary_supports_host_architecture "${LOCAL_RELEASE_BIN}"; then
        INSTALL_SOURCE_BIN="${LOCAL_RELEASE_BIN}"
        return
      fi

      print_intel_prebuild_instructions
      exit 1
      ;;
    *)
      echo "setup.sh: unsupported architecture '${HOST_ARCH}'." >&2
      exit 1
      ;;
  esac
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

mkdir -p "${STATE_DIR}"
chmod 700 "${STATE_DIR}"

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

select_install_source

clear_quarantine_if_present "${INSTALL_SOURCE_BIN}"

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
  sudo "${INSTALL_SOURCE_BIN}" setup "${SETUP_ARGS[@]}"
else
  sudo "${INSTALL_SOURCE_BIN}" setup
fi

if [[ ! -x "${PRIVILEGED_INSTALL_BIN}" ]]; then
  echo "setup.sh: setup did not install ${PRIVILEGED_INSTALL_BIN}" >&2
  exit 1
fi

INSTALLED_VERSION="$("${PRIVILEGED_INSTALL_BIN}" version)"

install -m 644 "${ALIASES_SRC}" "${ALIASES_INSTALLED}"
SHELL_SETUP_ARGS=(install-shell-integration --legacy-source "${ALIASES_SRC}")
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
       ovpn        # use the default mode from ${CONFIG_PATH}
       ovpnfull    # connect in full-tunnel mode
       ovpnsplit   # connect in split-tunnel mode
  4. Disconnect with:
       ovpnd
EOF
