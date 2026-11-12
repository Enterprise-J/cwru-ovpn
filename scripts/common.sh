SCRIPT_NAME="$(basename "${0}")"

app_identity_value() {
  local constant_name="$1"
  local identity_source="$2"

  awk -F'"' -v declaration="static let ${constant_name}" 'index($0, declaration) { print $2; exit }' "${identity_source}"
}

validate_macos_versions() {
  local app_version="$1"
  local major_version
  shift

  for major_version in "$@"; do
    if [[ ! "${major_version}" =~ ^[0-9]+$ ]]; then
      echo "${SCRIPT_NAME}: invalid macOS major version '${major_version}'." >&2
      exit 1
    fi
    if [[ "${major_version}" -lt 15 ]]; then
      echo "${SCRIPT_NAME}: cwru-ovpn ${app_version} supports macOS 15 or later." >&2
      exit 1
    fi
  done
}

ensure_private_tmp_root() {
  local tmp_root="$1"

  mkdir -p "${tmp_root}"
  if [[ -L "${tmp_root}" || ! -d "${tmp_root}" ]]; then
    echo "${SCRIPT_NAME}: refusing unsafe temporary build directory ${tmp_root}" >&2
    exit 1
  fi
  if [[ "$(stat -f '%u' "${tmp_root}")" != "$(id -u)" ]]; then
    echo "${SCRIPT_NAME}: temporary build directory ${tmp_root} is not owned by the current user" >&2
    exit 1
  fi
  chmod 700 "${tmp_root}"
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
