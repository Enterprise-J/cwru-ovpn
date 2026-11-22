SCRIPT_NAME="$(basename "${0}")"

app_identity_value() {
  local constant_name="$1"
  local identity_source="$2"

  awk -F'"' -v declaration="static let ${constant_name}" 'index($0, declaration) { print $2; exit }' "${identity_source}"
}

validate_macos_versions() {
  local app_version="$1"
  local major_version seen=" "
  shift

  for major_version in "$@"; do
    if [[ ! "${major_version}" =~ ^[1-9][0-9]*$ ]]; then
      echo "${SCRIPT_NAME}: invalid macOS major version '${major_version}'." >&2
      exit 1
    fi
    if [[ "${major_version}" -lt 15 ]]; then
      echo "${SCRIPT_NAME}: cwru-ovpn ${app_version} supports macOS 15 or later." >&2
      exit 1
    fi
    if [[ "$seen" == *" $major_version "* ]]; then
      echo "$SCRIPT_NAME: duplicate macOS deployment target $major_version." >&2
      return 1
    fi
    seen+="$major_version "
  done
}

verify_ad_hoc_signature() {
  local app="$1" details
  /usr/bin/codesign --verify --deep --strict "$app" || return 1
  details="$(/usr/bin/codesign --display --verbose=4 "$app" 2>&1)" || return 1
  if ! /usr/bin/grep -Fxq 'Signature=adhoc' <<<"$details"; then
    echo "Expected an ad-hoc signature on $app." >&2
    return 1
  fi
}

release_archive_checksum() {
  local archive_name="$2" expected_version="$3" expected_target="$4"
  local build_info_path="$1/build-info.json"
  local sums_path="$1/SHA256SUMS"
  local configuration signing app_version count index name record="" deployment_target manifest_sha listed_sha
  configuration="$(/usr/bin/plutil -extract configuration raw -expect string -o - "$build_info_path")" || return 1
  signing="$(/usr/bin/plutil -extract signing raw -expect string -o - "$build_info_path")" || return 1
  if [[ "$configuration" != Release || "$signing" != ad-hoc ]]; then
    echo "setup.sh: expected an ad-hoc Release build in $build_info_path" >&2
    return 1
  fi
  app_version="$(/usr/bin/plutil -extract appVersion raw -expect string -o - "$build_info_path")" || return 1
  if [[ "$app_version" != "$expected_version" ]]; then
    echo "setup.sh: $build_info_path appVersion is $app_version, expected $expected_version" >&2
    return 1
  fi

  count="$(/usr/bin/plutil -extract artifacts raw -expect array -o - "$build_info_path")" || return 1
  for ((index = 0; index < count; index++)); do
    name="$(/usr/bin/plutil -extract "artifacts.$index.file" raw -expect string -o - "$build_info_path")" || return 1
    if [[ "$name" == "$archive_name" ]]; then
      if [[ -n "$record" ]]; then
        echo "setup.sh: duplicate entry for $archive_name in $build_info_path" >&2
        return 1
      fi
      record="artifacts.$index"
    fi
  done
  if [[ -z "$record" ]]; then
    echo "setup.sh: no entry for $archive_name in $build_info_path" >&2
    return 1
  fi
  deployment_target="$(/usr/bin/plutil -extract "$record.deploymentTarget" raw -expect string -o - "$build_info_path")" || return 1
  if [[ "$deployment_target" != "$expected_target" ]]; then
    echo "setup.sh: deployment target for $archive_name is $deployment_target, expected $expected_target" >&2
    return 1
  fi
  manifest_sha="$(/usr/bin/plutil -extract "$record.sha256" raw -expect string -o - "$build_info_path")" || return 1
  listed_sha="$(/usr/bin/awk -v name="$archive_name" '$2 == name { print $1 }' "$sums_path")" || return 1
  if [[ ! "$listed_sha" =~ ^[0-9a-f]{64}$ || "$listed_sha" != "$manifest_sha" ]]; then
    echo "setup.sh: expected one matching SHA-256 for $archive_name in $sums_path and $build_info_path" >&2
    return 1
  fi
  printf '%s\n' "$listed_sha"
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
