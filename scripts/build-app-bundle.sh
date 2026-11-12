#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT}/scripts/common.sh"
SOURCE_BINARY="${1:?Usage: build-app-bundle.sh BINARY OUTPUT.app [SIGNING_IDENTITY]}"
OUTPUT_APP="${2:?Usage: build-app-bundle.sh BINARY OUTPUT.app [SIGNING_IDENTITY]}"
SIGNING_IDENTITY="${3:--}"
IDENTITY_SOURCE="${ROOT}/Sources/cwru-ovpn/AppIdentity.swift"

if [[ ! -f "${SOURCE_BINARY}" || "${OUTPUT_APP}" != *.app || -e "${OUTPUT_APP}" || -L "${OUTPUT_APP}" ]]; then
  echo "build-app-bundle.sh: expected a binary and a new .app destination" >&2
  exit 1
fi

APP_EXECUTABLE="$(app_identity_value executableName "${IDENTITY_SOURCE}")"
APP_IDENTIFIER="$(app_identity_value bundleIdentifier "${IDENTITY_SOURCE}")"
APP_NAME="$(app_identity_value bundleName "${IDENTITY_SOURCE}")"
APP_VERSION="$(app_identity_value version "${IDENTITY_SOURCE}")"
if [[ -z "${APP_EXECUTABLE}" || -z "${APP_IDENTIFIER}" || -z "${APP_NAME}" || -z "${APP_VERSION}" ]]; then
  echo "build-app-bundle.sh: could not read application identity" >&2
  exit 1
fi

mkdir -p "${OUTPUT_APP}/Contents/MacOS"
install -m 755 "${SOURCE_BINARY}" "${OUTPUT_APP}/Contents/MacOS/${APP_EXECUTABLE}"
INFO_PLIST="${OUTPUT_APP}/Contents/Info.plist"
/usr/bin/plutil -create xml1 "${INFO_PLIST}"
/usr/bin/plutil -insert CFBundleIdentifier -string "${APP_IDENTIFIER}" "${INFO_PLIST}"
/usr/bin/plutil -insert CFBundleExecutable -string "${APP_EXECUTABLE}" "${INFO_PLIST}"
/usr/bin/plutil -insert CFBundleName -string "${APP_NAME}" "${INFO_PLIST}"
/usr/bin/plutil -insert CFBundleVersion -string "${APP_VERSION}" "${INFO_PLIST}"
/usr/bin/plutil -insert CFBundleShortVersionString -string "${APP_VERSION}" "${INFO_PLIST}"
/usr/bin/plutil -insert CFBundlePackageType -string APPL "${INFO_PLIST}"
/usr/bin/plutil -insert CFBundleInfoDictionaryVersion -string 6.0 "${INFO_PLIST}"
/usr/bin/plutil -insert LSUIElement -bool YES "${INFO_PLIST}"

if [[ "${SIGNING_IDENTITY}" == - ]]; then
  /usr/bin/codesign --force --options runtime --sign - "${OUTPUT_APP}"
else
  /usr/bin/codesign --force --options runtime --timestamp --sign "${SIGNING_IDENTITY}" "${OUTPUT_APP}"
fi
/usr/bin/codesign --verify --deep --strict --verbose=2 "${OUTPUT_APP}"
