#!/usr/bin/env sh

if [ -z "${CWRU_OVPN_BIN+x}" ]; then
  CWRU_OVPN_BIN="/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn"
fi

if command -v unalias >/dev/null 2>&1; then
  unalias ovpn 2>/dev/null || true
  unalias ovpnd 2>/dev/null || true
  unalias ovpnfull 2>/dev/null || true
  unalias ovpnsplit 2>/dev/null || true
  unalias ovpnstatus 2>/dev/null || true
fi

unset -f ovpn 2>/dev/null || true
unset -f ovpnd 2>/dev/null || true
unset -f ovpnfull 2>/dev/null || true
unset -f ovpnsplit 2>/dev/null || true
unset -f ovpnstatus 2>/dev/null || true

ovpn() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "ovpn: unexpected argument '$1'. Use: ovpn | ovpnfull | ovpnsplit" >&2
    return 2
  fi

  sudo "$CWRU_OVPN_BIN" connect
}

ovpnd() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "ovpnd: unexpected argument '$1'. Use: ovpnd" >&2
    printf '%s\n' "For explicit forced cleanup, run: sudo \"$CWRU_OVPN_BIN\" disconnect --force" >&2
    return 2
  fi

  sudo "$CWRU_OVPN_BIN" disconnect
}

ovpnfull() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "ovpnfull: unexpected argument '$1'. Use: ovpnfull" >&2
    return 2
  fi

  sudo "$CWRU_OVPN_BIN" connect --mode full
}

ovpnsplit() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "ovpnsplit: unexpected argument '$1'. Use: ovpnsplit" >&2
    return 2
  fi

  sudo "$CWRU_OVPN_BIN" connect --mode split
}

ovpnstatus() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "ovpnstatus: unexpected argument '$1'. Use: ovpnstatus" >&2
    return 2
  fi

  "$CWRU_OVPN_BIN" status
}
