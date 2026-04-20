#!/usr/bin/env sh

if [ -z "${CWRU_OVPN_STATE_DIR+x}" ]; then
  CWRU_OVPN_STATE_DIR="$HOME/.cwru-ovpn"
fi

if [ -z "${CWRU_OVPN_BIN+x}" ]; then
  CWRU_OVPN_BIN="$CWRU_OVPN_STATE_DIR/bin/cwru-ovpn"
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

# Connect using the default tunnel mode from the config file.
ovpn() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "ovpn: unexpected argument '$1'. Use: ovpn | ovpnfull | ovpnsplit" >&2
    return 2
  fi

  sudo "$CWRU_OVPN_BIN" connect
}

# Disconnect the current session. Force cleanup remains available through the
# underlying binary for explicit recovery flows.
ovpnd() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "ovpnd: unexpected argument '$1'. Use: ovpnd" >&2
    printf '%s\n' "For explicit forced cleanup, run: sudo \"$CWRU_OVPN_BIN\" disconnect --force" >&2
    return 2
  fi

  sudo "$CWRU_OVPN_BIN" disconnect
}

# Connect in full-tunnel mode (all traffic through VPN).
ovpnfull() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "ovpnfull: unexpected argument '$1'. Use: ovpnfull" >&2
    return 2
  fi

  sudo "$CWRU_OVPN_BIN" connect --mode full
}

# Connect in split-tunnel mode (only campus traffic through VPN).
ovpnsplit() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "ovpnsplit: unexpected argument '$1'. Use: ovpnsplit" >&2
    return 2
  fi

  sudo "$CWRU_OVPN_BIN" connect --mode split
}

# Show the current connection status.
ovpnstatus() {
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "ovpnstatus: unexpected argument '$1'. Use: ovpnstatus" >&2
    return 2
  fi

  sudo "$CWRU_OVPN_BIN" status
}
