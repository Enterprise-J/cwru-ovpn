CWRU_OVPN_BIN="/Library/PrivilegedHelperTools/cwru-ovpn/cwru-ovpn.app/Contents/MacOS/cwru-ovpn"

for _cwru_ovpn_name in ovpn ovpnd ovpnfull ovpnsplit ovpnstatus; do
  unalias "$_cwru_ovpn_name" 2>/dev/null || true
  unset -f "$_cwru_ovpn_name" 2>/dev/null || true
done
unset _cwru_ovpn_name

_cwru_ovpn_reject_arguments() {
  [ "$#" -le 1 ] && return 0
  printf '%s\n' "$1: unexpected argument '$2'. Use: $1" >&2
  if [ "$1" = ovpnd ]; then
    printf '%s\n' "For explicit forced cleanup, run: sudo \"$CWRU_OVPN_BIN\" disconnect --force" >&2
  fi
  return 2
}

ovpn() {
  _cwru_ovpn_reject_arguments ovpn "$@" || return
  sudo "$CWRU_OVPN_BIN" connect
}

ovpnfull() {
  _cwru_ovpn_reject_arguments ovpnfull "$@" || return
  sudo "$CWRU_OVPN_BIN" connect --mode full
}

ovpnsplit() {
  _cwru_ovpn_reject_arguments ovpnsplit "$@" || return
  sudo "$CWRU_OVPN_BIN" connect --mode split
}

ovpnd() {
  _cwru_ovpn_reject_arguments ovpnd "$@" || return
  sudo "$CWRU_OVPN_BIN" disconnect
}

ovpnstatus() {
  _cwru_ovpn_reject_arguments ovpnstatus "$@" || return
  "$CWRU_OVPN_BIN" status
}
