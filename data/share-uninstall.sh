#!/bin/bash
# Restores the Codex config changed by __BASE__/install.sh (macOS/Linux).
main() {
  MARKER='__MARKER__'
  OFF='__OFF__'
  CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
  CFG="$CODEX_HOME/config.toml"
  CAT="$CODEX_HOME/ch-relay-catalog.json"

  if [ -f "$CFG" ]; then
    tmp=$(mktemp) || return 1
    trap 'rm -f "$tmp"' EXIT
    awk -v M="$MARKER" -v OFF="$OFF" '
      skip { skip = 0; next }
      { t = $0; sub(/^[ \t]+/, "", t); sub(/[ \t\r]+$/, "", t) }
      t == M { skip = 1; next }
      index($0, OFF) == 1 { print substr($0, length(OFF) + 1); next }
      { print }
    ' "$CFG" > "$tmp" || return 1
    cat "$tmp" > "$CFG" || return 1
  fi
  rm -f "$CAT"
  printf '\033[32m%s\033[0m\n' 'Đã gỡ. Codex trở lại cấu hình cũ.'
}
main "$@"
