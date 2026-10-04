#!/bin/bash
# Points Codex at __BASE__ using your own ChatGPT login (macOS/Linux). Undo: curl -fsSL "__BASE__/uninstall.sh__KQ__" | bash
# Everything runs inside main() so a partially downloaded script never executes.
main() {
  BASE='__BASE__'
  MARKER='__MARKER__'
  OFF='__OFF__'
  CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
  AUTH="$CODEX_HOME/auth.json"
  CFG="$CODEX_HOME/config.toml"
  CAT="$CODEX_HOME/ch-relay-catalog.json"
  red() { printf '\033[31m%s\033[0m\n' "$1" >&2; }
  green() { printf '\033[32m%s\033[0m\n' "$1"; }

  if [ ! -f "$AUTH" ]; then
    red 'Chưa thấy đăng nhập Codex. Chạy "codex login", chọn "Sign in with ChatGPT", rồi chạy lại lệnh này.'
    return 1
  fi
  # plutil ships with every macOS and reads JSON; elsewhere fall back to sed (the JWT has no quotes).
  tok=''
  if command -v plutil >/dev/null 2>&1; then tok=$(plutil -extract tokens.access_token raw -o - "$AUTH" 2>/dev/null); fi
  if [ -z "$tok" ]; then tok=$(sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$AUTH" | head -n 1); fi
  if [ -z "$tok" ]; then
    red 'Codex đang đăng nhập bằng API key. Chạy "codex login" và chọn "Sign in with ChatGPT".'
    return 1
  fi

  tmp=$(mktemp -d) || return 1
  trap 'rm -rf "$tmp"' EXIT
  code=$(curl -sS -o "$tmp/catalog.json" -D "$tmp/headers" -w '%{http_code}' -H "Authorization: Bearer $tok" "$BASE/client/catalog__KQ__") || code=000
  case "$code" in
    200) ;;
    403) red 'License key không hợp lệ, hoặc tài khoản ChatGPT này chưa được cấp quyền. Kiểm tra lại key / liên hệ người bán.'; return 1 ;;
    401) red 'Phiên đăng nhập Codex đã hết hạn. Mở Codex dùng thử một lần rồi chạy lại lệnh này.'; return 1 ;;
    *) red "Không kết nối được máy chủ ($BASE): HTTP $code"; return 1 ;;
  esac
  default_model=$(tr -d '\r' < "$tmp/headers" | awk 'tolower($1) == "x-default-model:" { print $2 }' | tail -n 1)
  case "$default_model" in *[!A-Za-z0-9._/-]*) default_model='' ;; esac

  mkdir -p "$CODEX_HOME" || return 1
  cp "$tmp/catalog.json" "$CAT" || return 1
  if [ -f "$CFG" ]; then
    cp "$CFG" "$CFG.bak-remote-$(date +%Y%m%d%H%M%S)" || return 1
  else
    : > "$tmp/empty"; CFG_SRC="$tmp/empty"
  fi

  # Drop our previous lines (marker + the line under it); comment out (not delete) the root keys
  # we take over so uninstall can restore them.
  awk -v M="$MARKER" -v OFF="$OFF" '
    skip { skip = 0; next }
    { t = $0; sub(/^[ \t]+/, "", t); sub(/[ \t\r]+$/, "", t) }
    t == M { skip = 1; next }
    !in_table && /^[ \t]*\[/ { in_table = 1 }
    !in_table {
      k = $0; sub(/=.*/, "", k); gsub(/[ \t]/, "", k)
      if (k == "openai_base_url" || k == "model_catalog_json" || k == "model" || k == "model_provider") $0 = OFF $0
    }
    { print }
  ' "${CFG_SRC:-$CFG}" > "$tmp/kept" || return 1

  cat_toml=$(printf '%s' "$CAT" | sed 's/\\/\\\\/g; s/"/\\"/g')
  {
    printf '%s\n' "$MARKER" "openai_base_url = \"$BASE/v1\"" "$MARKER" "model_catalog_json = \"$cat_toml\""
    if [ -n "$default_model" ]; then printf '%s\n' "$MARKER" "model = \"$default_model\""; fi
    cat "$tmp/kept"
  } > "$tmp/config.toml" || return 1
  cat "$tmp/config.toml" > "$CFG" || return 1

  green 'Xong! Mở lại Codex, model mặc định là GPT-6 Astra.'
  echo "Gỡ cài đặt: curl -fsSL \"$BASE/uninstall.sh__KQ__\" | bash"
}
main "$@"
