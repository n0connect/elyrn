#!/bin/sh
# Run by the nginx image's entrypoint at every start (/docker-entrypoint.d/, before nginx reads
# its config; dev.frontend.Dockerfile), after nginx-edge-proxies.sh. The one home of HSTS: it
# validates APP_ENV, HSTS_MAX_AGE, HSTS_INCLUDE_SUBDOMAINS and HSTS_PRELOAD and renders the one
# file nginx.conf's $hsts map includes:
#
#   hsts.map   in production with a max-age above 0, one entry: "|https" "max-age=N[; ...]";
#              the key is "<PROXY protocol address>|<forwarded protocol>", so it matches only on
#              the clearnet listener (the onion listener always has a PROXY address) and only when
#              a listed edge proxy said the request came over HTTPS ($forwarded_proto: nginx itself
#              listens on plain HTTP). Otherwise no entry: $hsts stays empty and nginx-site.conf's
#              server-level add_header sends nothing.
#
# HSTS_MAX_AGE unset or empty means 31536000 (one year); 0 turns HSTS off; at most 63072000 (two
# years). The booleans take true/false/1/0/yes/no (any case) and default to false. Any malformed
# value stops the container with a message naming the setting: nginx never starts on a value it
# would read differently from what the operator meant. HSTS_OUT_DIR overrides where the file goes
# (scripts/check-hardening.py renders it into a temporary directory to check this script).
set -eu

OUT_DIR=${HSTS_OUT_DIR:-/etc/nginx/conf.d}
MAP_FILE=hsts.map
DEFAULT_MAX_AGE=31536000
MAX_MAX_AGE=63072000
MAX_AGE_DIGITS=8

fail() {
    echo "[ERROR] $1: $2" >&2
    exit 1
}

lower() {
    printf '%s' "$1" | tr -d ' \t' | tr 'A-Z' 'a-z'
}

# A boolean setting as 1 (on) or 0 (off); empty is off
boolean() {
    case "$(lower "$2")" in
        "" | false | 0 | no) echo 0 ;;
        true | 1 | yes) echo 1 ;;
        *) fail "$1" "must be true or false" ;;
    esac
}

app_env=$(lower "${APP_ENV:-development}")
case "$app_env" in
    production | prod) production=1 ;;
    development | test) production=0 ;;
    *) fail APP_ENV "must be one of development, test, production" ;;
esac

max_age=$(printf '%s' "${HSTS_MAX_AGE:-}" | tr -d ' \t')
case "$max_age" in
    "") max_age=$DEFAULT_MAX_AGE ;;
    0) ;;
    *[!0-9]* | 0?*) fail HSTS_MAX_AGE "must be an integer between 0 and $MAX_MAX_AGE seconds (0 turns HSTS off; empty means $DEFAULT_MAX_AGE)" ;;
esac
if [ "${#max_age}" -gt "$MAX_AGE_DIGITS" ] || [ "$max_age" -gt "$MAX_MAX_AGE" ]; then
    fail HSTS_MAX_AGE "must be an integer between 0 and $MAX_MAX_AGE seconds (0 turns HSTS off; empty means $DEFAULT_MAX_AGE)"
fi
subdomains=$(boolean HSTS_INCLUDE_SUBDOMAINS "${HSTS_INCLUDE_SUBDOMAINS:-}")
preload=$(boolean HSTS_PRELOAD "${HSTS_PRELOAD:-}")

map="# Rendered from APP_ENV and HSTS_* at start (nginx-hsts.sh); no entry: no HSTS"
if [ "$production" -eq 1 ] && [ "$max_age" -gt 0 ]; then
    value="max-age=$max_age"
    [ "$subdomains" -eq 1 ] && value="$value; includeSubDomains"
    [ "$preload" -eq 1 ] && value="$value; preload"
    map="$map
\"|https\" \"$value\";"
fi

# Written beside, then moved: nginx never reads half a file
printf '%s\n' "$map" > "$OUT_DIR/$MAP_FILE.tmp"
mv -f "$OUT_DIR/$MAP_FILE.tmp" "$OUT_DIR/$MAP_FILE"
