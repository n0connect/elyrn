#!/bin/sh
# Run by the nginx image's entrypoint at every start (/docker-entrypoint.d/, before nginx reads
# its config; dev.frontend.Dockerfile). Renders EDGE_TRUSTED_PROXIES, the operator's own
# TLS-terminating reverse proxies in front of nginx (comma-separated IPv4/IPv6 addresses or
# CIDRs, empty by default), into the two files nginx.conf includes:
#
#   edge-proxies.realip  inside the clearnet server: set_real_ip_from <each>; real_ip_header
#                        X-Forwarded-For; real_ip_recursive on;  so $remote_addr becomes the
#                        client the listed proxy names, and only for a request from a listed proxy
#   edge-proxies.geo     "<each> 1;" for nginx.conf's geo on $realip_remote_addr (the TCP peer):
#                        X-Forwarded-Proto is taken from the peer only when it is listed
#
# Empty (the default) renders both files without a single entry: no address and no protocol a
# request sends is ever believed, exactly as before the setting existed. Any malformed entry,
# an empty one (",,"), or a prefix of 0 (that would list every address on the internet) stops
# the container with a message naming the setting: nginx never starts on a list it cannot read.
# EDGE_PROXIES_OUT_DIR overrides where the files go (scripts/check-hardening.py renders them
# into a temporary directory to check this script).
set -eu

SETTING=EDGE_TRUSTED_PROXIES
OUT_DIR=${EDGE_PROXIES_OUT_DIR:-/etc/nginx/conf.d}
REALIP_FILE=edge-proxies.realip
GEO_FILE=edge-proxies.geo
IPV4_BITS=32
IPV6_BITS=128
IPV4_OCTETS=4
IPV6_MAX_GROUPS=8
IPV6_GROUP_CHARS=4
OCTET_MAX=255

fail() {
    echo "[ERROR] $SETTING: $1 (comma-separated IPv4/IPv6 addresses or CIDRs of your own reverse proxy; empty for none)" >&2
    exit 1
}

# A decimal without sign or leading zero, at most max
is_number() {
    case "$1" in
        "" | *[!0-9]* | 0?*) return 1 ;;
    esac
    [ "${#1}" -le 3 ] && [ "$1" -le "$2" ]
}

is_ipv4() {
    case "$1" in
        "" | *[!0-9.]* | .* | *. | *..*) return 1 ;;
    esac
    old_ifs=$IFS
    IFS=.
    # shellcheck disable=SC2086 # split on dots on purpose
    set -- $1
    IFS=$old_ifs
    [ "$#" -eq "$IPV4_OCTETS" ] || return 1
    for octet in "$@"; do
        is_number "$octet" "$OCTET_MAX" || return 1
    done
}

# Hex groups and at most one "::"; no embedded IPv4 (nginx parses the result once more)
is_ipv6() {
    case "$1" in
        "" | *[!0-9A-Fa-f:]* | *:::*) return 1 ;;
        *:*) ;;
        *) return 1 ;;
    esac
    after=${1#*::}
    if [ "$after" != "$1" ]; then
        case "$after" in *::*) return 1 ;; esac
    fi
    old_ifs=$IFS
    IFS=:
    # shellcheck disable=SC2086 # split on colons on purpose
    set -- $1
    IFS=$old_ifs
    [ "$#" -le "$IPV6_MAX_GROUPS" ] || return 1
    for group in "$@"; do
        [ "${#group}" -le "$IPV6_GROUP_CHARS" ] || return 1
    done
}

# One entry: an address, or an address and a prefix length from 1 to the family's width
is_entry() {
    address=${1%/*}
    prefix=
    if [ "$address" != "$1" ]; then
        prefix=${1#*/}
        case "$prefix" in */*) return 1 ;; esac
    fi
    if is_ipv4 "$address"; then
        bits=$IPV4_BITS
    elif is_ipv6 "$address"; then
        bits=$IPV6_BITS
    else
        return 1
    fi
    [ -z "$prefix" ] && [ "$address" = "$1" ] && return 0
    # A prefix of 0 would list every address there is
    is_number "$prefix" "$bits" && [ "$prefix" -ge 1 ]
}

raw=${EDGE_TRUSTED_PROXIES:-}
# Spaces around the commas are allowed; any other whitespace fails the entry check below
list=$(printf '%s' "$raw" | tr -d ' ')

realip="# Rendered from $SETTING at start (nginx-edge-proxies.sh); empty: no proxy is trusted"
geo=$realip
if [ -n "$list" ]; then
    case "$list" in ,* | *, | *,,*) fail "an entry is empty" ;; esac
    old_ifs=$IFS
    IFS=,
    # shellcheck disable=SC2086 # split on commas on purpose
    set -- $list
    IFS=$old_ifs
    for entry in "$@"; do
        is_entry "$entry" || fail "'$entry' is not an address or CIDR with a prefix from 1 to its width"
        realip="$realip
set_real_ip_from $entry;"
        geo="$geo
$entry 1;"
    done
    realip="$realip
real_ip_header X-Forwarded-For;
real_ip_recursive on;"
fi

# Written beside, then moved: nginx never reads half a file
printf '%s\n' "$realip" > "$OUT_DIR/$REALIP_FILE.tmp"
printf '%s\n' "$geo" > "$OUT_DIR/$GEO_FILE.tmp"
mv -f "$OUT_DIR/$REALIP_FILE.tmp" "$OUT_DIR/$REALIP_FILE"
mv -f "$OUT_DIR/$GEO_FILE.tmp" "$OUT_DIR/$GEO_FILE"
