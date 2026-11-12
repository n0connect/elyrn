#!/bin/sh
# Creates or renews the TLS material between the backend and the bundled PostgreSQL (make certs).
# Idempotent: a run with everything current changes nothing. Never touches .env or any volume.
#
#   certs/ca.key              private CA key, 0600, never mounted into any container
#   certs/ca/ca.crt           CA certificate, mounted read-only into the backend (PGSSLROOTCERT)
#   certs/postgres/server.*   server certificate and key, mounted read-only into postgres
#
# openssl only (OpenSSL 1.1+/3.x on Linux, LibreSSL on macOS). OPENSSL overrides the binary.
set -eu

dir=${1:-certs}
openssl=${OPENSSL:-openssl}

# Validity: the CA 10 years, the server certificate 2 years; each is renewed by this script
# once it expires within 30 days, so any `make up` in that window rotates it
ca_days=3650
server_days=730
renew_seconds=$((30 * 24 * 3600))
# Every name the backend or a host-side client may dial: the compose service name, the
# container name, and loopback for psql/tests through the published port
san="DNS:postgres,DNS:elyrn-postgres,DNS:localhost,IP:127.0.0.1,IP:::1"

fail() { echo "[ERROR] certs: $*" >&2; exit 1; }

command -v "$openssl" >/dev/null 2>&1 || fail "openssl is required"

umask 077
mkdir -p "$dir/ca" "$dir/postgres"
chmod 700 "$dir"
# Readable by the containers' users (the backend's uid 10001, postgres' entrypoint as root)
chmod 755 "$dir/ca" "$dir/postgres"

tmp=$(mktemp -d "$dir/.tmp.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

# Own configuration file per subject: LibreSSL and OpenSSL disagree on -addext and default
# config paths, and LibreSSL ignores -subj when prompt = no. $1 = file, $2 = common name.
write_cnf() {
	cat > "$1" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = $2
[ca_ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[server_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $san
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
}
write_cnf "$tmp/ca.cnf" "elyrn database CA"
write_cnf "$tmp/server.cnf" "postgres"

# Positive 128-bit serial (a leading 0x7f keeps the top bit clear on every implementation)
serial() { echo "0x7f$("$openssl" rand -hex 15)"; }

valid_for_a_while() { "$openssl" x509 -noout -checkend "$renew_seconds" -in "$1" >/dev/null 2>&1; }

renewed=""

if [ ! -s "$dir/ca.key" ] || [ ! -s "$dir/ca/ca.crt" ] || ! valid_for_a_while "$dir/ca/ca.crt"; then
	echo "[INFO] certs: creating the database CA (valid $ca_days days)"
	"$openssl" ecparam -name prime256v1 -genkey -noout -out "$tmp/ca.key"
	"$openssl" req -new -x509 -config "$tmp/ca.cnf" \
		-extensions ca_ext -key "$tmp/ca.key" -sha256 -days "$ca_days" -set_serial "$(serial)" \
		-out "$tmp/ca.crt"
	mv -f "$tmp/ca.key" "$dir/ca.key"
	mv -f "$tmp/ca.crt" "$dir/ca/ca.crt"
	renewed="CA"
fi

server_current() {
	[ -s "$dir/postgres/server.key" ] && [ -s "$dir/postgres/server.crt" ] &&
		valid_for_a_while "$dir/postgres/server.crt" &&
		"$openssl" verify -CAfile "$dir/ca/ca.crt" "$dir/postgres/server.crt" >/dev/null 2>&1
}

if [ -n "$renewed" ] || ! server_current; then
	echo "[INFO] certs: issuing the PostgreSQL server certificate (valid $server_days days)"
	"$openssl" ecparam -name prime256v1 -genkey -noout -out "$tmp/server.key"
	"$openssl" req -new -config "$tmp/server.cnf" \
		-key "$tmp/server.key" -out "$tmp/server.csr"
	"$openssl" x509 -req -in "$tmp/server.csr" -CA "$dir/ca/ca.crt" -CAkey "$dir/ca.key" \
		-set_serial "$(serial)" -sha256 -days "$server_days" \
		-extfile "$tmp/server.cnf" -extensions server_ext -out "$tmp/server.crt" 2>/dev/null
	"$openssl" verify -CAfile "$dir/ca/ca.crt" "$tmp/server.crt" >/dev/null || fail "the new server certificate does not verify"
	mv -f "$tmp/server.key" "$dir/postgres/server.key"
	mv -f "$tmp/server.crt" "$dir/postgres/server.crt"
	renewed="${renewed:+$renewed and }server certificate"
fi

# Permissions are re-asserted on every run: keys owner-only, certificates public
chmod 600 "$dir/ca.key" "$dir/postgres/server.key"
chmod 644 "$dir/ca/ca.crt" "$dir/postgres/server.crt"

until=$("$openssl" x509 -noout -enddate -in "$dir/postgres/server.crt" | cut -d= -f2-)
if [ -n "$renewed" ]; then
	echo "[OK] certs: $renewed written to $dir/ (server certificate until $until)"
else
	echo "[OK] certs: current (server certificate until $until)"
fi
