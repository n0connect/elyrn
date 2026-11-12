#!/bin/sh
# Entrypoint of the bundled PostgreSQL (docker-compose.yaml). Runs as root only long enough to
# hand the TLS key to the postgres user, then execs the image's own entrypoint, which drops to
# postgres (uid 70) before the server starts.
#
# PostgreSQL refuses a key file that is not owned by its user (or root with group access only)
# or that others can read. The bind-mounted key keeps the host owner's uid, so instead of
# loosening it on the host, it is copied into a tmpfs owned by postgres with mode 0600. The key
# never touches the image, the container's writable layer or the data volume.
set -eu

src=/etc/elyrn/tls      # make certs output, mounted read-only
dst=/run/elyrn-tls      # tmpfs, gone when the container stops

for f in server.crt server.key; do
	if [ ! -r "$src/$f" ]; then
		echo "elyrn: $src/$f is missing: run 'make certs' on the host, then start again" >&2
		exit 1
	fi
done

install -d -o postgres -g postgres -m 0700 "$dst"
install -o postgres -g postgres -m 0644 "$src/server.crt" "$dst/server.crt"
install -o postgres -g postgres -m 0600 "$src/server.key" "$dst/server.key"

exec docker-entrypoint.sh "$@"
