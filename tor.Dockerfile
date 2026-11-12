# Publishes elyrn. as a Tor onion service (make onion). tor runs unprivileged and connects only
# to nginx's onion listener; the service identity key lives in the tor_data volume.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

RUN apt-get update \
  && apt-get install -y --no-install-recommends tor \
  && rm -rf /var/lib/apt/lists/*

COPY tor/torrc /etc/tor/torrc

USER debian-tor
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
