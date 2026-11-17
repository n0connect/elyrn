# Onion Service (Tor)

`make onion` starts the normal stack plus a `tor` container that publishes the app as a Tor
v3 onion service. Users reach it with Tor Browser; neither side learns the other's IP address,
and the server's location stays hidden.

It is **opt-in**: a plain `make up` keeps every service on loopback. Publishing an onion
service makes the instance reachable from anywhere on the Tor network.

```bash
make onion            # build and start everything, including tor
make onion-address    # print the .onion address (about a minute after the first start)
```

`make onion` runs only in **production mode**: set `APP_ENV=production` in `.env` first (it
stops with an error otherwise). That turns on the `__Host-Session` cookie (`Secure`) and every
production startup check; the backend reaches the bundled PostgreSQL over TLS 1.3 with the
certificate checked (`make certs`, run by `make onion`). See
[Production Mode](configuration-and-tuning.md#production-mode).

---

## How a request travels

```text
Tor Browser ──Tor──▶ tor container ──PROXY header + HTTP──▶ nginx :8081 ──X-Forwarded-For──▶ backend
                     (172.29.72.11)   source = this circuit   (onion       = the circuit
                                                               listener)
```

1. **tor** (`tor.Dockerfile`, `tor/torrc`) publishes the service and forwards onion port 80 to
   nginx's onion listener (`frontend:8081`, over the `edge` network). With `HiddenServiceExportCircuitID haproxy` it opens every
   connection with a PROXY header whose source address encodes the Tor circuit
   (`fc00:dead:beef:4dad::/64`, circuit ID in the low 32 bits).
2. **nginx** listens on `8081 proxy_protocol` and accepts connections from the tor container
   only (`allow ${TOR_IP}; deny all;`). Nothing else can reach that port, so nobody else can
   claim to be a Tor circuit. The circuit address becomes `$client_addr`, which feeds nginx's
   rate limit and is the only address forwarded.
3. **backend** trusts the forwarded address only from nginx (`TRUSTED_PROXIES`), as for
   clearnet traffic, and keys each Tor circuit separately
   (`backend/internal/middleware/trustedproxy.go`).

## Zero trust behind Tor

Every request arrives from the tor container, so without circuit IDs all Tor users would share
one rate-limit bucket: a few failed logins or PoW challenges would lock everyone out. The
defenses stay layered and none of them needs an identity:

| Layer | Defense |
|---|---|
| Tor | `HiddenServicePoWDefensesEnabled` (client puzzles when the service is under load), `HiddenServiceEnableIntroDoSDefense` (rate-limited introductions), `HiddenServiceMaxStreams 32` (a circuit asking for more open connections is torn down: rate limits count requests, not idle connections) |
| nginx | 20 req/s per circuit, onion listener open to the tor container only |
| backend | Per-circuit rate limits and PoW challenge budget, PoW for registration, invites and rooms, per-circuit share of live event streams (16), every input validated as for clearnet traffic. The PoW issuer forgets a client once it has been idle for a whole window (its budget has refilled by then), so filling its client cap takes 50,000 circuits within a minute, not within an hour |

A client can open new circuits, but each one costs a Tor rendezvous, and under load also the
Tor-layer puzzle. Registration, invites and rooms still cost an application-level proof of work per
request, whatever circuit they arrive on.

## The onion address key

The service identity lives in the `tor_data` volume
(`/var/lib/tor/noaddx/hs_ed25519_secret_key`; `noaddx` is a storage name kept across the rename
to elyrn., so existing onion addresses survive). Losing it changes the address; leaking it lets
someone impersonate the service. Back it up encrypted and offline (it is not part of
`make backup-accounts`; see [Disaster Recovery](disaster-recovery.md#what-must-survive)).
`make clean` deletes it along with every other volume.

The tor container's healthcheck only tests that the address was published (a file); check
reachability from outside with Tor Browser ([Hardening](hardening.md#known-limits)).

## Browser requirements

- **Tor Browser 15 or newer.** The client needs X25519 in WebCrypto (Firefox ESR 140).
- **Security level Standard.** The client needs JavaScript for all of its cryptography.
  "Safest" disables JavaScript everywhere; "Safer" disables it on non-HTTPS sites, and the Tor
  Project does not document whether that includes a plain-HTTP onion.
- Tor Browser treats `.onion` as a secure context, which WebCrypto requires and which lets the
  production `__Host-Session` cookie (Secure, HttpOnly, SameSite=Strict) be set over the onion
  connection. Confirm the first login in Tor Browser after deploying.

Writes need no extra configuration: Tor Browser sends `Sec-Fetch-Site: same-origin`. Add the
onion origin (`http://<address>.onion`) to `ALLOWED_ORIGINS` only for clients that send no
`Sec-Fetch-Site` header.
