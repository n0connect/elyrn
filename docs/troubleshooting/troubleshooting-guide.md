# Troubleshooting Guide

This guide details real-world pitfalls, diagnostic commands, and immediate copy-paste solutions for common development, deployment, and cryptographic situations.

---

## Quick Diagnostic Checklist

| Error Symptom | Root Cause | Quick Solution |
|---|---|---|
| `Pool overlaps with other one on this address space` | Another Docker network already uses `172.29.73.0/24`. | Pick a free range: set `COMPOSE_SUBNET` and `PROXY_IP` in `.env`. |
| Everyone gets `429` on login or registration | Behind your own reverse proxy, nginx sees every request come from that proxy, so all users share its address. | List your proxy's address in `EDGE_TRUSTED_PROXIES`; see section 1. |
| `TypeError: Cannot read properties of undefined (reading 'subtle')` | Accessing via non-secure HTTP on IP address (e.g. `192.168.x.x`). | Use `http://localhost` or configure HTTPS/TLS. |
| `bash: \r: invalid command` | Git on Windows converted script line endings to CRLF. | `dos2unix Makefile` |
| `bind: address already in use (port 80 or 5432)` | Port occupied by another local service (Apache, local Postgres). | `sudo lsof -i :80` or remap ports in `docker-compose.yaml`. |
| Backend log: `E_DB_UNREACHABLE ... [connection refused]` | The backend cannot reach PostgreSQL (not running, or `DOCKER_DB_HOST` names another host). | `docker compose ps`; keep `DOCKER_DB_HOST=postgres` in `.env` (section 5). |
| Backend container exits with code `137` | Linux Out-Of-Memory (OOM) Killer killed the backend: the host has less memory than the containers' limits. | Enable host swap, or lower `BACKEND_MEM_LIMIT` no further than `make check-hardening` allows; see section 6. |
| Session lost immediately upon browser reload | Private/Incognito mode blocked IndexedDB storage, or the browser could not keep the identity. | Normal window or save AccountNumber to log in again; see section 7. |
| New messages appear late (up to about 30 s), then every few seconds | A proxy in front of the stack buffers the event stream (`/api/v2/events`); the console shows `W_LIVE_STREAM_SILENT`. | Turn buffering off for that path in the proxy; see [Deployment](../operations/deployment.md). |
| Backend restarts in a loop with `E_KEY_CHECK` | `.env` does not belong to this database (regenerated, or an old master key removed too early). | Restore the original `.env`; see section 9. |
| `bind source path does not exist: .../certs/postgres` (or `certs/ca`) | The stack was started without `make certs` (plain `docker compose up`). | `make certs`, or start with `make up`, which runs it. |
| Backend log: `E_DB_UNREACHABLE ... [TLS: the database certificate does not verify against PGSSLROOTCERT; ...]` (or `has expired`) | `certs/` was replaced but a container still holds the old material, a certificate expired, or `DOCKER_DB_HOST` names a host the certificate does not list. | `make up` (renews and recreates what must reload); keep `DOCKER_DB_HOST=postgres`. |
| `pg_hba.conf rejects connection ... no encryption` | A client connected to PostgreSQL over TCP without TLS; the bundled database refuses that. | Connect with TLS: `sslmode=verify-full sslrootcert=certs/ca/ca.crt` ([Database TLS](../operations/configuration-and-tuning.md#database-tls-make-certs)). |
| `make onion` stops with `requires APP_ENV=production` | The onion service publishes the instance; development mode is refused. | Set `APP_ENV=production` in `.env` ([Production Mode](../operations/configuration-and-tuning.md#production-mode)). |
| `pool overlaps` after adding `BACKEND_IP` or changing `COMPOSE_SUBNET` | `PROXY_IP` and `BACKEND_IP` must lie inside `COMPOSE_SUBNET`, `TOR_IP` inside `EDGE_SUBNET`. | Move each range with its addresses in `.env`. |
| `make onion`: `Invalid address 172.29.73.11` for tor | `.env` still sets the pre-split `TOR_IP`; tor now lives on `edge`. | `TOR_IP=172.29.72.11` (or delete the line). |
| `curl localhost:8080` or `psql -p $DB_HOST_PORT` refused | Production layout: only nginx is published. | Use `http://localhost/api/...`, or `make shell-db` (psql inside the database container as `DB_USER` on `DB_NAME`); or run development (`APP_ENV=development`). See [Hardening](../operations/hardening.md#layouts). |
| Backend killed with code `137` after lowering `BACKEND_MEM_LIMIT` | The limit no longer holds the file-request pool plus 128 MiB. | Raise `BACKEND_MEM_LIMIT` (and `BACKEND_GOMEMLIMIT`); `make check-hardening` names the size. |

---

## 1. Docker Network Range and the Trusted Proxy

### Symptom
`make up` fails with `Pool overlaps with other one on this address space`, or, behind your own reverse proxy, every user receives `429 Too Many Requests` after a handful of logins.

### Cause
Rate limits are keyed by the client address. nginx reaches the backend from a fixed address on the compose network (`PROXY_IP`, default `172.29.73.10` in `COMPOSE_SUBNET` `172.29.73.0/24`), and the backend accepts `X-Forwarded-For`/`X-Real-IP` only from that address (`TRUSTED_PROXIES`). nginx sets both headers itself, to the client address as nginx sees it, and replaces whatever the request carried (`nginx-api-proxy.conf`). If the range is taken by another Docker network, compose cannot create it; if another proxy sits in front of nginx, nginx's client is that proxy unless nginx is told to trust it, and all users share one rate-limit bucket.

### Fix
1. **Range collision:** choose a free private range in `.env`, keeping the proxy address inside it:
   ```bash
   COMPOSE_SUBNET=172.31.200.0/24
   PROXY_IP=172.31.200.10
   ```
2. **Your own reverse proxy in front of nginx:** adding it to the backend's `TRUSTED_PROXIES` does not help: the backend trusts nginx alone, and nginx overwrites `X-Forwarded-For`. Set `EDGE_TRUSTED_PROXIES` in `.env` to your proxy's address as nginx sees it (a proxy on the same host: the gateway of `EDGE_SUBNET`, `172.29.72.1` by default) and run `make up`: nginx then takes the client address and protocol from that proxy alone. See [Deployment](../operations/deployment.md#4-tls-in-front-of-the-stack).

---

## 2. WebCrypto "crypto.subtle is undefined" (Secure Context)

### Symptom
The main menu shows *"this browser cannot run elyrn. securely (needs https and WebCrypto X25519) — update your browser"*, or **new identity** / **login** does nothing and the developer console shows:
```text
TypeError: Cannot read properties of undefined (reading 'subtle')
```

### Cause
W3C WebCrypto API specification requires a **Secure Context**. Modern browsers automatically disable `window.crypto.subtle` when accessing via unencrypted HTTP on remote IP addresses (such as `http://192.168.1.45/` or `http://your-server-ip/`).

### Fix
1. **For Local Testing:** Always navigate to **`http://localhost`** or **`http://127.0.0.1`** (browsers treat loopback addresses as secure contexts even over HTTP).
2. **For Remote / LAN Testing:** You **must** terminate TLS with a reverse proxy or generate a self-signed / Let's Encrypt SSL certificate.

---

## 3. Windows / WSL2: CRLF Line-Ending Failure

### Symptom
Inside WSL2, executing `make` fails with:
```text
bash: \r: invalid command
```

### Cause
When cloned using Git for Windows, text files have Unix `LF` line-endings replaced with Windows `CRLF` (`\r\n`). Bash cannot parse carriage return characters.

### Immediate Fix
Inside your WSL terminal, run:
```bash
sed -i 's/\r$//' Makefile
# Or using dos2unix:
sudo apt-get install -y dos2unix
dos2unix Makefile
```
To prevent Git from doing this in future checkouts:
```bash
git config --global core.autocrlf input
```

---

## 4. Port Conflict: Port 80 or 5432 Already in Use

### Symptom
Running `make up` fails during Docker startup:
```text
Error response from daemon: driver failed programming external connectivity on endpoint elyrn-frontend:
Bind for 0.0.0.0:80 failed: port is already allocated
```

### Cause
Another web server (Nginx, Apache, IIS) or database server (local PostgreSQL) is already running on port 80 or 5432.

### Diagnosis & Fix
1. **Find what is holding the port:**
   ```bash
   # On macOS or Linux:
   sudo lsof -i :80
   sudo lsof -i :5432
   ```
2. **Option A: Stop the conflicting service:**
   ```bash
   # Stop local Apache / Nginx:
   sudo systemctl stop nginx
   sudo systemctl stop apache2
   # Stop local Postgres:
   sudo systemctl stop postgresql
   ```
3. **Option B: Move the published ports in `.env`:** `HTTP_PORT=8000` serves the app at
   `http://localhost:8000` (add that origin to `ALLOWED_ORIGINS`); `DB_HOST_PORT` moves
   PostgreSQL's development port.

---

## 5. Docker Backend Database Connection Failure

### Symptom
The `elyrn-backend` container restarts repeatedly. Its log shows one coded line (the driver's own text, which names the user, database and host, never reaches the log):
```text
[STARTUP] E_DB_UNREACHABLE: the database did not accept a connection within the startup wait; ... [connection refused]
```
Other details in the same place: `the database host name does not resolve`, `timed out`, `SQLSTATE 28P01` (wrong password), `SQLSTATE 3D000` (no such database), or a `TLS: ...` sentence (see the checklist above).

### Cause
In Docker Compose networking, `localhost` inside the `backend` container refers to the container itself, not the `postgres` container.

### Fix
`docker-compose.yaml` is configured to use `${DOCKER_DB_HOST:-postgres}`. Ensure `DOCKER_DB_HOST` in `.env` is set to `postgres` (the Docker service name):
```ini
DOCKER_DB_HOST=postgres
```
*Note: in the development layout Docker publishes PostgreSQL on `127.0.0.1:$DB_HOST_PORT` (TLS only, `sslmode=verify-full sslrootcert=certs/ca/ca.crt`); the production layout publishes nothing but nginx.*

---

## 6. Out-Of-Memory (OOM) Crash on Low-RAM VPS

### Symptom
Backend exits abruptly with exit code `137` (SIGKILL by Linux kernel OOM killer). `dmesg` reports:
```text
Out of memory: Killed process 1234 (main) total-vm:854320kB, anon-rss:524100kB
```

### Cause
On a 512MB or 1GB VPS the containers' memory limits together (the backend's `BACKEND_MEM_LIMIT` is 512 MiB by default) can exceed what the host has.

### Fix
Lower `BACKEND_MEM_LIMIT` (and `BACKEND_GOMEMLIMIT` with it), never below what `make check-hardening` names (the file-request pool plus 128 MiB, 177 MiB). Add a 2GB swap file to prevent kernel kills:
```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## 7. Reloading the Browser Says "session ended — log in again"

### Symptom
After reloading or opening a new tab, the user is unexpectedly returned to the Login screen.

### Cause
The browser is operating in **Incognito / Private Browsing mode** or **Tor Browser Strict mode**, where IndexedDB write permissions are disabled or wiped on tab close.
In this mode, `keystore.js` keeps private keys in volatile memory only.

When storage fails, the page says so once: *"this browser is not keeping anything — you will be logged out on reload, and replay protection lasts only until then"*. Two related warnings name another tab: *"another elyrn. tab is holding the storage — close the other tabs, then reload this one"* (an upgrade is held back by a tab still running an older version) and *"another elyrn. tab changed this browser's storage — reload this tab"* (another tab upgraded the storage, or logged out and deleted it; this tab stops using storage until reloaded).

In Safari (WebKit) before this was fixed, every reload opened on the main menu with no warning: WebKit stores the identity's X25519 key in IndexedDB without error and cannot read it back. Such a browser now keeps the identity in its sealed form ([Cryptography](../security/cryptography.md#3-the-identity-kept-across-reloads-indexeddb)); a record written by an older version is still unreadable, so the first reload after the update opens the main menu once with *"your key could not be read back in this browser — log in once with your account number; nothing is lost"* (`W_IDENTITY_UNREADABLE`); that unreadable record is removed (nothing else is), so later reloads open the plain main menu until you log in. If the warning shows on every reload, the browser refused the removal (logged `W_IDENTITY_NOT_FORGOTTEN`): log in once, which replaces the record. A browser that can keep neither form says so after login: *"this browser cannot keep your identity — you will need your account number after a reload"*.

A reload keeps the stored identity whatever the server answers its `/me` check, except a `401` (the session is gone) or another public key than this device's: a busy server (`429`), a `404`, any `5xx` or no answer shows that answer's sentence on the main menu with **retry**, and nothing is wiped.

### Handling
- If privacy settings block IndexedDB, keep your 43-character `AccountNumber` copied in a password manager.
- You can log back in at any time: the derived keys and conversations will be restored.
- For the two tab warnings, close the other elyrn. tabs and reload.

---

## 8. Onion Service (`make onion`)

| Symptom | Cause | Fix |
|---|---|---|
| `make onion-address` says *Not published yet* | tor is still bootstrapping into the Tor network (about a minute on first start). | Wait, then retry; `docker logs elyrn-tor` must show `Bootstrapped 100%`. |
| Tor Browser shows the page, but **new identity** / **login** does nothing | JavaScript is off ("Safest" security level) or Tor Browser is older than 15 (no X25519 in WebCrypto). | Security level **Standard**; update Tor Browser. |
| `nginx: [emerg] invalid parameter "${TOR_IP}"` | The frontend image was started without `TOR_IP` (outside compose). | Set `TOR_IP` (compose defaults it to `172.29.72.11`); nginx refuses to start rather than open the onion port to anyone. |
| Every onion request answers `403` | The connection does not come from the tor container: `TOR_IP` differs from the tor container's address. | Keep `TOR_IP` and the tor service's `ipv4_address` equal (both come from `.env`). |

---

## 9. `E_KEY_CHECK` at Startup

### Symptom
The backend never becomes ready and restarts in a loop. Its log names the variable to restore (never a key or a key id):
```text
[STARTUP] E_KEY_CHECK: the keys in .env do not open this database ... [variable MASTER_KEY_OLD] [records are encrypted under a master key id that is not configured: restore that key as MASTER_KEY_ACTIVE or in MASTER_KEY_OLD (the ids in use: SELECT DISTINCT master_key_id FROM users)]
[STARTUP] E_KEY_CHECK: the keys in .env do not open this database ... [variable MASTER_KEY_OLD] [a configured master key does not open the records stored under its id]
[STARTUP] E_KEY_CHECK: the keys in .env do not open this database ... [variable ACCOUNT_LOOKUP_PEPPER] [is not the pepper this database was created with: restore the original (it can never change, every account is keyed by it)]
```
Every other refused start has its own code too (`E_CONFIG_INVALID`, `E_SECOND_INSTANCE`, `E_SCHEMA_NEWER`, ...); [Disaster Recovery](../operations/disaster-recovery.md#startup-refusals) lists them.

### Cause
The `.env` does not belong to the database in `postgres_data`: it was regenerated (`rm .env && make setup`), copied from another instance, or an old master key was dropped from `MASTER_KEY_OLD` while records still use it. Starting anyway would answer every user with errors, so the backend refuses.

### Fix
Restore the `.env` that wrote this database (or put the old key back into `MASTER_KEY_OLD`), then `docker compose up -d backend`. If that `.env` is gone for good, the data cannot be read by anyone; see [Disaster Recovery](../operations/disaster-recovery.md) for starting over.

---

## 10. Rooms

### "a room failed verification against its code — it cannot be opened, only left"
The server listed a room whose vault does not open for this account, or whose member limit or expiry differ from the code inside it. The browser never opens it and never trusts the server's numbers for it: the list shows it under the name its id gives, marked *failed verification · cannot be opened*, with one action, **leave** (**burn** if the server says you own it), which asks first and frees the seat. The warning appears once per room per session, not on every refresh. On an honest server this does not happen; if it does, report it with the time it appeared.

### "the member list failed verification — not sending to it"
The roster lacked this member's own card, listed more members than the code allows, or attributed a card wrongly. Nothing is encrypted for such a list. Reload; if it persists, the server is tampering with the room. A roster that could not be fetched at all (no answer, a server error, a rate limit) is reported as that, not as a verification failure.

### "the server refused the room — check your device clock" / "the server refused the room's settings — reload the page and try again"
The server checks a new room's expiry against its own clock and refuses it (`400`) when it strays more than ten minutes. The browser compares its clock with the server's time on the proof-of-work challenge: only when they differ by more than that does it name the clock; otherwise the settings themselves were refused, and a reload fetches the server's current limits. A rate-limited challenge or room says *"too many rooms or attempts — wait a moment"*.

### "this room has expired — if it should not have, check your device clock"
Room expiry is judged by this device's clock before anything is sent. A clock running fast makes a live room look expired; set the clock right and try again.

### "no such room — the code is wrong, or the room expired or was burned"
The server answers a wrong code, an unknown room and an expired room the same way (`404`), so it cannot tell you which. Check the code was copied whole (56 characters starting with `elyrn#`, or 57 for an older `noaddx#` code); a room also stops answering at the hour its code names.

### A message to a room is not sent and the member list changes
Someone joined or left between fetching the member list and sending (`412`). The browser fetches the list again and re-encrypts under the same message id, twice at most. If it still fails the room is changing faster than that; send again.

### After an upgrade the page asks for the account number again
Sessions saved before rooms existed do not hold the rooms key; logging in once more derives and keeps it.

### Member roles
- *"only the room's owner can set another member's role"*: the server refused (`403 Role not allowed`). The page offers the control only where it can be used, so this means the page's view of who owns the room is stale; reload.
- *"that member is no longer in this room"*: they left (or the room changed) before the role was stored (`404`).
- *"too many role changes — wait a moment"*: the role rate bucket is spent (`429`).
- A role that was set shows as nothing: it did not open for this room and member, or its text breaks the role rule (logged as `W_ROLE_UNREADABLE`, never its text). Only the members of the room can set roles; a server can at most show an older role of the same member.

### "two seats claim this identity"
Two cards of the member list open to one member's key: someone holding the room code took a seat with a card carrying that member's key ([rooms](../architecture/rooms.md#disputed-seats)). The member is shown once, with no role, and cannot be befriended or given a role until one seat leaves; the room says so once per session (*"two seats in this room claim one identity — …"*), and the member whose key it is reads *"another seat in this room claims to be you — …"*. Compare the room safety number with the others on another channel; the owner can burn the room and open a new one with a fresh code.

### "replay protection is not kept for this sender on this device"
This device's replay record for the room is full (4096 senders, far more than a room's seats): a sender new to it who is not a member is not recorded, so a replay of its messages after a reload would not be caught on this device. The room says so once per session (*"this room's replay record on this device is full — …"*). Members and your own messages stay protected; a member new to the full record takes the place of the off-roster sender recorded most recently, which is then tagged the same way. So many senders mean someone sent under keys of their own making; a server of this release refuses that (`400 Sender card mismatch`).

### Friend requests
- *"this request did not come from the member who sent it — the conversation it opened was burned"*: the request's binder did not match the account that created its invite: another member relayed someone else's invite. The conversation it opened was burned at once and the request removed.
- *"sent by an older elyrn and cannot be checked — ignore it and ask them to send a new request"*: the request has no binder (its sender's page is older than binders). Only **ignore** is offered; ask them to reload and send it again.
- *"sent by a newer elyrn; reload this page to read it"* in place of a request: this page is older than the sender's. Reload.
- A request you sent never shows up on the other side: their page may be older than binders, which drops such a request unread; ask them to reload.

---

## 11. Sign-in, Sending and Outages

Every sentence the browser shows comes from one registry, `frontend/js/errors.js`; the server's
own text is never shown.

| The page says | What happened | What to do |
|---|---|---|
| *"that is an invite or a room code — log in first, then use join"* | An `elyrn:` invite or `elyrn#` room code was pasted into the login field. | Log in with the account number, then paste the code under **join**. |
| *"that looks like an account number — never send it. nothing was sent"* | The message (or one word of it, fullwidth look-alikes included) reads as an account number. | Remove it. An account number is the only key to an identity. |
| *"that looks like an account number — never share it. ask for an invite instead"* | An account number was pasted into **join**. | Ask for an invite or a room code. |
| *"the server said the message id is already in use, twice — nothing was sent, press send again"* | The server answered `409 Id taken` for the message id and again for the one fresh id the browser drew. | Press send again. If it repeats, the server is misbehaving. |
| *"the server refused the message as a duplicate — press send again"* | A `409` on a first attempt (no earlier answer was lost), which is never taken as stored. | Press send again. |
| *"message not sent — press send again"* | No answer, or the server failed (`5xx`; a database outage answers `503`). | Wait a moment and press send again: a retry reuses the message id, so it never arrives twice. |
| *"no answer from the server — check your connection and try again"* / *"cannot reach the server — …"* | The request timed out, or never reached the server. | Check the connection; the page has a **retry** where loading failed. |
| *"the server does not accept this request — reload the page and try again"* | nginx refused the request itself (`E_EDGE_NOT_FOUND`, `E_EDGE_METHOD_NOT_ALLOWED`): usually a page older than the server. | Reload the page. |
| *"service unavailable — try again in a moment"* | nginx could not reach the backend (`503 E_BACKEND_UNAVAILABLE`). | Wait; the operator checks `docker compose ps` and the backend log. |
| *"your account may already exist and this number is the only way into it — save it now …"* | **← back to main menu** (or Escape) was pressed after the account was requested. | Save the number, then press back again to leave. |
| *"sent by a newer elyrn; reload this page to read it"* (in place of a message) | The message is authentic, but its sender's elyrn. writes a field this page does not know yet (the page is older than the server's). Nothing was tampered with. | Reload the page to get the current client; the message then opens. |
| *"files can be at most … on this server — choose a smaller one"* / *"that file is empty — choose another one"* / *"one file per message — choose a single file"* | The chosen file is over this server's `MAX_FILE_BYTES`, empty, or more than one file was dropped or pasted. Nothing was read or sent. | Choose one file within the limit. |
| the chosen file shows another name, `file-` and eight letters and digits | Every file is sent under such a name (with its extension when it is short and plain): the name you gave it never leaves your device. | Nothing; tell the other side what it is if they need to know. |
| *"this file is delivered exactly as it is. …"* under every chosen file | elyrn. never reads, cleans or changes a file: photos and documents keep their location, device, author and time, and the file can be recognised wherever the same file turns up. This is said every time and cannot be turned off. | Remove what should not go with your own tools before choosing the file, or do not send it. |
| a received file has only **save** | elyrn. never opens or previews a file; it hands the exact bytes to your browser. A received file is whatever another member chose to send. | Open it only if you trust it, with a program you trust. |
| *"could not clear the clipboard — copy something else to overwrite it"* | elyrn. tried to clear the account number, an invite or a room code from the clipboard (on continue, or two minutes after a code was copied) and the browser refused the write or did not answer within 3 seconds (a tab without focus). | Copy something harmless to overwrite it; clear your clipboard history if your system keeps one. |
| *"the server holds another member card for you in this room — nothing was sent; reload the page, then send again"* | `400 Sender card mismatch`: this page sent under a card the server does not hold for your seat (its view of the member list is stale). | Reload the page, then send again. |
| *"this browser did not copy your account number — select it, copy it by hand and keep it safe, then press continue"* | The clipboard refused the copy, or did not answer within 3 seconds (a tab without focus can wait forever). The number stays on screen. | Select the number, copy it by hand, keep it, then press continue. |
| *"the file could not be read — it may have changed or moved; choose it again"* | The file changed, moved or vanished on disk while the browser read it. | Choose it again. |
| *"the file stopped uploading — check your connection, then press send again to continue"* / *"the server is busy — press send again in a moment to continue the upload"* | A part got no answer, or a `502`, `503` or `504`, three times. The parts already stored stay and the file stays attached. | Press send again: the upload continues where it stopped (same file id), while the page stays open. |
| *"the server lost track of this upload — press send again to upload the file afresh"* | `409 Id taken` or `File part out of order` (part 0 expired or was never stored). | Press send again: the file goes again under a new id. |
| *"you have sent as many files today as this server allows — try again tomorrow"* / *"too many new files at once — …"* | `429 File budget spent` (`FILE_ACCOUNT_DAILY_BYTES`) or the `file` rate bucket. | Wait. |
| *"you already hold your share of this conversation's files — …"* | `507 File share reached`: the files you sent in this conversation fill your share of its quota (the quota divided by its seats). | Send it once some of yours have expired. |
| *"this conversation holds as many files as the server allows — …"* / *"the server has no room for files right now — …"* | `507 File quota reached` (`FILE_CONVERSATION_QUOTA_BYTES`) or `507 File store full` (`FILE_STORE_MAX_BYTES`). | Wait for older files to expire; the operator can raise the limits. |
| *"this conversation is gone (burned, expired or left) — the file was not sent"* | `404` during the upload: the room expired or the conversation was burned or left meanwhile. | Nothing to do: no message was sent. |
| *"this file is no longer available — …"* | A part answered `404`: it expired with the messages' day rule, or its conversation lost it. | Ask the sender to send it again. |
| *"this file failed its integrity check — nothing of it was kept"* | A part did not open, its padding was not zero, or the file did not match its hash: altered in storage or announced wrongly. | Ask the sender to send it again; if it repeats, the server is misbehaving. |
| no **alerts** bell in the header | This browser has no Notification API (some embedded browsers, older mobile browsers): content-free alerts cannot exist here. | Use a browser that has it. |
| *"this browser blocks notifications for this site — allow them in its site settings, then turn alerts on"* | Notifications for this site were denied in the browser. | Allow them in the browser's site settings, then press the hollow, struck-through bell (**alerts off**) again. |
| *"notifications were not allowed — alerts stay off"* | The browser's question was closed without an answer. | Press the struck-through bell (**alerts off**) again and allow. |
| *"notifications are no longer allowed for this site — alerts turned off"* | Permission was withdrawn after alerts were turned on. | Allow them again in the site settings, then turn alerts on. |
| alerts are on and nothing shows | An alert shows only while elyrn. is open in some tab and that tab is hidden, once until the tab is seen again; the operating system's do-not-disturb or the browser's own notification settings can still hold it back, and some browsers refuse page notifications altogether (logged as `W_ALERT_NOT_SHOWN`). | Keep a tab open; check the system's notification settings for the browser. |

Every screen before login (login, new identity, the robot side) has a way back: its
**← back to main menu** button (**← back to the human door** on the robot entrance), the brand
title, or Escape. Leaving registration stops its proof of work and clears the account number from
the screen and, when the page put it there, tries to clear it from the clipboard (and says so when
it could not). Leaving login while a login runs abandons it: nothing is saved and the app does not
open; the number is never shown in clear while logging in, whether login was pressed with the
pointer or with Enter.

---

### Next Steps:
- Review [**Testing & Development**](../development/testing-and-contributing.md) for automated test suites.
- Read [**Configuration & Tuning**](../operations/configuration-and-tuning.md) for full parameter references.
- Plan for failures with [**Disaster Recovery**](../operations/disaster-recovery.md).
