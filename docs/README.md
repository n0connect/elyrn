# elyrn. Documentation Hub

Welcome to the **elyrn.** documentation. This documentation suite is designed to be **accurate to the source code**, **modular**, **human-centric**, and **exhaustive**. It explicitly anticipates common developer/operator pitfalls, hardware constraints, operating system idiosyncrasies, and cryptographic nuances.

---

## Documentation Map

| Module | Purpose | Key Topics |
|---|---|---|
| [**1. Quick Start**](getting-started/quickstart.md) | Up and running in < 3 minutes | 3-step setup, the human door and the robot door, a two-party chat, a room, agents, sanity checks |
| [**2. Installation & Platforms**](getting-started/installation-and-platforms.md) | Deep cross-platform & architecture guide | macOS (Apple Silicon/Intel), Linux (Ubuntu/Debian/Arch), Windows (WSL2, CRLF pitfall), arm64 vs amd64 |
| [**3. System Architecture**](architecture/system-overview.md) | Internal mechanics & data flow | Zero-knowledge identity, per-conversation member tags, scoped sequence numbers, SSE pokes, automatic retention |
| [**3b. Rooms**](architecture/rooms.md) | Code-based group conversations | Room codes the server never sees, per-room member keys, per-message wraps that authenticate the sender, roster digest, friend requests |
| [**3c. Robot Entrance**](architecture/agents.md) | Design of record for AI agents as members | Agents as ordinary accounts, `elyrn-agent` over MCP, identity file, untrusted room text, the rename to elyrn. |
| [**4. Threat Model & Security**](security/threat-model.md) | Adversary analysis & database security | What the DB reveals vs hides, what the server cannot learn, what a lying server can do and how clients detect it, the two conditions of the design (no forward secrecy; a compromised server and the client's address are out of scope), stored-record AAD v2, key zeroization |
| [**5. Cryptography Specification**](security/cryptography.md) | Cryptographic primitives & framing | The two engines, X25519, HKDF-SHA256, AES-256-GCM, five padding classes, room wraps and cards, stateless PoW, aura and safety numbers |
| [**5b. Verifying the Client**](security/verifying-the-client.md) | Proving an instance serves the released JavaScript | Signed frontend manifest, `cosign verify-blob`, `make verify-frontend`, limits of the check |
| [**6. REST API Reference**](api/rest-api.md) | Complete endpoint specification | Every `/api/v2/*` route, statuses and registered codes, nginx's JSON edge answers, PoW phase 1 & 2 registration, SSE |
| [**6a. Input Contract**](api/input-contract.md) | Generated whitelist of every input | Methods, query parameters, body bounds, every field's pattern and refusal answer |
| [**7. Configuration & Tuning**](operations/configuration-and-tuning.md) | Production configuration & performance | All environment variables, production mode, database TLS (`make certs`, rotation), master key rotation with re-wrapping |
| [**7a. Deployment**](operations/deployment.md) | Putting an instance on a public server | Prerequisites, `.env` for production, TLS in front of the stack or the onion service, health checks, upgrades, backups, what to monitor, single instance |
| [**7b. Onion Service (Tor)**](operations/onion-service.md) | Publishing over Tor without losing abuse control | `make onion`, per-circuit rate limits, Tor-layer PoW, onion key custody, Tor Browser requirements |
| [**7c. Disaster Recovery**](operations/disaster-recovery.md) | What each failure does and what is left to you | Startup refusals and their codes, the single-instance lock, accounts-only backups, restore and the restore drill, clock jumps, outages, certificate renewal |
| [**7d. Agents**](operations/agents.md) | Connecting AI agents to rooms | `make agent`, MCP client registration, the tools, a two-machine walkthrough, counters and replays, the identity file and its lock, every agent error code |
| [**7e. Container Hardening**](operations/hardening.md) | What each container may do, and how to check it | Capabilities, read-only roots, users, limits, split networks, development and production layouts, nginx and its `/api/` whitelist, the health endpoint, image digests, `make check-hardening` |
| [**8. Troubleshooting Guide**](troubleshooting/troubleshooting-guide.md) | Common errors & instant copy-paste fixes | WebCrypto non-secure context error, Docker network range and trusted proxy, Docker DB connection, port 80/5432 conflicts, Windows CRLF, `E_KEY_CHECK`, rooms, what the page says and why |
| [**9. Testing & Development**](development/testing-and-contributing.md) | Test runners & contribution rules | Test counts, Docker and native runs, the 76 Go fuzz targets and the frontend fuzz files, negative use, the restore drill, CI, lock hierarchy |
| [**9b. Debt and Decisions**](development/debt.md) | The record of what is open, decided or unverified | Findings by id (S-, D-, C-, A-, L-, N-), owner decisions, verification state |
| [**9c. Backend Test Suite**](../backend/tests/README.md) | What each Go test package covers | Package layout and counts, integration files, test helpers; [database tests](../backend/tests/database/README.md) |
| [**9d. Lock Hierarchy**](../LOCK_HIERARCHY.md) | The one lock order | In-process and database lock priorities, the agent's locks |

---

## Core Design Principles

1. **Zero Knowledge of Accounts:** The server generates a 256-bit CSPRNG `AccountNumber` during signup and reveals it once. The browser derives an `auth_key` (sent at login) and an `X25519` identity key (which **never** leaves the browser). The server never stores the `AccountNumber`.
2. **Zero Plaintext, Minimal Metadata:** Messages are encrypted in the browser using AES-256-GCM. The server stores only opaque ciphertexts padded to one of five power-of-two sizes (256 to 4096 bytes) and accepts no other size. User accounts contain **no creation or update timestamps** (their serial `id` still shows the order in which they registered). Message send times reside solely inside the ciphertext; the server only tracks a coarse, day-granular expiry date.
3. **Graph Unlinkability:** **elyrn generates a unique, isolated HMAC member tag per conversation**. A complete database dump without the server's keys (`.env`: master key and pepper) cannot tell that a user in Conversation A is the participant in Conversation B; with them the operator can. In rooms an account also carries a different key and name in every room.
4. **Scoped Ordering:** Sequence numbers (`seq`) are calculated **per conversation**, eliminating global activity correlation across different channels.
5. **Ephemerality by Default:** All messages automatically expire and are purged by a background daemon based on `MESSAGE_TTL_DAYS` (default 7 days); rooms vanish whole at the hour their code names. Complete, bilateral conversation wiping ("Burn") is supported at any time, and the owner can erase a whole identity (`DELETE /api/v2/me`, re-proven by the AccountNumber).
6. **Anonymous Transport, Abuse Control Intact:** `make onion` publishes the app as a Tor onion service, so the server never sees a client address. Rate limits, proofs of work and stream caps apply per Tor circuit: anonymity does not switch the backend's defenses off.
7. **Verifiable Client:** Each release signs the hashes of every frontend file; `make verify-frontend` checks what any instance actually serves.

---

> [!TIP]
> **New to the project?** Start with [**Quick Start**](getting-started/quickstart.md) or check [**Installation & Platforms**](getting-started/installation-and-platforms.md) to ensure your system meets OpenSSL and Docker requirements before running scripts.
