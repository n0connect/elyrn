# Lock Hierarchy Documentation (RULES.md §4.2)

## Global Lock Ordering

Locks MUST be acquired in the following order (lowest to highest priority) to prevent deadlocks:

### Priority Level 1 (Lowest) - Application State
- `globalRateLimiter.mu` (RWMutex) - Rate limiting buckets map; held for every lookup/insert and
  for the bucket's own take or refund in the same hold (`RateLimiter.take`/`refund`), so nobody
  spends from a bucket evicted meanwhile; while held it takes a bucket's `TokenBucket.mu` and
  reads each bucket's `lastAccess` and deficit when evicting (Priority 1 -> 2, the permitted
  direction)
- `middleware.fileBudgets.mu` (RWMutex) - the per-account file upload budgets map; its own
  `RateLimiter` instance with the same discipline, never held together with
  `globalRateLimiter.mu`. An upload takes and gives back a part inside its transaction, under
  the conversation row lock, each as one short hold (with the budget's `TokenBucket.mu` inside
  it); nothing else is acquired while it is held
- `rateLimiterMutex` - PoW per-client limiters map (never held together with `spentMutex`).
  Held only to find, create or choose a limiter (`limiterFor`); the chosen limiter's own lock is
  taken after it is released. The shared overflow bucket (`overflowLimiter`, serving untracked
  clients while the map is at its bound) is one more `RateLimiter` with its own per-bucket lock
  (Priority Level 2), taken the same way
- `spentMutex` - PoW spent (solved, unexpired) challenges map; leaf lock. Issued challenges are
  no longer stored (S-03)
- `realtime.Hub.mu` (`utils.SafeMutex`, 5 s timeout) - SSE subscriber map, the per-client (network) stream
  counts (S-04) and the revocation generation per kicked stream tag (`kicked`, its floor and
  sequence: read by `Generation`, compared by `Subscribe`, bumped by `Kick`, at most 4,096
  entries); leaf lock, channel sends under it never block. `middleware.StreamRevocationMark`
  takes it for one read before the session check and holds nothing else meanwhile; a `Kick` that
  cannot take it in time is reported (logout and account deletion answer 503)
- `pendingStore.mu` - Pending registration map (leaf lock)

### Priority Level 2 - Per-Resource Locks
- `TokenBucket.mu` - Individual rate limit bucket
- `RateLimiter per-bucket locks` - Individual PoW rate limiter

### Priority Level 3 (Highest) - Database/Critical Resources
- Database transaction locks (implicit via GORM)
- `invites` row locks (`ChatRepository.TakeInvite`, `ChatRepository.DeleteInvites`): always taken
  **before** any `users` row lock in the same transaction (redeem, account deletion) — the reverse
  order would deadlock a redemption against the deletion of its creator
- `users` row locks (`SELECT … FOR UPDATE`, `ChatRepository.LockUsers`): always taken in ascending
  `uuid` order inside one transaction (redeem, burn, index prune, account deletion, room create,
  join and leave) — a global order rules out deadlocks. Account deletion locks only its own row:
  peers' encrypted indexes drop the vanished conversations at their next listing instead
- `rooms` row lock (`ChatRepository.LockRoom`, and the delete in `DeleteConversation` / retention):
  taken **after** any `users` row lock and **before** the room's conversation row lock. Joins of
  one room are serialised by it (seats, duplicate cards). `DeleteConversation` deletes the `rooms`
  row before anything else for the same reason
- `conversations` row lock (`ChatRepository.NextSeq`, `UPDATE … RETURNING`, and
  `ChatRepository.LockConversation`): serialises senders of one conversation until the transaction
  ends. Room joins, leaves, notes, role changes (`SetRole`) and file part uploads
  (`UploadFilePart`) take it too, so a message is always checked against the roster it is stored
  under, a role is written only for a current member, and a conversation's file quota is counted
  exactly. Never held while acquiring a `users` or `rooms` row lock.
  `DeleteConversation` takes it (`LockConversation`) right after the `rooms` delete and **before**
  deleting the children (messages, file parts, memberships, notes) and the conversation row itself,
  so a sender or uploader holding it finishes first and nothing it stores outlives the delete
- Stored file parts counter (`chat.storedParts.mu`, `utils.SafeMutex`, 5 s timeout, leaf): held
  for the counter's arithmetic only, never across a statement. An upload takes it while it holds
  the conversation row lock (to reserve its part); burns, account deletions and retention take it
  after their transaction. Nothing is acquired while it is held

Order in one transaction: `invites` → `users` → `rooms` → `conversations`.
- Master key re-wrapping (`KeyRepository.Rewrap*`): single-row updates outside any transaction,
  conditional on the row still naming the old key; it holds no lock while taking another
- Master key initialization lock (`masterKeyOnce`)
- Master key use lock (`encryption.keyUse`, RWMutex, leaf): every seal and open holds it for
  reading for the one operation; `encryption.Close` (shutdown) takes it for writing, so it waits
  for the operations in flight before zeroizing. Nothing else is acquired while it is held
- PostgreSQL advisory locks (database/startup.go, database/instance.go): the migration lock is a
  transaction-level lock taken first in the migration transaction; the single-instance lock is a
  session-level lock on its own dedicated connection, held for the process's life and never
  combined with any other lock
- Log flood table (`utils.throttleMu`, leaf): held only to count one line

## The agent (`elyrn-agent`) and its MCP server

A separate process with its own locks; none of them is ever held together with a server lock.

- Identity lock file (`agent.json.lock` beside the identity file, `agent.Agent.held`;
   `lockFile` in `permissions_unix.go` (exclusive non-blocking `flock`) and
   `permissions_windows.go` (a file opened with no sharing)): taken first, in `agent.New`, before
   the identity and counter files are read, and held for the process's life. A second process on
   the same identity fails at once (`E_AGENT_IDENTITY_IN_USE`); it never waits. Released last,
   in `closeAfterCall` while the call lock is held. A read-only agent (`whoami`) does not take it
- Agent call lock (`agent.Agent.lock`, `utils.SafeMutex`, timeout `callLockTimeout`: the longest
  `room_wait` plus two request timeouts, 6 minutes): taken after the identity lock, one public
  call at a time (`serialized`), and by `closeAfterCall` at shutdown. Nothing else in the agent
  is locked while it is held; a call that cannot get it fails with `E_AGENT_BUSY`
- MCP write lock (`mcp.Server.outLock`, `utils.SafeMutex`, timeout 30 s): serialises the lines
  written to stdout. Held for one `Write` only and never while the agent runs, so it never nests
  with the call lock; a leaf

Order: identity lock file → call lock. The MCP write lock nests with neither.

## Acquisition Rules

1. **Always acquire locks from lowest to highest priority**
2. **Never acquire a lower-priority lock while holding a higher-priority lock**
3. **Release locks in LIFO order (stack discipline)**
4. **New in-process locks use `utils.SafeMutex` (timeout-bounded); database locks are bounded by
   their transaction**, and every session waits at most `lock_timeout` (5 s) for a row lock and
   is ended after `idle_in_transaction_session_timeout` (30 s) idle inside a transaction

## Examples

### CORRECT - Acquire low-priority first
```go
// Acquire global map lock first (Priority 1)
rl.mu.RLock()
bucket, exists := rl.buckets[ip]
rl.mu.RUnlock()

// Then acquire bucket lock (Priority 2)
if exists {
    bucket.mu.Lock()
    defer bucket.mu.Unlock()
    // ... use bucket
}
```

### INCORRECT - Would cause deadlock
```go
// Holding bucket lock (Priority 2)
bucket.mu.Lock()

// Then trying to acquire global lock (Priority 1) - DEADLOCK RISK!
rl.mu.Lock()
```

## Lock Timeout Policy

- Locks held across channel operations or I/O use `utils.SafeMutex` (a bounded wait, 5 s by
  default; on timeout the caller gets an error and logs it): the realtime hub (5 s), the agent's call lock
  and the MCP write lock (their own timeouts, above). The stored file parts counter uses it too,
  because it is taken inside a database transaction
- Map-guarding locks (`sync.Mutex`/`sync.RWMutex`) protect short, non-blocking critical
  sections only: no I/O, no channel operation, no call that can wait while they are held

## Audit Process

- Code reviews MUST verify lock ordering
- Use `go test -race` to detect race conditions
- Document any new locks in this file with assigned priority level

---

**Last Updated**: 2026-11-18
**Next Review**: Every sprint or when adding new locks
