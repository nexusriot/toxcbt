# toxcbt — Design

`toxcbt` (a.k.a. **go-tox-bot**) is a minimal, single-binary [Tox](https://tox.chat/)
bot written in Go. It starts as an echo bot but ships an extensible slash-command
system, admin-gated operations, persistent (optionally encrypted) identity, an
offline outbox, friend-request policies, per-peer rate limiting, an audit trail,
a health/metrics endpoint, and optional SOCKS5 (e.g. Tor) transport.

This document describes the architecture, the runtime model, the data and control
flow, the configuration surface, and the trade-offs behind the current
implementation. It is intended to be enough for a contributor to extend the bot
confidently.

---

## 1. Goals & non-goals

### Goals
- **Legible core.** The bot is one package (`cmd/toxcbt`) split into files that
  each own one concern (see §16); every file is meant to be read top-to-bottom.
- **Stable identity.** The bot keeps the same Tox ID across restarts via
  persisted savedata, and refuses to start rather than silently re-key.
- **Stays connected.** Bootstrapping is not a one-shot startup step: nodes are
  registered as DHT peers *and* TCP relays, and retried while offline.
- **Extensible commands.** Adding a command is a single registry entry, not a
  new branch in a growing `switch`.
- **Operable.** Structured logs, an audit trail for privileged actions, and a
  health/metrics endpoint; privileged operations are gated behind an explicit
  admin allowlist.
- **Deployable.** Reproducible multi-stage Docker build + docker-compose with a
  persistent data volume and a non-root runtime user.

### Non-goals (today)
- Group/conference chat, file transfer, A/V (toxcore supports these; see
  §15 Future work).
- Multi-process / horizontal scaling. One bot = one process = one Tox identity.
- A plugin ABI or hot-reload. Commands are compiled in.

---

## 2. Dependencies & build model

| Layer | Choice | Notes |
|-------|--------|-------|
| Language | Go 1.22+ | standard library only |
| Tox binding | `github.com/TokTok/go-toxcore-c v0.2.17` | CGO wrapper over the C `libtoxcore` |
| Native libs | `libtoxcore`, `libsodium` | provided by Alpine `toxcore-dev`/`libsodium-dev` at build, `toxcore`/`libsodium` at runtime |

Because the binding is CGO, **`CGO_ENABLED=1` is required** and the resulting
binary is dynamically linked against the toxcore/libsodium shared objects. The
Dockerfile therefore uses a multi-stage build:

1. **build stage** (`alpine:3.20` + Go + dev headers) compiles `./cmd/toxcbt`
   with `-trimpath -ldflags="-s -w -X main.version=…"`.
2. **test stage** runs `go vet` and `go test` against those same libraries —
   this is what CI invokes (`docker build --target test .`), because a clean
   runner has no libtoxcore.
3. **runtime stage** (`alpine:3.20` + runtime shared libs only) copies the
   binary in and drops to an unprivileged user.

> Implication: a plain `go build` only works on a host that already has
> libtoxcore/libsodium installed. CI and clean machines build via Docker.

---

## 3. High-level architecture

```
                         ┌─────────────────────────────────────────┐
                         │                 main()                   │
                         │  - load config (env)                     │
                         │  - build ToxOptions (proxy + savedata)   │
                         │  - decrypt/validate the profile          │
                         │  - create Tox instance                   │
                         │  - load state sidecar + audit log        │
                         │  - construct Bot + command registry      │
                         │  - bootstrap DHT + TCP relays            │
                         │  - register callbacks                    │
                         │  - start health endpoint                 │
                         │  - run event loop                        │
                         └───────────────┬─────────────────────────┘
                                         │
       ┌──────────────┬──────────────────┼──────────────────┬──────────────────┐
       │              │                  │                  │                  │
┌──────▼──────┐ ┌─────▼──────┐  ┌────────▼───────┐ ┌────────▼──────┐ ┌─────────▼────────┐
│ callbacks   │ │ event loop │  │ persistence    │ │ reconnection  │ │ health endpoint  │
│ (toxcore →  │ │ (tickers/  │  │ profile (+enc) │ │ bootstrapper  │ │ snapshot →       │
│  closures)  │ │  select)   │  │ state.json     │ │ w/ backoff    │ │ /healthz /metrics│
└──────┬──────┘ └────────────┘  └────────────────┘ └───────────────┘ └──────────────────┘
       │
┌──────▼────────────────┐
│  Bot.handleMessage    │  block → rate limit → parse → authorize → run → audit → reply
└──────┬────────────────┘
       │
┌──────▼────────────────┐      ┌──────────────────────────────────────┐
│  command.run(cmdCtx)  │─────▶│ Bot.deliver: send, or queue if absent │
└───────────────────────┘      └──────────────────────────────────────┘
```

The design separates five concerns:

- **Wiring** (`main`): one-time setup and the event loop.
- **State** (`Bot` + `botState`): everything a handler might need at runtime.
- **Dispatch** (`handleMessage` + registry): filter, parse, authorize, route.
- **Behavior** (`command` handlers): the actual command logic.
- **Delivery** (`deliver`/`sendChunks`): chunking, caps, and the outbox.

---

## 4. Core types

### `Bot`
Holds shared runtime state, passed by pointer to handlers via `cmdCtx`.

```go
type Bot struct {
    t        toxClient         // the live Tox instance
    saveFile string            // path to savedata
    admins   map[string]bool   // uppercase-hex pubkey → allowed (from the env)
    started  time.Time         // for /uptime
    connSt   int               // last self connection status (NONE/TCP/UDP)

    cipher  *profileCipher     // nil unless a passphrase is configured
    state   *botState          // runtime admins, blocklist, outbox (nil-safe)
    audit   *auditLog          // append-only privileged-action log (nil-safe)
    limiter *rateLimiter       // per-peer token buckets (nil = unlimited)
    policy  friendPolicy       // who may become a friend

    maxReplyChunks int
    logMessages    bool
    version        string

    metrics  botMetrics                        // plain counters, loop-owned
    pending  map[receiptKey]pendingReceipt     // awaiting delivery confirmation
    lastSave time.Time
    now      func() time.Time                  // overridden in tests
}
```

`toxClient` is a local interface listing exactly the `*tox.Tox` methods the bot
calls. `main` passes the real instance; tests substitute an in-memory fake,
which is what makes the command layer testable without a live DHT node (§14). A
compile-time assertion in the tests keeps `*tox.Tox` conforming.

The optional subsystems (`state`, `audit`, `limiter`, `cipher`) all tolerate a
nil receiver on every method. That is deliberate: each is genuinely optional in
production, and "disabled" then needs no branches at the call sites.

`connSt` and `metrics` are written only from the event-loop goroutine and read
by `/stats` and the health snapshot. Because toxcore callbacks fire
synchronously from `Iterate()` on that same goroutine (§6), no mutex is needed.

### `command` + `cmdCtx`
```go
type command struct {
    name  string
    admin bool                 // requires sender ∈ admins
    help  string               // shown by /help
    run   func(c *cmdCtx) string  // returns reply ("" = no reply)
}

type cmdCtx struct {
    bot     *Bot
    friend  uint32             // toxcore friend number
    pubKey  string             // sender pubkey (uppercase hex)
    args    string             // text after the command word
    isAdmin bool
}
```

A handler is a function from context to a reply string. Returning `""` sends
nothing. Handlers never touch the socket directly except via `Bot.deliver`,
which keeps chunking, caps and queueing centralized.

---

## 5. Command system

### Registry construction
`Bot.buildCommands()` returns `map[string]*command`. Commands are declared as a
slice literal, then folded into the map. `/help` is appended last and closes
over the finished map so it can enumerate every command (it filters admin-only
entries for non-admin callers).

Adding a command is one entry:

```go
{name: "echoargs", help: "echo the args back", run: func(c *cmdCtx) string {
    return c.args
}},
```

Admin command: set `admin: true`. Authorization is enforced centrally in
`handleMessage`, not inside each handler — which is also why the admin entries
carry no section marker in the slice: `admin: true` *is* the grouping, and a
divider comment would be a second place to keep in sync.

A handler that delivers something (`/say`, `/broadcast`) must check the result
of `Bot.deliver` and distinguish sent from queued from failed; replying "sent"
unconditionally reports success for messages that were never delivered. Note
that `/broadcast` is O(friends) on the event loop, which is acceptable because
it is admin-only and rare; anything that could block for longer belongs on a
goroutine per §6. A
handler that changes the friend list (`/remove`, `/block`) or the identity
(`/nospam`) calls `b.save()`, per §8.

### Dispatch flow (`handleMessage`)
1. Count the message; resolve the sender's public key and admin status.
2. If the sender is **blocked** → return silently. No reply at all: a bot that
   answers "you are blocked" is a way to confirm it is still listening.
3. Unless the sender is an admin, charge the message against their **token
   bucket**; over budget → drop, and send at most one notice per minute.
4. Log the message (body redacted unless `TOX_LOG_MESSAGES`).
5. If it does **not** start with `/` → echo (`"echo: " + original`).
6. Split `"/word rest"` into `word` + `args` at the first **whitespace**
   (`cutWord`), so `/ping\nstray` still dispatches — not just the first space.
7. Look up `word` (lowercased) in the registry; unknown → hint to `/help`.
8. If `cmd.admin && !isAdmin` → reply "not authorized", log and **audit** the
   denial.
9. Run the handler; audit privileged invocations; if the reply is non-empty,
   deliver it.

### Current commands

| Command | Admin | Purpose |
|---------|:-----:|---------|
| `/help` | | List commands (admin entries hidden from non-admins) |
| `/ping` | | Reply `pong` |
| `/id` | | Show the bot's Tox ID |
| `/uptime` | | Time since start |
| `/version` | | Build version |
| `/whoami` | | Caller's friend number, public key, privilege level |
| `/stats` | | name, status, connection, friends, uptime, queued, rate-limit drops |
| `/friends` | ✓ | List friends: number, pubkey, connection status |
| `/remove <n>` | ✓ | `FriendDelete` by friend number |
| `/say <n> <text>` | ✓ | Message a friend; queues if offline, confirms on receipt |
| `/broadcast <text>` | ✓ | Message every friend but the sender |
| `/save` | ✓ | Persist savedata immediately |
| `/nospam [hex]` | ✓ | Rotate the nospam half of the Tox ID |
| `/admin …` | ✓ | List/add/remove runtime admins |
| `/block`, `/unblock`, `/blocked` | ✓ | Blocklist management |
| `/outbox [clear]` | ✓ | Inspect or drop queued messages |
| `/audit [n]` | ✓ | Tail the audit log |

---

## 6. Runtime model & concurrency

Tox is a **single-threaded poll loop**: the application repeatedly calls
`t.Iterate()`, which drives the DHT, processes incoming packets, and invokes the
registered callbacks **synchronously on the calling goroutine**. The cadence is
advisory — `t.IterationInterval()` returns how many ms to wait before the next
`Iterate()`.

The event loop is fully `select`-driven (no busy `default:` branch):

```go
saveTick  := time.NewTicker(TOX_SAVE_INTERVAL)   // profile + state
houseTick := time.NewTicker(5s)                  // reconnect, snapshot, upkeep
iterTick  := time.NewTicker(IterationInterval ms)

for {
    select {
    case <-ctx.Done():   // SIGINT/SIGTERM → save + stop the health server
    case <-saveTick.C:   // periodic snapshot
    case <-houseTick.C:  // re-bootstrap if offline; publish health; upkeep every minute
    case <-iterTick.C:
        t.Iterate()
        iterTick.Reset(iterInterval(t.IterationInterval()))
    }
}
```

**Concurrency invariant:** all callbacks (friend request, friend message,
friend connection status, read receipt, self connection status) and all command
handlers run on the single event-loop goroutine, interleaved only between
`Iterate()` calls. Consequently:

- `Bot` fields require **no synchronization**.
- Handlers must **not block** — a slow handler stalls the whole bot (DHT
  maintenance, message delivery).

The one other goroutine is the HTTP health server. It never touches `Bot` or
toxcore: the event loop publishes an immutable `healthSnapshot` into an
`atomic.Pointer` every 5 seconds and the handlers serve the last one. That is
the only place a lock-free hand-off exists, and it exists precisely so the
invariant above can stay unqualified.

---

## 7. Message length, chunking & caps

toxcore rejects messages longer than `tox.MAX_MESSAGE_LENGTH` (1372 bytes).
Every outbound reply goes through `chunkMessage`:

- If `len(s) <= max`, send as one message.
- Otherwise repeatedly take up to `max` bytes, but **prefer to break on the last
  newline or space** in the second half of the window (`i > max/2`) so words and
  lines stay intact; trailing whitespace at the break is trimmed.

The window is measured in **bytes** (that is what toxcore limits) but every cut
is walked back to a **UTF-8 rune boundary** first, so no chunk carries a
truncated multibyte sequence. Whitespace breaks are inherently rune-aligned
because space and newline are single-byte ASCII.

`TOX_MAX_REPLY_CHUNKS` then caps how many chunks one reply may become, followed
by a short "truncated" notice. Without it a single short message could be turned
into hundreds of outbound ones — an amplification lever pointed at whoever the
bot is talking to.

`sendChunks` returns the receipt id of the final chunk (what read receipts key
on) and stops at the first send error, so a handler that was asked to deliver
something can report the failure instead of claiming success.

---

## 8. Persistence

Three files live in the data directory, all written `0600` via temp file →
`fsync` → `rename` → directory `fsync`.

### 8.1 The profile (`bot.tox`)
Identity and friend list live in toxcore *savedata*.

- **Load** (`loadProfile`) classifies the file, because "start fresh" is not a
  safe default for anything but a real absence:

  | State | Behaviour |
  |-------|-----------|
  | missing, or present but 0 bytes | fresh identity (new Tox ID) |
  | plaintext and structurally valid | loaded as `SAVEDATA_TYPE_TOX_SAVE` |
  | encrypted, passphrase configured and correct | decrypted, then validated |
  | encrypted, no passphrase, or the wrong one | **fatal** |
  | unreadable (permissions, `EISDIR`, I/O) or not a tox profile | **fatal** |

  The fatal rows are the important ones. toxcore does **not** report a damaged
  profile: `tox_new` quietly ignores it and derives a brand-new random key
  (verified — the same corrupt bytes produce a *different* public key on each
  run), and the very next save then overwrites the file. The failure therefore
  presents as "the bot lost all its friends" with the evidence already
  destroyed. `validateSavedata` checks the documented header (a zero `uint32`
  followed by little-endian magic `0x15ED1B1F`, i.e. `00 00 00 00 1f 1b ed 15`
  on disk) and refuses to start instead, leaving the file recoverable.

- **Encryption at rest** is enabled by `TOX_SAVEDATA_PASSPHRASE` (or
  `…_PASSPHRASE_FILE`, which suits a container secret). The container format is
  toxcore's own `toxEsave`, so a profile written by a desktop client can be
  opened with its passphrase, and vice versa. The key is derived **once** at
  startup — derivation is deliberately expensive, and the bot writes a profile
  every 30 seconds. A plaintext profile plus a configured passphrase is read as
  a migration request: it loads as is and the next save encrypts it.

  > Implementation note: the binding's package-level `tox.PassDecrypt` cannot be
  > used. In v0.2.17 it passes the *plaintext output buffer* as the passphrase
  > pointer, so it fails for every input. The pass-key API is correct, so the
  > bot goes `GetSalt` → `DeriveWithSalt` → `(*ToxPassKey).Decrypt`.

- **Writability** is probed at startup (`ensureWritable` creates and removes
  `<savedata>.probe`), so a read-only volume fails immediately rather than
  silently dropping every save until the identity is lost on restart.

- **When:** every `TOX_SAVE_INTERVAL`, on graceful shutdown, on demand via
  `/save`, and immediately after any **friend-list or identity change**
  (accepted request, `/remove`, `/block`, `/nospam`). Without the last one a
  restart inside the save window would drop a friendship the peer still
  believes exists.

Empty savedata is a no-op, checked via `GetSavedataSize()` *before*
`GetSavedata()` (which panics on a zero-length buffer).

### 8.2 The state sidecar (`state.json`)
What the bot learns at runtime and savedata cannot carry: runtime admins, the
blocklist, and the outbox. It is written only when something changed (a dirty
flag), flushed alongside the profile and on shutdown.

A damaged sidecar is **fatal**, on the same reasoning as the profile though for
a smaller stake: silently continuing would un-block everyone the operator ever
blocked. Moving the file aside is an explicit, one-line recovery.

### 8.3 The audit log (`audit.log`)
Append-only JSONL: time, actor key, friend number, command, args, allowed,
result. Only privileged activity is recorded — admin commands, denied admin
attempts, and friend-request decisions — so the log stays readable and does not
grow with `/ping`. Message bodies never appear in it. It rotates to `.1` at
`TOX_AUDIT_MAX_BYTES`, keeping exactly one previous generation.

---

## 9. Networking: bootstrap, relays and reconnection

`tox_bootstrap` seeds the DHT over **UDP**. `tox_add_tcp_relay` registers a node
as a **TCP relay**. Clients need both, and toxcbt registers every configured
node as both (the relay port defaults to the UDP port; `/0` opts a node out).

This is not belt-and-braces. Two measurements against live nodes:

- With any `SOCKS5_PROXY` set, toxcore refuses to bind a UDP socket at all
  (`tox_self_get_udp_port` → `NOT_BOUND`, even with `udp_enabled` true). Every
  proxied deployment is therefore TCP-only.
- In TCP-only mode, bootstrap **without** relays never connected (60s budget,
  four nodes); the same nodes added as relays connected in 12 seconds.

So the previously documented "falls back to TCP relays when proxied" only became
true once the relays were actually registered.

`bootstrapper` also owns reconnection. While `connSt == CONNECTION_NONE` the
house tick re-runs the whole bootstrap+relay pass, backing off 15s → 5min and
resetting the moment the bot comes online. A container that starts before its
network is ready used to log four failures and then wait forever.

---

## 10. Configuration

All configuration is environment-driven (`loadConfig`, with `getenv*` helpers).
No flags, no config file — friendly to containers. Malformed values are logged
and replaced with the default. The full table lives in `README.md`; the parsing
subtleties are here.

- `parseHostPort` splits a trailing `:port` off using the **last** colon, so an
  IPv6 literal (`[2001:db8::1]:33445`, or the bare `::1:33445`) survives; square
  brackets are stripped because toxcore wants a bare address. Port `0` and an
  empty host are rejected.
- `parseNodeAddr` peels an optional `/tcpPort` off first, so the remainder is a
  plain `host:port` and IPv6 keeps working.
- `normalizePubKey` uppercases, strips spaces, and requires **exactly
  `2 × TOX_PUBLIC_KEY_SIZE` = 64 hex characters**. A full 76-character Tox ID is
  accepted and reduced to its public-key prefix, because that is the string
  `/id` prints and therefore the one users paste.

  The length check is a safety requirement, not just hygiene: `Tox.Bootstrap`
  and `FriendAddNorequest` index the decoded key at `[0]` and hand C a pointer
  that toxcore reads 32 bytes from. An empty key (`host:port:` — trivially
  produced by a trailing colon in the env var) **panics the process**; a short
  one reads out of bounds.
- **Proxy** (`applyProxy`): strips an optional `user:pass@` prefix (toxcore has
  **no proxy-auth support**, so credentials are discarded with a warning rather
  than silently ignored), then `parseHostPort`.
- **Friend policy**: `secret` with an empty secret is downgraded to `closed` and
  logged as an error — `strings.Contains(msg, "")` is true for every message, so
  the strictest-looking setting would otherwise be the most permissive one.
  Admins are merged into the allowlist under every policy: locking the operator
  out is never the intended reading of a strict setting.

---

## 11. Lifecycle (startup → shutdown)

1. Install the logger, then resolve config from env.
2. `MkdirAll` the data dir and the parent of every file the bot writes;
   `ensureWritable` the savedata path.
3. `NewToxOptions()` → `applyProxy()` → optional toxcore log callback →
   `loadProfile()` into the options (fatal on unreadable, undecryptable or
   non-tox profiles; see §8).
4. `NewTox(opts)`; fatal if nil. `defer t.Kill()`.
5. Set name/status; log Tox ID + public key.
6. Load `state.json` (fatal if damaged) and open the audit log (non-fatal).
7. Construct `Bot` + `buildCommands()`.
8. Bootstrap + add TCP relays (failures logged, non-fatal, retried later).
9. Register callbacks:
   - `CallbackSelfConnectionStatus` → update `connSt`, reset the backoff.
   - `CallbackFriendRequestAdd` → `onFriendRequest` (policy, then accept).
   - `CallbackFriendMessageAdd` → `handleMessage` (note: in binding v0.2.17
     this callback signature has **no** message-type parameter).
   - `CallbackFriendConnectionStatusAdd` → presence log + outbox flush.
   - `CallbackFriendReadReceiptAdd` → delivery confirmation.
10. Start the health endpoint (fatal if the port cannot be bound — it was asked
    for explicitly).
11. Install `signal.NotifyContext` for SIGINT/SIGTERM.
12. Run the event loop (§6) until the context is cancelled, then save, stop the
    HTTP server, close the audit log and free the pass key (deferred `Kill`
    tears the instance down).

---

## 12. Security model

- **Friend acceptance is policy-driven** (`TOX_FRIEND_POLICY`): `open` (the
  historical default), `secret` (the request message must contain a shared
  secret), `allowlist`, or `closed`, with an optional `TOX_MAX_FRIENDS` cap.
  Admins and allowlisted keys bypass the cap and the secret.
- **Privilege boundary** is the admin allowlist keyed on the **friend's public
  key** (cryptographically bound to the peer's identity by toxcore), not on a
  display name or friend number, both of which are spoofable/reused. Runtime
  grants live in `state.json`; keys from `TOX_ADMINS` are permanent and cannot
  be revoked over the wire, so a compromised runtime admin cannot lock the
  operator out.
- **Flood resistance**: a per-public-key token bucket with a burst, a cap on
  outbound chunks per reply, and a blocklist whose members get no reply at all.
  Rate-limit notices are themselves limited to one per minute per peer.
- **Auditability**: every privileged action, denial and friend-request decision
  is appended to `audit.log` with the actor's key.
- **Transport privacy**: SOCKS5 lets the bot run over Tor. Note that toxcore
  disables UDP entirely under a proxy (§9), so the TCP relays are what make that
  configuration work at all.
- **Privacy in logs**: message bodies are redacted unless `TOX_LOG_MESSAGES=true`
  — only their length is logged. Public keys are abbreviated. The bot logs its
  own Tox ID/pubkey (public by design) but never savedata or passphrases.
- **At rest**: savedata `0600` and optionally encrypted; `state.json` `0600`
  because it holds queued message bodies.

Threats explicitly **out of scope**: a peer who is already an admin, denial of
service against the DHT itself, and compromise of the host (savedata = the
bot's private identity).

---

## 13. Error-handling philosophy

- **Config/parse errors are non-fatal and skipped with a log line** (bad
  bootstrap node, bad admin key, bad proxy, malformed numbers) so one typo can't
  take the bot down.
- **Instance creation failures are fatal** — there is no useful degraded mode
  without a Tox instance.
- **Threats to persistent state are fatal, deliberately breaking the non-fatal
  rule above**: unreadable/corrupt/undecryptable savedata, an unwritable
  savedata path, a damaged `state.json`. Skipping a bad bootstrap node costs one
  node; "skipping" a bad profile silently changes the bot's Tox ID and then
  overwrites the only copy. A crash-looping container is a signal; a silently
  re-keyed bot is not.
- **An explicitly requested port that cannot be bound is fatal** (the health
  endpoint), because the operator asked for it and a silent no-op would be
  discovered by an alert that never fires.
- **Send/save failures are logged and swallowed** by the event loop — a
  transient delivery failure shouldn't crash the bot — but they are *counted*
  (`toxcbt_save_errors_total`) and, for messages, retried via the outbox.
- **Untrusted input never reaches an unchecked C boundary.** The binding
  dereferences decoded byte slices directly, so anything crossing into cgo
  (bootstrap keys, friend-request keys, savedata buffers) is length-validated
  first — otherwise "non-fatal config error" would become a startup panic.

---

## 14. Tests

`cmd/toxcbt/*_test.go` (package `main`, so unexported helpers are reachable),
161 test functions. Groups:

- **Pure functions** — parsers (`parseBootstrapEnv`, `parseNodeAddr`,
  `parseAdmins`, `normalizePubKey`, `parseHostPort`, `applyProxy`), env helpers,
  `chunkMessage`, `cutWord`, `iterInterval`, log-level parsing, and the friend
  policy matrix. Table-driven. The chunking tests assert three invariants over
  several alphabets and window sizes: no chunk exceeds `max`, every chunk is
  valid UTF-8, and nothing but whitespace is lost across the join.
- **Command layer** — a `fakeTox` implementing `toxClient` records outbound
  messages, deletions, friend additions and the nospam, and can be told to fail.
  That covers dispatch, the admin boundary in both directions, and each
  handler's success and failure replies.
- **Delivery** — offline queueing, flush-on-reconnect (including a partial flush
  that requeues the remainder), receipt tracking and expiry, reply-chunk caps.
- **Policy and abuse control** — token-bucket burst/refill/notice-throttling,
  blocked peers getting no reply, admins exempt from limiting, every rejection
  path of the friend policy, and the audit line each produces.
- **Persistence** — `readSavedata`/`validateSavedata`/`ensureWritable`/
  `writeFileSync`/`Bot.save()` against real temp directories, plus the whole
  encryption path (round trip, wrong passphrase, migration from plaintext,
  damaged ciphertext, decrypted garbage). The header fixture is asserted against
  the real on-disk bytes so it cannot drift into agreeing with a wrong
  implementation. Cases that depend on permission bits skip when running as root.
- **State and audit** — load/normalize/refuse, queue caps and TTL, atomic flush
  and `0600`, log rotation and tailing, and that every accessor works on a nil
  receiver.
- **Health** — snapshot publication, 200/503 semantics, and the rendered
  Prometheus text (including label escaping).

Running them needs the same native libs as a local build, because package `main`
imports the binding:

```bash
go test ./...          # with libtoxcore + libsodium installed
docker build --target test .   # otherwise; this is what CI runs
```

---

## 15. Future work

- **Conferences / groups**: join/host a Tox conference and relay or respond.
- **File transfer**: implement the file-transfer callbacks (accept/echo files),
  and an avatar via `FILE_KIND_AVATAR`.
- **Richer friend info**: `/info <n>` with name, status message and last-online;
  friend GC for peers unseen in N days.
- **Reminders** (`/remind 10m …`) on the existing tick.
- **Webhook bridge**: inbound HTTP → Tox message, outbound POST on receipt.
- **A/V (toxav)** — out of scope for a text bot but supported by the binding.

---

## 16. File map

```
cmd/toxcbt/main.go        wiring + event loop
cmd/toxcbt/config.go      environment parsing, friend policy, shared parsers
cmd/toxcbt/bot.go         Bot, dispatch, delivery/outbox, receipts, callbacks
cmd/toxcbt/commands.go    the command registry
cmd/toxcbt/dht.go         bootstrap nodes, TCP relays, reconnection backoff
cmd/toxcbt/savedata.go    profile load/validate/encrypt/save
cmd/toxcbt/state.go       state.json: runtime admins, blocklist, outbox
cmd/toxcbt/audit.go       append-only audit log with rotation
cmd/toxcbt/ratelimit.go   per-peer token buckets
cmd/toxcbt/health.go      /healthz + /metrics and the snapshot they serve
cmd/toxcbt/logging.go     slog setup, level mapping, message redaction
cmd/toxcbt/*_test.go      unit tests + the in-memory toxClient fake
Dockerfile                build → test → slim non-root runtime stages
docker-compose.yml        service def + persistent ./data volume + env examples
.github/workflows/ci.yml  vet + test through the Dockerfile, gofmt check
go.mod / go.sum           module + pinned go-toxcore-c v0.2.17
data/                     runtime savedata, state and audit log (gitignored)
README.md                 user-facing usage
DESIGN.md                 this document
```
