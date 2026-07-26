# toxcbt — Design

`toxcbt` (a.k.a. **go-tox-bot**) is a minimal, single-binary [Tox](https://tox.chat/)
bot written in Go. It starts as an echo bot but ships an extensible slash-command
system, admin-gated operations, persistent identity, connection-status logging,
and optional SOCKS5 (e.g. Tor) transport.

This document describes the architecture, the runtime model, the data and control
flow, the configuration surface, and the trade-offs behind the current
implementation. It is intended to be enough for a contributor to extend the bot
confidently.

---

## 1. Goals & non-goals

### Goals
- **Tiny, legible core.** The entire bot lives in one file
  (`cmd/toxcbt/main.go`, ~690 LOC) and is meant to be read top-to-bottom.
- **Stable identity.** The bot keeps the same Tox ID across restarts via
  persisted savedata.
- **Extensible commands.** Adding a command is a single registry entry, not a
  new branch in a growing `switch`.
- **Operable.** Connection state, friend events, and command activity are logged;
  privileged actions are gated behind an explicit admin allowlist.
- **Deployable.** Reproducible multi-stage Docker build + docker-compose with a
  persistent data volume.

### Non-goals (today)
- Group/conference chat, file transfer, A/V (toxcore supports these; see
  §14 Future work).
- Multi-process / horizontal scaling. One bot = one process = one Tox identity.
- A plugin ABI or hot-reload. Commands are compiled in.
- Rate limiting / abuse mitigation beyond auto-accepting friends.

---

## 2. Dependencies & build model

| Layer | Choice | Notes |
|-------|--------|-------|
| Language | Go 1.22+ | |
| Tox binding | `github.com/TokTok/go-toxcore-c v0.2.17` | CGO wrapper over the C `libtoxcore` |
| Native libs | `libtoxcore`, `libsodium` | provided by Alpine `toxcore-dev`/`libsodium-dev` at build, `toxcore`/`libsodium` at runtime |

Because the binding is CGO, **`CGO_ENABLED=1` is required** and the resulting
binary is dynamically linked against the toxcore/libsodium shared objects. The
Dockerfile therefore uses a two-stage build:

1. **build stage** (`alpine:3.20` + Go + dev headers) compiles
   `./cmd/toxcbt` with `-trimpath -ldflags="-s -w"`.
2. **runtime stage** (`alpine:3.20` + runtime shared libs only) copies the
   binary in. This keeps the final image small while preserving the dynamic
   link.

> Implication: a pure `go build` only works on a host that already has
> libtoxcore/libsodium installed. CI and clean machines should build via Docker.

---

## 3. High-level architecture

```
                         ┌─────────────────────────────────────────┐
                         │                 main()                   │
                         │  - load config (env)                     │
                         │  - build ToxOptions (proxy + savedata)   │
                         │  - create Tox instance                   │
                         │  - construct Bot + command registry      │
                         │  - bootstrap DHT                         │
                         │  - register callbacks                    │
                         │  - run event loop                        │
                         └───────────────┬─────────────────────────┘
                                         │
              ┌──────────────────────────┼───────────────────────────┐
              │                          │                           │
     ┌────────▼────────┐      ┌──────────▼─────────┐      ┌──────────▼─────────┐
     │  callbacks      │      │   event loop       │      │   persistence      │
     │  (toxcore →     │      │  (tickers/select)  │      │   save() atomic    │
     │   Go closures)  │      │                    │      │   tmp+rename       │
     └────────┬────────┘      └────────────────────┘      └────────────────────┘
              │
   ┌──────────▼───────────┐
   │  Bot.handleMessage    │  parse "/cmd args" → registry lookup → authz → run → reply
   └──────────┬───────────┘
              │
   ┌──────────▼───────────┐
   │  command.run(cmdCtx)  │  pure-ish handlers returning a reply string
   └──────────────────────┘
```

The design separates four concerns:

- **Wiring** (`main`): one-time setup and the event loop.
- **State** (`Bot`): everything a handler might need at runtime.
- **Dispatch** (`handleMessage` + registry): parse, authorize, route.
- **Behavior** (`command` handlers): the actual command logic.

---

## 4. Core types

### `Bot`
Holds shared runtime state, passed by pointer to handlers via `cmdCtx`.

```go
type Bot struct {
    t        toxClient         // the live Tox instance
    saveFile string            // path to savedata
    admins   map[string]bool   // uppercase-hex pubkey → allowed
    started  time.Time         // for /uptime
    connSt   int               // last self connection status (NONE/TCP/UDP)
}
```

`toxClient` is a local interface listing exactly the dozen `*tox.Tox` methods
the bot calls. `main` passes the real instance; tests substitute an in-memory
fake, which is what makes the command layer testable without a live DHT node
(see §15). A compile-time assertion in the tests keeps `*tox.Tox` conforming.

`connSt` is written only from the connection-status callback and read by
`/stats`. Because toxcore callbacks fire synchronously from `Iterate()` on the
same goroutine as the event loop (see §6), no mutex is needed.

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
nothing. Handlers never touch the socket directly except via `Bot.sendMessage`
(used by `/say`), which keeps chunking centralized.

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

A handler that delivers something (`/say`) must check the error from
`Bot.sendMessage` and return a failure string; replying "sent" unconditionally
reports success for messages that were never delivered. A handler that changes
the friend list (`/remove`) calls `b.save()`, per §8.

### Dispatch flow (`handleMessage`)
1. Trim the message; log it.
2. If it does **not** start with `/` → echo (`"echo: " + original`).
3. Split `"/word rest"` into `word` + `args` at the first **whitespace**
   (`cutWord`), so `/ping\nstray` still dispatches — not just the first space.
4. Look up `word` (lowercased) in the registry; unknown → hint to `/help`.
5. Resolve the sender's public key via `FriendGetPublicKey`, compute `isAdmin`.
6. If `cmd.admin && !isAdmin` → reply "not authorized", log the denial.
7. Run the handler; if it returns non-empty, send it (chunked).

### Current commands

| Command | Admin | Purpose |
|---------|:-----:|---------|
| `/help` | | List commands (admin entries hidden from non-admins) |
| `/ping` | | Reply `pong` |
| `/id` | | Show the bot's Tox ID |
| `/uptime` | | Time since start |
| `/stats` | | name, status, connection, friend count, uptime |
| `/friends` | ✓ | List friends: number, pubkey, connection status |
| `/remove <n>` | ✓ | `FriendDelete` by friend number |
| `/say <n> <text>` | ✓ | Send a message to friend `n` |
| `/save` | ✓ | Persist savedata immediately |

---

## 6. Runtime model & concurrency

Tox is a **single-threaded poll loop**: the application repeatedly calls
`t.Iterate()`, which drives the DHT, processes incoming packets, and invokes the
registered callbacks **synchronously on the calling goroutine**. The cadence is
advisory — `t.IterationInterval()` returns how many ms to wait before the next
`Iterate()`.

The event loop is fully `select`-driven (no busy `default:` branch):

```go
iterTick := time.NewTicker(IterationInterval ms)
saveTick := time.NewTicker(30s)

for {
    select {
    case <-ctx.Done():          // SIGINT/SIGTERM → save + return
    case <-saveTick.C:          // periodic snapshot
    case <-iterTick.C:
        t.Iterate()
        iterTick.Reset(IterationInterval ms)  // interval can change over time
    }
}
```

**Concurrency invariant:** all callbacks (friend request, friend message,
connection status) and all command handlers run on the single event-loop
goroutine, interleaved only between `Iterate()` calls. Consequently:
- `Bot` fields require **no synchronization**.
- Handlers must **not block** — a slow handler stalls the whole bot (DHT
  maintenance, message delivery). Anything long-running should be offloaded to a
  goroutine and communicated back via a channel (none needed today).

---

## 7. Message length & chunking

toxcore rejects messages longer than `tox.MAX_MESSAGE_LENGTH` (1372 bytes).
`Bot.sendMessage` routes every outbound reply through `chunkMessage`:

- If `len(s) <= max`, send as one message.
- Otherwise repeatedly take up to `max` bytes, but **prefer to break on the last
  newline or space** in the second half of the window (`i > max/2`) so words and
  lines stay intact; trailing whitespace at the break is trimmed.

The window is measured in **bytes** (that is what toxcore limits) but every cut
is walked back to a **UTF-8 rune boundary** first, so no chunk carries a
truncated multibyte sequence. Whitespace breaks are inherently rune-aligned
because space and newline are single-byte ASCII. The only case that can still
emit a partial rune is `max` smaller than the rune itself, which cannot happen
at the real 1372-byte limit.

`Bot.sendMessage` returns the first send error it hits and stops, so a handler
like `/say` can report failure instead of claiming success.

---

## 8. Persistence

Identity and friend list live in toxcore *savedata* (`t.GetSavedata()` /
loaded via `opts.Savedata_*`).

- **Load:** at startup `readSavedata` classifies the file into exactly three
  outcomes, because "start fresh" is not a safe default for anything but a real
  absence:

  | State | Behaviour |
  |-------|-----------|
  | missing, or present but 0 bytes | fresh identity (new Tox ID) |
  | readable and structurally valid | loaded as `SAVEDATA_TYPE_TOX_SAVE` |
  | unreadable (permissions, `EISDIR`, I/O) or not a plaintext tox profile | **fatal** |

  The last row is the important one. toxcore does **not** report a damaged
  profile: `tox_new` quietly ignores it and derives a brand-new random key
  (verified — the same corrupt bytes produce a *different* public key on each
  run), and the very next save then overwrites the file. The failure therefore
  presents as "the bot lost all its friends" with the evidence already
  destroyed. `validateSavedata` checks the documented header (a zero `uint32`
  followed by little-endian magic `0x15ED1B1F`, i.e. `00 00 00 00 1f 1b ed 15`
  on disk) and refuses to start instead, leaving the file recoverable. A profile
  beginning with the ASCII marker `toxEsave` is reported specifically as
  encrypted, since desktop Tox clients write those by default and pointing
  `TOX_SAVEDATA` at one is an easy mistake.

- **Writability** is probed at startup (`ensureWritable` creates and removes
  `<savedata>.probe`), so a read-only volume fails immediately rather than
  silently dropping every save until the identity is lost on restart. The
  tradeoff is deliberate: a deployment that *wants* an immutable read-only
  profile has to be changed, but the far more common case — a misconfigured
  volume quietly discarding the identity — is caught.
- **Save:** `Bot.save()` writes to `path + ".tmp"`, **fsyncs it**, then
  `os.Rename`s over the target and fsyncs the parent directory — an *atomic and
  durable* replace. The fsync is what extends the guarantee from "survives a
  process crash" to "survives power loss": without it the rename can complete
  while the new name still points at a truncated file, which is precisely the
  corruption the load path now has to refuse. Empty savedata is a no-op, checked
  via `GetSavedataSize()` *before* `GetSavedata()` (which panics on a zero-length
  buffer); this also guards against clobbering a good file with garbage. A failed
  write or rename removes the temp file. Mode `0600`.
- **When:** every 30s (`saveTick`), on graceful shutdown, on demand via `/save`,
  and immediately after any **friend-list change** (auto-accepted request,
  `/remove`). Without the last one a restart inside the 30s window would drop a
  friendship the peer still believes exists.

> The Tox ID changes only if the savedata file is lost. The docker-compose
> mounts `./data:/data` to keep it across container recreation.

---

## 9. Configuration

All configuration is environment-driven (`getenv` with defaults). No flags, no
config file — friendly to containers.

| Var | Default | Meaning |
|-----|---------|---------|
| `TOX_NAME` | `go-tox-bot` | Self name |
| `TOX_STATUS` | `echo bot` | Status message |
| `TOX_DATA_DIR` | `/data` | Data directory (created `0755` if absent) |
| `TOX_SAVEDATA` | `<TOX_DATA_DIR>/bot.tox` | Savedata path |
| `TOX_BOOTSTRAP_NODES` | (2 built-in) | `host:port:pubkeyhex,...` |
| `TOX_ADMINS` | (none) | Comma-separated admin pubkeys (hex) |
| `SOCKS5_PROXY` | (none) | `[user:pass@]host:port` |

### Parsing details
All three parsers share two helpers:

- `parseHostPort` splits a trailing `:port` off using the **last** colon, so an
  IPv6 literal (`[2001:db8::1]:33445`, or the bare `::1:33445`) survives; square
  brackets are stripped because toxcore wants a bare address. Port `0` and an
  empty host are rejected.
- `normalizePubKey` uppercases, strips spaces, and requires **exactly
  `2 × TOX_PUBLIC_KEY_SIZE` = 64 hex characters**. A full 76-character Tox ID is
  accepted and reduced to its public-key prefix, because that is the string
  `/id` prints and therefore the one users paste.

The length check is a safety requirement, not just hygiene: `Tox.Bootstrap`
indexes the decoded key at `[0]` and hands C a pointer that toxcore reads 32
bytes from. An empty key (`host:port:` — trivially produced by a trailing colon
in the env var) **panics the process at startup**; a short one reads out of
bounds.

- **Bootstrap** (`parseBootstrapEnv`): per entry, takes the pubkey off the right
  end, then `parseHostPort` on the remainder, then `normalizePubKey`. Bad
  entries are logged and skipped, not fatal. All entries invalid → falls back to
  `defaultBootstrap()`.
- **Admins** (`parseAdmins`): `normalizePubKey` per entry. Comparison against
  `FriendGetPublicKey` (also uppercased) is exact-string; a friend whose key
  cannot be read is never admin.
- **Proxy** (`applyProxy`): strips an optional `user:pass@` prefix (toxcore has
  **no proxy-auth support**, so credentials are discarded with a warning rather
  than silently ignored), then `parseHostPort`, then sets
  `Proxy_type = PROXY_TYPE_SOCKS5`. Malformed input logs and disables the proxy
  rather than aborting startup.

---

## 10. Lifecycle (startup → shutdown)

1. Resolve config from env; `MkdirAll` the data dir (and the savedata parent, if
   `TOX_SAVEDATA` points elsewhere); `ensureWritable` the savedata path.
2. `NewToxOptions()` → `applyProxy()` → `readSavedata()` into options (fatal on
   an unreadable or non-tox profile; see §8).
3. `NewTox(opts)`; fatal if nil. `defer t.Kill()`.
4. Set name/status; log Tox ID + public key.
5. Construct `Bot` + `buildCommands()`.
6. Parse + bootstrap DHT nodes (failures logged, non-fatal).
7. Register callbacks:
   - `CallbackSelfConnectionStatus` → update `connSt`, log transition.
   - `CallbackFriendRequestAdd` → auto-accept via `FriendAddNorequest`.
   - `CallbackFriendMessageAdd` → `bot.handleMessage` (note: in binding v0.2.17
     this callback signature has **no** message-type parameter).
8. Install `signal.NotifyContext` for SIGINT/SIGTERM.
9. Run the event loop (§6) until the context is cancelled, then save and return
   (deferred `Kill` tears down the instance).

---

## 11. Security model

- **Friend acceptance is open**: any peer can friend the bot
  (`FriendAddNorequest` on every request). This is appropriate for an echo bot;
  a private deployment would gate this (e.g. only accept requests whose message
  contains a shared secret).
- **Privilege boundary** is the admin allowlist keyed on the **friend's public
  key** (cryptographically bound to the peer's identity by toxcore), not on a
  display name or friend number, both of which are spoofable/reused.
- **Transport privacy**: SOCKS5 lets the bot run over Tor so its IP isn't
  exposed to bootstrap nodes / peers (UDP must be disabled by the proxy path;
  toxcore falls back to TCP relays when proxied).
- **No secrets in logs**: the bot logs its own Tox ID/pubkey and peer pubkeys
  (public by design) but never savedata.
- Savedata is written `0600`.

Threats explicitly **out of scope**: spam/abuse from open friend acceptance,
denial-of-service via message floods, and compromise of the host (savedata = the
bot's private identity).

---

## 12. Error-handling philosophy

- **Config/parse errors are non-fatal and skipped with a log line** (bad
  bootstrap node, bad admin key, bad proxy) so one typo can't take the bot down.
- **Instance creation failures are fatal** (`log.Fatal`) — there is no useful
  degraded mode without a Tox instance.
- **Threats to the stored identity are fatal, deliberately breaking the
  non-fatal rule above** (unreadable/corrupt savedata, unwritable savedata
  path). Skipping a bad bootstrap node costs one node; "skipping" a bad profile
  silently changes the bot's Tox ID and then overwrites the only copy. Goal #2
  is a stable identity, so the loud failure is the correct one — a crash-looping
  container is a signal, a silently re-keyed bot is not.
- **Send/save failures are logged and swallowed** by the event loop — a
  transient delivery failure shouldn't crash the bot. `sendMessage` still
  *returns* the error so a handler that was asked to deliver something (`/say`)
  can report the failure instead of replying "sent".
- **Untrusted input never reaches an unchecked C boundary.** The binding
  dereferences decoded byte slices directly, so anything crossing into cgo
  (bootstrap keys) is length-validated first — otherwise "non-fatal config
  error" would become a startup panic.

---

## 13. Extending the bot

**Add a command:** append a `command` literal in `buildCommands()`. Use
`admin: true` for privileged ones. Read `c.args` for arguments; return a string
(it will be chunked automatically). Keep it non-blocking.

**Add state for handlers:** add a field to `Bot` and populate it in `main`. No
locking needed as long as it's only touched on the event-loop goroutine.

**Add a new toxcore event:** register another `Callback…Add` in `main` and route
into a `Bot` method, mirroring `handleMessage`.

**Background work:** spawn a goroutine, but funnel any toxcore calls back onto
the event loop (toxcore is not goroutine-safe). Today nothing needs this.

---

## 14. Future work

- **Conferences / groups**: join/host a Tox conference and relay or respond.
- **File transfer**: implement the file-transfer callbacks (accept/echo files).
- **Friend-request gating**: shared-secret or allowlist instead of open accept.
- **Persisted command/audit log** and basic per-friend rate limiting.
- **Metrics/health endpoint** for container orchestration.
- **A/V (toxav)** — out of scope for a text bot but supported by the binding.

---

## 15. Tests

`cmd/toxcbt/main_test.go` (package `main`, so unexported helpers are reachable).
Two groups:

- **Pure functions** — `parseBootstrapEnv`, `parseAdmins`, `normalizePubKey`,
  `parseHostPort`, `applyProxy`, `chunkMessage`, `cutWord`, `iterInterval`,
  `getenv`. Table-driven. The chunking tests assert three invariants over
  several alphabets and window sizes: no chunk exceeds `max`, every chunk is
  valid UTF-8, and nothing but whitespace is lost across the join.
- **Command layer** — a `fakeTox` implementing `toxClient` records outbound
  messages and friend deletions and can be told to fail. That covers dispatch
  (echo, case-folding, whitespace splitting, unknown commands), the admin
  boundary in both directions, and each handler's success and failure replies.
- **Persistence** — `readSavedata` / `validateSavedata` / `ensureWritable` /
  `writeFileSync` / `Bot.save()` against real temp directories: the three load
  outcomes, header and encrypted-profile rejection, read-only directories,
  truncating rewrites, `0600`, empty-data no-op, and temp-file cleanup after a
  failed write *or* rename. The header fixture is asserted against the real
  on-disk bytes so it cannot drift into agreeing with a wrong implementation.
  Cases that depend on permission bits skip when running as root.

Running them needs the same native libs as a local build (`CGO_ENABLED=1` plus
libtoxcore/libsodium), because package `main` imports the binding:

```bash
go test ./...
```

---

## 16. File map

```
cmd/toxcbt/main.go   the entire bot (config, Bot, command registry, event loop, persistence)
cmd/toxcbt/main_test.go  unit tests + the in-memory toxClient fake
Dockerfile           two-stage CGO build (build deps → slim runtime)
docker-compose.yml   service def + persistent ./data volume + env examples
go.mod / go.sum      module + pinned go-toxcore-c v0.2.17
data/                runtime savedata (gitignored)
README.md            user-facing usage
DESIGN.md            this document
```
