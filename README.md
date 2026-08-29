# go-tox-bot

Minimal **Tox** bot written in **Go**, ready to run locally or via **Docker Compose**.

- Echo bot with an extensible slash-command system
- Admin-gated commands (friend management, broadcast, blocklist, runtime admins, manual save)
- Persistent Tox profile, optionally **encrypted at rest**
- Reconnects on its own: DHT bootstrap **and TCP relays**, retried with backoff while offline
- **Offline outbox** — messages for absent friends are queued and delivered when they return
- Delivery confirmation via read receipts
- Friend-request policies (open / shared secret / allowlist / closed) and a friend cap
- Per-peer rate limiting, blocklist, and an append-only audit log of privileged actions
- `/healthz` + Prometheus `/metrics` endpoint
- Structured logging (text or JSON), with message bodies redacted by default
- Optional SOCKS5 proxy (e.g. Tor)
- Docker & docker-compose support

## Commands
Send these to the bot as a friend message. Anything not starting with `/` is echoed back.

- `/help` – list available commands
- `/ping` – reply `pong`
- `/id` – show the bot's Tox ID
- `/uptime` – how long the bot has been running
- `/version` – build version
- `/whoami` – your friend number, public key and privilege level
- `/stats` – name, status, connection state, friend count, uptime, queued messages, rate-limit drops

Admin-only (sender's public key must be in `TOX_ADMINS`, or granted with `/admin add`):

- `/friends` – list friends (number, public key, connection status)
- `/remove <friendNumber>` – delete a friend
- `/say <friendNumber> <text>` – send a message to a friend; queued if they are offline,
  and confirmed with `delivered: #n` once their client acknowledges it
- `/broadcast <text>` – message every friend (queuing for those offline)
- `/save` – persist savedata immediately
- `/nospam [8 hex digits]` – rotate the nospam half of the Tox ID to shed a spam wave.
  Existing friendships are unaffected: they are bound to the public key, not the Tox ID.
- `/admin [list|add <key|#n>|remove <key>]` – manage runtime admins. Keys from
  `TOX_ADMINS` are permanent and cannot be removed at runtime.
- `/block <key|#n>` / `/unblock <key>` / `/blocked` – blocklist. Blocking also drops
  the friendship and discards anything queued for that peer.
- `/outbox [clear]` – what is waiting for offline friends
- `/audit [n]` – tail the audit log

## Requirements
- Go 1.22+
- Docker + Docker Compose (optional)

## Build (local)
```bash
go build -o tox-bot ./cmd/toxcbt
```

Needs `libtoxcore` + `libsodium` and their headers, since the binding is CGO.
On a clean machine, build via Docker instead.

## Test
```bash
go test ./...
```

Or, with no native libraries installed, through the Dockerfile's test stage — which
is exactly what CI runs:

```bash
docker build --target test .
```

## Run (local)
```bash
./tox-bot
```

## Run with Docker
```bash
docker build -t tox-bot .
```

## Run with Docker Compose
```bash
docker compose up --build
```

The image runs as uid 1000, so the mounted `./data` directory has to be writable by
it (`chown -R 1000:1000 data`). The bot refuses to start on an unwritable data
directory rather than lose its identity at the first save.

## Configuration
All configuration is done via environment variables (see `docker-compose.yml`).

### Identity and storage

| Variable | Default | Meaning |
|---|---|---|
| `TOX_NAME` | `go-tox-bot` | Bot name |
| `TOX_STATUS` | `echo bot` | Status message |
| `TOX_DATA_DIR` | `/data` | Data directory |
| `TOX_SAVEDATA` | `<TOX_DATA_DIR>/bot.tox` | Savedata path |
| `TOX_SAVEDATA_PASSPHRASE` | (none) | Encrypt the profile at rest |
| `TOX_SAVEDATA_PASSPHRASE_FILE` | (none) | Read the passphrase from a file (a container secret); wins over the variable, and a trailing newline is stripped |
| `TOX_STATE_FILE` | `<TOX_DATA_DIR>/state.json` | Runtime state: runtime admins, blocklist, outbox |
| `TOX_SAVE_INTERVAL` | `30s` | How often the profile is written |

Setting a passphrase against an existing plaintext profile migrates it: the profile
loads as is and the next save writes it encrypted. The format is the same
`toxEsave` container the desktop clients use, so an encrypted profile made
elsewhere can be pointed at with the right passphrase. A wrong passphrase is a
startup failure, never a silent new identity.

### Network

| Variable | Default | Meaning |
|---|---|---|
| `TOX_BOOTSTRAP_NODES` | 4 built-in nodes | `host:port[/tcpPort]:pubkeyhex,...` |
| `SOCKS5_PROXY` | (none) | `[user:pass@]host:port` (auth is ignored; toxcore does not support proxy auth) |

Every node is registered both as a DHT bootstrap node **and** as a TCP relay. The
relay port defaults to the UDP port and can be given separately (`.../3389`) or
disabled per node (`/0`). This matters: toxcore refuses to bind UDP whenever a
proxy is configured, and in TCP-only mode bootstrapping alone never connects —
measured against live nodes, bootstrap-only stayed offline indefinitely while the
same nodes added as relays connected in about 12 seconds.

Bootstrapping is retried while the bot is offline, backing off from 15s to 5
minutes, so a container that starts before its network is ready still comes up.

Notes on the address-shaped values:

- IPv6 literals work in both `TOX_BOOTSTRAP_NODES` and `SOCKS5_PROXY`, bracketed
  (`[2001:db8::1]:33445:<key>`) or bare (`::1:33445:<key>`).
- Keys must be 64 hex characters. A full 76-character **Tox ID** — what `/id`
  prints — is also accepted and trimmed to its public-key half.
- Anything malformed is logged and skipped; the bot still starts.

### Access control

| Variable | Default | Meaning |
|---|---|---|
| `TOX_ADMINS` | (none) | Comma-separated admin public keys (hex) |
| `TOX_FRIEND_POLICY` | `open` | `open`, `secret`, `allowlist` or `closed` |
| `TOX_FRIEND_SECRET` | (none) | Required substring of the friend-request message when the policy is `secret` |
| `TOX_FRIEND_ALLOWLIST` | (none) | Public keys accepted under any policy |
| `TOX_MAX_FRIENDS` | `0` (unlimited) | Reject requests past this many friends |
| `TOX_RATE_PER_MINUTE` | `30` | Per-peer message allowance (`0` disables limiting) |
| `TOX_RATE_BURST` | `10` | How many may arrive at once |
| `TOX_MAX_REPLY_CHUNKS` | `8` | Cap on outbound chunks per reply (`0` unlimited) |

Admins are exempt from rate limiting and are always allowed to friend the bot.
A `secret` policy with an empty secret is treated as `closed`, because an empty
secret would otherwise match every request.

### Outbox, audit and observability

| Variable | Default | Meaning |
|---|---|---|
| `TOX_OUTBOX_MAX` | `50` | Messages queued per offline friend (`0` disables the outbox) |
| `TOX_OUTBOX_TTL` | `168h` | How long a queued message is worth delivering |
| `TOX_AUDIT_LOG` | `<TOX_DATA_DIR>/audit.log` | Audit trail (empty disables it) |
| `TOX_AUDIT_MAX_BYTES` | `5242880` | Rotate to `.1` past this size |
| `TOX_HEALTH_ADDR` | (none; `:8080` in the image) | Listen address for `/healthz` and `/metrics` |
| `TOX_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `TOX_LOG_FORMAT` | `text` | `text` or `json` |
| `TOX_LOG_MESSAGES` | `false` | Log message bodies (off by default: they are private correspondence) |
| `TOX_TOXCORE_LOG` | `false` | Forward toxcore's own (very chatty) log |

`/healthz` returns 200 once the bot is on the Tox network and 503 before that, so
it doubles as the container's health check. `/metrics` is Prometheus text format:
connection state, friends online, messages in/out, delivery confirmations,
rate-limit drops, queue depth, friend-request outcomes and save errors.

## Data
The Tox profile is stored in a persistent volume to keep the same Tox ID across
restarts. Alongside it, `state.json` holds runtime admins, the blocklist and the
outbox, and `audit.log` records privileged actions. Both the profile and the state
file are written `0600` through a temp file, fsync and rename.

## License
MIT
