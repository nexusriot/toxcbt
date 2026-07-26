# go-tox-bot

Minimal **Tox** echo bot written in **Go**, ready to run locally or via **Docker Compose**.


- Echo bot with an extensible slash-command system
- Admin-gated commands (friend management, broadcast, manual save)
- Persistent Tox profile
- Connection-status logging
- Optional SOCKS5 proxy (e.g. Tor)
- Docker & docker-compose support
- Configurable bootstrap nodes

## Commands
Send these to the bot as a friend message. Anything not starting with `/` is echoed back.

- `/help` – list available commands
- `/ping` – reply `pong`
- `/id` – show the bot's Tox ID
- `/uptime` – how long the bot has been running
- `/stats` – name, status, connection state, friend count, uptime

Admin-only (sender's public key must be in `TOX_ADMINS`):

- `/friends` – list friends (number, public key, connection status)
- `/remove <friendNumber>` – delete a friend
- `/say <friendNumber> <text>` – send a message to a friend
- `/save` – persist savedata immediately

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

## Run (local)
```bash
./tox-bot
```

## Run with Docker
```bash
docker build -t tox-bot .
docker run --rm tox-bot
```

## Run with Docker Compose
```bash
docker compose up --build
```

## Configuration
All configuration is done via environment variables (see `docker-compose.yml`):

- `TOX_NAME` – bot name
- `TOX_STATUS` – status message
- `TOX_DATA_DIR` – data directory (default `/data`)
- `TOX_SAVEDATA` – savedata path (default `<TOX_DATA_DIR>/bot.tox`)
- `TOX_BOOTSTRAP_NODES` – comma-separated bootstrap nodes (`host:port:pubkeyhex,...`)
- `TOX_ADMINS` – comma-separated admin public keys (hex) for privileged commands
- `SOCKS5_PROXY` – optional SOCKS5 proxy as `[user:pass@]host:port` (auth is ignored; toxcore does not support proxy auth)

Notes on the address-shaped values:

- IPv6 literals work in both `TOX_BOOTSTRAP_NODES` and `SOCKS5_PROXY`, bracketed
  (`[2001:db8::1]:33445:<key>`) or bare (`::1:33445:<key>`).
- Keys must be 64 hex characters. A full 76-character **Tox ID** — what `/id`
  prints — is also accepted and trimmed to its public-key half, so pasting one
  into `TOX_ADMINS` does the expected thing.
- Anything malformed is logged and skipped; the bot still starts.

## Data
Tox profile is stored in a persistent volume to keep the same Tox ID across restarts.

## License
MIT
