# go-tox-bot

Minimal **Tox** echo bot written in **Go**, ready to run locally or via **Docker Compose**.


- Simple echo bot
- Persistent Tox profile
- Docker & docker-compose support
- Configurable bootstrap nodes

## Requirements
- Go 1.22+
- Docker + Docker Compose (optional)

## Build (local)
```bash
go build -o tox-bot .
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
- `TOX_BOOTSTRAP_NODES` – comma-separated bootstrap nodes
- `SOCKS5_PROXY` – optional SOCKS5 proxy (`user:pass@host:port`)

## Data
Tox profile is stored in a persistent volume to keep the same Tox ID across restarts.

## License
MIT
