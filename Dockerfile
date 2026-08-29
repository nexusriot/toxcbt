FROM alpine:3.20 AS build

RUN apk add --no-cache \
    go \
    git \
    build-base \
    pkgconf \
    toxcore-dev \
    libsodium-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ENV CGO_ENABLED=1
ARG VERSION=docker
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/tox-bot ./cmd/toxcbt


# `docker build --target test .` runs the suite with the same native libraries
# the binary links against, which is what CI (and any clean machine) needs
# since the binding is CGO.
FROM build AS test
RUN go vet ./... && go test -count=1 ./...


FROM alpine:3.20 AS runtime

RUN apk add --no-cache \
    toxcore \
    libsodium \
    ca-certificates \
    wget

# The bot needs no privileges; /data must be writable by this uid.
RUN adduser -D -u 1000 -h /data tox

WORKDIR /app
COPY --from=build /out/tox-bot /app/tox-bot

VOLUME ["/data"]
ENV TOX_DATA_DIR=/data
ENV TOX_SAVEDATA=/data/bot.tox
ENV TOX_HEALTH_ADDR=:8080
EXPOSE 8080

# /healthz answers 503 until the bot reaches the DHT, so an unhealthy container
# means "not on the network", not merely "not running".
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

USER tox
ENTRYPOINT ["/app/tox-bot"]
