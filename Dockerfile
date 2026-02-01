FROM alpine:3.20 AS build

RUN apk add --no-cache \
    go \
    git \
    build-base \
    pkgconf \
    toxcore-dev \
    libsodium-dev

WORKDIR /src
COPY go.mod ./
RUN go mod download

COPY . .
ENV CGO_ENABLED=1
RUN go build -trimpath -ldflags="-s -w" -o /out/tox-bot ./cmd/toxcbt


FROM alpine:3.20 AS runtime

RUN apk add --no-cache \
    toxcore \
    libsodium \
    ca-certificates

WORKDIR /app
COPY --from=build /out/tox-bot /app/tox-bot

VOLUME ["/data"]
ENV TOX_DATA_DIR=/data
ENV TOX_SAVEDATA=/data/bot.tox

ENTRYPOINT ["/app/tox-bot"]
