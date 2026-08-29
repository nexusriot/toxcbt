package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	tox "github.com/TokTok/go-toxcore-c"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

// buildVersion falls back to the VCS stamp the Go toolchain embeds, so a
// plain `go build` still reports something specific.
func buildVersion() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	revision, suffix := "", ""
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				suffix = "-dirty"
			}
		}
	}
	if revision == "" {
		return version
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	return revision + suffix
}

// mkdirFor creates the parent directory of a file the bot must be able to
// write, so a path pointing outside TOX_DATA_DIR does not fail on every write.
func mkdirFor(path string) error {
	if path == "" {
		return nil
	}
	return os.MkdirAll(filepath.Dir(path), 0o755)
}

func main() {
	setupLogging(
		parseLogLevel(getenv("TOX_LOG_LEVEL", "info")),
		strings.ToLower(getenv("TOX_LOG_FORMAT", "text")),
	)
	cfg := loadConfig()
	slog.Info("starting", "version", buildVersion())

	if err := os.MkdirAll(cfg.dataDir, 0o755); err != nil {
		slog.Error("mkdir data dir", "err", err)
		os.Exit(1)
	}
	for _, path := range []string{cfg.saveFile, cfg.stateFile, cfg.auditFile} {
		if err := mkdirFor(path); err != nil {
			slog.Error("mkdir failed", "path", path, "err", err)
			os.Exit(1)
		}
	}
	if err := ensureWritable(cfg.saveFile); err != nil {
		slog.Error("savedata path is not writable", "path", cfg.saveFile, "err", err)
		os.Exit(1)
	}

	opts := tox.NewToxOptions()
	applyProxy(opts, cfg.proxy)
	if cfg.toxcoreLog {
		opts.LogCallback = func(_ *tox.Tox, level int, file string, line uint32, fname string, msg string) {
			slog.Log(context.Background(), toxcoreLogLevel(level), "toxcore",
				"file", file, "line", line, "func", fname, "msg", msg)
		}
	}

	// Load savedata if present (identity / keys), decrypting it when needed.
	savedata, cipher, haveSavedata, err := loadProfile(cfg.saveFile, cfg.passphrase)
	if err != nil {
		slog.Error("savedata is unusable -- refusing to start, because toxcore would silently "+
			"generate a new Tox ID and the next save would overwrite this file; fix it, or move "+
			"it aside to accept a new identity", "path", cfg.saveFile, "err", err)
		os.Exit(1)
	}
	defer cipher.close()

	if haveSavedata {
		opts.Savedata_type = tox.SAVEDATA_TYPE_TOX_SAVE
		opts.Savedata_data = savedata
		slog.Info("loaded savedata", "path", cfg.saveFile, "bytes", len(savedata),
			"encrypt_at_rest", cipher != nil)
	} else {
		slog.Info("no savedata; starting with a fresh identity", "path", cfg.saveFile)
	}

	t := tox.NewTox(opts)
	if t == nil {
		if haveSavedata {
			slog.Error("failed to create tox instance from savedata: the file may be corrupt; "+
				"move it aside to start a new identity", "path", cfg.saveFile)
			os.Exit(1)
		}
		slog.Error("failed to create tox instance")
		os.Exit(1)
	}
	defer t.Kill()

	if err := t.SelfSetName(cfg.name); err != nil {
		slog.Warn("set name failed", "name", cfg.name, "err", err)
	}
	if _, err := t.SelfSetStatusMessage(cfg.status); err != nil {
		slog.Warn("set status failed", "status", cfg.status, "err", err)
	}

	slog.Info("identity", "tox_id", t.SelfGetAddress(), "public_key", t.SelfGetPublicKey())

	state, err := loadState(cfg.stateFile, cfg.outboxMax, cfg.outboxTTL)
	if err != nil {
		slog.Error("state file is unusable -- refusing to start, because continuing would drop the "+
			"blocklist and every queued message; fix it, or move it aside to start with an empty state",
			"path", cfg.stateFile, "err", err)
		os.Exit(1)
	}

	audit, err := openAudit(cfg.auditFile, cfg.auditBytes)
	if err != nil {
		// Not fatal: losing the audit trail is bad, but it is not the identity,
		// and a bot that refuses to run is not more auditable.
		slog.Error("audit log disabled", "path", cfg.auditFile, "err", err)
	}
	defer audit.close()

	bot := &Bot{
		t:              t,
		saveFile:       cfg.saveFile,
		admins:         cfg.admins,
		started:        time.Now(),
		connSt:         tox.CONNECTION_NONE,
		cipher:         cipher,
		state:          state,
		audit:          audit,
		limiter:        newRateLimiter(cfg.rateBurst, cfg.ratePerMinute),
		policy:         cfg.policy,
		maxReplyChunks: cfg.maxReplyChunks,
		logMessages:    cfg.logMessages,
		version:        buildVersion(),
		pending:        map[receiptKey]pendingReceipt{},
	}
	cmds := bot.buildCommands()

	slog.Info("policy",
		"admins", len(bot.admins)+len(state.adminList()),
		"friend_policy", cfg.policy.mode,
		"max_friends", cfg.policy.maxFriends,
		"blocked", len(state.blockedList()),
		"queued", state.queued(),
		"rate_per_minute", cfg.ratePerMinute,
		"log_messages", cfg.logMessages,
	)

	dht := newBootstrapper(cfg.nodes, 15*time.Second, 5*time.Minute)
	nodes, relays := dht.run(t, time.Now())
	slog.Info("bootstrapped", "nodes", nodes, "relays", relays, "configured", len(cfg.nodes))

	// Log when the bot reaches / leaves the DHT.
	t.CallbackSelfConnectionStatus(func(_ *tox.Tox, status int, _ interface{}) {
		bot.connSt = status
		if status != tox.CONNECTION_NONE {
			dht.connected()
		}
		slog.Info("self connection status", "status", tox.ConnStatusString(status))
	}, nil)

	t.CallbackFriendRequestAdd(func(_ *tox.Tox, pubKey string, msg string, _ interface{}) {
		bot.onFriendRequest(pubKey, msg)
	}, nil)

	// In v0.2.17 the friend-message callback type does NOT include mtype.
	// So the signature must be: func(*tox.Tox, uint32, string, interface{})
	t.CallbackFriendMessageAdd(func(_ *tox.Tox, friend uint32, message string, _ interface{}) {
		bot.handleMessage(friend, message, cmds)
	}, nil)

	t.CallbackFriendConnectionStatusAdd(func(_ *tox.Tox, friend uint32, status int, _ interface{}) {
		bot.onFriendConnectionStatus(friend, status)
	}, nil)

	t.CallbackFriendReadReceiptAdd(func(_ *tox.Tox, friend uint32, receipt uint32, _ interface{}) {
		bot.onReadReceipt(friend, receipt)
	}, nil)

	health := newHealthServer(cfg.healthAddr)
	if err := health.start(); err != nil {
		slog.Error("cannot start the health endpoint", "addr", cfg.healthAddr, "err", err)
		os.Exit(1)
	}
	if health != nil {
		health.publish(bot.snapshot())
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	saveTick := time.NewTicker(cfg.saveInterval)
	defer saveTick.Stop()

	// One slow ticker drives everything that is not message handling:
	// reconnection, the health snapshot, and periodic housekeeping.
	const houseInterval = 5 * time.Second
	houseTick := time.NewTicker(houseInterval)
	defer houseTick.Stop()

	iterTick := time.NewTicker(iterInterval(t.IterationInterval()))
	defer iterTick.Stop()

	slog.Info("bot started")
	houseTicks := 0

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			bot.save()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			health.shutdown(shutdownCtx)
			cancel()
			return

		case <-saveTick.C:
			bot.save()

		case <-houseTick.C:
			now := time.Now()
			if bot.connSt == tox.CONNECTION_NONE && dht.due(now) {
				nodes, relays := dht.run(t, now)
				slog.Warn("offline; re-bootstrapping", "nodes", nodes, "relays", relays,
					"attempt", dht.attempts)
			}
			if health != nil {
				health.publish(bot.snapshot())
			}
			if houseTicks++; houseTicks%12 == 0 { // once a minute
				bot.maintenance()
			}

		case <-iterTick.C:
			t.Iterate()
			iterTick.Reset(iterInterval(t.IterationInterval()))
		}
	}
}

// iterInterval turns toxcore's advisory poll interval into a duration a
// time.Ticker will accept; the C API is free to report 0.
func iterInterval(ms int) time.Duration {
	if ms <= 0 {
		return time.Millisecond
	}
	return time.Duration(ms) * time.Millisecond
}
