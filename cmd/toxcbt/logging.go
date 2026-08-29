package main

import (
	"log/slog"
	"os"
	"strings"

	tox "github.com/TokTok/go-toxcore-c"
)

// parseLogLevel maps TOX_LOG_LEVEL onto slog's levels, defaulting to info for
// anything unrecognised.
func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "", "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		slog.Warn("unknown TOX_LOG_LEVEL, using info", "value", s)
		return slog.LevelInfo
	}
}

// setupLogging installs the process-wide structured logger. It is called after
// the configuration is parsed, so anything logged during parsing goes through
// the default handler at info level.
func setupLogging(level slog.Level, format string) {
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}

// toxcoreLogLevel maps toxcore's own log levels onto slog's. toxcore is chatty
// at trace/debug, so everything below its warning level lands at slog debug.
func toxcoreLogLevel(level int) slog.Level {
	switch level {
	case tox.LOG_LEVEL_ERROR:
		return slog.LevelError
	case tox.LOG_LEVEL_WARNING:
		return slog.LevelWarn
	default:
		return slog.LevelDebug
	}
}

// messageAttr renders a friend's message for the log. Private correspondence
// is not something a bot should write to a container's stdout by default, so
// unless TOX_LOG_MESSAGES is set only the length is recorded.
func messageAttr(msg string, allowed bool) slog.Attr {
	if allowed {
		return slog.String("msg", msg)
	}
	return slog.Int("msg_len", len(msg))
}
