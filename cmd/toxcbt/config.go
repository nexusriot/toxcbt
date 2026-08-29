package main

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tox "github.com/TokTok/go-toxcore-c"
)

const (
	defaultName   = "go-tox-bot"
	defaultStatus = "echo bot"
)

// config is the whole environment-driven configuration surface, resolved once
// at startup so the rest of the bot never reads os.Getenv.
type config struct {
	name   string
	status string

	dataDir    string
	saveFile   string
	stateFile  string
	auditFile  string
	auditBytes int64
	passphrase []byte

	nodes  []bootstrapNode
	admins map[string]bool
	proxy  string

	healthAddr string

	logLevel    slog.Level
	logFormat   string
	logMessages bool
	toxcoreLog  bool

	policy friendPolicy

	rateBurst      int
	ratePerMinute  int
	maxReplyChunks int

	outboxMax int
	outboxTTL time.Duration

	saveInterval time.Duration
}

// friendPolicy decides which friend requests are accepted.
type friendPolicy struct {
	mode       string
	secret     string
	allow      map[string]bool
	maxFriends int
}

const (
	policyOpen      = "open"
	policySecret    = "secret"
	policyAllowlist = "allowlist"
	policyClosed    = "closed"
)

// loadConfig resolves every setting from the environment. Following the
// existing error philosophy, a malformed value is logged and replaced with the
// default rather than taken as fatal; only things that would endanger the
// stored identity fail later, at startup.
func loadConfig() config {
	dataDir := getenv("TOX_DATA_DIR", "/data")
	c := config{
		name:      getenv("TOX_NAME", defaultName),
		status:    getenv("TOX_STATUS", defaultStatus),
		dataDir:   dataDir,
		saveFile:  getenv("TOX_SAVEDATA", filepath.Join(dataDir, "bot.tox")),
		stateFile: getenv("TOX_STATE_FILE", filepath.Join(dataDir, "state.json")),
		auditFile: getenvPath("TOX_AUDIT_LOG", filepath.Join(dataDir, "audit.log")),
		admins:    parseAdmins(os.Getenv("TOX_ADMINS")),
		proxy:     os.Getenv("SOCKS5_PROXY"),

		healthAddr: getenv("TOX_HEALTH_ADDR", ""),

		logFormat:   strings.ToLower(getenv("TOX_LOG_FORMAT", "text")),
		logMessages: getenvBool("TOX_LOG_MESSAGES", false),
		toxcoreLog:  getenvBool("TOX_TOXCORE_LOG", false),

		auditBytes:     int64(getenvInt("TOX_AUDIT_MAX_BYTES", 5*1024*1024)),
		rateBurst:      getenvInt("TOX_RATE_BURST", 10),
		ratePerMinute:  getenvInt("TOX_RATE_PER_MINUTE", 30),
		maxReplyChunks: getenvInt("TOX_MAX_REPLY_CHUNKS", 8),
		outboxMax:      getenvInt("TOX_OUTBOX_MAX", 50),
		outboxTTL:      getenvDuration("TOX_OUTBOX_TTL", 7*24*time.Hour),
		saveInterval:   getenvDuration("TOX_SAVE_INTERVAL", 30*time.Second),
	}

	c.logLevel = parseLogLevel(getenv("TOX_LOG_LEVEL", "info"))
	c.passphrase = loadPassphrase()
	c.policy = loadFriendPolicy(c.admins)

	c.nodes = parseBootstrapEnv(os.Getenv("TOX_BOOTSTRAP_NODES"))
	if len(c.nodes) == 0 {
		c.nodes = defaultBootstrap()
	}
	if c.saveInterval <= 0 {
		c.saveInterval = 30 * time.Second
	}
	return c
}

// loadPassphrase reads the savedata passphrase from the environment or, better
// for containers, from a file (a Docker/Kubernetes secret).
func loadPassphrase() []byte {
	if path := getenv("TOX_SAVEDATA_PASSPHRASE_FILE", ""); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Error("cannot read TOX_SAVEDATA_PASSPHRASE_FILE", "path", path, "err", err)
			return nil
		}
		// A trailing newline is what every editor and `echo` adds; it is
		// almost never meant to be part of the passphrase.
		return []byte(strings.TrimRight(string(data), "\r\n"))
	}
	if pass := os.Getenv("TOX_SAVEDATA_PASSPHRASE"); pass != "" {
		return []byte(pass)
	}
	return nil
}

func loadFriendPolicy(admins map[string]bool) friendPolicy {
	p := friendPolicy{
		mode:       strings.ToLower(getenv("TOX_FRIEND_POLICY", policyOpen)),
		secret:     os.Getenv("TOX_FRIEND_SECRET"),
		allow:      parseAdmins(os.Getenv("TOX_FRIEND_ALLOWLIST")),
		maxFriends: getenvInt("TOX_MAX_FRIENDS", 0),
	}
	// Admins can always get back in, whatever the policy says; locking out the
	// operator is never the intended reading of a strict policy.
	for key := range admins {
		p.allow[key] = true
	}

	switch p.mode {
	case policyOpen, policyAllowlist, policyClosed:
	case policySecret:
		// An empty secret would make the containment test match every request,
		// turning the strictest-looking policy into the most permissive one.
		if strings.TrimSpace(p.secret) == "" {
			slog.Error("TOX_FRIEND_POLICY=secret needs TOX_FRIEND_SECRET; refusing all requests instead")
			p.mode = policyClosed
		}
	default:
		slog.Warn("unknown TOX_FRIEND_POLICY, using open", "value", p.mode)
		p.mode = policyOpen
	}
	return p
}

// accepts decides a single friend request. The reason is for the log and the
// audit trail, and is never sent to the peer.
func (p friendPolicy) accepts(pubKey, message string, friendCount int, blocked bool) (bool, string) {
	switch {
	case blocked:
		return false, "blocked"
	case p.allow[pubKey]:
		// An allowlisted peer (or an admin) bypasses the cap and the secret.
		return true, "allowlisted"
	case p.maxFriends > 0 && friendCount >= p.maxFriends:
		return false, fmt.Sprintf("friend limit reached (%d)", p.maxFriends)
	}

	switch p.mode {
	case policyOpen:
		return true, "open policy"
	case policySecret:
		if strings.Contains(message, p.secret) {
			return true, "secret matched"
		}
		return false, "secret missing"
	case policyAllowlist:
		return false, "not on allowlist"
	default:
		return false, "closed policy"
	}
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// getenvPath is getenv for optional paths, where an explicitly empty value is
// a choice ("disable this file") rather than an absent setting.
func getenvPath(key, def string) string {
	if raw, ok := os.LookupEnv(key); ok {
		return strings.TrimSpace(raw)
	}
	return def
}

func getenvBool(key string, def bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		slog.Warn("ignoring malformed boolean", "var", key, "value", raw, "using", def)
		return def
	}
	return v
}

func getenvInt(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		slog.Warn("ignoring malformed integer", "var", key, "value", raw, "using", def)
		return def
	}
	return v
}

func getenvDuration(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := time.ParseDuration(raw)
	if err != nil || v < 0 {
		slog.Warn("ignoring malformed duration", "var", key, "value", raw, "using", def)
		return def
	}
	return v
}

// cutLast splits s around the last instance of sep.
func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

// normalizePubKey validates a Tox public key written as hex and returns it
// uppercased. A full 76-character Tox ID (public key + nospam + checksum) is
// accepted and reduced to its public-key prefix, since that is what /id prints
// and what users tend to paste.
func normalizePubKey(s string) (string, error) {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if len(s) == 2*tox.ADDRESS_SIZE {
		s = s[:2*tox.PUBLIC_KEY_SIZE]
	}
	if len(s) != 2*tox.PUBLIC_KEY_SIZE {
		return "", fmt.Errorf("need %d hex chars, got %d", 2*tox.PUBLIC_KEY_SIZE, len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", err
	}
	return s, nil
}

// parseHostPort splits a trailing ":port" off s. Splitting from the right keeps
// IPv6 literals intact; surrounding brackets are stripped because toxcore wants
// a bare address.
func parseHostPort(s string) (host string, port uint16, err error) {
	hostPart, portStr, ok := cutLast(s, ":")
	if !ok {
		return "", 0, fmt.Errorf("need host:port")
	}
	host = strings.Trim(strings.TrimSpace(hostPart), "[]")
	if host == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	p64, err := strconv.ParseUint(strings.TrimSpace(portStr), 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("bad port: %w", err)
	}
	if p64 == 0 {
		return "", 0, fmt.Errorf("port must not be 0")
	}
	return host, uint16(p64), nil
}

// parseAdmins parses a comma-separated list of hex public keys. Keys are
// normalized to uppercase, no spaces, for comparison.
func parseAdmins(s string) map[string]bool {
	admins := map[string]bool{}
	for _, item := range strings.Split(s, ",") {
		if strings.TrimSpace(item) == "" {
			continue
		}
		key, err := normalizePubKey(item)
		if err != nil {
			slog.Warn("key entry skipped", "reason", err, "entry", strings.TrimSpace(item))
			continue
		}
		admins[key] = true
	}
	return admins
}

// applyProxy wires SOCKS5_PROXY into the Tox options.
// Format: [user:pass@]host:port. Auth is NOT supported by toxcore and is
// stripped with a warning if present.
func applyProxy(opts *tox.ToxOptions, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	if at := strings.LastIndex(raw, "@"); at >= 0 {
		slog.Warn("SOCKS5_PROXY: auth credentials are not supported by toxcore; ignoring user:pass")
		raw = raw[at+1:]
	}
	host, port, err := parseHostPort(raw)
	if err != nil {
		slog.Warn("SOCKS5_PROXY ignored", "reason", err, "value", raw)
		return
	}
	opts.Proxy_type = int32(tox.PROXY_TYPE_SOCKS5)
	opts.Proxy_host = host
	opts.Proxy_port = port
	slog.Info("using SOCKS5 proxy", "host", opts.Proxy_host, "port", opts.Proxy_port)
}
