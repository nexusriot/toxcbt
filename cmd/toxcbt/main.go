package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	tox "github.com/TokTok/go-toxcore-c"
)

const (
	defaultName   = "go-tox-bot"
	defaultStatus = "echo bot"
)

type bootstrapNode struct {
	host string
	port uint16
	key  string // hex public key
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

// TOX_BOOTSTRAP_NODES format:
// host:port:pubkeyhex,host:port:pubkeyhex,...
func parseBootstrapEnv(s string) []bootstrapNode {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	var out []bootstrapNode
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		// The public key is the last field, so split from the right: anything
		// before it may be an IPv6 literal full of colons.
		addr, keyPart, ok := cutLast(item, ":")
		if !ok {
			log.Printf("bootstrap entry skipped (need host:port:pubkey): %q", item)
			continue
		}
		host, port, err := parseHostPort(addr)
		if err != nil {
			log.Printf("bootstrap entry skipped (%v): %q", err, item)
			continue
		}
		// A key of the wrong length is not merely useless: toxcore reads
		// exactly 32 bytes from it, and an empty one panics the binding.
		pubKey, err := normalizePubKey(keyPart)
		if err != nil {
			log.Printf("bootstrap entry skipped (bad pubkey: %v): %q", err, item)
			continue
		}

		out = append(out, bootstrapNode{
			host: host,
			port: port,
			key:  pubKey,
		})
	}
	return out
}

func defaultBootstrap() []bootstrapNode {
	return []bootstrapNode{
		{"tox.abilinski.com", 33445, "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E"},
		{"144.217.167.73", 33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C"},
	}
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// parseAdmins parses TOX_ADMINS: a comma-separated list of hex public keys.
// Keys are normalized to uppercase, no spaces, for comparison.
func parseAdmins(s string) map[string]bool {
	admins := map[string]bool{}
	for _, item := range strings.Split(s, ",") {
		if strings.TrimSpace(item) == "" {
			continue
		}
		key, err := normalizePubKey(item)
		if err != nil {
			log.Printf("admin entry skipped (%v): %q", err, strings.TrimSpace(item))
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
		log.Printf("SOCKS5_PROXY: auth credentials are not supported by toxcore; ignoring user:pass")
		raw = raw[at+1:]
	}
	host, port, err := parseHostPort(raw)
	if err != nil {
		log.Printf("SOCKS5_PROXY ignored (%v): %q", err, raw)
		return
	}
	opts.Proxy_type = int32(tox.PROXY_TYPE_SOCKS5)
	opts.Proxy_host = host
	opts.Proxy_port = port
	log.Printf("using SOCKS5 proxy %s:%d", opts.Proxy_host, opts.Proxy_port)
}

// toxClient is the slice of *tox.Tox the bot actually uses. Depending on the
// interface rather than the concrete type keeps the command layer exercisable
// without a live toxcore instance.
type toxClient interface {
	SelfGetAddress() string
	SelfGetName() string
	SelfGetStatusMessage() (string, error)
	SelfGetFriendList() []uint32
	SelfGetFriendListSize() uint32
	FriendGetPublicKey(friendNumber uint32) (string, error)
	FriendGetConnectionStatus(friendNumber uint32) (int, error)
	FriendDelete(friendNumber uint32) (bool, error)
	FriendSendMessage(friendNumber uint32, message string) (uint32, error)
	GetSavedataSize() int32
	GetSavedata() []byte
}

// Bot holds shared runtime state for command handlers.
type Bot struct {
	t        toxClient
	saveFile string
	admins   map[string]bool
	started  time.Time
	connSt   int // last known self connection status
}

// cmdCtx is the per-invocation context passed to a command handler.
type cmdCtx struct {
	bot     *Bot
	friend  uint32
	pubKey  string // sender public key (uppercase hex)
	args    string // everything after the command word
	isAdmin bool
}

type command struct {
	name  string
	admin bool
	help  string
	run   func(c *cmdCtx) string
}

func (b *Bot) buildCommands() map[string]*command {
	cmds := []*command{
		{name: "ping", help: "reply with pong", run: func(c *cmdCtx) string {
			return "pong"
		}},
		{name: "id", help: "show my Tox ID", run: func(c *cmdCtx) string {
			return "my tox id: " + b.t.SelfGetAddress()
		}},
		{name: "uptime", help: "how long I've been running", run: func(c *cmdCtx) string {
			return "uptime: " + time.Since(b.started).Round(time.Second).String()
		}},
		{name: "stats", help: "connection + friend stats", run: func(c *cmdCtx) string {
			name := b.t.SelfGetName()
			st, _ := b.t.SelfGetStatusMessage()
			return fmt.Sprintf(
				"name: %s\nstatus: %s\nconnection: %s\nfriends: %d\nuptime: %s",
				name, st, tox.ConnStatusString(b.connSt),
				b.t.SelfGetFriendListSize(), time.Since(b.started).Round(time.Second),
			)
		}},
		{name: "friends", admin: true, help: "list friends (admin)", run: func(c *cmdCtx) string {
			list := b.t.SelfGetFriendList()
			if len(list) == 0 {
				return "no friends"
			}
			var sb strings.Builder
			for _, fn := range list {
				pk, _ := b.t.FriendGetPublicKey(fn)
				st, _ := b.t.FriendGetConnectionStatus(fn)
				fmt.Fprintf(&sb, "#%d %s %s\n", fn, pk, tox.ConnStatusString(st))
			}
			return strings.TrimRight(sb.String(), "\n")
		}},
		{name: "remove", admin: true, help: "remove <friendNumber> (admin)", run: func(c *cmdCtx) string {
			fn, err := strconv.ParseUint(strings.TrimSpace(c.args), 10, 32)
			if err != nil {
				return "usage: /remove <friendNumber>"
			}
			if ok, err := b.t.FriendDelete(uint32(fn)); err != nil || !ok {
				return fmt.Sprintf("remove failed: ok=%v err=%v", ok, err)
			}
			b.save()
			return fmt.Sprintf("removed friend #%d", fn)
		}},
		{name: "say", admin: true, help: "say <friendNumber> <text> (admin)", run: func(c *cmdCtx) string {
			numStr, text := cutWord(strings.TrimSpace(c.args))
			if text == "" {
				return "usage: /say <friendNumber> <text>"
			}
			fn, err := strconv.ParseUint(numStr, 10, 32)
			if err != nil {
				return "usage: /say <friendNumber> <text>"
			}
			if err := b.sendMessage(uint32(fn), text); err != nil {
				return fmt.Sprintf("send to #%d failed: %v", fn, err)
			}
			return "sent"
		}},
		{name: "save", admin: true, help: "persist savedata now (admin)", run: func(c *cmdCtx) string {
			b.save()
			return "saved"
		}},
	}

	m := map[string]*command{}
	for _, c := range cmds {
		m[c.name] = c
	}
	// /help is built from the registry itself.
	m["help"] = &command{name: "help", help: "list commands", run: func(c *cmdCtx) string {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		var sb strings.Builder
		sb.WriteString("commands:\n")
		for _, n := range names {
			cmd := m[n]
			if cmd.admin && !c.isAdmin {
				continue
			}
			tag := ""
			if cmd.admin {
				tag = " *"
			}
			fmt.Fprintf(&sb, "/%s%s — %s\n", cmd.name, tag, cmd.help)
		}
		return strings.TrimRight(sb.String(), "\n")
	}}
	return m
}

// sendMessage delivers msg to a friend, splitting it into chunks that fit
// within toxcore's per-message length limit. Delivery stops at the first
// failing chunk.
func (b *Bot) sendMessage(friend uint32, msg string) error {
	for _, chunk := range chunkMessage(msg, tox.MAX_MESSAGE_LENGTH) {
		if _, err := b.t.FriendSendMessage(friend, chunk); err != nil {
			log.Printf("send to %d failed: %v", friend, err)
			return err
		}
	}
	return nil
}

// chunkMessage splits s into byte-bounded chunks no larger than max, preferring
// to break on a newline or space near the limit so words stay intact. Cuts
// always land on a rune boundary, so no chunk carries a truncated UTF-8
// sequence.
func chunkMessage(s string, max int) []string {
	if max <= 0 {
		max = tox.MAX_MESSAGE_LENGTH
	}
	if len(s) <= max {
		return []string{s}
	}
	var out []string
	for len(s) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		if cut == 0 { // a single rune wider than max: split anyway rather than spin
			cut = max
		}
		// Whitespace is single-byte ASCII, so a break here stays rune-aligned.
		if i := strings.LastIndexAny(s[:cut], "\n "); i > max/2 {
			cut = i + 1
		}
		out = append(out, strings.TrimRight(s[:cut], "\n "))
		s = s[cut:]
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}

// cutWord splits s at the first whitespace, returning the leading word and the
// remainder with its leading whitespace removed. Unlike a plain cut on " " this
// also separates arguments written after a tab or newline.
func cutWord(s string) (word, rest string) {
	i := strings.IndexFunc(s, unicode.IsSpace)
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeftFunc(s[i:], unicode.IsSpace)
}

func (b *Bot) handleMessage(friend uint32, message string, cmds map[string]*command) {
	msg := strings.TrimSpace(message)
	log.Printf("msg from %d: %q", friend, msg)

	if !strings.HasPrefix(msg, "/") {
		_ = b.sendMessage(friend, "echo: "+message)
		return
	}

	word, args := cutWord(strings.TrimPrefix(msg, "/"))
	cmd, ok := cmds[strings.ToLower(word)]
	if !ok {
		_ = b.sendMessage(friend, "unknown command: /"+word+" (try /help)")
		return
	}

	pubKey := ""
	if pk, err := b.t.FriendGetPublicKey(friend); err == nil {
		pubKey = strings.ToUpper(pk)
	}
	isAdmin := pubKey != "" && b.admins[pubKey]

	if cmd.admin && !isAdmin {
		_ = b.sendMessage(friend, "not authorized")
		log.Printf("denied admin command /%s from %d (%s)", cmd.name, friend, pubKey)
		return
	}

	reply := cmd.run(&cmdCtx{
		bot:     b,
		friend:  friend,
		pubKey:  pubKey,
		args:    args,
		isAdmin: isAdmin,
	})
	if reply != "" {
		_ = b.sendMessage(friend, reply)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	dataDir := getenv("TOX_DATA_DIR", "/data")
	saveFile := getenv("TOX_SAVEDATA", filepath.Join(dataDir, "bot.tox"))
	name := getenv("TOX_NAME", defaultName)
	status := getenv("TOX_STATUS", defaultStatus)

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("mkdir data dir: %v", err)
	}
	// TOX_SAVEDATA may point outside TOX_DATA_DIR, in which case every save
	// would fail on a missing parent.
	if dir := filepath.Dir(saveFile); dir != dataDir {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("mkdir savedata dir: %v", err)
		}
	}

	if err := ensureWritable(saveFile); err != nil {
		log.Fatalf("savedata path is not writable: %v", err)
	}

	opts := tox.NewToxOptions()
	applyProxy(opts, os.Getenv("SOCKS5_PROXY"))

	// Load savedata if present (identity / keys)
	savedata, haveSavedata, err := readSavedata(saveFile)
	if err != nil {
		log.Fatalf("savedata %s is unusable: %v -- refusing to start, because "+
			"toxcore would silently generate a new Tox ID and the next save would "+
			"overwrite this file. Fix it, or move it aside to accept a new identity.",
			saveFile, err)
	}
	if haveSavedata {
		opts.Savedata_type = tox.SAVEDATA_TYPE_TOX_SAVE
		opts.Savedata_data = savedata
		log.Printf("loaded savedata: %s (%d bytes)", saveFile, len(savedata))
	} else {
		log.Printf("no savedata at %s; starting with a fresh identity", saveFile)
	}

	t := tox.NewTox(opts)
	if t == nil {
		if haveSavedata {
			log.Fatalf("failed to create tox instance from savedata %s: the file "+
				"may be corrupt; move it aside to start a new identity", saveFile)
		}
		log.Fatal("failed to create tox instance")
	}
	defer t.Kill()

	if err := t.SelfSetName(name); err != nil {
		log.Printf("set name %q failed: %v", name, err)
	}
	if _, err := t.SelfSetStatusMessage(status); err != nil {
		log.Printf("set status %q failed: %v", status, err)
	}

	log.Printf("Tox ID: %s", t.SelfGetAddress())
	log.Printf("Public Key: %s", t.SelfGetPublicKey())

	bot := &Bot{
		t:        t,
		saveFile: saveFile,
		admins:   parseAdmins(os.Getenv("TOX_ADMINS")),
		started:  time.Now(),
		connSt:   tox.CONNECTION_NONE,
	}
	if len(bot.admins) > 0 {
		log.Printf("loaded %d admin(s)", len(bot.admins))
	}
	cmds := bot.buildCommands()

	// Bootstrap nodes
	nodes := parseBootstrapEnv(os.Getenv("TOX_BOOTSTRAP_NODES"))
	if len(nodes) == 0 {
		nodes = defaultBootstrap()
		log.Printf("TOX_BOOTSTRAP_NODES empty; using %d default nodes", len(nodes))
	} else {
		log.Printf("using %d nodes from TOX_BOOTSTRAP_NODES", len(nodes))
	}

	for _, n := range nodes {
		ok, err := t.Bootstrap(n.host, n.port, n.key)
		if err != nil || !ok {
			log.Printf("bootstrap failed %s:%d: ok=%v err=%v", n.host, n.port, ok, err)
		} else {
			log.Printf("bootstrapped %s:%d", n.host, n.port)
		}
	}

	// Log when the bot reaches / leaves the DHT.
	t.CallbackSelfConnectionStatus(func(_ *tox.Tox, status int, _ interface{}) {
		bot.connSt = status
		log.Printf("self connection status: %s", tox.ConnStatusString(status))
	}, nil)

	// Auto-accept friend requests
	t.CallbackFriendRequestAdd(func(_ *tox.Tox, pubKey string, msg string, _ interface{}) {
		log.Printf("friend request from %s msg=%q", pubKey, msg)
		fn, err := t.FriendAddNorequest(pubKey)
		if err != nil {
			log.Printf("accept failed: %v", err)
			return
		}
		log.Printf("friend accepted: #%d", fn)
		// Persist immediately: a restart before the next tick would drop the
		// friendship on our side while the peer still has us listed.
		bot.save()
	}, nil)

	// In v0.2.17 the friend-message callback type does NOT include mtype.
	// So the signature must be: func(*tox.Tox, uint32, string, interface{})
	t.CallbackFriendMessageAdd(func(_ *tox.Tox, friend uint32, message string, _ interface{}) {
		bot.handleMessage(friend, message, cmds)
	}, nil)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	saveTick := time.NewTicker(30 * time.Second)
	defer saveTick.Stop()

	iterTick := time.NewTicker(iterInterval(t.IterationInterval()))
	defer iterTick.Stop()

	log.Println("bot started")

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			bot.save()
			return

		case <-saveTick.C:
			bot.save()

		case <-iterTick.C:
			t.Iterate()
			iterTick.Reset(iterInterval(t.IterationInterval()))
		}
	}
}

// A tox profile starts with a zero uint32 followed by a little-endian magic.
// An encrypted profile — what the desktop clients write by default — starts
// with an ASCII marker instead and cannot be read without a passphrase.
const (
	savedataMagic    = 0x15ED1B1F
	savedataHeadSize = 8
)

var encryptedSavedataMagic = []byte("toxEsave")

// validateSavedata rejects anything that is not a plaintext tox profile.
//
// This check is load-bearing rather than cosmetic: toxcore does not report a
// damaged profile. tox_new quietly ignores it, derives a brand-new random key
// (verified: the same corrupt bytes yield a different public key on each run),
// and the next save overwrites the file — so a recoverable profile is destroyed
// and every existing friend silently sees the bot as a stranger.
func validateSavedata(data []byte) error {
	if bytes.HasPrefix(data, encryptedSavedataMagic) {
		return errors.New("profile is encrypted; this bot cannot read encrypted savedata")
	}
	if len(data) < savedataHeadSize {
		return fmt.Errorf("too short to be a tox profile (%d bytes)", len(data))
	}
	if leading := binary.LittleEndian.Uint32(data[:4]); leading != 0 {
		return fmt.Errorf("not a tox profile (leading word %#08x, want 0)", leading)
	}
	if magic := binary.LittleEndian.Uint32(data[4:savedataHeadSize]); magic != savedataMagic {
		return fmt.Errorf("not a tox profile (magic %#08x, want %#08x)", magic, uint32(savedataMagic))
	}
	return nil
}

// readSavedata loads the stored profile. A missing or empty file means "start
// fresh"; an unreadable or damaged one is an error rather than a silent fresh
// start, because either would abandon the identity the file exists to preserve.
func readSavedata(path string) (data []byte, found bool, err error) {
	data, err = os.ReadFile(path)
	switch {
	case err == nil && len(data) > 0:
		if err := validateSavedata(data); err != nil {
			return nil, false, err
		}
		return data, true, nil
	case err == nil, errors.Is(err, os.ErrNotExist):
		return nil, false, nil
	default:
		return nil, false, err
	}
}

// ensureWritable checks the savedata path can be written before the bot commits
// to an identity, so a read-only volume fails at startup instead of silently
// dropping every save until the profile is lost on restart.
func ensureWritable(path string) error {
	probe := path + ".probe"
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(probe)
}

// writeFileSync writes data to path and flushes it to stable storage. The fsync
// is what makes the rename in save() atomic against power loss and not merely
// against a process crash: without it the new name can survive pointing at a
// truncated file.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// syncDir flushes a directory entry so a completed rename survives power loss.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}

// save atomically writes the current savedata to disk. Empty savedata is a
// no-op: it would clobber a good profile, and GetSavedata itself panics on a
// zero-length buffer.
func (b *Bot) save() {
	if b.t.GetSavedataSize() <= 0 {
		log.Printf("save skipped: empty savedata")
		return
	}
	data := b.t.GetSavedata()
	tmp := b.saveFile + ".tmp"

	if err := writeFileSync(tmp, data, 0o600); err != nil {
		_ = os.Remove(tmp)
		log.Printf("save failed: %v", err)
		return
	}
	if err := os.Rename(tmp, b.saveFile); err != nil {
		_ = os.Remove(tmp)
		log.Printf("save rename failed: %v", err)
		return
	}
	syncDir(filepath.Dir(b.saveFile))
	log.Printf("saved: %s (%d bytes)", b.saveFile, len(data))
}

// iterInterval turns toxcore's advisory poll interval into a duration a
// time.Ticker will accept; the C API is free to report 0.
func iterInterval(ms int) time.Duration {
	if ms <= 0 {
		return time.Millisecond
	}
	return time.Duration(ms) * time.Millisecond
}
