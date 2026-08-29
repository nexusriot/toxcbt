package main

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	tox "github.com/TokTok/go-toxcore-c"
)

// toxClient is the slice of *tox.Tox the bot actually uses. Depending on the
// interface rather than the concrete type keeps the command layer exercisable
// without a live toxcore instance.
type toxClient interface {
	SelfGetAddress() string
	SelfGetName() string
	SelfGetStatusMessage() (string, error)
	SelfGetFriendList() []uint32
	SelfGetFriendListSize() uint32
	SelfGetNospam() uint32
	SelfSetNospam(nospam uint32)
	FriendGetPublicKey(friendNumber uint32) (string, error)
	FriendGetConnectionStatus(friendNumber uint32) (int, error)
	FriendDelete(friendNumber uint32) (bool, error)
	FriendAddNorequest(friendId string) (uint32, error)
	FriendSendMessage(friendNumber uint32, message string) (uint32, error)
	GetSavedataSize() int32
	GetSavedata() []byte
}

// botMetrics are plain counters: everything that touches them runs on the
// event-loop goroutine, so no atomics are needed. They leave that goroutine
// only inside a healthSnapshot.
type botMetrics struct {
	messagesIn  uint64
	messagesOut uint64
	commands    uint64
	rateLimited uint64
	delivered   uint64
	requestsOK  uint64
	requestsNo  uint64
	saveErrors  uint64
}

// receiptKey identifies one outstanding message. Receipt numbers are only
// unique per friend, so the friend number is part of the key.
type receiptKey struct {
	friend  uint32
	receipt uint32
}

// pendingReceipt remembers who asked for a message to be sent, so the delivery
// confirmation can be reported back to them.
type pendingReceipt struct {
	requester uint32
	label     string
	at        time.Time
}

// Bot holds shared runtime state for command handlers.
type Bot struct {
	t        toxClient
	saveFile string
	admins   map[string]bool // admins from the environment; permanent
	started  time.Time
	connSt   int // last known self connection status

	cipher  *profileCipher
	state   *botState
	audit   *auditLog
	limiter *rateLimiter
	policy  friendPolicy

	maxReplyChunks int
	logMessages    bool
	version        string

	metrics  botMetrics
	pending  map[receiptKey]pendingReceipt
	lastSave time.Time

	// now overrides the clock in tests.
	now func() time.Time
}

func (b *Bot) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

// friendKey resolves a friend number to its public key, uppercased. An empty
// result means toxcore does not know the friend, and is never treated as a
// match for anything.
func (b *Bot) friendKey(friend uint32) string {
	pk, err := b.t.FriendGetPublicKey(friend)
	if err != nil {
		return ""
	}
	return strings.ToUpper(pk)
}

// isAdminKey reports whether a public key is privileged, from either the
// environment allowlist or the runtime one in the state sidecar.
func (b *Bot) isAdminKey(pubKey string) bool {
	if pubKey == "" {
		return false
	}
	return b.admins[pubKey] || b.state.isAdmin(pubKey)
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

// deliverResult reports what happened to a message handed to deliver.
type deliverResult struct {
	queued bool   // stored in the outbox instead of sent
	id     uint32 // receipt id of the last chunk, when sent
}

// deliver sends a message, or queues it when the friend is offline.
//
// toxcore does not hold messages for absent friends — it rejects the send with
// FRIEND_NOT_CONNECTED — so without an outbox every /say and /broadcast
// silently reaches only whoever happens to be online at that instant.
func (b *Bot) deliver(friend uint32, text string) (deliverResult, error) {
	// Only an explicit "offline" queues. A status lookup that fails says
	// nothing useful, and refusing to try would be worse than trying.
	if st, err := b.t.FriendGetConnectionStatus(friend); err == nil && st == tox.CONNECTION_NONE {
		if pk := b.friendKey(friend); pk != "" && b.state.enqueue(pk, text, b.clock()) {
			slog.Info("message queued for offline friend", "friend", friend, "key", shortKey(pk))
			return deliverResult{queued: true}, nil
		}
	}

	id, err := b.sendChunks(friend, text)
	if err == nil {
		return deliverResult{id: id}, nil
	}
	// A send can also fail because the friend went offline between the status
	// check and the call; queue rather than lose the message.
	if pk := b.friendKey(friend); pk != "" && b.state.enqueue(pk, text, b.clock()) {
		slog.Warn("send failed; message queued", "friend", friend, "key", shortKey(pk), "err", err)
		return deliverResult{queued: true}, nil
	}
	return deliverResult{}, err
}

// sendMessage delivers msg to a friend, splitting it into chunks that fit
// within toxcore's per-message length limit. Delivery stops at the first
// failing chunk.
func (b *Bot) sendMessage(friend uint32, msg string) error {
	_, err := b.sendChunks(friend, msg)
	return err
}

// sendChunks is sendMessage plus the receipt id of the final chunk, which is
// what a delivery confirmation has to wait for.
func (b *Bot) sendChunks(friend uint32, msg string) (uint32, error) {
	chunks := chunkMessage(msg, tox.MAX_MESSAGE_LENGTH)

	// An unbounded reply is an amplification lever: one short message from a
	// peer must not turn into hundreds of outbound ones.
	dropped := 0
	if b.maxReplyChunks > 0 && len(chunks) > b.maxReplyChunks {
		dropped = len(chunks) - b.maxReplyChunks
		chunks = chunks[:b.maxReplyChunks]
	}

	var last uint32
	for _, chunk := range chunks {
		id, err := b.t.FriendSendMessage(friend, chunk)
		if err != nil {
			slog.Warn("send failed", "friend", friend, "err", err)
			return 0, err
		}
		b.metrics.messagesOut++
		last = id
	}
	if dropped > 0 {
		notice := fmt.Sprintf("[truncated: %d more chunk(s) dropped]", dropped)
		if id, err := b.t.FriendSendMessage(friend, notice); err == nil {
			b.metrics.messagesOut++
			last = id
		}
	}
	return last, nil
}

// trackReceipt remembers that requester wants to know when a message arrives.
func (b *Bot) trackReceipt(friend uint32, id uint32, requester uint32, label string) {
	if b.pending == nil {
		b.pending = map[receiptKey]pendingReceipt{}
	}
	b.pending[receiptKey{friend: friend, receipt: id}] = pendingReceipt{
		requester: requester,
		label:     label,
		at:        b.clock(),
	}
}

// onReadReceipt turns toxcore's delivery confirmation into a reply to whoever
// asked for the message to be sent.
func (b *Bot) onReadReceipt(friend uint32, receipt uint32) {
	b.metrics.delivered++
	key := receiptKey{friend: friend, receipt: receipt}
	p, ok := b.pending[key]
	if !ok {
		return
	}
	delete(b.pending, key)
	_ = b.sendMessage(p.requester, "delivered: "+p.label)
}

// expirePending drops confirmations that never arrived, so a friend that
// vanishes mid-send cannot grow the map forever.
func (b *Bot) expirePending(now time.Time, ttl time.Duration) {
	for key, p := range b.pending {
		if now.Sub(p.at) > ttl {
			delete(b.pending, key)
		}
	}
}

// onFriendConnectionStatus logs presence changes and flushes anything queued
// for a friend that just came back.
func (b *Bot) onFriendConnectionStatus(friend uint32, status int) {
	pubKey := b.friendKey(friend)
	slog.Info("friend connection status",
		"friend", friend, "key", shortKey(pubKey), "status", tox.ConnStatusString(status))
	if status == tox.CONNECTION_NONE || pubKey == "" {
		return
	}
	if sent := b.flushOutbox(friend, pubKey); sent > 0 {
		slog.Info("flushed queued messages", "friend", friend, "key", shortKey(pubKey), "count", sent)
	}
}

// flushOutbox sends everything queued for a friend, oldest first, stopping at
// the first failure and putting the remainder back.
func (b *Bot) flushOutbox(friend uint32, pubKey string) int {
	items := b.state.takeQueue(pubKey)
	sent := 0
	for i, item := range items {
		text := fmt.Sprintf("[queued %s] %s", item.Queued.UTC().Format(time.RFC3339), item.Text)
		if err := b.sendMessage(friend, text); err != nil {
			b.state.requeue(pubKey, items[i:])
			return sent
		}
		sent++
	}
	return sent
}

// onFriendRequest applies the friend policy and accepts what it allows.
func (b *Bot) onFriendRequest(pubKey, message string) {
	pk, err := normalizePubKey(pubKey)
	if err != nil {
		// The binding hands this straight to C, which reads a fixed 32 bytes.
		slog.Warn("friend request with an unusable public key", "key", pubKey, "err", err)
		return
	}

	ok, reason := b.policy.accepts(pk, message, int(b.t.SelfGetFriendListSize()), b.state.isBlocked(pk))
	if !ok {
		b.metrics.requestsNo++
		slog.Warn("friend request rejected", "key", shortKey(pk), "reason", reason,
			messageAttr(message, b.logMessages))
		b.recordAudit(auditEvent{Actor: pk, Command: "friend-request", Allowed: false, Result: reason})
		return
	}

	fn, err := b.t.FriendAddNorequest(pk)
	if err != nil {
		slog.Error("friend request accept failed", "key", shortKey(pk), "err", err)
		return
	}
	b.metrics.requestsOK++
	slog.Info("friend accepted", "friend", fn, "key", shortKey(pk), "reason", reason)
	b.recordAudit(auditEvent{Actor: pk, Friend: fn, Command: "friend-request", Allowed: true, Result: reason})
	// Persist immediately: a restart before the next tick would drop the
	// friendship on our side while the peer still has us listed.
	b.save()
}

// recordAudit appends to the audit trail, filling in the timestamp.
func (b *Bot) recordAudit(ev auditEvent) {
	if b.audit == nil {
		return
	}
	ev.Time = b.clock()
	if err := b.audit.record(ev); err != nil {
		slog.Error("audit write failed", "err", err)
	}
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
	b.metrics.messagesIn++

	pubKey := b.friendKey(friend)
	isAdmin := b.isAdminKey(pubKey)

	// A blocked peer is ignored entirely: no reply, so the bot is not a
	// convenient way to confirm it is still here.
	if b.state.isBlocked(pubKey) {
		slog.Debug("message from a blocked peer ignored", "friend", friend, "key", shortKey(pubKey))
		return
	}

	// Admins are exempt: the limiter exists to blunt floods from strangers,
	// and locking the operator out mid-incident would be the wrong trade.
	if !isAdmin {
		key := pubKey
		if key == "" {
			key = fmt.Sprintf("#%d", friend)
		}
		if allowed, notify := b.limiter.allow(key, b.clock()); !allowed {
			b.metrics.rateLimited++
			slog.Warn("rate limited", "friend", friend, "key", shortKey(pubKey))
			if notify {
				_ = b.sendMessage(friend, "you are sending messages too quickly; slow down")
			}
			return
		}
	}

	slog.Info("friend message", "friend", friend, "key", shortKey(pubKey),
		messageAttr(msg, b.logMessages))

	if !strings.HasPrefix(msg, "/") {
		_, _ = b.deliver(friend, "echo: "+message)
		return
	}

	word, args := cutWord(strings.TrimPrefix(msg, "/"))
	cmd, ok := cmds[strings.ToLower(word)]
	if !ok {
		_, _ = b.deliver(friend, "unknown command: /"+word+" (try /help)")
		return
	}

	if cmd.admin && !isAdmin {
		_, _ = b.deliver(friend, "not authorized")
		slog.Warn("admin command denied", "command", cmd.name, "friend", friend, "key", shortKey(pubKey))
		b.recordAudit(auditEvent{Actor: pubKey, Friend: friend, Command: cmd.name, Args: args, Allowed: false,
			Result: "not an admin"})
		return
	}

	b.metrics.commands++
	reply := cmd.run(&cmdCtx{
		bot:     b,
		friend:  friend,
		pubKey:  pubKey,
		args:    args,
		isAdmin: isAdmin,
	})
	if cmd.admin {
		b.recordAudit(auditEvent{Actor: pubKey, Friend: friend, Command: cmd.name, Args: args, Allowed: true,
			Result: firstLine(reply)})
	}
	if reply != "" {
		_, _ = b.deliver(friend, reply)
	}
}

// firstLine keeps an audit result to one readable line.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " …"
	}
	return s
}

// maintenance is the periodic housekeeping the event loop drives: expiring
// queued messages and confirmations, and forgetting idle rate-limit buckets.
func (b *Bot) maintenance() {
	now := b.clock()
	if dropped := b.state.pruneOutbox(now); dropped > 0 {
		slog.Info("dropped expired queued messages", "count", dropped)
	}
	b.limiter.prune(now, 10*time.Minute)
	b.expirePending(now, 10*time.Minute)
}

// snapshot copies the state the health endpoints report. It runs on the event
// loop, which is the only goroutine allowed to touch toxcore.
func (b *Bot) snapshot() healthSnapshot {
	friends := b.t.SelfGetFriendList()
	online := 0
	for _, fn := range friends {
		if st, err := b.t.FriendGetConnectionStatus(fn); err == nil && st != tox.CONNECTION_NONE {
			online++
		}
	}
	var lastSave int64
	if !b.lastSave.IsZero() {
		lastSave = b.lastSave.Unix()
	}
	return healthSnapshot{
		Version:       b.version,
		ToxID:         b.t.SelfGetAddress(),
		Connection:    tox.ConnStatusString(b.connSt),
		Online:        b.connSt != tox.CONNECTION_NONE,
		Friends:       len(friends),
		FriendsOnline: online,
		UptimeSeconds: b.clock().Sub(b.started).Seconds(),
		MessagesIn:    b.metrics.messagesIn,
		MessagesOut:   b.metrics.messagesOut,
		Commands:      b.metrics.commands,
		RateLimited:   b.metrics.rateLimited,
		Queued:        b.state.queued(),
		Delivered:     b.metrics.delivered,
		RequestsOK:    b.metrics.requestsOK,
		RequestsNo:    b.metrics.requestsNo,
		SaveErrors:    b.metrics.saveErrors,
		LastSaveUnix:  lastSave,
	}
}
