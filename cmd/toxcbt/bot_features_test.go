package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tox "github.com/TokTok/go-toxcore-c"
)

// newFullBot returns a bot wired up the way main() wires one: a state sidecar,
// an audit log, and a fixed clock. Friend #1 (keyA) is online; friend #2
// (keyB) exists but is offline.
// keyStranger is a well-formed public key belonging to nobody the bot knows.
const keyStranger = "B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506"

func newFullBot(t *testing.T, admin bool) (*Bot, *fakeTox, map[string]*command) {
	t.Helper()
	dir := t.TempDir()

	ft := newFakeTox()
	ft.friends = []uint32{1, 2}
	ft.pubKeys[1] = keyA
	ft.pubKeys[2] = keyB
	ft.connStatus[1] = tox.CONNECTION_UDP
	ft.connStatus[2] = tox.CONNECTION_NONE

	state, err := loadState(filepath.Join(dir, "state.json"), 10, time.Hour)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	audit, err := openAudit(filepath.Join(dir, "audit.log"), 1<<20)
	if err != nil {
		t.Fatalf("openAudit: %v", err)
	}
	t.Cleanup(func() { audit.close() })

	admins := map[string]bool{}
	if admin {
		admins[keyA] = true
	}
	b := &Bot{
		t:        ft,
		saveFile: filepath.Join(dir, "bot.tox"),
		admins:   admins,
		started:  time.Unix(1700000000, 0).Add(-time.Minute),
		connSt:   tox.CONNECTION_UDP,
		state:    state,
		audit:    audit,
		policy:   friendPolicy{mode: policyOpen},
		version:  "v-test",
		pending:  map[receiptKey]pendingReceipt{},
		now:      func() time.Time { return time.Unix(1700000000, 0) },
	}
	return b, ft, b.buildCommands()
}

func TestDeliverQueuesForOfflineFriend(t *testing.T) {
	b, ft, _ := newFullBot(t, true)

	res, err := b.deliver(2, "are you there")

	if err != nil || !res.queued {
		t.Fatalf("deliver = %+v, err = %v; want it queued", res, err)
	}
	if len(ft.sent) != 0 {
		t.Errorf("sent %v to an offline friend", ft.texts())
	}
	if b.state.queued() != 1 {
		t.Errorf("queued = %d, want 1", b.state.queued())
	}
}

func TestDeliverSendsToOnlineFriend(t *testing.T) {
	b, ft, _ := newFullBot(t, true)

	res, err := b.deliver(1, "hello")

	if err != nil || res.queued {
		t.Fatalf("deliver = %+v, err = %v; want a direct send", res, err)
	}
	if len(ft.sent) != 1 || ft.sent[0].text != "hello" {
		t.Errorf("sent = %v", ft.texts())
	}
	if b.state.queued() != 0 {
		t.Error("an online delivery should not queue anything")
	}
}

// The status can go stale between the check and the call, so a failed send is
// queued rather than lost.
func TestDeliverQueuesWhenTheSendFails(t *testing.T) {
	b, ft, _ := newFullBot(t, true)
	ft.sendErr = errors.New("friend not connected")

	res, err := b.deliver(1, "hello")

	if err != nil || !res.queued {
		t.Fatalf("deliver = %+v, err = %v; want it queued after the failure", res, err)
	}
	if b.state.queued() != 1 {
		t.Errorf("queued = %d, want 1", b.state.queued())
	}
}

// Without an outbox the error must still reach the caller.
func TestDeliverWithoutStateReportsTheError(t *testing.T) {
	b, ft, _ := newTestBot(t, true)
	ft.sendErr = errors.New("boom")

	if _, err := b.deliver(1, "hi"); err == nil {
		t.Error("deliver swallowed the send error")
	}
}

// A status lookup that fails says nothing useful; try the send anyway.
func TestDeliverAttemptsSendWhenStatusIsUnknown(t *testing.T) {
	b, ft, _ := newFullBot(t, true)
	delete(ft.connStatus, 1)

	if _, err := b.deliver(1, "hello"); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(ft.sent) != 1 {
		t.Errorf("sent = %v, want the message attempted", ft.texts())
	}
}

func TestOutboxFlushesWhenAFriendComesOnline(t *testing.T) {
	b, ft, _ := newFullBot(t, true)
	b.deliver(2, "first")
	b.deliver(2, "second")

	ft.connStatus[2] = tox.CONNECTION_TCP
	b.onFriendConnectionStatus(2, tox.CONNECTION_TCP)

	texts := ft.texts()
	if len(texts) != 2 {
		t.Fatalf("sent %v, want both queued messages", texts)
	}
	if !strings.Contains(texts[0], "first") || !strings.Contains(texts[1], "second") {
		t.Errorf("queued messages arrived out of order: %v", texts)
	}
	if !strings.HasPrefix(texts[0], "[queued ") {
		t.Errorf("a delayed message should say when it was queued: %q", texts[0])
	}
	if b.state.queued() != 0 {
		t.Errorf("queued = %d after a flush, want 0", b.state.queued())
	}
}

func TestOutboxFlushStopsAndRequeuesOnFailure(t *testing.T) {
	b, ft, _ := newFullBot(t, true)
	b.deliver(2, "first")
	b.deliver(2, "second")
	ft.sendErr = errors.New("gone again")

	ft.connStatus[2] = tox.CONNECTION_TCP
	b.onFriendConnectionStatus(2, tox.CONNECTION_TCP)

	if b.state.queued() != 2 {
		t.Errorf("queued = %d, want both messages put back", b.state.queued())
	}
}

func TestGoingOfflineDoesNotFlush(t *testing.T) {
	b, ft, _ := newFullBot(t, true)
	b.deliver(2, "later")

	b.onFriendConnectionStatus(2, tox.CONNECTION_NONE)

	if len(ft.sent) != 0 {
		t.Errorf("sent %v to a friend that just went offline", ft.texts())
	}
}

func TestSayConfirmsDeliveryOnReadReceipt(t *testing.T) {
	b, ft, cmds := newFullBot(t, true)

	reply := cmds["say"].run(&cmdCtx{bot: b, friend: 1, isAdmin: true, args: "1 hello there"})
	if reply != "sent" {
		t.Fatalf("reply = %q, want \"sent\"", reply)
	}
	if len(b.pending) != 1 {
		t.Fatalf("pending = %v, want the receipt tracked", b.pending)
	}

	// toxcore reports the id returned by the send.
	b.onReadReceipt(1, ft.sent[len(ft.sent)-1].id)

	texts := ft.texts()
	if len(texts) != 2 || !strings.Contains(texts[1], "delivered") {
		t.Errorf("sent = %v, want a delivery confirmation", texts)
	}
	if len(b.pending) != 0 {
		t.Error("a confirmed message should stop being tracked")
	}
}

func TestSayToAnOfflineFriendQueuesInsteadOfClaimingSuccess(t *testing.T) {
	b, _, cmds := newFullBot(t, true)

	reply := cmds["say"].run(&cmdCtx{bot: b, friend: 1, isAdmin: true, args: "2 you are away"})

	if !strings.Contains(reply, "queued") {
		t.Errorf("reply = %q, want it to say the message was queued", reply)
	}
	if len(b.pending) != 0 {
		t.Error("nothing was sent, so nothing should be awaiting a receipt")
	}
}

func TestUnknownReceiptIsIgnored(t *testing.T) {
	b, ft, _ := newFullBot(t, true)

	b.onReadReceipt(1, 12345) // an echo reply nobody asked to be notified about

	if len(ft.sent) != 0 {
		t.Errorf("sent %v for an untracked receipt", ft.texts())
	}
	if b.metrics.delivered != 1 {
		t.Errorf("delivered = %d, want the receipt still counted", b.metrics.delivered)
	}
}

func TestPendingReceiptsExpire(t *testing.T) {
	b, _, _ := newFullBot(t, true)
	b.trackReceipt(1, 7, 1, "#1")

	b.expirePending(time.Unix(1700000000, 0).Add(time.Hour), 10*time.Minute)

	if len(b.pending) != 0 {
		t.Error("a confirmation that never arrived should be forgotten")
	}
}

func TestRateLimitedMessagesAreDroppedWithOneNotice(t *testing.T) {
	b, ft, cmds := newFullBot(t, false)
	b.limiter = newRateLimiter(1, 1)

	for i := 0; i < 5; i++ {
		b.handleMessage(1, "hello", cmds)
	}

	texts := ft.texts()
	if len(texts) != 2 {
		t.Fatalf("sent %v, want the first echo plus one notice", texts)
	}
	if texts[0] != "echo: hello" || !strings.Contains(texts[1], "too quickly") {
		t.Errorf("sent = %v", texts)
	}
	if b.metrics.rateLimited != 4 {
		t.Errorf("rateLimited = %d, want 4", b.metrics.rateLimited)
	}
}

func TestAdminsAreExemptFromTheRateLimiter(t *testing.T) {
	b, ft, cmds := newFullBot(t, true)
	b.limiter = newRateLimiter(1, 1)

	for i := 0; i < 5; i++ {
		b.handleMessage(1, "/ping", cmds)
	}

	if len(ft.texts()) != 5 {
		t.Errorf("sent %v, want every admin command answered", ft.texts())
	}
}

func TestBlockedPeersAreIgnoredEntirely(t *testing.T) {
	b, ft, cmds := newFullBot(t, false)
	b.state.block(keyA)

	b.handleMessage(1, "/ping", cmds)

	if len(ft.sent) != 0 {
		t.Errorf("replied %v to a blocked peer", ft.texts())
	}
}

func TestRuntimeAdminsGetPrivileges(t *testing.T) {
	b, _, cmds := newFullBot(t, false)

	if reply := cmds["ping"].run(&cmdCtx{bot: b}); reply != "pong" {
		t.Fatal("sanity check failed")
	}
	if b.isAdminKey(keyA) {
		t.Fatal("keyA should not be an admin yet")
	}

	b.state.addAdmin(keyA)

	if !b.isAdminKey(keyA) {
		t.Error("an admin added at runtime should be privileged")
	}
	if b.isAdminKey("") {
		t.Error("an unknown public key must never be an admin")
	}
}

func TestReplyChunksAreCapped(t *testing.T) {
	b, ft, _ := newFullBot(t, true)
	b.maxReplyChunks = 2

	// Three chunks' worth of text, on word boundaries.
	long := strings.TrimSpace(strings.Repeat(strings.Repeat("a", 100)+" ", 40))
	if err := b.sendMessage(1, long); err != nil {
		t.Fatalf("sendMessage: %v", err)
	}

	texts := ft.texts()
	if len(texts) != 3 {
		t.Fatalf("sent %d messages, want 2 chunks plus a notice", len(texts))
	}
	if !strings.Contains(texts[2], "truncated") {
		t.Errorf("last message = %q, want a truncation notice", texts[2])
	}
}

func TestFriendRequestAcceptedUnderTheOpenPolicy(t *testing.T) {
	b, ft, _ := newFullBot(t, true)

	b.onFriendRequest(strings.ToLower(keyStranger), "hi")

	if len(ft.added) != 1 || ft.added[0] != keyStranger {
		t.Errorf("added = %v, want the normalized stranger key", ft.added)
	}
	if b.metrics.requestsOK != 1 {
		t.Errorf("requestsOK = %d", b.metrics.requestsOK)
	}
}

func TestFriendRequestRejectedByPolicy(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(b *Bot)
		key    string
		msg    string
		reason string
	}{
		{
			name:   "closed",
			setup:  func(b *Bot) { b.policy = friendPolicy{mode: policyClosed} },
			key:    keyStranger,
			reason: "closed",
		},
		{
			name:   "blocked",
			setup:  func(b *Bot) { b.state.block(keyStranger) },
			key:    keyStranger,
			reason: "blocked",
		},
		{
			name: "friend limit",
			setup: func(b *Bot) {
				b.policy = friendPolicy{mode: policyOpen, maxFriends: 2}
			},
			key:    keyStranger,
			reason: "limit",
		},
		{
			name: "wrong secret",
			setup: func(b *Bot) {
				b.policy = friendPolicy{mode: policySecret, secret: "swordfish"}
			},
			key:    keyStranger,
			msg:    "let me in",
			reason: "secret",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, ft, _ := newFullBot(t, true)
			tc.setup(b)

			b.onFriendRequest(tc.key, tc.msg)

			if len(ft.added) != 0 {
				t.Errorf("accepted %v despite the policy", ft.added)
			}
			if b.metrics.requestsNo != 1 {
				t.Errorf("requestsNo = %d, want 1", b.metrics.requestsNo)
			}
			lines, err := b.audit.tail(10)
			if err != nil {
				t.Fatalf("audit tail: %v", err)
			}
			if len(lines) != 1 || !strings.Contains(lines[0], "DENIED") ||
				!strings.Contains(lines[0], tc.reason) {
				t.Errorf("audit = %v, want a denial mentioning %q", lines, tc.reason)
			}
		})
	}
}

func TestFriendRequestWithSecretAccepted(t *testing.T) {
	b, ft, _ := newFullBot(t, true)
	b.policy = friendPolicy{mode: policySecret, secret: "swordfish"}

	b.onFriendRequest(keyStranger, "hello, swordfish, please let me in")

	if len(ft.added) != 1 {
		t.Errorf("added = %v, want the request accepted", ft.added)
	}
}

// The binding hands the key straight to C, which reads a fixed 32 bytes.
func TestFriendRequestWithAnUnusableKeyIsDropped(t *testing.T) {
	b, ft, _ := newFullBot(t, true)

	b.onFriendRequest("not-a-key", "hi")

	if len(ft.added) != 0 {
		t.Errorf("added = %v, want nothing to reach the binding", ft.added)
	}
}

func TestAdminCommandsAreAudited(t *testing.T) {
	b, _, cmds := newFullBot(t, true)

	b.handleMessage(1, "/save", cmds)
	b.handleMessage(1, "/ping", cmds)

	lines, err := b.audit.tail(10)
	if err != nil {
		t.Fatalf("audit tail: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("audit = %v, want only the admin command recorded", lines)
	}
	if !strings.Contains(lines[0], "/save") || !strings.Contains(lines[0], "ok") {
		t.Errorf("audit line = %q", lines[0])
	}
}

func TestDeniedAdminCommandIsAudited(t *testing.T) {
	b, _, cmds := newFullBot(t, false)

	b.handleMessage(1, "/save", cmds)

	lines, _ := b.audit.tail(10)
	if len(lines) != 1 || !strings.Contains(lines[0], "DENIED") {
		t.Errorf("audit = %v, want the denial recorded", lines)
	}
}

func TestSnapshotReportsRuntimeState(t *testing.T) {
	b, _, _ := newFullBot(t, true)
	b.deliver(2, "queued")
	b.metrics.messagesIn = 4

	snap := b.snapshot()

	if snap.Friends != 2 || snap.FriendsOnline != 1 {
		t.Errorf("friends = %d (%d online), want 2 (1)", snap.Friends, snap.FriendsOnline)
	}
	if !snap.Online || snap.Connection != "CONNECTION_UDP" {
		t.Errorf("connection = %q online = %v", snap.Connection, snap.Online)
	}
	if snap.Queued != 1 || snap.MessagesIn != 4 || snap.Version != "v-test" {
		t.Errorf("snapshot = %+v", snap)
	}
	if snap.UptimeSeconds != 60 {
		t.Errorf("uptime = %v, want 60", snap.UptimeSeconds)
	}
}

func TestMaintenancePrunesQueuesAndBuckets(t *testing.T) {
	b, _, _ := newFullBot(t, true)
	b.limiter = newRateLimiter(1, 60)
	b.state.enqueue(keyB, "ancient", time.Unix(1700000000, 0).Add(-48*time.Hour))
	b.limiter.allow(keyA, time.Unix(1700000000, 0).Add(-time.Hour))
	b.trackReceipt(1, 1, 1, "#1")
	b.pending[receiptKey{friend: 1, receipt: 1}] = pendingReceipt{at: time.Unix(1700000000, 0).Add(-time.Hour)}

	b.maintenance()

	if b.state.queued() != 0 {
		t.Errorf("queued = %d, want the expired message dropped", b.state.queued())
	}
	if b.limiter.tracked() != 0 {
		t.Errorf("tracked = %d, want the idle bucket forgotten", b.limiter.tracked())
	}
	if len(b.pending) != 0 {
		t.Errorf("pending = %v, want the stale receipt dropped", b.pending)
	}
}
