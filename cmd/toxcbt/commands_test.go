package main

import (
	"strings"
	"testing"

	tox "github.com/TokTok/go-toxcore-c"
)

func adminCtx(b *Bot) *cmdCtx {
	return &cmdCtx{bot: b, friend: 1, pubKey: keyA, isAdmin: true}
}

func runCmd(t *testing.T, cmds map[string]*command, name string, c *cmdCtx, args string) string {
	t.Helper()
	cmd, ok := cmds[name]
	if !ok {
		t.Fatalf("no such command: /%s", name)
	}
	c.args = args
	return cmd.run(c)
}

func TestVersionCommand(t *testing.T) {
	b, _, cmds := newFullBot(t, false)
	if reply := runCmd(t, cmds, "version", &cmdCtx{bot: b}, ""); !strings.Contains(reply, "v-test") {
		t.Errorf("reply = %q", reply)
	}
}

func TestWhoamiReportsKeyAndRole(t *testing.T) {
	b, _, cmds := newFullBot(t, true)

	user := runCmd(t, cmds, "whoami", &cmdCtx{bot: b, friend: 4, pubKey: keyB}, "")
	if !strings.Contains(user, keyB) || !strings.Contains(user, "user") || !strings.Contains(user, "#4") {
		t.Errorf("reply = %q", user)
	}
	admin := runCmd(t, cmds, "whoami", adminCtx(b), "")
	if !strings.Contains(admin, "admin") {
		t.Errorf("reply = %q, want the admin role", admin)
	}
}

func TestBroadcastReachesEveryFriendButTheSender(t *testing.T) {
	b, ft, cmds := newFullBot(t, true)

	reply := runCmd(t, cmds, "broadcast", adminCtx(b), "maintenance in 5 minutes")

	if !strings.Contains(reply, "sent 0") && !strings.Contains(reply, "sent") {
		t.Errorf("reply = %q", reply)
	}
	// Friend #1 is the sender, friend #2 is offline: nothing sent, one queued.
	if len(ft.sent) != 0 {
		t.Errorf("sent = %v, want the sender skipped", ft.texts())
	}
	if b.state.queued() != 1 {
		t.Errorf("queued = %d, want the offline friend's copy", b.state.queued())
	}
	if !strings.Contains(reply, "queued 1") {
		t.Errorf("reply = %q, want it to report the queued copy", reply)
	}

	// And an online third friend gets it immediately, prefixed.
	ft.friends = append(ft.friends, 3)
	ft.pubKeys[3] = keyStranger
	ft.connStatus[3] = tox.CONNECTION_UDP
	runCmd(t, cmds, "broadcast", adminCtx(b), "hello")
	if len(ft.sent) != 1 || !strings.HasPrefix(ft.sent[0].text, "[broadcast] ") {
		t.Errorf("sent = %v, want one prefixed broadcast", ft.texts())
	}
}

func TestBroadcastRequiresText(t *testing.T) {
	b, _, cmds := newFullBot(t, true)
	if reply := runCmd(t, cmds, "broadcast", adminCtx(b), "   "); !strings.HasPrefix(reply, "usage:") {
		t.Errorf("reply = %q, want usage", reply)
	}
}

func TestNospamRotatesAndReportsTheNewID(t *testing.T) {
	b, ft, cmds := newFullBot(t, true)
	ft.savedata = toxProfile('x')

	reply := runCmd(t, cmds, "nospam", adminCtx(b), "DEADBEEF")

	if ft.nospam != 0xDEADBEEF {
		t.Errorf("nospam = %08X, want DEADBEEF", ft.nospam)
	}
	if !strings.Contains(reply, "DEADBEEF") || !strings.Contains(reply, ft.address) {
		t.Errorf("reply = %q, want the new nospam and Tox ID", reply)
	}
}

func TestNospamWithoutAnArgumentPicksARandomValue(t *testing.T) {
	b, ft, cmds := newFullBot(t, true)
	ft.savedata = toxProfile('x')

	if reply := runCmd(t, cmds, "nospam", adminCtx(b), ""); !strings.Contains(reply, "nospam set to") {
		t.Errorf("reply = %q", reply)
	}
	if ft.nospam == 0 {
		t.Error("nospam was not changed")
	}
}

func TestNospamRejectsGarbage(t *testing.T) {
	b, ft, cmds := newFullBot(t, true)
	if reply := runCmd(t, cmds, "nospam", adminCtx(b), "zzz"); !strings.HasPrefix(reply, "usage:") {
		t.Errorf("reply = %q, want usage", reply)
	}
	if ft.nospam != 0 {
		t.Error("a malformed argument changed the nospam anyway")
	}
}

func TestAdminCommandListsAddsAndRemoves(t *testing.T) {
	b, _, cmds := newFullBot(t, true)

	if reply := runCmd(t, cmds, "admin", adminCtx(b), ""); !strings.Contains(reply, keyA+" (env)") {
		t.Errorf("list = %q, want the environment admin", reply)
	}

	if reply := runCmd(t, cmds, "admin", adminCtx(b), "add #2"); !strings.Contains(reply, keyB) {
		t.Errorf("add by friend number = %q", reply)
	}
	if !b.state.isAdmin(keyB) {
		t.Error("the runtime admin was not stored")
	}
	if reply := runCmd(t, cmds, "admin", adminCtx(b), "add "+keyB); !strings.Contains(reply, "already") {
		t.Errorf("adding twice = %q", reply)
	}
	if reply := runCmd(t, cmds, "admin", adminCtx(b), ""); !strings.Contains(reply, keyB+" (runtime)") {
		t.Errorf("list = %q, want the runtime admin", reply)
	}

	if reply := runCmd(t, cmds, "admin", adminCtx(b), "remove "+keyB); !strings.Contains(reply, "removed") {
		t.Errorf("remove = %q", reply)
	}
	if b.state.isAdmin(keyB) {
		t.Error("the runtime admin was not removed")
	}
}

// An admin from the environment is the operator's own key; a peer who talks
// their way into the runtime admin list must not be able to remove it.
func TestEnvironmentAdminsCannotBeRemovedAtRuntime(t *testing.T) {
	b, _, cmds := newFullBot(t, true)

	reply := runCmd(t, cmds, "admin", adminCtx(b), "remove "+keyA)

	if !strings.Contains(reply, "TOX_ADMINS") {
		t.Errorf("reply = %q, want a refusal explaining why", reply)
	}
	if !b.isAdminKey(keyA) {
		t.Error("the environment admin lost their privileges")
	}
}

func TestAdminCommandUsageErrors(t *testing.T) {
	b, _, cmds := newFullBot(t, true)
	for _, args := range []string{"add nope", "remove nope", "add #99", "wat"} {
		if reply := runCmd(t, cmds, "admin", adminCtx(b), args); !strings.Contains(reply, "usage:") {
			t.Errorf("/admin %s = %q, want usage", args, reply)
		}
	}
}

func TestBlockRemovesTheFriendAndRefusesAdmins(t *testing.T) {
	b, ft, cmds := newFullBot(t, true)

	reply := runCmd(t, cmds, "block", adminCtx(b), "#2")

	if !strings.Contains(reply, keyB) || !strings.Contains(reply, "removed friend #2") {
		t.Errorf("reply = %q", reply)
	}
	if !b.state.isBlocked(keyB) {
		t.Error("the peer was not blocked")
	}
	if len(ft.deleted) != 1 || ft.deleted[0] != 2 {
		t.Errorf("deleted = %v, want friend #2", ft.deleted)
	}

	if reply := runCmd(t, cmds, "block", adminCtx(b), keyA); !strings.Contains(reply, "refusing") {
		t.Errorf("blocking an admin = %q, want a refusal", reply)
	}
}

func TestBlockByPublicKeyFindsTheFriendNumber(t *testing.T) {
	b, ft, cmds := newFullBot(t, true)

	runCmd(t, cmds, "block", adminCtx(b), strings.ToLower(keyB))

	if len(ft.deleted) != 1 || ft.deleted[0] != 2 {
		t.Errorf("deleted = %v, want the friend behind that key", ft.deleted)
	}
}

func TestUnblockAndBlockedList(t *testing.T) {
	b, _, cmds := newFullBot(t, true)

	if reply := runCmd(t, cmds, "blocked", adminCtx(b), ""); reply != "nothing blocked" {
		t.Errorf("reply = %q", reply)
	}
	runCmd(t, cmds, "block", adminCtx(b), keyB)
	if reply := runCmd(t, cmds, "blocked", adminCtx(b), ""); !strings.Contains(reply, keyB) {
		t.Errorf("reply = %q", reply)
	}
	if reply := runCmd(t, cmds, "unblock", adminCtx(b), keyB); !strings.Contains(reply, "unblocked") {
		t.Errorf("reply = %q", reply)
	}
	if reply := runCmd(t, cmds, "unblock", adminCtx(b), keyB); reply != "not blocked" {
		t.Errorf("reply = %q", reply)
	}
}

func TestOutboxCommandShowsAndClears(t *testing.T) {
	b, _, cmds := newFullBot(t, true)

	if reply := runCmd(t, cmds, "outbox", adminCtx(b), ""); reply != "outbox is empty" {
		t.Errorf("reply = %q", reply)
	}

	b.deliver(2, "one")
	b.deliver(2, "two")

	reply := runCmd(t, cmds, "outbox", adminCtx(b), "")
	if !strings.Contains(reply, "2 queued") || !strings.Contains(reply, keyB+" 2") {
		t.Errorf("reply = %q", reply)
	}
	if reply := runCmd(t, cmds, "outbox", adminCtx(b), "CLEAR"); !strings.Contains(reply, "dropped 2") {
		t.Errorf("reply = %q", reply)
	}
	if b.state.queued() != 0 {
		t.Error("the outbox was not cleared")
	}
}

func TestAuditCommandTailsTheLog(t *testing.T) {
	b, _, cmds := newFullBot(t, true)

	if reply := runCmd(t, cmds, "audit", adminCtx(b), ""); reply != "audit log is empty" {
		t.Errorf("reply = %q", reply)
	}

	for i := 0; i < 3; i++ {
		b.recordAudit(auditEvent{Actor: keyA, Command: "save", Allowed: true})
	}

	reply := runCmd(t, cmds, "audit", adminCtx(b), "2")
	if lines := strings.Split(reply, "\n"); len(lines) != 2 {
		t.Errorf("reply has %d lines, want 2:\n%s", len(lines), reply)
	}
	if reply := runCmd(t, cmds, "audit", adminCtx(b), "zero"); !strings.HasPrefix(reply, "usage:") {
		t.Errorf("reply = %q, want usage", reply)
	}
}

func TestStatsIncludesQueueAndRateCounters(t *testing.T) {
	b, _, cmds := newFullBot(t, true)
	b.deliver(2, "queued")
	b.metrics.rateLimited = 3

	reply := runCmd(t, cmds, "stats", adminCtx(b), "")

	if !strings.Contains(reply, "queued: 1") || !strings.Contains(reply, "rate-limited: 3") {
		t.Errorf("reply = %q", reply)
	}
}

func TestHelpListsTheNewAdminCommands(t *testing.T) {
	b, _, cmds := newFullBot(t, true)

	public := cmds["help"].run(&cmdCtx{bot: b, isAdmin: false})
	privileged := cmds["help"].run(&cmdCtx{bot: b, isAdmin: true})

	for _, name := range []string{"/version", "/whoami"} {
		if !strings.Contains(public, name) {
			t.Errorf("public help is missing %s:\n%s", name, public)
		}
	}
	for _, name := range []string{"/broadcast", "/nospam", "/admin", "/block", "/unblock", "/outbox", "/audit"} {
		if strings.Contains(public, name) {
			t.Errorf("public help leaks admin command %s:\n%s", name, public)
		}
		if !strings.Contains(privileged, name) {
			t.Errorf("admin help is missing %s:\n%s", name, privileged)
		}
	}
}

func TestResolveKeyAcceptsKeysIDsAndFriendNumbers(t *testing.T) {
	b, _, _ := newFullBot(t, true)

	for _, in := range []string{keyB, strings.ToLower(keyB), keyB + "1A2B3C4D5E6F", "#2"} {
		got, err := b.resolveKey(in)
		if err != nil {
			t.Errorf("resolveKey(%q): %v", in, err)
			continue
		}
		if got != keyB {
			t.Errorf("resolveKey(%q) = %q, want %q", in, got, keyB)
		}
	}
	for _, in := range []string{"", "#nope", "#99", "zzz"} {
		if _, err := b.resolveKey(in); err == nil {
			t.Errorf("resolveKey(%q) should have failed", in)
		}
	}
}

// Rotating the nospam must persist, or a restart brings the spammed ID back.
func TestNospamPersists(t *testing.T) {
	b, ft, cmds := newFullBot(t, true)
	ft.savedata = toxProfile('x')

	runCmd(t, cmds, "nospam", adminCtx(b), "0000000A")

	if b.lastSave.IsZero() {
		t.Error("changing the nospam did not save the profile")
	}
}
