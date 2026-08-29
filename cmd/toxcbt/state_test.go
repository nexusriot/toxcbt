package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestState(t *testing.T) *botState {
	t.Helper()
	s, err := loadState(filepath.Join(t.TempDir(), "state.json"), 3, time.Hour)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	return s
}

func TestLoadStateMissingFileIsEmpty(t *testing.T) {
	s := newTestState(t)
	if len(s.Admins) != 0 || len(s.Blocked) != 0 || s.queued() != 0 {
		t.Errorf("a missing state file should load empty, got %+v", s)
	}
	if s.dirty {
		t.Error("a freshly loaded state must not be dirty")
	}
}

func TestLoadStateEmptyFileIsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(path, 10, time.Hour); err != nil {
		t.Errorf("an empty state file should be treated as absent, got %v", err)
	}
}

// A damaged state file is refused rather than silently replaced: starting with
// an empty blocklist would quietly un-block everyone.
func TestLoadStateRejectsDamagedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(path, 10, time.Hour); err == nil {
		t.Error("damaged state loaded without error")
	}
}

func TestLoadStateRejectsNewerVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadState(path, 10, time.Hour)
	if err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("err = %v, want a complaint about the version", err)
	}
}

func TestLoadStateNormalizesAndDropsBadKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	body := `{"version":1,"admins":["` + strings.ToLower(keyA) + `","nope"],` +
		`"blocked":["` + keyB + `"],"outbox":{"` + strings.ToLower(keyA) + `":[{"text":"hi"}]}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := loadState(path, 10, time.Hour)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if !s.isAdmin(keyA) {
		t.Error("a lowercase admin key should be normalized and kept")
	}
	if len(s.Admins) != 1 {
		t.Errorf("admins = %v, want the unusable entry dropped", s.Admins)
	}
	if !s.isBlocked(keyB) {
		t.Error("blocklist entry lost")
	}
	if len(s.Outbox[keyA]) != 1 {
		t.Errorf("outbox = %v, want the queue under the normalized key", s.Outbox)
	}
}

func TestStateAdminsAndBlocklist(t *testing.T) {
	s := newTestState(t)

	if !s.addAdmin(keyA) || s.addAdmin(keyA) {
		t.Error("adding an admin twice should report false the second time")
	}
	if !s.isAdmin(keyA) || !s.dirty {
		t.Error("addAdmin must record the key and mark the state dirty")
	}
	if !s.removeAdmin(keyA) || s.isAdmin(keyA) {
		t.Error("removeAdmin did not take effect")
	}
	if s.removeAdmin(keyA) {
		t.Error("removing an absent admin should report false")
	}

	if !s.block(keyB) || !s.isBlocked(keyB) {
		t.Error("block did not take effect")
	}
	if s.block(keyB) {
		t.Error("blocking twice should report false")
	}
	if !s.unblock(keyB) || s.isBlocked(keyB) {
		t.Error("unblock did not take effect")
	}
}

// Blocking a peer should not leave their queued messages waiting to be
// delivered the moment they are unblocked.
func TestBlockDropsQueuedMessages(t *testing.T) {
	s := newTestState(t)
	s.enqueue(keyA, "hello", time.Now())

	s.block(keyA)

	if s.queued() != 0 {
		t.Errorf("queued = %d after blocking, want 0", s.queued())
	}
}

func TestOutboxQueueCapKeepsNewest(t *testing.T) {
	s := newTestState(t) // maxQueue = 3
	now := time.Unix(1700000000, 0)
	for i, text := range []string{"one", "two", "three", "four"} {
		if !s.enqueue(keyA, text, now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("enqueue(%q) reported the outbox as disabled", text)
		}
	}

	items := s.takeQueue(keyA)
	if len(items) != 3 {
		t.Fatalf("queue holds %d items, want the cap of 3", len(items))
	}
	if items[0].Text != "two" || items[2].Text != "four" {
		t.Errorf("queue = %v, want the oldest dropped", items)
	}
	if s.queued() != 0 {
		t.Error("takeQueue should empty the queue")
	}
}

func TestOutboxDisabledWhenMaxIsZero(t *testing.T) {
	s, err := loadState(filepath.Join(t.TempDir(), "state.json"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if s.enqueue(keyA, "hi", time.Now()) {
		t.Error("enqueue should report false when the outbox is disabled")
	}
}

func TestOutboxRequeueKeepsOrder(t *testing.T) {
	s := newTestState(t)
	now := time.Unix(1700000000, 0)
	s.enqueue(keyA, "first", now)
	items := s.takeQueue(keyA)
	s.enqueue(keyA, "second", now.Add(time.Second))

	s.requeue(keyA, items)

	got := s.takeQueue(keyA)
	if len(got) != 2 || got[0].Text != "first" || got[1].Text != "second" {
		t.Errorf("queue = %v, want the requeued item back in front", got)
	}
}

func TestPruneOutboxDropsExpiredItems(t *testing.T) {
	s := newTestState(t) // ttl = 1h
	now := time.Unix(1700000000, 0)
	s.enqueue(keyA, "old", now.Add(-2*time.Hour))
	s.enqueue(keyA, "fresh", now)
	s.enqueue(keyB, "ancient", now.Add(-48*time.Hour))

	if dropped := s.pruneOutbox(now); dropped != 2 {
		t.Errorf("dropped %d, want 2", dropped)
	}
	if s.queued() != 1 {
		t.Errorf("queued = %d, want only the fresh message", s.queued())
	}
	if _, ok := s.Outbox[keyB]; ok {
		t.Error("an emptied queue should be removed entirely")
	}
}

func TestOutboxSummaryAndClear(t *testing.T) {
	s := newTestState(t)
	now := time.Now()
	s.enqueue(keyA, "a", now)
	s.enqueue(keyB, "b", now)
	s.enqueue(keyB, "c", now)

	summary := s.outboxSummary()
	if len(summary) != 2 || !strings.HasPrefix(summary[0], keyA) || !strings.HasSuffix(summary[1], " 2") {
		t.Errorf("summary = %v", summary)
	}
	if n := s.clearOutbox(); n != 3 || s.queued() != 0 {
		t.Errorf("clearOutbox = %d, queued = %d; want 3 and 0", n, s.queued())
	}
}

func TestStateFlushIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, err := loadState(path, 10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.flush(); err != nil {
		t.Fatalf("flush of a clean state: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("flushing an unchanged state should not write anything")
	}

	s.addAdmin(keyA)
	s.enqueue(keyB, "queued text", time.Unix(1700000000, 0))
	if err := s.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if s.dirty {
		t.Error("flush should clear the dirty flag")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("state file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("state mode = %o, want 600 (it holds queued message bodies)", perm)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temp file was left behind")
	}

	reloaded, err := loadState(path, 10, time.Hour)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.isAdmin(keyA) || reloaded.queued() != 1 {
		t.Errorf("reloaded state lost data: %+v", reloaded)
	}

	var raw map[string]any
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("state file is not valid JSON: %v", err)
	}
	if raw["version"] != float64(stateVersion) {
		t.Errorf("version = %v, want %d", raw["version"], stateVersion)
	}
}

// Every accessor has to work on a bot that has no state file at all.
func TestNilStateIsUsable(t *testing.T) {
	var s *botState
	if s.isAdmin(keyA) || s.isBlocked(keyA) || s.queued() != 0 || s.clearOutbox() != 0 {
		t.Error("a nil state should read as empty")
	}
	if s.addAdmin(keyA) || s.removeAdmin(keyA) || s.block(keyA) || s.unblock(keyA) {
		t.Error("mutating a nil state should report no change")
	}
	if s.enqueue(keyA, "x", time.Now()) || s.takeQueue(keyA) != nil {
		t.Error("a nil state has no outbox")
	}
	s.requeue(keyA, []outboxItem{{Text: "x"}})
	s.pruneOutbox(time.Now())
	s.markDirty()
	if err := s.flush(); err != nil {
		t.Errorf("flushing a nil state: %v", err)
	}
	if s.adminList() != nil || s.blockedList() != nil || s.outboxSummary() != nil {
		t.Error("a nil state should list nothing")
	}
}
