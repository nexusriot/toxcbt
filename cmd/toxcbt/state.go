package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// stateVersion is bumped when the on-disk shape changes incompatibly. A file
// from the future is refused rather than silently downgraded.
const stateVersion = 1

// outboxItem is one message waiting for a friend to come back online.
type outboxItem struct {
	Text   string    `json:"text"`
	Queued time.Time `json:"queued"`
}

// botState is the JSON sidecar holding what the bot learns at runtime and
// toxcore's savedata cannot carry: runtime-granted admins, the blocklist, and
// messages queued for friends that were offline when we tried to send.
//
// It is deliberately a separate file from the profile. Savedata is the
// identity, written by toxcore and validated byte-for-byte on load; this is
// ours, and losing it costs a blocklist rather than a Tox ID.
//
// Every method tolerates a nil receiver, so a bot constructed without a state
// file (the tests, and any deployment that disables it) behaves as if the
// state were empty instead of panicking.
type botState struct {
	Version int                     `json:"version"`
	Admins  []string                `json:"admins"`
	Blocked []string                `json:"blocked"`
	Outbox  map[string][]outboxItem `json:"outbox"`

	path     string
	dirty    bool
	maxQueue int
	ttl      time.Duration
}

// loadState reads the sidecar. A missing or empty file is an empty state; a
// damaged one is an error, because silently starting with an empty blocklist
// would un-block everyone the operator ever blocked.
func loadState(path string, maxQueue int, ttl time.Duration) (*botState, error) {
	s := &botState{
		Version:  stateVersion,
		Outbox:   map[string][]outboxItem{},
		path:     path,
		maxQueue: maxQueue,
		ttl:      ttl,
	}

	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	case len(bytes.TrimSpace(data)) == 0:
		return s, nil
	}

	var onDisk botState
	if err := json.Unmarshal(data, &onDisk); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if onDisk.Version > stateVersion {
		return nil, fmt.Errorf("written by a newer bot (version %d, this bot understands %d)",
			onDisk.Version, stateVersion)
	}

	s.Admins = normalizeKeyList(onDisk.Admins, "state admin")
	s.Blocked = normalizeKeyList(onDisk.Blocked, "state blocklist")
	for key, items := range onDisk.Outbox {
		pk, err := normalizePubKey(key)
		if err != nil {
			slog.Warn("state outbox entry skipped", "key", key, "err", err)
			continue
		}
		s.Outbox[pk] = capQueue(items, maxQueue)
	}
	return s, nil
}

// normalizeKeyList validates, uppercases, sorts and de-duplicates public keys.
func normalizeKeyList(in []string, what string) []string {
	seen := map[string]bool{}
	for _, raw := range in {
		pk, err := normalizePubKey(raw)
		if err != nil {
			slog.Warn("entry skipped", "what", what, "key", raw, "err", err)
			continue
		}
		seen[pk] = true
	}
	return sortedKeys(seen)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// capQueue keeps only the newest max items, because an outbox for a friend who
// never comes back must not grow without bound.
func capQueue(items []outboxItem, max int) []outboxItem {
	if max > 0 && len(items) > max {
		return append([]outboxItem(nil), items[len(items)-max:]...)
	}
	return items
}

func (s *botState) markDirty() {
	if s != nil {
		s.dirty = true
	}
}

// flush writes the state atomically, and only when something changed.
func (s *botState) flush() error {
	if s == nil || !s.dirty || s.path == "" {
		return nil
	}
	s.Version = stateVersion
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp := s.path + ".tmp"
	if err := writeFileSync(tmp, data, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(s.path))
	s.dirty = false
	return nil
}

func (s *botState) isAdmin(pubKey string) bool {
	return s != nil && contains(s.Admins, pubKey)
}

func (s *botState) adminList() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.Admins...)
}

func (s *botState) addAdmin(pubKey string) bool {
	if s == nil || contains(s.Admins, pubKey) {
		return false
	}
	s.Admins = append(s.Admins, pubKey)
	sort.Strings(s.Admins)
	s.markDirty()
	return true
}

func (s *botState) removeAdmin(pubKey string) bool {
	if s == nil {
		return false
	}
	out, removed := without(s.Admins, pubKey)
	if removed {
		s.Admins = out
		s.markDirty()
	}
	return removed
}

func (s *botState) isBlocked(pubKey string) bool {
	return s != nil && contains(s.Blocked, pubKey)
}

func (s *botState) blockedList() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.Blocked...)
}

func (s *botState) block(pubKey string) bool {
	if s == nil || contains(s.Blocked, pubKey) {
		return false
	}
	s.Blocked = append(s.Blocked, pubKey)
	sort.Strings(s.Blocked)
	// A blocked peer's queued messages are pointless; drop them.
	delete(s.Outbox, pubKey)
	s.markDirty()
	return true
}

func (s *botState) unblock(pubKey string) bool {
	if s == nil {
		return false
	}
	out, removed := without(s.Blocked, pubKey)
	if removed {
		s.Blocked = out
		s.markDirty()
	}
	return removed
}

// enqueue stores a message for an offline friend. It reports false when the
// outbox is disabled, so the caller can tell "queued" from "dropped".
func (s *botState) enqueue(pubKey, text string, now time.Time) bool {
	if s == nil || s.maxQueue == 0 {
		return false
	}
	if s.Outbox == nil {
		s.Outbox = map[string][]outboxItem{}
	}
	q := append(s.Outbox[pubKey], outboxItem{Text: text, Queued: now})
	s.Outbox[pubKey] = capQueue(q, s.maxQueue)
	s.markDirty()
	return true
}

// takeQueue removes and returns everything queued for a friend.
func (s *botState) takeQueue(pubKey string) []outboxItem {
	if s == nil {
		return nil
	}
	items := s.Outbox[pubKey]
	if len(items) == 0 {
		return nil
	}
	delete(s.Outbox, pubKey)
	s.markDirty()
	return items
}

// requeue puts unsent items back at the front, preserving order, after a flush
// that failed part way through.
func (s *botState) requeue(pubKey string, items []outboxItem) {
	if s == nil || len(items) == 0 {
		return
	}
	if s.Outbox == nil {
		s.Outbox = map[string][]outboxItem{}
	}
	s.Outbox[pubKey] = capQueue(append(items, s.Outbox[pubKey]...), s.maxQueue)
	s.markDirty()
}

// queued counts everything waiting, across friends.
func (s *botState) queued() int {
	if s == nil {
		return 0
	}
	n := 0
	for _, items := range s.Outbox {
		n += len(items)
	}
	return n
}

// outboxSummary lists queued counts per friend, newest-queued timestamp first
// discarded; ordering is by key so the reply is stable.
func (s *botState) outboxSummary() []string {
	if s == nil {
		return nil
	}
	keys := make([]string, 0, len(s.Outbox))
	for k := range s.Outbox {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s %d", k, len(s.Outbox[k])))
	}
	return out
}

func (s *botState) clearOutbox() int {
	if s == nil {
		return 0
	}
	n := s.queued()
	if n > 0 {
		s.Outbox = map[string][]outboxItem{}
		s.markDirty()
	}
	return n
}

// pruneOutbox drops items older than the TTL and reports how many went. A
// message queued a week ago is noise by the time the friend reappears.
func (s *botState) pruneOutbox(now time.Time) int {
	if s == nil || s.ttl <= 0 {
		return 0
	}
	dropped := 0
	for key, items := range s.Outbox {
		kept := items[:0]
		for _, it := range items {
			if now.Sub(it.Queued) > s.ttl {
				dropped++
				continue
			}
			kept = append(kept, it)
		}
		if len(kept) == 0 {
			delete(s.Outbox, key)
			continue
		}
		s.Outbox[key] = kept
	}
	if dropped > 0 {
		s.markDirty()
	}
	return dropped
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func without(list []string, drop string) ([]string, bool) {
	for i, v := range list {
		if v == drop {
			return append(append([]string(nil), list[:i]...), list[i+1:]...), true
		}
	}
	return list, false
}
