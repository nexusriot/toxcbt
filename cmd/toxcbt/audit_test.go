package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditDisabledWithoutAPath(t *testing.T) {
	a, err := openAudit("   ", 1024)
	if err != nil {
		t.Fatalf("openAudit: %v", err)
	}
	if a != nil {
		t.Fatal("an empty path should disable auditing")
	}
	// Every method must tolerate that.
	if err := a.record(auditEvent{Command: "save"}); err != nil {
		t.Errorf("record on a disabled log: %v", err)
	}
	if lines, err := a.tail(5); err != nil || lines != nil {
		t.Errorf("tail = %v, %v; want nothing", lines, err)
	}
	if err := a.close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestAuditRecordsAndTails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := openAudit(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()

	when := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	for i, cmd := range []string{"save", "remove", "say"} {
		if err := a.record(auditEvent{
			Time: when.Add(time.Duration(i) * time.Second), Actor: keyA, Friend: uint32(i),
			Command: cmd, Args: "arg", Allowed: cmd != "say", Result: "done",
		}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	lines, err := a.tail(2)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("tail returned %d lines, want the last 2", len(lines))
	}
	if !strings.Contains(lines[0], "/remove") || !strings.Contains(lines[1], "/say") {
		t.Errorf("tail = %v, want the newest entries in order", lines)
	}
	if !strings.Contains(lines[1], "DENIED") {
		t.Errorf("a denied command should be obvious: %q", lines[1])
	}
	if !strings.Contains(lines[0], "2026-08-28T12:00:01Z") {
		t.Errorf("line = %q, want a UTC timestamp", lines[0])
	}
	if strings.Contains(lines[0], keyA) {
		t.Errorf("line = %q, want the key abbreviated for readability", lines[0])
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("audit log mode = %o, want 600", perm)
	}
}

// An unattended bot must not fill its volume with audit lines.
func TestAuditRotatesAtTheSizeCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := openAudit(path, 200)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()

	for i := 0; i < 20; i++ {
		if err := a.record(auditEvent{Time: time.Now(), Actor: keyA, Command: "save", Result: "done"}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 200 {
		t.Errorf("live log is %d bytes, want it rotated below the 200 byte cap", info.Size())
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("previous generation missing: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("directory holds %d files, want exactly the log and one rotation", len(entries))
	}
}

func TestAuditTailSkipsUnparseableLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("garbage\n{\"command\":\"save\",\"allowed\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := openAudit(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()

	lines, err := a.tail(10)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "/save") {
		t.Errorf("tail = %v, want only the parseable entry", lines)
	}
}

func TestShortKey(t *testing.T) {
	if got := shortKey(keyA); got != keyA[:8]+"…" {
		t.Errorf("shortKey = %q", got)
	}
	if got := shortKey(""); got != "-" {
		t.Errorf("shortKey(\"\") = %q, want a placeholder", got)
	}
	if got := shortKey("abc"); got != "abc" {
		t.Errorf("shortKey(%q) = %q, want it unchanged", "abc", got)
	}
}
