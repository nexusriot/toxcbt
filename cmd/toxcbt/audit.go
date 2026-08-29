package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// auditEvent is one line of the admin audit trail. Message bodies never appear
// here — only command names and their arguments, which are operational rather
// than private correspondence.
type auditEvent struct {
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	Friend  uint32    `json:"friend"`
	Command string    `json:"command"`
	Args    string    `json:"args,omitempty"`
	Allowed bool      `json:"allowed"`
	Result  string    `json:"result,omitempty"`
}

// auditLog is an append-only JSONL record of privileged activity, with a size
// cap so an unattended bot cannot fill its volume. A nil *auditLog is a
// working no-op, which is what a deployment with auditing disabled gets.
type auditLog struct {
	path     string
	maxBytes int64
	f        *os.File
	size     int64
}

// openAudit opens (or creates) the log. An empty path disables auditing.
func openAudit(path string, maxBytes int64) (*auditLog, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	a := &auditLog{path: path, maxBytes: maxBytes}
	if err := a.reopen(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *auditLog) reopen() error {
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	a.f, a.size = f, st.Size()
	return nil
}

// record appends an event. Failures are reported to the caller rather than
// logged here, so the caller decides whether a broken audit log is worth a
// warning on every command.
func (a *auditLog) record(ev auditEvent) error {
	if a == nil || a.f == nil {
		return nil
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	if a.maxBytes > 0 && a.size+int64(len(line)) > a.maxBytes {
		if err := a.rotate(); err != nil {
			return err
		}
	}
	n, err := a.f.Write(line)
	a.size += int64(n)
	return err
}

// rotate moves the current log aside, keeping exactly one previous generation.
func (a *auditLog) rotate() error {
	if err := a.f.Close(); err != nil {
		return err
	}
	if err := os.Rename(a.path, a.path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return a.reopen()
}

// tail returns the last n events, oldest first, as formatted lines.
func (a *auditLog) tail(n int) ([]string, error) {
	if a == nil || n <= 0 {
		return nil, nil
	}
	f, err := os.Open(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	// A ring buffer keeps memory bounded by n rather than by file size.
	ring := make([]string, 0, n)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var ev auditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		if len(ring) == n {
			ring = ring[1:]
		}
		ring = append(ring, formatAuditEvent(ev))
	}
	return ring, sc.Err()
}

func formatAuditEvent(ev auditEvent) string {
	verdict := "DENIED"
	if ev.Allowed {
		verdict = "ok"
	}
	line := fmt.Sprintf("%s %s #%d /%s %s",
		ev.Time.UTC().Format(time.RFC3339), shortKey(ev.Actor), ev.Friend, ev.Command, verdict)
	if ev.Args != "" {
		line += " args=" + ev.Args
	}
	if ev.Result != "" {
		line += " (" + ev.Result + ")"
	}
	return line
}

// shortKey abbreviates a public key for human-facing output.
func shortKey(pubKey string) string {
	if len(pubKey) <= 12 {
		if pubKey == "" {
			return "-"
		}
		return pubKey
	}
	return pubKey[:8] + "…"
}

func (a *auditLog) close() error {
	if a == nil || a.f == nil {
		return nil
	}
	return a.f.Close()
}
