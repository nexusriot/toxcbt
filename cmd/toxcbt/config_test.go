package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetenvBool(t *testing.T) {
	t.Setenv("TOX_TEST_BOOL", "")
	if got := getenvBool("TOX_TEST_BOOL", true); !got {
		t.Error("an unset variable should fall back to the default")
	}
	for _, raw := range []string{"true", "1", "TRUE"} {
		t.Setenv("TOX_TEST_BOOL", raw)
		if !getenvBool("TOX_TEST_BOOL", false) {
			t.Errorf("%q should parse as true", raw)
		}
	}
	t.Setenv("TOX_TEST_BOOL", "0")
	if getenvBool("TOX_TEST_BOOL", true) {
		t.Error(`"0" should parse as false`)
	}
	t.Setenv("TOX_TEST_BOOL", "maybe")
	if !getenvBool("TOX_TEST_BOOL", true) {
		t.Error("a malformed value should fall back to the default, not to false")
	}
}

func TestGetenvInt(t *testing.T) {
	t.Setenv("TOX_TEST_INT", "42")
	if got := getenvInt("TOX_TEST_INT", 7); got != 42 {
		t.Errorf("got %d, want 42", got)
	}
	for _, raw := range []string{"", "lots", "-1"} {
		t.Setenv("TOX_TEST_INT", raw)
		if got := getenvInt("TOX_TEST_INT", 7); got != 7 {
			t.Errorf("%q: got %d, want the default", raw, got)
		}
	}
}

func TestGetenvDuration(t *testing.T) {
	t.Setenv("TOX_TEST_DUR", "90s")
	if got := getenvDuration("TOX_TEST_DUR", time.Minute); got != 90*time.Second {
		t.Errorf("got %s, want 90s", got)
	}
	for _, raw := range []string{"", "soon", "-5m"} {
		t.Setenv("TOX_TEST_DUR", raw)
		if got := getenvDuration("TOX_TEST_DUR", time.Minute); got != time.Minute {
			t.Errorf("%q: got %s, want the default", raw, got)
		}
	}
}

func TestParseLogLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"":      slog.LevelInfo,
		"INFO":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
		"loud":  slog.LevelInfo,
	}
	for in, want := range cases {
		if got := parseLogLevel(in); got != want {
			t.Errorf("parseLogLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLoadPassphraseFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(path, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TOX_SAVEDATA_PASSPHRASE_FILE", path)
	t.Setenv("TOX_SAVEDATA_PASSPHRASE", "ignored")

	// The file wins, and the trailing newline every editor adds is not part
	// of the passphrase.
	if got := string(loadPassphrase()); got != "s3cret" {
		t.Errorf("passphrase = %q, want %q", got, "s3cret")
	}
}

func TestLoadPassphraseFromEnv(t *testing.T) {
	t.Setenv("TOX_SAVEDATA_PASSPHRASE_FILE", "")
	t.Setenv("TOX_SAVEDATA_PASSPHRASE", "s3cret")
	if got := string(loadPassphrase()); got != "s3cret" {
		t.Errorf("passphrase = %q", got)
	}

	t.Setenv("TOX_SAVEDATA_PASSPHRASE", "")
	if got := loadPassphrase(); got != nil {
		t.Errorf("passphrase = %q, want none", got)
	}
}

// An empty secret would make the containment test match every request, so the
// strictest-sounding policy would become the most permissive one.
func TestSecretPolicyWithoutASecretClosesTheDoor(t *testing.T) {
	t.Setenv("TOX_FRIEND_POLICY", "secret")
	t.Setenv("TOX_FRIEND_SECRET", "   ")

	p := loadFriendPolicy(nil)

	if p.mode != policyClosed {
		t.Errorf("mode = %q, want %q", p.mode, policyClosed)
	}
	if ok, _ := p.accepts(keyA, "anything", 0, false); ok {
		t.Error("a secret policy with no secret must accept nobody")
	}
}

func TestUnknownPolicyFallsBackToOpen(t *testing.T) {
	t.Setenv("TOX_FRIEND_POLICY", "vibes")
	if p := loadFriendPolicy(nil); p.mode != policyOpen {
		t.Errorf("mode = %q, want %q", p.mode, policyOpen)
	}
}

// Admins are always allowed back in, whatever the policy says.
func TestAdminsAreAlwaysAllowlisted(t *testing.T) {
	t.Setenv("TOX_FRIEND_POLICY", "closed")
	t.Setenv("TOX_FRIEND_ALLOWLIST", "")

	p := loadFriendPolicy(map[string]bool{keyA: true})

	if ok, reason := p.accepts(keyA, "", 0, false); !ok {
		t.Errorf("admin rejected by a closed policy: %s", reason)
	}
	if ok, _ := p.accepts(keyB, "", 0, false); ok {
		t.Error("a closed policy accepted a stranger")
	}
}

func TestFriendPolicyAccepts(t *testing.T) {
	tests := []struct {
		name    string
		policy  friendPolicy
		key     string
		message string
		friends int
		blocked bool
		want    bool
	}{
		{name: "open accepts", policy: friendPolicy{mode: policyOpen}, key: keyA, want: true},
		{name: "blocked always wins", policy: friendPolicy{mode: policyOpen}, key: keyA, blocked: true, want: false},
		{
			name:   "friend limit",
			policy: friendPolicy{mode: policyOpen, maxFriends: 2}, key: keyA, friends: 2, want: false,
		},
		{
			name:   "allowlisted peer bypasses the limit",
			policy: friendPolicy{mode: policyClosed, maxFriends: 1, allow: map[string]bool{keyA: true}},
			key:    keyA, friends: 99, want: true,
		},
		{
			name:   "secret present",
			policy: friendPolicy{mode: policySecret, secret: "open sesame"},
			key:    keyA, message: "hi, open sesame please", want: true,
		},
		{
			name:   "secret absent",
			policy: friendPolicy{mode: policySecret, secret: "open sesame"},
			key:    keyA, message: "hello", want: false,
		},
		{
			name:   "allowlist rejects a stranger",
			policy: friendPolicy{mode: policyAllowlist, allow: map[string]bool{keyB: true}},
			key:    keyA, want: false,
		},
		{name: "closed rejects", policy: friendPolicy{mode: policyClosed}, key: keyA, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := tc.policy.accepts(tc.key, tc.message, tc.friends, tc.blocked)
			if got != tc.want {
				t.Errorf("accepts() = %v (%s), want %v", got, reason, tc.want)
			}
			if reason == "" {
				t.Error("every decision must carry a reason for the audit trail")
			}
		})
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	for _, key := range []string{
		"TOX_NAME", "TOX_STATUS", "TOX_SAVEDATA", "TOX_STATE_FILE", "TOX_AUDIT_LOG",
		"TOX_BOOTSTRAP_NODES", "TOX_ADMINS", "TOX_HEALTH_ADDR", "TOX_FRIEND_POLICY",
		"TOX_RATE_PER_MINUTE", "TOX_SAVE_INTERVAL", "TOX_SAVEDATA_PASSPHRASE",
		"TOX_SAVEDATA_PASSPHRASE_FILE", "TOX_MAX_FRIENDS", "TOX_FRIEND_SECRET",
	} {
		// t.Setenv records the old value for restoration; unsetting afterwards
		// is what "not configured" actually looks like, and TOX_AUDIT_LOG now
		// distinguishes that from an explicit empty value.
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
	dir := t.TempDir()
	t.Setenv("TOX_DATA_DIR", dir)

	cfg := loadConfig()

	if cfg.name != defaultName || cfg.status != defaultStatus {
		t.Errorf("name/status = %q/%q", cfg.name, cfg.status)
	}
	if cfg.saveFile != filepath.Join(dir, "bot.tox") {
		t.Errorf("saveFile = %q", cfg.saveFile)
	}
	if cfg.stateFile != filepath.Join(dir, "state.json") {
		t.Errorf("stateFile = %q", cfg.stateFile)
	}
	if cfg.auditFile != filepath.Join(dir, "audit.log") {
		t.Errorf("auditFile = %q", cfg.auditFile)
	}
	if len(cfg.nodes) == 0 {
		t.Error("an empty TOX_BOOTSTRAP_NODES should fall back to the built-in nodes")
	}
	if cfg.policy.mode != policyOpen {
		t.Errorf("policy = %q, want the historical open default", cfg.policy.mode)
	}
	if cfg.logMessages {
		t.Error("message bodies must not be logged unless asked for")
	}
	if cfg.saveInterval != 30*time.Second {
		t.Errorf("saveInterval = %s", cfg.saveInterval)
	}
	if cfg.passphrase != nil {
		t.Error("no passphrase should be configured by default")
	}
}

// A zero save interval would panic time.NewTicker.
func TestLoadConfigRejectsZeroSaveInterval(t *testing.T) {
	t.Setenv("TOX_SAVE_INTERVAL", "0s")
	if got := loadConfig().saveInterval; got <= 0 {
		t.Errorf("saveInterval = %s, want a positive fallback", got)
	}
}

// An explicitly empty path is a choice, not an absent setting: it is how a
// deployment turns the audit log off.
func TestEmptyAuditPathDisablesAuditing(t *testing.T) {
	t.Setenv("TOX_DATA_DIR", t.TempDir())
	t.Setenv("TOX_AUDIT_LOG", "")

	cfg := loadConfig()

	if cfg.auditFile != "" {
		t.Errorf("auditFile = %q, want it disabled", cfg.auditFile)
	}
	a, err := openAudit(cfg.auditFile, cfg.auditBytes)
	if err != nil || a != nil {
		t.Errorf("openAudit = %v, %v; want a disabled log", a, err)
	}
}
