package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tox "github.com/TokTok/go-toxcore-c"
)

// The parsers deliberately log every rejected entry; keep test output readable.
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

const (
	keyA = "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E"
	keyB = "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C"
)

// fakeTox implements toxClient in memory.
type fakeTox struct {
	address    string
	name       string
	status     string
	friends    []uint32
	pubKeys    map[uint32]string
	connStatus map[uint32]int
	savedata   []byte

	sent      []sentMessage
	sendErr   error
	deleted   []uint32
	deleteOK  bool
	deleteErr error
}

type sentMessage struct {
	friend uint32
	text   string
}

func newFakeTox() *fakeTox {
	return &fakeTox{
		address:    strings.Repeat("A", 2*tox.ADDRESS_SIZE),
		name:       "test-bot",
		status:     "testing",
		pubKeys:    map[uint32]string{},
		connStatus: map[uint32]int{},
		savedata:   []byte("savedata"),
		deleteOK:   true,
	}
}

func (f *fakeTox) SelfGetAddress() string                { return f.address }
func (f *fakeTox) SelfGetName() string                   { return f.name }
func (f *fakeTox) SelfGetStatusMessage() (string, error) { return f.status, nil }
func (f *fakeTox) SelfGetFriendList() []uint32           { return f.friends }
func (f *fakeTox) SelfGetFriendListSize() uint32         { return uint32(len(f.friends)) }
func (f *fakeTox) GetSavedataSize() int32                { return int32(len(f.savedata)) }
func (f *fakeTox) GetSavedata() []byte                   { return f.savedata }
func (f *fakeTox) FriendGetConnectionStatus(fn uint32) (int, error) {
	st, ok := f.connStatus[fn]
	if !ok {
		return tox.CONNECTION_NONE, errors.New("no such friend")
	}
	return st, nil
}

func (f *fakeTox) FriendGetPublicKey(fn uint32) (string, error) {
	pk, ok := f.pubKeys[fn]
	if !ok {
		return "", errors.New("no such friend")
	}
	return pk, nil
}

func (f *fakeTox) FriendDelete(fn uint32) (bool, error) {
	if f.deleteErr != nil {
		return false, f.deleteErr
	}
	f.deleted = append(f.deleted, fn)
	return f.deleteOK, nil
}

func (f *fakeTox) FriendSendMessage(fn uint32, msg string) (uint32, error) {
	if f.sendErr != nil {
		return 0, f.sendErr
	}
	f.sent = append(f.sent, sentMessage{friend: fn, text: msg})
	return uint32(len(f.sent)), nil
}

func (f *fakeTox) texts() []string {
	out := make([]string, 0, len(f.sent))
	for _, m := range f.sent {
		out = append(out, m.text)
	}
	return out
}

// newTestBot returns a bot backed by a fake instance, with one friend (#1)
// whose key is keyA. admin decides whether that key is privileged.
func newTestBot(t *testing.T, admin bool) (*Bot, *fakeTox, map[string]*command) {
	t.Helper()
	ft := newFakeTox()
	ft.friends = []uint32{1}
	ft.pubKeys[1] = keyA
	ft.connStatus[1] = tox.CONNECTION_UDP

	admins := map[string]bool{}
	if admin {
		admins[keyA] = true
	}
	b := &Bot{
		t:        ft,
		saveFile: filepath.Join(t.TempDir(), "bot.tox"),
		admins:   admins,
		started:  time.Now().Add(-90 * time.Second),
		connSt:   tox.CONNECTION_UDP,
	}
	return b, ft, b.buildCommands()
}

func TestParseBootstrapEnv(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []bootstrapNode
	}{
		{
			name: "empty",
			in:   "   ",
			want: nil,
		},
		{
			name: "single entry",
			in:   "tox.example.com:33445:" + keyA,
			want: []bootstrapNode{{"tox.example.com", 33445, keyA}},
		},
		{
			name: "two entries with whitespace",
			in:   " tox.example.com:33445:" + keyA + " , 10.0.0.1:1234:" + keyB + " ",
			want: []bootstrapNode{
				{"tox.example.com", 33445, keyA},
				{"10.0.0.1", 1234, keyB},
			},
		},
		{
			name: "lowercase key is normalized",
			in:   "h:33445:" + strings.ToLower(keyA),
			want: []bootstrapNode{{"h", 33445, keyA}},
		},
		{
			name: "bracketed IPv6 literal",
			in:   "[2001:db8::1]:33445:" + keyA,
			want: []bootstrapNode{{"2001:db8::1", 33445, keyA}},
		},
		{
			name: "bare IPv6 literal",
			in:   "::1:33445:" + keyA,
			want: []bootstrapNode{{"::1", 33445, keyA}},
		},
		{
			name: "trailing comma is ignored",
			in:   "h:33445:" + keyA + ",",
			want: []bootstrapNode{{"h", 33445, keyA}},
		},
		{
			name: "bad port skipped",
			in:   "h:nope:" + keyA,
			want: nil,
		},
		{
			name: "port zero skipped",
			in:   "h:0:" + keyA,
			want: nil,
		},
		{
			name: "port out of range skipped",
			in:   "h:70000:" + keyA,
			want: nil,
		},
		{
			name: "missing pubkey field skipped",
			in:   "h:33445",
			want: nil,
		},
		{
			name: "empty host skipped",
			in:   ":33445:" + keyA,
			want: nil,
		},
		{
			name: "non-hex pubkey skipped",
			in:   "h:33445:" + strings.Repeat("Z", 64),
			want: nil,
		},
		{
			name: "one bad entry does not drop the good one",
			in:   "bad:entry," + "h:33445:" + keyA,
			want: []bootstrapNode{{"h", 33445, keyA}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseBootstrapEnv(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseBootstrapEnv(%q)\n got %+v\nwant %+v", tc.in, got, tc.want)
			}
		})
	}
}

// tox.Tox.Bootstrap indexes the decoded key at [0] and hands C a pointer that
// toxcore reads 32 bytes from: an empty key panics, a short one reads out of
// bounds. Neither may survive parsing.
func TestParseBootstrapEnvRejectsWrongLengthKeys(t *testing.T) {
	for _, key := range []string{
		"",                      // "host:port:"
		"AABB",                  // valid hex, 2 bytes
		strings.Repeat("A", 62), // one byte short
		strings.Repeat("A", 66), // one byte long
		strings.Repeat("A", 63), // odd length
		keyA + keyB,             // two keys glued together
	} {
		in := "tox.example.com:33445:" + key
		if got := parseBootstrapEnv(in); got != nil {
			t.Errorf("parseBootstrapEnv(%q) = %+v, want nil (key of %d hex chars must be rejected)",
				in, got, len(key))
		}
	}
}

// A full Tox ID is what /id prints, so it is the string users paste; accept it
// by reducing to the public-key prefix.
func TestParseBootstrapEnvAcceptsFullToxID(t *testing.T) {
	toxID := keyA + "1A2B3C4D" + "5E6F"
	if len(toxID) != 2*tox.ADDRESS_SIZE {
		t.Fatalf("test fixture is %d chars, want %d", len(toxID), 2*tox.ADDRESS_SIZE)
	}
	got := parseBootstrapEnv("h:33445:" + toxID)
	want := []bootstrapNode{{"h", 33445, keyA}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestDefaultBootstrapKeysAreWellFormed(t *testing.T) {
	nodes := defaultBootstrap()
	if len(nodes) == 0 {
		t.Fatal("no default bootstrap nodes")
	}
	for _, n := range nodes {
		if _, err := normalizePubKey(n.key); err != nil {
			t.Errorf("default node %s:%d has an unusable key: %v", n.host, n.port, err)
		}
		if n.host == "" || n.port == 0 {
			t.Errorf("default node has empty host or zero port: %+v", n)
		}
	}
}

func TestNormalizePubKey(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "uppercase passthrough", in: keyA, want: keyA},
		{name: "lowercase is uppercased", in: strings.ToLower(keyA), want: keyA},
		{name: "spaces are stripped", in: " " + keyA[:32] + " " + keyA[32:] + " ", want: keyA},
		{name: "tox id truncated to pubkey", in: keyA + "AABBCCDD1122", want: keyA},
		{name: "empty", in: "", wantErr: true},
		{name: "too short", in: keyA[:62], wantErr: true},
		{name: "too long", in: keyA + "AA", wantErr: true},
		{name: "non hex", in: strings.Repeat("G", 64), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizePubKey(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizePubKey(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizePubKey(%q): unexpected error %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalizePubKey(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{in: "127.0.0.1:9050", wantHost: "127.0.0.1", wantPort: 9050},
		{in: " example.com : 33445 ", wantHost: "example.com", wantPort: 33445},
		{in: "[::1]:9050", wantHost: "::1", wantPort: 9050},
		{in: "::1:9050", wantHost: "::1", wantPort: 9050},
		{in: "[2001:db8::1]:1", wantHost: "2001:db8::1", wantPort: 1},
		{in: "hostonly", wantErr: true},
		{in: ":9050", wantErr: true},
		{in: "host:", wantErr: true},
		{in: "host:0", wantErr: true},
		{in: "host:65536", wantErr: true},
		{in: "host:-1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			host, port, err := parseHostPort(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseHostPort(%q) = %q,%d, want error", tc.in, host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseHostPort(%q): unexpected error %v", tc.in, err)
			}
			if host != tc.wantHost || port != tc.wantPort {
				t.Errorf("parseHostPort(%q) = %q,%d, want %q,%d", tc.in, host, port, tc.wantHost, tc.wantPort)
			}
		})
	}
}

func TestParseAdmins(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]bool
	}{
		{name: "empty", in: "", want: map[string]bool{}},
		{name: "single", in: keyA, want: map[string]bool{keyA: true}},
		{name: "lowercase normalized", in: strings.ToLower(keyA), want: map[string]bool{keyA: true}},
		{
			name: "two keys with whitespace",
			in:   " " + keyA + " , " + keyB + " ",
			want: map[string]bool{keyA: true, keyB: true},
		},
		{name: "trailing comma", in: keyA + ",", want: map[string]bool{keyA: true}},
		{name: "tox id reduced to pubkey", in: keyA + "AABBCCDD1122", want: map[string]bool{keyA: true}},
		{name: "non hex dropped", in: strings.Repeat("Z", 64), want: map[string]bool{}},
		{name: "wrong length dropped", in: keyA[:32], want: map[string]bool{}},
		{name: "bad key does not drop good key", in: "nope," + keyA, want: map[string]bool{keyA: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAdmins(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseAdmins(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestApplyProxy(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantSet  bool
		wantHost string
		wantPort uint16
	}{
		{name: "empty leaves options untouched", in: "", wantSet: false},
		{name: "host port", in: "127.0.0.1:9050", wantSet: true, wantHost: "127.0.0.1", wantPort: 9050},
		{name: "auth is stripped", in: "user:pass@127.0.0.1:9050", wantSet: true, wantHost: "127.0.0.1", wantPort: 9050},
		{name: "bracketed IPv6", in: "[::1]:9050", wantSet: true, wantHost: "::1", wantPort: 9050},
		{name: "bare IPv6", in: "::1:9050", wantSet: true, wantHost: "::1", wantPort: 9050},
		{name: "no port ignored", in: "127.0.0.1", wantSet: false},
		{name: "bad port ignored", in: "127.0.0.1:nope", wantSet: false},
		{name: "port zero ignored", in: "127.0.0.1:0", wantSet: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := tox.NewToxOptions()
			applyProxy(opts, tc.in)

			if !tc.wantSet {
				if opts.Proxy_type == int32(tox.PROXY_TYPE_SOCKS5) {
					t.Fatalf("applyProxy(%q) enabled the proxy, want it left disabled", tc.in)
				}
				return
			}
			if opts.Proxy_type != int32(tox.PROXY_TYPE_SOCKS5) {
				t.Fatalf("applyProxy(%q): proxy type = %d, want SOCKS5", tc.in, opts.Proxy_type)
			}
			if opts.Proxy_host != tc.wantHost || opts.Proxy_port != tc.wantPort {
				t.Errorf("applyProxy(%q) = %q:%d, want %q:%d",
					tc.in, opts.Proxy_host, opts.Proxy_port, tc.wantHost, tc.wantPort)
			}
		})
	}
}

func TestGetenv(t *testing.T) {
	t.Setenv("TOXCBT_TEST_VAR", "value")
	if got := getenv("TOXCBT_TEST_VAR", "fallback"); got != "value" {
		t.Errorf("getenv = %q, want %q", got, "value")
	}
	t.Setenv("TOXCBT_TEST_VAR", "   ")
	if got := getenv("TOXCBT_TEST_VAR", "fallback"); got != "fallback" {
		t.Errorf("whitespace-only value should fall back, got %q", got)
	}
	if got := getenv("TOXCBT_TEST_UNSET_VAR", "fallback"); got != "fallback" {
		t.Errorf("getenv = %q, want %q", got, "fallback")
	}
}

func TestIterInterval(t *testing.T) {
	// time.NewTicker panics on a non-positive interval.
	for _, ms := range []int{-5, 0} {
		if got := iterInterval(ms); got <= 0 {
			t.Errorf("iterInterval(%d) = %v, want a positive duration", ms, got)
		}
	}
	if got := iterInterval(50); got != 50*time.Millisecond {
		t.Errorf("iterInterval(50) = %v, want 50ms", got)
	}
}

func TestCutWord(t *testing.T) {
	tests := []struct {
		in       string
		wantWord string
		wantRest string
	}{
		{in: "", wantWord: "", wantRest: ""},
		{in: "ping", wantWord: "ping", wantRest: ""},
		{in: "say 3 hello", wantWord: "say", wantRest: "3 hello"},
		{in: "say  3   hello", wantWord: "say", wantRest: "3   hello"},
		{in: "say\t3 hello", wantWord: "say", wantRest: "3 hello"},
		{in: "ping\nextra", wantWord: "ping", wantRest: "extra"},
		{in: "ping\r\n", wantWord: "ping", wantRest: ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			word, rest := cutWord(tc.in)
			if word != tc.wantWord || rest != tc.wantRest {
				t.Errorf("cutWord(%q) = %q,%q want %q,%q", tc.in, word, rest, tc.wantWord, tc.wantRest)
			}
		})
	}
}

func TestChunkMessageShortInputIsUnchanged(t *testing.T) {
	for _, s := range []string{"", "hi", strings.Repeat("x", 10)} {
		got := chunkMessage(s, 10)
		if !reflect.DeepEqual(got, []string{s}) {
			t.Errorf("chunkMessage(%q, 10) = %q, want one unchanged chunk", s, got)
		}
	}
}

func TestChunkMessageBreaksOnWhitespace(t *testing.T) {
	// "aaaa bbbbbb" with max 10: the space at index 4 is not past max/2, so the
	// break falls back to a hard cut; with the space at index 6 it is used.
	s := "aaaaaa bbbbbb"
	got := chunkMessage(s, 10)
	want := []string{"aaaaaa", "bbbbbb"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chunkMessage(%q, 10) = %q, want %q", s, got, want)
	}
}

func TestChunkMessageHardSplitsWhenNoBreakAvailable(t *testing.T) {
	s := strings.Repeat("x", 25)
	got := chunkMessage(s, 10)
	want := []string{"xxxxxxxxxx", "xxxxxxxxxx", "xxxxx"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("chunkMessage = %q, want %q", got, want)
	}
}

func TestChunkMessageDefaultsMax(t *testing.T) {
	s := strings.Repeat("x", tox.MAX_MESSAGE_LENGTH+50)
	for _, max := range []int{0, -1} {
		got := chunkMessage(s, max)
		if len(got) != 2 {
			t.Fatalf("chunkMessage(max=%d) produced %d chunks, want 2", max, len(got))
		}
		if len(got[0]) != tox.MAX_MESSAGE_LENGTH {
			t.Errorf("chunkMessage(max=%d) first chunk = %d bytes, want %d",
				max, len(got[0]), tox.MAX_MESSAGE_LENGTH)
		}
	}
}

// A byte-bounded cut can land inside a UTF-8 sequence; toxcore would then carry
// a truncated rune on the wire.
func TestChunkMessageNeverSplitsARune(t *testing.T) {
	tests := []struct {
		name string
		s    string
		max  int
	}{
		{name: "two byte runes", s: strings.Repeat("é", 200), max: 7},
		{name: "three byte runes", s: strings.Repeat("€", 200), max: 10},
		{name: "four byte runes", s: strings.Repeat("𝄞", 200), max: 10},
		{name: "mixed with spaces", s: strings.Repeat("héllo wörld ", 60), max: 13},
		{name: "cyrillic no spaces", s: strings.Repeat("привет", 100), max: 31},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chunks := chunkMessage(tc.s, tc.max)
			for i, c := range chunks {
				if !utf8.ValidString(c) {
					t.Errorf("chunk %d is not valid UTF-8: %q", i, c)
				}
				if len(c) > tc.max {
					t.Errorf("chunk %d is %d bytes, over the %d limit", i, len(c), tc.max)
				}
			}
			assertOnlyWhitespaceLost(t, tc.s, chunks)
		})
	}
}

func TestChunkMessageChunksStayWithinLimit(t *testing.T) {
	inputs := []string{
		strings.Repeat("word ", 500),
		strings.Repeat("a", 5000),
		strings.Repeat("line\n", 400),
		strings.Repeat(" ", 100) + strings.Repeat("x", 100),
		strings.Repeat("x", 100) + strings.Repeat(" ", 100),
	}
	for _, max := range []int{1, 2, 7, 64, tox.MAX_MESSAGE_LENGTH} {
		for _, s := range inputs {
			chunks := chunkMessage(s, max)
			for i, c := range chunks {
				if len(c) > max {
					t.Fatalf("max=%d: chunk %d is %d bytes", max, i, len(c))
				}
			}
			assertOnlyWhitespaceLost(t, s, chunks)
		}
	}
}

// Chunking may drop whitespace at a break point, but must not lose or reorder
// anything else.
func assertOnlyWhitespaceLost(t *testing.T, orig string, chunks []string) {
	t.Helper()
	strip := func(s string) string {
		return strings.NewReplacer(" ", "", "\n", "").Replace(s)
	}
	if got, want := strip(strings.Join(chunks, "")), strip(orig); got != want {
		t.Errorf("chunking lost or reordered content:\n got %d bytes\nwant %d bytes", len(got), len(want))
	}
}

func TestSendMessageChunksLongReplies(t *testing.T) {
	b, ft, _ := newTestBot(t, false)
	msg := strings.Repeat("x", tox.MAX_MESSAGE_LENGTH+10)

	if err := b.sendMessage(1, msg); err != nil {
		t.Fatalf("sendMessage: %v", err)
	}
	if len(ft.sent) != 2 {
		t.Fatalf("sent %d messages, want 2", len(ft.sent))
	}
	for i, m := range ft.sent {
		if m.friend != 1 {
			t.Errorf("chunk %d went to friend %d, want 1", i, m.friend)
		}
		if len(m.text) > tox.MAX_MESSAGE_LENGTH {
			t.Errorf("chunk %d is %d bytes, over the limit", i, len(m.text))
		}
	}
}

func TestSendMessageReportsAndStopsOnError(t *testing.T) {
	b, ft, _ := newTestBot(t, false)
	ft.sendErr = errors.New("friend not connected")

	err := b.sendMessage(1, strings.Repeat("x", tox.MAX_MESSAGE_LENGTH+10))
	if err == nil {
		t.Fatal("sendMessage returned nil, want the underlying send error")
	}
	if len(ft.sent) != 0 {
		t.Errorf("recorded %d sends after a failure, want 0", len(ft.sent))
	}
}

func TestHandleMessageEchoesNonCommands(t *testing.T) {
	b, ft, cmds := newTestBot(t, false)
	b.handleMessage(1, "hello there", cmds)

	if got := ft.texts(); !reflect.DeepEqual(got, []string{"echo: hello there"}) {
		t.Errorf("got %q, want the message echoed back", got)
	}
}

func TestHandleMessagePing(t *testing.T) {
	b, ft, cmds := newTestBot(t, false)
	b.handleMessage(1, "  /PING  ", cmds)

	if got := ft.texts(); !reflect.DeepEqual(got, []string{"pong"}) {
		t.Errorf("got %q, want [pong] (commands are trimmed and case-insensitive)", got)
	}
}

// A command followed by a newline rather than a space must still dispatch.
func TestHandleMessageSplitsOnAnyWhitespace(t *testing.T) {
	b, ft, cmds := newTestBot(t, false)
	b.handleMessage(1, "/ping\nstray", cmds)

	if got := ft.texts(); !reflect.DeepEqual(got, []string{"pong"}) {
		t.Errorf("got %q, want [pong]", got)
	}
}

func TestHandleMessageUnknownCommand(t *testing.T) {
	b, ft, cmds := newTestBot(t, false)
	b.handleMessage(1, "/nope", cmds)

	got := ft.texts()
	if len(got) != 1 || !strings.Contains(got[0], "unknown command") {
		t.Errorf("got %q, want an unknown-command reply", got)
	}
}

func TestHandleMessageDeniesAdminCommandsToStrangers(t *testing.T) {
	b, ft, cmds := newTestBot(t, false)

	for _, msg := range []string{"/friends", "/remove 1", "/say 1 hi", "/save"} {
		ft.sent = nil
		ft.deleted = nil
		b.handleMessage(1, msg, cmds)

		if got := ft.texts(); !reflect.DeepEqual(got, []string{"not authorized"}) {
			t.Errorf("%s: got %q, want [not authorized]", msg, got)
		}
		if len(ft.deleted) != 0 {
			t.Errorf("%s: performed a friend deletion despite being denied", msg)
		}
	}
}

// An unknown sender (public key lookup fails) must never be treated as admin,
// even when the admin set happens to contain the empty string.
func TestHandleMessageDeniesWhenPublicKeyIsUnknown(t *testing.T) {
	b, ft, cmds := newTestBot(t, true)
	b.admins[""] = true

	b.handleMessage(99, "/save", cmds) // friend 99 has no recorded public key

	if got := ft.texts(); !reflect.DeepEqual(got, []string{"not authorized"}) {
		t.Errorf("got %q, want [not authorized]", got)
	}
}

func TestHandleMessageAllowsAdminCommands(t *testing.T) {
	b, ft, cmds := newTestBot(t, true)
	b.handleMessage(1, "/friends", cmds)

	got := ft.texts()
	if len(got) != 1 || !strings.Contains(got[0], keyA) {
		t.Errorf("got %q, want the friend list including %s", got, keyA)
	}
}

func TestAdminMatchIsCaseInsensitive(t *testing.T) {
	b, ft, cmds := newTestBot(t, true)
	// toxcore reports uppercase keys; the admin set is normalized the same way.
	ft.pubKeys[1] = strings.ToLower(keyA)

	b.handleMessage(1, "/save", cmds)

	if got := ft.texts(); !reflect.DeepEqual(got, []string{"saved"}) {
		t.Errorf("got %q, want [saved]", got)
	}
}

func TestSayReportsDeliveryFailure(t *testing.T) {
	b, ft, cmds := newTestBot(t, true)
	ft.sendErr = errors.New("no such friend")

	reply := cmds["say"].run(&cmdCtx{bot: b, friend: 1, pubKey: keyA, args: "42 hello", isAdmin: true})

	if !strings.Contains(reply, "failed") {
		t.Errorf("/say replied %q, want a failure report rather than a false success", reply)
	}
}

func TestSayDeliversToTheRequestedFriend(t *testing.T) {
	b, ft, cmds := newTestBot(t, true)

	reply := cmds["say"].run(&cmdCtx{bot: b, friend: 1, pubKey: keyA, args: "7  hello world ", isAdmin: true})

	if reply != "sent" {
		t.Fatalf("/say replied %q, want \"sent\"", reply)
	}
	want := []sentMessage{{friend: 7, text: "hello world"}}
	if !reflect.DeepEqual(ft.sent, want) {
		t.Errorf("sent %+v, want %+v", ft.sent, want)
	}
}

func TestSayUsageErrors(t *testing.T) {
	b, _, cmds := newTestBot(t, true)
	for _, args := range []string{"", "7", "notanumber hello", "   "} {
		reply := cmds["say"].run(&cmdCtx{bot: b, friend: 1, pubKey: keyA, args: args, isAdmin: true})
		if !strings.HasPrefix(reply, "usage:") {
			t.Errorf("/say %q replied %q, want a usage hint", args, reply)
		}
	}
}

func TestRemoveDeletesAndPersists(t *testing.T) {
	b, ft, cmds := newTestBot(t, true)

	reply := cmds["remove"].run(&cmdCtx{bot: b, friend: 1, pubKey: keyA, args: " 3 ", isAdmin: true})

	if !strings.Contains(reply, "removed friend #3") {
		t.Errorf("reply = %q, want a removal confirmation", reply)
	}
	if !reflect.DeepEqual(ft.deleted, []uint32{3}) {
		t.Errorf("deleted %v, want [3]", ft.deleted)
	}
	// The friend list lives in savedata; losing it on restart would resurrect
	// the removed friend.
	if _, err := os.Stat(b.saveFile); err != nil {
		t.Errorf("savedata was not written after a friend-list change: %v", err)
	}
}

func TestRemoveRejectsBadArgument(t *testing.T) {
	b, ft, cmds := newTestBot(t, true)

	reply := cmds["remove"].run(&cmdCtx{bot: b, friend: 1, pubKey: keyA, args: "abc", isAdmin: true})

	if !strings.HasPrefix(reply, "usage:") {
		t.Errorf("reply = %q, want a usage hint", reply)
	}
	if len(ft.deleted) != 0 {
		t.Errorf("deleted %v, want nothing", ft.deleted)
	}
}

func TestRemoveReportsFailure(t *testing.T) {
	b, ft, cmds := newTestBot(t, true)
	ft.deleteErr = errors.New("no such friend")

	reply := cmds["remove"].run(&cmdCtx{bot: b, friend: 1, pubKey: keyA, args: "9", isAdmin: true})

	if !strings.Contains(reply, "failed") {
		t.Errorf("reply = %q, want a failure report", reply)
	}
}

func TestHelpHidesAdminCommandsFromStrangers(t *testing.T) {
	b, _, cmds := newTestBot(t, false)

	public := cmds["help"].run(&cmdCtx{bot: b, isAdmin: false})
	privileged := cmds["help"].run(&cmdCtx{bot: b, isAdmin: true})

	for _, name := range []string{"/ping", "/help", "/id", "/uptime", "/stats"} {
		if !strings.Contains(public, name) {
			t.Errorf("public help is missing %s:\n%s", name, public)
		}
	}
	for _, name := range []string{"/friends", "/remove", "/say", "/save"} {
		if strings.Contains(public, name) {
			t.Errorf("public help leaks admin command %s:\n%s", name, public)
		}
		if !strings.Contains(privileged, name) {
			t.Errorf("admin help is missing %s:\n%s", name, privileged)
		}
	}
}

func TestStatsReportsRuntimeState(t *testing.T) {
	b, ft, cmds := newTestBot(t, false)
	ft.friends = []uint32{1, 2, 3}

	reply := cmds["stats"].run(&cmdCtx{bot: b})

	for _, want := range []string{"test-bot", "testing", "CONNECTION_UDP", "friends: 3"} {
		if !strings.Contains(reply, want) {
			t.Errorf("stats reply missing %q:\n%s", want, reply)
		}
	}
}

func TestFriendsWithNoFriends(t *testing.T) {
	b, ft, cmds := newTestBot(t, true)
	ft.friends = nil

	if reply := cmds["friends"].run(&cmdCtx{bot: b, isAdmin: true}); reply != "no friends" {
		t.Errorf("reply = %q, want \"no friends\"", reply)
	}
}

func TestIDReportsAddress(t *testing.T) {
	b, ft, cmds := newTestBot(t, false)

	if reply := cmds["id"].run(&cmdCtx{bot: b}); !strings.Contains(reply, ft.address) {
		t.Errorf("reply = %q, want it to contain the Tox ID", reply)
	}
}

func TestSaveWritesAtomically(t *testing.T) {
	b, ft, _ := newTestBot(t, false)
	ft.savedata = []byte("profile-bytes")

	b.save()

	got, err := os.ReadFile(b.saveFile)
	if err != nil {
		t.Fatalf("read savedata: %v", err)
	}
	if string(got) != "profile-bytes" {
		t.Errorf("savedata = %q, want %q", got, "profile-bytes")
	}
	if _, err := os.Stat(b.saveFile + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file was left behind")
	}
	info, err := os.Stat(b.saveFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("savedata mode = %v, want 0600 (it holds the bot's private key)", perm)
	}
}

// GetSavedata panics on a zero-length buffer, and an empty write would destroy
// a working profile.
func TestSaveSkipsEmptySavedataWithoutClobbering(t *testing.T) {
	b, ft, _ := newTestBot(t, false)
	if err := os.WriteFile(b.saveFile, []byte("good-profile"), 0o600); err != nil {
		t.Fatal(err)
	}
	ft.savedata = nil

	b.save()

	got, err := os.ReadFile(b.saveFile)
	if err != nil {
		t.Fatalf("read savedata: %v", err)
	}
	if string(got) != "good-profile" {
		t.Errorf("savedata = %q, want the existing profile left intact", got)
	}
}

func TestSaveOverwritesPreviousProfile(t *testing.T) {
	b, ft, _ := newTestBot(t, false)
	ft.savedata = []byte("first")
	b.save()
	ft.savedata = []byte("second-and-longer")
	b.save()

	got, err := os.ReadFile(b.saveFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second-and-longer" {
		t.Errorf("savedata = %q, want the newest profile", got)
	}
}

func TestReadSavedataMissingFileStartsFresh(t *testing.T) {
	data, found, err := readSavedata(filepath.Join(t.TempDir(), "absent.tox"))
	if err != nil {
		t.Fatalf("a missing profile is not an error: %v", err)
	}
	if found || data != nil {
		t.Errorf("got found=%v data=%q, want no savedata", found, data)
	}
}

func TestReadSavedataEmptyFileStartsFresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.tox")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	data, found, err := readSavedata(path)
	if err != nil {
		t.Fatalf("an empty profile is not an error: %v", err)
	}
	if found || data != nil {
		t.Errorf("got found=%v data=%q, want no savedata", found, data)
	}
}

// toxProfile builds bytes with a valid plaintext tox-save header, matching what
// a real profile on disk starts with (00 00 00 00 1f 1b ed 15 ...).
func toxProfile(payload ...byte) []byte {
	head := make([]byte, savedataHeadSize)
	binary.LittleEndian.PutUint32(head[4:], savedataMagic)
	return append(head, payload...)
}

func TestToxProfileFixtureMatchesRealHeader(t *testing.T) {
	want := []byte{0x00, 0x00, 0x00, 0x00, 0x1f, 0x1b, 0xed, 0x15}
	if got := toxProfile(); !bytes.Equal(got, want) {
		t.Fatalf("fixture header = % x, want % x", got, want)
	}
}

func TestReadSavedataReturnsStoredProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.tox")
	profile := toxProfile('k', 'e', 'y')
	if err := os.WriteFile(path, profile, 0o600); err != nil {
		t.Fatal(err)
	}

	data, found, err := readSavedata(path)
	if err != nil {
		t.Fatalf("readSavedata: %v", err)
	}
	if !found || !bytes.Equal(data, profile) {
		t.Errorf("got found=%v data=% x, want the stored profile", found, data)
	}
}

// toxcore silently ignores a damaged profile and generates a new identity, then
// the next save overwrites the file. Refusing to start is the only way the
// operator finds out while the file is still recoverable.
func TestValidateSavedata(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "real header", data: toxProfile('x'), wantErr: false},
		{name: "header alone", data: toxProfile(), wantErr: false},
		{name: "empty", data: nil, wantErr: true},
		{name: "too short", data: []byte{0, 0, 0, 0, 0x1f}, wantErr: true},
		{name: "random garbage", data: []byte("not a tox profile at all"), wantErr: true},
		{name: "wrong magic", data: []byte{0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef}, wantErr: true},
		{name: "nonzero leading word", data: []byte{1, 0, 0, 0, 0x1f, 0x1b, 0xed, 0x15}, wantErr: true},
		{name: "byte-swapped magic", data: []byte{0, 0, 0, 0, 0x15, 0xed, 0x1b, 0x1f}, wantErr: true},
		{name: "encrypted profile", data: []byte("toxEsave\x00\x01\x02\x03"), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSavedata(tc.data)
			if tc.wantErr && err == nil {
				t.Errorf("validateSavedata(% x) = nil, want an error", tc.data)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateSavedata(% x) = %v, want nil", tc.data, err)
			}
		})
	}
}

// The encrypted case deserves its own message: desktop Tox clients write
// encrypted profiles by default, so pointing TOX_SAVEDATA at one is a likely
// mistake and "not a tox profile" would be misleading.
func TestValidateSavedataNamesEncryptedProfiles(t *testing.T) {
	err := validateSavedata([]byte("toxEsave\x00\x01\x02\x03"))
	if err == nil {
		t.Fatal("want an error for an encrypted profile")
	}
	if !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("error = %q, want it to mention encryption", err)
	}
}

func TestReadSavedataCorruptFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.tox")
	if err := os.WriteFile(path, []byte("garbage that is long enough"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, found, err := readSavedata(path); err == nil {
		t.Errorf("got found=%v err=nil, want an error rather than a silent new identity", found)
	}
}

// An unreadable profile must not be reported as "no savedata": the caller would
// start a fresh identity and abandon the Tox ID the file exists to preserve.
func TestReadSavedataUnreadableFileIsAnError(t *testing.T) {
	// A directory at the path fails ReadFile regardless of the test's uid.
	path := filepath.Join(t.TempDir(), "bot.tox")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, found, err := readSavedata(path); err == nil {
		t.Errorf("got found=%v err=nil, want an error rather than a silent fresh start", found)
	}
}

func TestReadSavedataUnreadablePermissionsAreAnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not deny access")
	}
	path := filepath.Join(t.TempDir(), "bot.tox")
	if err := os.WriteFile(path, []byte("profile"), 0o000); err != nil {
		t.Fatal(err)
	}

	if _, found, err := readSavedata(path); err == nil {
		t.Errorf("got found=%v err=nil, want an error for an unreadable profile", found)
	}
}

func TestEnsureWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bot.tox")

	if err := ensureWritable(path); err != nil {
		t.Fatalf("ensureWritable on a writable dir: %v", err)
	}
	if _, err := os.Stat(path + ".probe"); !os.IsNotExist(err) {
		t.Errorf("probe file was left behind")
	}
	// The probe must not disturb an existing profile.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("probe created the savedata file")
	}
}

func TestEnsureWritableDetectsAReadOnlyDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not deny access")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}

	if err := ensureWritable(filepath.Join(dir, "bot.tox")); err == nil {
		t.Error("ensureWritable succeeded on a read-only directory, want an error")
	}
}

func TestEnsureWritableLeavesAnExistingProfileIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bot.tox")
	if err := os.WriteFile(path, []byte("profile"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ensureWritable(path); err != nil {
		t.Fatalf("ensureWritable: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "profile" {
		t.Errorf("profile = %q (err %v), want it untouched", got, err)
	}
}

func TestWriteFileSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")

	if err := writeFileSync(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("writeFileSync: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want %q", got, "hello")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %v, want 0600", perm)
	}

	// Rewriting with less data must truncate, not leave a tail behind.
	if err := writeFileSync(path, []byte("hi"), 0o600); err != nil {
		t.Fatalf("writeFileSync (rewrite): %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "hi" {
		t.Errorf("content = %q, want %q", got, "hi")
	}
}

func TestWriteFileSyncReportsFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dir")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := writeFileSync(path, []byte("x"), 0o600); err == nil {
		t.Error("writeFileSync on a directory returned nil, want an error")
	}
}

func TestSaveCleansUpAfterAFailedWrite(t *testing.T) {
	b, _, _ := newTestBot(t, false)
	// A directory at the temp path makes the write fail.
	if err := os.Mkdir(b.saveFile+".tmp", 0o755); err != nil {
		t.Fatal(err)
	}

	b.save()

	if _, err := os.Stat(b.saveFile); !os.IsNotExist(err) {
		t.Errorf("savedata was created despite the write failing")
	}
}

func TestSaveCleansUpAfterAFailedRename(t *testing.T) {
	b, _, _ := newTestBot(t, false)
	// A directory at the destination makes the rename fail.
	if err := os.Mkdir(b.saveFile, 0o755); err != nil {
		t.Fatal(err)
	}

	b.save()

	if _, err := os.Stat(b.saveFile + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file was left behind after a failed rename")
	}
}

// *tox.Tox must keep satisfying the interface the bot is written against.
var _ toxClient = (*tox.Tox)(nil)
