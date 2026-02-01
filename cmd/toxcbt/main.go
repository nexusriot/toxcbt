package main

import (
	"context"
	"encoding/hex"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	tox "github.com/TokTok/go-toxcore-c"
)

const (
	defaultName   = "go-tox-bot"
	defaultStatus = "echo bot"
)

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
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

	opts := tox.NewToxOptions()

	// Load savedata if present (identity / keys)
	if b, err := tox.LoadSavedata(saveFile); err == nil && len(b) > 0 {
		opts.Savedata_type = tox.SAVEDATA_TYPE_TOX_SAVE
		opts.Savedata_data = b
		log.Printf("loaded savedata: %s (%d bytes)", saveFile, len(b))
	} else {
		log.Printf("no savedata found, starting fresh (%v)", err)
	}

	t := tox.NewTox(opts)
	if t == nil {
		log.Fatal("failed to create tox instance")
	}
	defer t.Kill()

	_ = t.SelfSetName(name)
	_, _ = t.SelfSetStatusMessage(status)

	log.Printf("Tox ID: %s", t.SelfGetAddress())
	log.Printf("Public Key: %s", t.SelfGetPublicKey())

	// Bootstrap nodes
	bootstrapNodes := []struct {
		host string
		port uint16
		key  string // hex public key (64 hex chars)
	}{
		{"tox.abilinski.com", 33445, "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E"},
		{"144.217.167.73", 33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C"},
	}

	for _, n := range bootstrapNodes {
		if _, err := hex.DecodeString(n.key); err != nil {
			log.Printf("skip bootstrap (bad pubkey hex) %s:%d: %v", n.host, n.port, err)
			continue
		}
		ok, err := t.Bootstrap(n.host, n.port, n.key) // (bool, error) :contentReference[oaicite:1]{index=1}
		if err != nil || !ok {
			log.Printf("bootstrap failed %s:%d: ok=%v err=%v", n.host, n.port, ok, err)
		} else {
			log.Printf("bootstrapped %s:%d", n.host, n.port)
		}
	}

	// Auto-accept friend requests
	t.CallbackFriendRequestAdd(func(_ *tox.Tox, pubKey string, msg string, _ interface{}) {
		log.Printf("friend request from %s msg=%q", pubKey, msg)
		fn, err := t.FriendAddNorequest(pubKey)
		if err != nil {
			log.Printf("accept failed: %v", err)
			return
		}
		log.Printf("friend accepted: #%d", fn)
	}, nil)

	// In v0.2.17 the friend-message callback type does NOT include mtype.
	// So the signature must be: func(*tox.Tox, uint32, string, interface{})
	t.CallbackFriendMessageAdd(func(_ *tox.Tox, friend uint32, message string, _ interface{}) {
		msg := strings.TrimSpace(message)
		log.Printf("msg from %d: %q", friend, msg)

		switch msg {
		case "/ping":
			_, _ = t.FriendSendMessage(friend, "pong")
		case "/id":
			_, _ = t.FriendSendMessage(friend, "my tox id: "+t.SelfGetAddress())
		default:
			_, _ = t.FriendSendMessage(friend, "echo: "+message)
		}
	}, nil)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	saveTick := time.NewTicker(30 * time.Second)
	defer saveTick.Stop()

	log.Println("bot started")

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			save(t, saveFile)
			return

		case <-saveTick.C:
			save(t, saveFile)

		default:
			t.Iterate()
			time.Sleep(time.Duration(t.IterationInterval()) * time.Millisecond)
		}
	}
}

func save(t *tox.Tox, path string) {
	tmp := path + ".tmp"

	data := t.GetSavedata()
	if len(data) == 0 {
		log.Printf("save skipped: empty savedata")
		return
	}

	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("save failed: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		log.Printf("save rename failed: %v", err)
		return
	}
	log.Printf("saved: %s (%d bytes)", path, len(data))
}
