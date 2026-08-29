package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	tox "github.com/TokTok/go-toxcore-c"
)

// resolveKey turns a command argument into a public key. Both a hex key (or a
// full Tox ID) and a "#3" friend number are accepted, because the first is
// what a peer can tell you about itself and the second is what /friends prints.
func (b *Bot) resolveKey(arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	if strings.HasPrefix(arg, "#") {
		fn, err := strconv.ParseUint(strings.TrimPrefix(arg, "#"), 10, 32)
		if err != nil {
			return "", fmt.Errorf("not a friend number: %s", arg)
		}
		pk := b.friendKey(uint32(fn))
		if pk == "" {
			return "", fmt.Errorf("no such friend: #%d", fn)
		}
		return pk, nil
	}
	return normalizePubKey(arg)
}

// friendNumberFor finds the friend number holding a public key, if any.
func (b *Bot) friendNumberFor(pubKey string) (uint32, bool) {
	for _, fn := range b.t.SelfGetFriendList() {
		if b.friendKey(fn) == pubKey {
			return fn, true
		}
	}
	return 0, false
}

func (b *Bot) buildCommands() map[string]*command {
	cmds := []*command{
		{name: "ping", help: "reply with pong", run: func(c *cmdCtx) string {
			return "pong"
		}},
		{name: "id", help: "show my Tox ID", run: func(c *cmdCtx) string {
			return "my tox id: " + b.t.SelfGetAddress()
		}},
		{name: "uptime", help: "how long I've been running", run: func(c *cmdCtx) string {
			return "uptime: " + time.Since(b.started).Round(time.Second).String()
		}},
		{name: "version", help: "show the build version", run: func(c *cmdCtx) string {
			return "version: " + b.version
		}},
		{name: "whoami", help: "show your public key and privilege level", run: func(c *cmdCtx) string {
			role := "user"
			if c.isAdmin {
				role = "admin"
			}
			key := c.pubKey
			if key == "" {
				key = "(unknown)"
			}
			return fmt.Sprintf("friend: #%d\nkey: %s\nrole: %s", c.friend, key, role)
		}},
		{name: "stats", help: "connection + friend stats", run: func(c *cmdCtx) string {
			name := b.t.SelfGetName()
			st, _ := b.t.SelfGetStatusMessage()
			return fmt.Sprintf(
				"name: %s\nstatus: %s\nconnection: %s\nfriends: %d\nuptime: %s\nqueued: %d\nrate-limited: %d",
				name, st, tox.ConnStatusString(b.connSt),
				b.t.SelfGetFriendListSize(), time.Since(b.started).Round(time.Second),
				b.state.queued(), b.metrics.rateLimited,
			)
		}},
		{name: "friends", admin: true, help: "list friends (admin)", run: func(c *cmdCtx) string {
			list := b.t.SelfGetFriendList()
			if len(list) == 0 {
				return "no friends"
			}
			var sb strings.Builder
			for _, fn := range list {
				pk, _ := b.t.FriendGetPublicKey(fn)
				st, _ := b.t.FriendGetConnectionStatus(fn)
				fmt.Fprintf(&sb, "#%d %s %s\n", fn, pk, tox.ConnStatusString(st))
			}
			return strings.TrimRight(sb.String(), "\n")
		}},
		{name: "remove", admin: true, help: "remove <friendNumber> (admin)", run: func(c *cmdCtx) string {
			fn, err := strconv.ParseUint(strings.TrimSpace(c.args), 10, 32)
			if err != nil {
				return "usage: /remove <friendNumber>"
			}
			if ok, err := b.t.FriendDelete(uint32(fn)); err != nil || !ok {
				return fmt.Sprintf("remove failed: ok=%v err=%v", ok, err)
			}
			b.save()
			return fmt.Sprintf("removed friend #%d", fn)
		}},
		{name: "say", admin: true, help: "say <friendNumber> <text> (admin)", run: func(c *cmdCtx) string {
			numStr, text := cutWord(strings.TrimSpace(c.args))
			if text == "" {
				return "usage: /say <friendNumber> <text>"
			}
			fn, err := strconv.ParseUint(numStr, 10, 32)
			if err != nil {
				return "usage: /say <friendNumber> <text>"
			}
			res, err := b.deliver(uint32(fn), text)
			if err != nil {
				return fmt.Sprintf("send to #%d failed: %v", fn, err)
			}
			if res.queued {
				return fmt.Sprintf("#%d is offline; queued", fn)
			}
			// The reply lands now; the confirmation follows when the friend's
			// client acknowledges the message.
			b.trackReceipt(uint32(fn), res.id, c.friend, fmt.Sprintf("#%d", fn))
			return "sent"
		}},
		{name: "broadcast", admin: true, help: "broadcast <text> — message every friend (admin)",
			run: func(c *cmdCtx) string {
				text := strings.TrimSpace(c.args)
				if text == "" {
					return "usage: /broadcast <text>"
				}
				var sent, queued, failed int
				for _, fn := range b.t.SelfGetFriendList() {
					if fn == c.friend {
						continue // the sender already has the text
					}
					res, err := b.deliver(fn, "[broadcast] "+text)
					switch {
					case err != nil:
						failed++
					case res.queued:
						queued++
					default:
						sent++
					}
				}
				return fmt.Sprintf("broadcast: sent %d, queued %d, failed %d", sent, queued, failed)
			}},
		{name: "save", admin: true, help: "persist savedata now (admin)", run: func(c *cmdCtx) string {
			b.save()
			return "saved"
		}},
		{name: "nospam", admin: true, help: "nospam [8 hex digits] — rotate the Tox ID's nospam (admin)",
			run: func(c *cmdCtx) string {
				arg := strings.TrimSpace(c.args)
				var value uint32
				if arg == "" {
					var buf [4]byte
					if _, err := rand.Read(buf[:]); err != nil {
						return "nospam: " + err.Error()
					}
					value = binary.BigEndian.Uint32(buf[:])
				} else {
					parsed, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(arg), "0x"), 16, 32)
					if err != nil {
						return "usage: /nospam [8 hex digits]"
					}
					value = uint32(parsed)
				}
				b.t.SelfSetNospam(value)
				b.save()
				// Existing friends are unaffected: the nospam changes the Tox
				// ID, not the public key the friendship is bound to.
				return fmt.Sprintf("nospam set to %08X\nnew tox id: %s", b.t.SelfGetNospam(), b.t.SelfGetAddress())
			}},
		{name: "admin", admin: true, help: "admin [add|remove <key|#n>] — manage runtime admins (admin)",
			run: func(c *cmdCtx) string {
				verb, rest := cutWord(strings.TrimSpace(c.args))
				switch strings.ToLower(verb) {
				case "", "list":
					var sb strings.Builder
					sb.WriteString("admins:\n")
					for _, key := range sortedKeys(b.admins) {
						fmt.Fprintf(&sb, "%s (env)\n", key)
					}
					for _, key := range b.state.adminList() {
						fmt.Fprintf(&sb, "%s (runtime)\n", key)
					}
					return strings.TrimRight(sb.String(), "\n")
				case "add":
					key, err := b.resolveKey(rest)
					if err != nil {
						return "usage: /admin add <pubkey|#friendNumber>: " + err.Error()
					}
					if b.admins[key] {
						return "already an admin (from TOX_ADMINS)"
					}
					if !b.state.addAdmin(key) {
						return "already an admin"
					}
					b.flushState()
					return "added admin " + key
				case "remove":
					key, err := b.resolveKey(rest)
					if err != nil {
						return "usage: /admin remove <pubkey|#friendNumber>: " + err.Error()
					}
					if b.admins[key] {
						// Otherwise a compromised admin could lock the
						// operator out of their own deployment.
						return "that admin comes from TOX_ADMINS and cannot be removed at runtime"
					}
					if !b.state.removeAdmin(key) {
						return "not a runtime admin"
					}
					b.flushState()
					return "removed admin " + key
				default:
					return "usage: /admin [list|add <key>|remove <key>]"
				}
			}},
		{name: "block", admin: true, help: "block <key|#n> — block a peer and drop the friendship (admin)",
			run: func(c *cmdCtx) string {
				key, err := b.resolveKey(c.args)
				if err != nil {
					return "usage: /block <pubkey|#friendNumber>: " + err.Error()
				}
				if b.admins[key] || b.state.isAdmin(key) {
					return "refusing to block an admin"
				}
				if !b.state.block(key) {
					return "already blocked"
				}
				removed := ""
				if fn, ok := b.friendNumberFor(key); ok {
					if ok, err := b.t.FriendDelete(fn); ok && err == nil {
						removed = fmt.Sprintf(" and removed friend #%d", fn)
					}
				}
				b.save()
				return "blocked " + key + removed
			}},
		{name: "unblock", admin: true, help: "unblock <key> (admin)", run: func(c *cmdCtx) string {
			key, err := b.resolveKey(c.args)
			if err != nil {
				return "usage: /unblock <pubkey>: " + err.Error()
			}
			if !b.state.unblock(key) {
				return "not blocked"
			}
			b.flushState()
			return "unblocked " + key
		}},
		{name: "blocked", admin: true, help: "list blocked peers (admin)", run: func(c *cmdCtx) string {
			list := b.state.blockedList()
			if len(list) == 0 {
				return "nothing blocked"
			}
			sort.Strings(list)
			return strings.Join(list, "\n")
		}},
		{name: "outbox", admin: true, help: "outbox [clear] — messages waiting for offline friends (admin)",
			run: func(c *cmdCtx) string {
				if strings.EqualFold(strings.TrimSpace(c.args), "clear") {
					n := b.state.clearOutbox()
					b.flushState()
					return fmt.Sprintf("dropped %d queued message(s)", n)
				}
				lines := b.state.outboxSummary()
				if len(lines) == 0 {
					return "outbox is empty"
				}
				return fmt.Sprintf("%d queued message(s):\n%s", b.state.queued(), strings.Join(lines, "\n"))
			}},
		{name: "audit", admin: true, help: "audit [n] — last n audit entries (admin)", run: func(c *cmdCtx) string {
			n := 10
			if arg := strings.TrimSpace(c.args); arg != "" {
				parsed, err := strconv.Atoi(arg)
				if err != nil || parsed <= 0 {
					return "usage: /audit [n]"
				}
				n = parsed
			}
			lines, err := b.audit.tail(n)
			if err != nil {
				return "audit read failed: " + err.Error()
			}
			if len(lines) == 0 {
				return "audit log is empty"
			}
			return strings.Join(lines, "\n")
		}},
	}

	m := map[string]*command{}
	for _, c := range cmds {
		m[c.name] = c
	}
	// /help is built from the registry itself.
	m["help"] = &command{name: "help", help: "list commands", run: func(c *cmdCtx) string {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		var sb strings.Builder
		sb.WriteString("commands:\n")
		for _, n := range names {
			cmd := m[n]
			if cmd.admin && !c.isAdmin {
				continue
			}
			tag := ""
			if cmd.admin {
				tag = " *"
			}
			fmt.Fprintf(&sb, "/%s%s — %s\n", cmd.name, tag, cmd.help)
		}
		return strings.TrimRight(sb.String(), "\n")
	}}
	return m
}
