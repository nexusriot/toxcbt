package main

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// bootstrapNode is one DHT entry. tcp is the port to register as a TCP relay,
// which is a different service from the UDP DHT port and frequently a
// different number (3389 and 443 are common); 0 means the node offers none.
type bootstrapNode struct {
	host string
	port uint16 // UDP DHT port
	tcp  uint16 // TCP relay port, 0 = do not add as a relay
	key  string // hex public key
}

func (n bootstrapNode) String() string {
	if n.tcp == 0 {
		return fmt.Sprintf("%s:%d", n.host, n.port)
	}
	return fmt.Sprintf("%s:%d/%d", n.host, n.port, n.tcp)
}

// dhtDialer is the slice of the Tox API the bootstrapper needs.
type dhtDialer interface {
	Bootstrap(addr string, port uint16, pubkey string) (bool, error)
	AddTcpRelay(addr string, port uint16, pubkey string) (bool, error)
}

// TOX_BOOTSTRAP_NODES format:
// host:port[/tcpport]:pubkeyhex,host:port[/tcpport]:pubkeyhex,...
//
// The TCP port defaults to the UDP port, which most public nodes also serve;
// "/0" opts a node out of being used as a relay.
func parseBootstrapEnv(s string) []bootstrapNode {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	var out []bootstrapNode
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		// The public key is the last field, so split from the right: anything
		// before it may be an IPv6 literal full of colons.
		addr, keyPart, ok := cutLast(item, ":")
		if !ok {
			slog.Warn("bootstrap entry skipped", "reason", "need host:port:pubkey", "entry", item)
			continue
		}
		host, port, tcp, err := parseNodeAddr(addr)
		if err != nil {
			slog.Warn("bootstrap entry skipped", "reason", err, "entry", item)
			continue
		}
		// A key of the wrong length is not merely useless: toxcore reads
		// exactly 32 bytes from it, and an empty one panics the binding.
		pubKey, err := normalizePubKey(keyPart)
		if err != nil {
			slog.Warn("bootstrap entry skipped", "reason", "bad pubkey: "+err.Error(), "entry", item)
			continue
		}

		out = append(out, bootstrapNode{host: host, port: port, tcp: tcp, key: pubKey})
	}
	return out
}

// parseNodeAddr splits "host:port[/tcpport]" into its parts. The optional TCP
// port is taken off first so the rest stays a plain host:port for
// parseHostPort, which is what keeps IPv6 literals working.
func parseNodeAddr(s string) (host string, udp, tcp uint16, err error) {
	base, tcpStr, hasTCP := cutLast(s, "/")
	host, udp, err = parseHostPort(base)
	if err != nil {
		return "", 0, 0, err
	}
	if !hasTCP {
		return host, udp, udp, nil
	}
	p64, err := strconv.ParseUint(strings.TrimSpace(tcpStr), 10, 16)
	if err != nil {
		return "", 0, 0, fmt.Errorf("bad tcp port: %w", err)
	}
	return host, udp, uint16(p64), nil
}

func defaultBootstrap() []bootstrapNode {
	return []bootstrapNode{
		{"tox.abilinski.com", 33445, 33445, "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7E"},
		{"144.217.167.73", 33445, 33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C"},
		{"tox1.mf-net.eu", 33445, 3389, "B3E5FA80DC8EBD1149AD2AB35ED8B85BD546DEDE261CA593234C619249419506"},
		{"205.185.115.131", 53, 443, "3091C6BEB2A993F13311F0F56F9E7C6EB47C1EAF9AE81E5CBD5D8AA6BC1C0E71"},
	}
}

// bootstrapper re-runs bootstrapping while the bot is offline.
//
// Bootstrapping once at startup is not enough in either of the two situations
// that actually happen: a container that starts before its network is up logs
// four failures and then waits forever, and a bot whose relays all go away
// mid-run has nothing left to reconnect through. Attempts back off so a long
// outage does not turn into a packet storm.
type bootstrapper struct {
	nodes    []bootstrapNode
	min      time.Duration
	max      time.Duration
	backoff  time.Duration
	nextAt   time.Time
	attempts int
}

func newBootstrapper(nodes []bootstrapNode, min, max time.Duration) *bootstrapper {
	return &bootstrapper{nodes: nodes, min: min, max: max, backoff: min}
}

// due reports whether another attempt is allowed yet.
func (b *bootstrapper) due(now time.Time) bool {
	return b != nil && len(b.nodes) > 0 && (b.nextAt.IsZero() || !now.Before(b.nextAt))
}

// run bootstraps every node and registers each as a TCP relay, then schedules
// the next attempt. Both calls matter: tox_bootstrap seeds the DHT over UDP,
// but a bot with UDP unavailable — which is every proxied deployment, since
// toxcore refuses to bind UDP behind a proxy — can only reach the network
// through a TCP relay.
func (b *bootstrapper) run(d dhtDialer, now time.Time) (nodes, relays int) {
	if b == nil {
		return 0, 0
	}
	b.attempts++
	for _, n := range b.nodes {
		if ok, err := d.Bootstrap(n.host, n.port, n.key); ok && err == nil {
			nodes++
		} else {
			slog.Warn("bootstrap failed", "node", n.String(), "ok", ok, "err", err)
		}
		if n.tcp == 0 {
			continue
		}
		if ok, err := d.AddTcpRelay(n.host, n.tcp, n.key); ok && err == nil {
			relays++
		} else {
			slog.Warn("tcp relay failed", "node", n.String(), "ok", ok, "err", err)
		}
	}

	b.nextAt = now.Add(b.backoff)
	if b.backoff *= 2; b.backoff > b.max {
		b.backoff = b.max
	}
	return nodes, relays
}

// connected resets the backoff so the next outage retries promptly.
func (b *bootstrapper) connected() {
	if b == nil {
		return
	}
	b.backoff = b.min
	b.nextAt = time.Time{}
}
