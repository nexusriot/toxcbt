package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// healthSnapshot is an immutable copy of everything the HTTP endpoints report.
//
// The event loop owns all bot state and toxcore is not goroutine-safe, so the
// HTTP handlers never touch either: the loop publishes a snapshot and the
// handlers serve whatever the last one said.
type healthSnapshot struct {
	Version       string  `json:"version"`
	ToxID         string  `json:"tox_id"`
	Connection    string  `json:"connection"`
	Online        bool    `json:"online"`
	Friends       int     `json:"friends"`
	FriendsOnline int     `json:"friends_online"`
	UptimeSeconds float64 `json:"uptime_seconds"`
	MessagesIn    uint64  `json:"messages_in"`
	MessagesOut   uint64  `json:"messages_out"`
	Commands      uint64  `json:"commands"`
	RateLimited   uint64  `json:"rate_limited"`
	Queued        int     `json:"queued"`
	Delivered     uint64  `json:"delivered"`
	RequestsOK    uint64  `json:"friend_requests_accepted"`
	RequestsNo    uint64  `json:"friend_requests_rejected"`
	SaveErrors    uint64  `json:"save_errors"`
	LastSaveUnix  int64   `json:"last_save_unix"`
}

// healthServer exposes /healthz and /metrics. A nil *healthServer is a working
// no-op, which is what an unset TOX_HEALTH_ADDR produces.
type healthServer struct {
	addr string
	snap atomic.Pointer[healthSnapshot]
	srv  *http.Server
}

func newHealthServer(addr string) *healthServer {
	if strings.TrimSpace(addr) == "" {
		return nil
	}
	h := &healthServer{addr: addr}
	h.publish(healthSnapshot{Connection: "CONNECTION_NONE"})
	h.srv = &http.Server{
		Addr:              addr,
		Handler:           h.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return h
}

func (h *healthServer) publish(s healthSnapshot) {
	if h == nil {
		return
	}
	h.snap.Store(&s)
}

func (h *healthServer) current() healthSnapshot {
	if h == nil {
		return healthSnapshot{}
	}
	if s := h.snap.Load(); s != nil {
		return *s
	}
	return healthSnapshot{}
}

func (h *healthServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		s := h.current()
		code := http.StatusServiceUnavailable
		if s.Online {
			code = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(s)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(renderMetrics(h.current())))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("toxcbt\n/healthz\n/metrics\n"))
	})
	return mux
}

// start binds the listener synchronously so a busy port is reported at
// startup, then serves in the background.
func (h *healthServer) start() error {
	if h == nil {
		return nil
	}
	ln, err := net.Listen("tcp", h.addr)
	if err != nil {
		return err
	}
	slog.Info("health endpoint listening", "addr", ln.Addr().String())
	go func() {
		if err := h.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("health endpoint stopped", "err", err)
		}
	}()
	return nil
}

func (h *healthServer) shutdown(ctx context.Context) {
	if h == nil {
		return
	}
	_ = h.srv.Shutdown(ctx)
}

// renderMetrics writes the snapshot in Prometheus text exposition format.
// Hand-rolling it keeps the bot dependency-free for the sake of one endpoint.
func renderMetrics(s healthSnapshot) string {
	var b strings.Builder
	metric := func(name, help, typ string, value float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %g\n", name, help, name, typ, name, value)
	}

	fmt.Fprintf(&b, "# HELP toxcbt_build_info Build information.\n# TYPE toxcbt_build_info gauge\n")
	fmt.Fprintf(&b, "toxcbt_build_info{version=%q} 1\n", escapeLabel(s.Version))

	fmt.Fprintf(&b, "# HELP toxcbt_connection_state Current DHT connection state.\n"+
		"# TYPE toxcbt_connection_state gauge\n")
	for _, state := range []string{"CONNECTION_NONE", "CONNECTION_TCP", "CONNECTION_UDP"} {
		value := 0
		if s.Connection == state {
			value = 1
		}
		fmt.Fprintf(&b, "toxcbt_connection_state{state=%q} %d\n", escapeLabel(state), value)
	}

	metric("toxcbt_up", "1 when the bot is connected to the Tox network.", "gauge", boolToFloat(s.Online))
	metric("toxcbt_uptime_seconds", "Seconds since the bot started.", "gauge", s.UptimeSeconds)
	metric("toxcbt_friends", "Number of friends in the friend list.", "gauge", float64(s.Friends))
	metric("toxcbt_friends_online", "Number of friends currently connected.", "gauge", float64(s.FriendsOnline))
	metric("toxcbt_messages_received_total", "Friend messages received.", "counter", float64(s.MessagesIn))
	metric("toxcbt_messages_sent_total", "Message chunks sent.", "counter", float64(s.MessagesOut))
	metric("toxcbt_messages_delivered_total", "Messages confirmed by a read receipt.", "counter", float64(s.Delivered))
	metric("toxcbt_commands_total", "Commands executed.", "counter", float64(s.Commands))
	metric("toxcbt_rate_limited_total", "Messages dropped by the rate limiter.", "counter", float64(s.RateLimited))
	metric("toxcbt_outbox_queued", "Messages waiting for a friend to come online.", "gauge", float64(s.Queued))
	metric("toxcbt_friend_requests_accepted_total", "Friend requests accepted.", "counter", float64(s.RequestsOK))
	metric("toxcbt_friend_requests_rejected_total", "Friend requests rejected by policy.", "counter", float64(s.RequestsNo))
	metric("toxcbt_save_errors_total", "Failed profile or state writes.", "counter", float64(s.SaveErrors))
	metric("toxcbt_last_save_timestamp_seconds", "Unix time of the last successful profile save.",
		"gauge", float64(s.LastSaveUnix))
	return b.String()
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// escapeLabel escapes a Prometheus label value; %q handles the quoting rules
// once backslashes and newlines are already escaped by Go's own quoting.
func escapeLabel(s string) string {
	return strings.ReplaceAll(s, `"`, `'`)
}
