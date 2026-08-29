package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewHealthServerDisabledWithoutAnAddress(t *testing.T) {
	h := newHealthServer("  ")
	if h != nil {
		t.Fatal("an empty address should disable the endpoint")
	}
	// Every method has to tolerate that.
	h.publish(healthSnapshot{})
	if err := h.start(); err != nil {
		t.Errorf("start on a disabled server: %v", err)
	}
	if got := h.current(); got.Version != "" {
		t.Errorf("current() = %+v, want the zero snapshot", got)
	}
}

func TestHealthzReportsStatusCodeFromConnection(t *testing.T) {
	h := newHealthServer(":0")
	srv := httptest.NewServer(h.handler())
	defer srv.Close()

	get := func() (int, healthSnapshot) {
		resp, err := http.Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var snap healthSnapshot
		if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
			t.Fatalf("decoding /healthz: %v", err)
		}
		return resp.StatusCode, snap
	}

	code, _ := get()
	if code != http.StatusServiceUnavailable {
		t.Errorf("offline /healthz = %d, want 503 so orchestrators notice", code)
	}

	h.publish(healthSnapshot{Online: true, Connection: "CONNECTION_UDP", Friends: 3, Version: "v1"})
	code, snap := get()
	if code != http.StatusOK {
		t.Errorf("online /healthz = %d, want 200", code)
	}
	if snap.Friends != 3 || snap.Version != "v1" {
		t.Errorf("body = %+v, want the published snapshot", snap)
	}
}

func TestMetricsEndpointRendersTheSnapshot(t *testing.T) {
	h := newHealthServer(":0")
	h.publish(healthSnapshot{
		Version: "v9", Connection: "CONNECTION_TCP", Online: true,
		Friends: 2, FriendsOnline: 1, MessagesIn: 5, Queued: 4, RateLimited: 7,
	})
	srv := httptest.NewServer(h.handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	for _, want := range []string{
		`toxcbt_build_info{version="v9"} 1`,
		`toxcbt_connection_state{state="CONNECTION_TCP"} 1`,
		`toxcbt_connection_state{state="CONNECTION_UDP"} 0`,
		"toxcbt_up 1",
		"toxcbt_friends 2",
		"toxcbt_friends_online 1",
		"toxcbt_messages_received_total 5",
		"toxcbt_outbox_queued 4",
		"toxcbt_rate_limited_total 7",
		"# TYPE toxcbt_messages_received_total counter",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics output is missing %q:\n%s", want, text)
		}
	}
}

func TestMetricsLabelsSurviveAWeirdVersion(t *testing.T) {
	out := renderMetrics(healthSnapshot{Version: `v1"; injected="yes`})
	if strings.Contains(out, `injected="yes"`) {
		t.Errorf("a quote in the version escaped its label:\n%s", out)
	}
	// The line must still parse as a single labelled sample.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "toxcbt_build_info{") && strings.Count(line, `"`) != 2 {
			t.Errorf("build_info line has unbalanced quoting: %s", line)
		}
	}
}

func TestHealthUnknownPathIs404(t *testing.T) {
	h := newHealthServer(":0")
	srv := httptest.NewServer(h.handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/secrets")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}
