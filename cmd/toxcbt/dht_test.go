package main

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestParseNodeAddr(t *testing.T) {
	tests := []struct {
		in      string
		host    string
		udp     uint16
		tcp     uint16
		wantErr bool
	}{
		{in: "h:33445", host: "h", udp: 33445, tcp: 33445},
		{in: "h:33445/3389", host: "h", udp: 33445, tcp: 3389},
		{in: "h:33445/0", host: "h", udp: 33445, tcp: 0},
		{in: "[2001:db8::1]:33445/443", host: "2001:db8::1", udp: 33445, tcp: 443},
		{in: "::1:33445/443", host: "::1", udp: 33445, tcp: 443},
		{in: "h:33445/nope", wantErr: true},
		{in: "h:33445/70000", wantErr: true},
		{in: "h:0/3389", wantErr: true},
	}
	for _, tc := range tests {
		host, udp, tcp, err := parseNodeAddr(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseNodeAddr(%q) = %q %d %d, want an error", tc.in, host, udp, tcp)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseNodeAddr(%q) failed: %v", tc.in, err)
			continue
		}
		if host != tc.host || udp != tc.udp || tcp != tc.tcp {
			t.Errorf("parseNodeAddr(%q) = %q %d %d, want %q %d %d",
				tc.in, host, udp, tcp, tc.host, tc.udp, tc.tcp)
		}
	}
}

func TestParseBootstrapEnvTCPPort(t *testing.T) {
	got := parseBootstrapEnv("h:33445/3389:" + keyA + ",g:33445:" + keyB)
	want := []bootstrapNode{
		{"h", 33445, 3389, keyA},
		{"g", 33445, 33445, keyB},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// Every default node must be usable as a TCP relay, because a proxied bot has
// no UDP at all and would otherwise never connect.
func TestDefaultBootstrapNodesOfferTCPRelays(t *testing.T) {
	for _, n := range defaultBootstrap() {
		if n.tcp == 0 {
			t.Errorf("default node %s has no TCP relay port", n.host)
		}
	}
}

// fakeDialer records what the bootstrapper asked toxcore to do.
type fakeDialer struct {
	boots   []string
	relays  []string
	bootErr error
}

func (d *fakeDialer) Bootstrap(addr string, port uint16, pubkey string) (bool, error) {
	if d.bootErr != nil {
		return false, d.bootErr
	}
	d.boots = append(d.boots, addr)
	return true, nil
}

func (d *fakeDialer) AddTcpRelay(addr string, port uint16, pubkey string) (bool, error) {
	d.relays = append(d.relays, addr)
	return true, nil
}

func TestBootstrapperAddsRelaysAlongsideBootstrap(t *testing.T) {
	d := &fakeDialer{}
	bs := newBootstrapper([]bootstrapNode{
		{"a", 33445, 3389, keyA},
		{"b", 33445, 0, keyB}, // opted out of relaying
	}, time.Second, time.Minute)

	nodes, relays := bs.run(d, time.Now())

	if nodes != 2 || relays != 1 {
		t.Errorf("run() = %d nodes, %d relays; want 2, 1", nodes, relays)
	}
	if !reflect.DeepEqual(d.boots, []string{"a", "b"}) {
		t.Errorf("bootstrapped %v, want both nodes", d.boots)
	}
	if !reflect.DeepEqual(d.relays, []string{"a"}) {
		t.Errorf("relays %v, want only the node with a TCP port", d.relays)
	}
}

func TestBootstrapperBacksOffAndResets(t *testing.T) {
	d := &fakeDialer{bootErr: errors.New("network unreachable")}
	start := time.Unix(1700000000, 0)
	bs := newBootstrapper([]bootstrapNode{{"a", 33445, 3389, keyA}}, 10*time.Second, 40*time.Second)

	if !bs.due(start) {
		t.Fatal("first attempt should be due immediately")
	}
	bs.run(d, start)
	if bs.due(start.Add(9 * time.Second)) {
		t.Error("retried before the backoff elapsed")
	}
	if !bs.due(start.Add(10 * time.Second)) {
		t.Error("should be due after the backoff")
	}

	// Each failure doubles the wait until it reaches the cap.
	for i, want := range []time.Duration{20, 40, 40} {
		now := start.Add(time.Duration(i+1) * time.Hour)
		bs.run(d, now)
		if got := bs.nextAt.Sub(now); got != want*time.Second {
			t.Errorf("attempt %d scheduled the next retry in %s, want %s", i+2, got, want*time.Second)
		}
	}

	bs.connected()
	if bs.backoff != 10*time.Second {
		t.Errorf("backoff after reconnect = %s, want the minimum", bs.backoff)
	}
	if !bs.due(start) {
		t.Error("a reconnect should clear the next-attempt time")
	}
}

func TestBootstrapperWithoutNodesIsNeverDue(t *testing.T) {
	bs := newBootstrapper(nil, time.Second, time.Minute)
	if bs.due(time.Now()) {
		t.Error("a bootstrapper with no nodes has nothing to do")
	}
}
