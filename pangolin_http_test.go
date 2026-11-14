package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// newHangingServer returns a server whose handler never answers until the
// test finishes, simulating a Pangolin instance that accepted the connection
// but stopped responding.
func newHangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	return srv
}

// returnsWithin runs fn and fails the test if it has not returned by limit.
func returnsWithin(t *testing.T, name string, limit time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s did not return within %v against a hanging server", name, limit)
	}
}

func TestPangolinHTTPClientHasTimeout(t *testing.T) {
	if pangolinHTTPClient.Timeout <= 0 {
		t.Fatalf("pangolinHTTPClient.Timeout = %v, want a positive bound", pangolinHTTPClient.Timeout)
	}
}

func TestPangolinCallsReturnWhenServerHangs(t *testing.T) {
	orig := pangolinHTTPClient
	pangolinHTTPClient = &http.Client{Timeout: 200 * time.Millisecond}
	t.Cleanup(func() { pangolinHTTPClient = orig })

	srv := newHangingServer(t)
	const limit = 3 * time.Second

	returnsWithin(t, "sendPeerBandwidthBatch", limit, func() {
		err := sendPeerBandwidthBatch(srv.URL, []PeerBandwidth{{PublicKey: "k", BytesIn: 1}})
		if err == nil {
			t.Error("sendPeerBandwidthBatch returned nil error against a hanging server")
		}
	})

	origNotify := notifyURL
	notifyURL = srv.URL
	t.Cleanup(func() { notifyURL = origNotify })
	returnsWithin(t, "notifyPeerChange", limit, func() {
		notifyPeerChange("add", "k")
	})

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	returnsWithin(t, "loadRemoteConfig", limit, func() {
		if _, err := loadRemoteConfig(srv.URL, key, ""); err == nil {
			t.Error("loadRemoteConfig returned nil error against a hanging server")
		}
	})
}
