package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestFetchInitialMappingsStopsWithServer checks that a hung get-all-relays
// request is abandoned once the relay is stopped instead of blocking forever.
func TestFetchInitialMappingsStopsWithServer(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s := NewUDPProxyServer(context.Background(), "127.0.0.1:0", srv.URL, key, "")

	done := make(chan error, 1)
	go func() { done <- s.fetchInitialMappings() }()

	time.Sleep(100 * time.Millisecond)
	s.Stop()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("fetchInitialMappings returned nil error after the relay was stopped")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fetchInitialMappings did not return after the relay was stopped")
	}
}
