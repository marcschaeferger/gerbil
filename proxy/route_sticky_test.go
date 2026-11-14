package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func newStickyRouteTestProxy(t *testing.T, endpoints []string) (*SNIProxy, *int32) {
	t.Helper()

	var apiCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&apiCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RouteAPIResponse{Endpoints: endpoints})
	}))
	t.Cleanup(srv.Close)

	p, err := NewSNIProxy(8443, srv.URL, "pubkey", "127.0.0.1", 443, nil, false, nil)
	if err != nil {
		t.Fatalf("NewSNIProxy: %v", err)
	}
	t.Cleanup(p.cancel)
	return p, &apiCalls
}

// A cached route must not hand the first client's sticky endpoint to every
// other client: each client keeps its own endpoint while the API is only
// queried once per hostname.
func TestGetRouteStickyEndpointIsPerClient(t *testing.T) {
	endpoints := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	p, apiCalls := newStickyRouteTestProxy(t, endpoints)

	const hostname = "app.example.com"
	seen := make(map[string]bool)
	for i := 1; i <= 32; i++ {
		clientAddr := fmt.Sprintf("192.0.2.%d:40000", i)
		route, err := p.getRoute(hostname, clientAddr)
		if err != nil {
			t.Fatalf("getRoute(%s): %v", clientAddr, err)
		}
		if route == nil {
			t.Fatalf("getRoute(%s): nil route", clientAddr)
		}
		want := p.selectStickyEndpoint(clientAddr, endpoints)
		if route.TargetHost != want {
			t.Fatalf("client %s routed to %s, want its sticky endpoint %s", clientAddr, route.TargetHost, want)
		}
		seen[route.TargetHost] = true
	}

	if len(seen) < 2 {
		t.Fatalf("all clients were routed to the same endpoint %v; expected spread across %v", seen, endpoints)
	}
	if got := atomic.LoadInt32(apiCalls); got != 1 {
		t.Fatalf("API called %d times, want 1 (endpoint list should be cached per hostname)", got)
	}
}

// Stickiness is per client IP: a new connection from the same IP (different
// source port) must land on the same endpoint, also after the cache expired.
func TestGetRouteStickyEndpointIgnoresClientPort(t *testing.T) {
	endpoints := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	p, _ := newStickyRouteTestProxy(t, endpoints)

	const hostname = "app.example.com"
	for _, ip := range []string{"192.0.2.10", "2001:db8::10"} {
		var first string
		for port := 40000; port < 40016; port++ {
			p.ClearCache()
			clientAddr := fmt.Sprintf("[%s]:%d", ip, port)
			if ip == "192.0.2.10" {
				clientAddr = fmt.Sprintf("%s:%d", ip, port)
			}
			route, err := p.getRoute(hostname, clientAddr)
			if err != nil {
				t.Fatalf("getRoute(%s): %v", clientAddr, err)
			}
			if route == nil {
				t.Fatalf("getRoute(%s): nil route", clientAddr)
			}
			if first == "" {
				first = route.TargetHost
				continue
			}
			if route.TargetHost != first {
				t.Fatalf("client %s routed to %s, want %s (same IP must stay sticky across ports)", clientAddr, route.TargetHost, first)
			}
		}
	}
}
