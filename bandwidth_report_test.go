package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const mib = 1024 * 1024

// TestReportPeerBandwidthRetainsDeltaAfterFailedReport verifies that bytes
// counted in a report cycle whose POST fails are included in the next
// successful report instead of being lost.
func TestReportPeerBandwidthRetainsDeltaAfterFailedReport(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey()

	var rx, tx int64
	origRead := readBandwidthDevice
	readBandwidthDevice = func() (*wgtypes.Device, error) {
		return &wgtypes.Device{Peers: []wgtypes.Peer{{PublicKey: pub, ReceiveBytes: rx, TransmitBytes: tx}}}, nil
	}
	t.Cleanup(func() { readBandwidthDevice = origRead })

	var (
		srvMu    sync.Mutex
		failNext bool
		received [][]PeerBandwidth
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []PeerBandwidth
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode body: %v", err)
		}
		srvMu.Lock()
		defer srvMu.Unlock()
		received = append(received, batch)
		if failNext {
			failNext = false
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Baseline reading.
	if err := reportPeerBandwidth(srv.URL); err != nil {
		t.Fatalf("baseline report: %v", err)
	}

	// Interval 1: 1 MiB in / 2 MiB out, but the report fails.
	rx, tx = 1*mib, 2*mib
	srvMu.Lock()
	failNext = true
	srvMu.Unlock()
	if err := reportPeerBandwidth(srv.URL); err == nil {
		t.Fatal("expected report to fail on HTTP 500")
	}

	// Interval 2: another 3 MiB in / 4 MiB out, report succeeds.
	rx, tx = 4*mib, 6*mib
	if err := reportPeerBandwidth(srv.URL); err != nil {
		t.Fatalf("second report: %v", err)
	}

	srvMu.Lock()
	if len(received) != 3 {
		srvMu.Unlock()
		t.Fatalf("expected 3 POSTs, got %d", len(received))
	}
	last := received[2]
	srvMu.Unlock()
	if len(last) != 1 || last[0].PublicKey != pub.String() {
		t.Fatalf("unexpected last batch: %+v", last)
	}
	if last[0].BytesIn != 4 || last[0].BytesOut != 6 {
		t.Fatalf("successful report after failure must include both intervals: got in=%v MB out=%v MB, want in=4 MB out=6 MB",
			last[0].BytesIn, last[0].BytesOut)
	}

	// The delivered delta must not be reported a second time.
	if err := reportPeerBandwidth(srv.URL); err != nil {
		t.Fatalf("third report: %v", err)
	}
	srvMu.Lock()
	got := received[len(received)-1]
	srvMu.Unlock()
	if len(got) != 1 || got[0].BytesIn != 0 || got[0].BytesOut != 0 {
		t.Fatalf("delivered delta reported again: %+v", got)
	}
}
