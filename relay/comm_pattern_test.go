package relay

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fosrl/gerbil/logger"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestTrackCommunicationPatternConcurrent drives the same communication
// pattern from several packet workers at once, in both directions, while the
// idle-pattern cleanup scans it. Run with -race: the pattern is shared through
// sync.Map, so every field access must be synchronized.
func TestTrackCommunicationPatternConcurrent(t *testing.T) {
	// Initialize the logger up front like main does; its lazy fallback is not
	// meant to be raced by concurrent first use.
	logger.Init()

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewUDPProxyServer(ctx, "127.0.0.1:0", "http://127.0.0.1:0", key, "")

	client := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 51820}
	dest := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 51821}
	const clientIndex, destIndex = 11, 22

	// Seed the pattern so every worker below takes the shared-pointer update path.
	s.trackCommunicationPattern(client, dest, clientIndex, true)

	const workers, perWorker = 8, 200
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(fromClient bool) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				if fromClient {
					s.trackCommunicationPattern(client, dest, clientIndex, true)
				} else {
					s.trackCommunicationPattern(dest, client, destIndex, false)
				}
			}
		}(w%2 == 0)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < perWorker; i++ {
			// Nothing is idle yet, so the scan only reads the pattern.
			s.removeIdleCommunicationPatterns(time.Now())
		}
	}()
	wg.Wait()

	v, ok := s.commPatterns.Load(client.String() + "-" + dest.String())
	if !ok {
		t.Fatal("communication pattern was removed while active")
	}
	// All writers have finished (wg.Wait), so this read needs no lock.
	got := v.(*CommunicationPattern).PacketCount
	if want := 1 + workers*perWorker; got != want {
		t.Fatalf("PacketCount = %d, want %d (lost updates)", got, want)
	}
	if _, ok := s.wgSessions.Load("22:11"); !ok {
		t.Fatal("session was not rebuilt from the bidirectional pattern")
	}
}
