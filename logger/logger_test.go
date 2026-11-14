package logger

import (
	"sync"
	"testing"
)

// TestGetLoggerConcurrentFirstUse calls GetLogger from many goroutines before
// the default logger exists. Run with -race: an unsynchronized nil check in
// GetLogger races with the write inside Init's sync.Once.
func TestGetLoggerConcurrentFirstUse(t *testing.T) {
	defaultLogger = nil
	once = sync.Once{}

	const n = 16
	got := make([]*Logger, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i] = GetLogger()
		}()
	}
	wg.Wait()

	for i, l := range got {
		if l == nil || l != got[0] {
			t.Fatalf("goroutine %d got logger %p, want the shared %p", i, l, got[0])
		}
	}
}
