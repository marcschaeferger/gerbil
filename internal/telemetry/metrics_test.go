package telemetry

import "testing"

func TestShortPeer(t *testing.T) {
	tests := map[string]string{
		"":                 "",
		"abc":              "ab:c",
		"ABCDEF0123":       "AB:CD:EF:01:23",
		"zzzzzz":           "unknown",
		"0011223344556677": "00:11:22:33:44:55",
	}
	for in, want := range tests {
		if got := shortPeer(in); got != want {
			t.Errorf("shortPeer(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLatencyBuckets(t *testing.T) {
	if len(LatencyBucketsSeconds) == 0 {
		t.Fatal("LatencyBucketsSeconds must not be empty")
	}
	for i := 1; i < len(LatencyBucketsSeconds); i++ {
		if LatencyBucketsSeconds[i] <= LatencyBucketsSeconds[i-1] {
			t.Fatalf("buckets must be strictly increasing: %v", LatencyBucketsSeconds)
		}
	}
}
