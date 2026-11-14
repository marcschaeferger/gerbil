package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fakeTCScript prints filters whose flowids share the "1:5"/"2:5" prefix and records every
// "tc filter del" invocation, so tests can assert which handles would have been deleted.
const fakeTCScript = `#!/bin/sh
if [ "$1" = "filter" ] && [ "$2" = "show" ]; then
	case "$6" in
	1:) p=1 ;;
	*) p=2 ;;
	esac
	echo "filter parent $p: protocol ip pref 1 u32 chain 0"
	echo "filter parent $p: protocol ip pref 1 u32 chain 0 fh 800: ht divisor 1"
	echo "filter parent $p: protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid $p:5 not_in_hw"
	echo "filter parent $p: protocol ip pref 1 u32 chain 0 fh 800::801 order 2049 key ht 800 bkt 0 flowid $p:50 not_in_hw"
	echo "filter parent $p: protocol ip pref 1 u32 chain 0 fh 800::802 order 2050 key ht 800 bkt 0 flowid $p:57"
	exit 0
fi
if [ "$1" = "filter" ] && [ "$2" = "del" ]; then
	echo "$*" >> "$TC_DEL_LOG"
fi
exit 0
`

// installFakeTC puts a fake tc binary first on PATH and returns the path of its deletion log.
func installFakeTC(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tc"), []byte(fakeTCScript), 0o755); err != nil {
		t.Fatalf("write fake tc: %v", err)
	}
	logPath := filepath.Join(dir, "del.log")
	t.Setenv("TC_DEL_LOG", logPath)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func readDeletedFilters(t *testing.T, logPath string) []string {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read deletion log: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func TestTCDeleteFiltersByFlowIDMatchesExactFlowID(t *testing.T) {
	logPath := installFakeTC(t)

	tcDeleteFiltersByFlowID("ifb_test", "2:", "2:5")

	want := []string{"filter del dev ifb_test parent 2: handle 800::800 prio 1 u32"}
	if got := readDeletedFilters(t, logPath); !reflect.DeepEqual(got, want) {
		t.Fatalf("deleted filters = %q, want %q", got, want)
	}
}

func TestRemovePeerBandwidthLimitKeepsFiltersOfOtherPeers(t *testing.T) {
	logPath := installFakeTC(t)

	oldIface, oldIFB := interfaceName, ifbName
	interfaceName, ifbName = "wg_test", "ifb_test"
	t.Cleanup(func() { interfaceName, ifbName = oldIface, oldIFB })

	if err := removePeerBandwidthLimit("10.0.0.5/32"); err != nil {
		t.Fatalf("removePeerBandwidthLimit: %v", err)
	}

	want := []string{"filter del dev wg_test parent 1: handle 800::800 prio 1 u32"}
	if _, err := os.Stat("/sys/module/ifb"); err == nil {
		want = append(want, "filter del dev ifb_test parent 2: handle 800::800 prio 1 u32")
	}
	if got := readDeletedFilters(t, logPath); !reflect.DeepEqual(got, want) {
		t.Fatalf("deleted filters = %q, want %q", got, want)
	}
}

func TestFilterLineHasFlowID(t *testing.T) {
	tests := []struct {
		line, flowID string
		want         bool
	}{
		{"filter parent 1: protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:5 not_in_hw", "1:5", true},
		{"filter parent 1: protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:5", "1:5", true},
		{"filter parent 1: protocol ip pref 1 u32 chain 0 fh 800::801 order 2049 key ht 800 bkt 0 flowid 1:50", "1:5", false},
		{"filter parent 1: protocol ip pref 1 u32 chain 0 fh 800::802 order 2050 key ht 800 bkt 0 flowid 1:57", "1:5", false},
		{"filter parent 1: protocol ip pref 1 u32 chain 0 fh 800: ht divisor 1", "1:5", false},
		{"filter parent 1: protocol ip pref 1 u32 chain 0 flowid", "1:5", false},
	}
	for _, tt := range tests {
		if got := filterLineHasFlowID(tt.line, tt.flowID); got != tt.want {
			t.Errorf("filterLineHasFlowID(%q, %q) = %v, want %v", tt.line, tt.flowID, got, tt.want)
		}
	}
}
