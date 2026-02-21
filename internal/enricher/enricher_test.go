package enricher

import (
	"testing"
)

func TestParseOOMTable(t *testing.T) {
	lines := []string{
		"some irrelevant log line",
		"[ pid ]   uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name",
		"[  100]  1000   100   500000    80000     400000       0             0 firefox",
		"[  200]  1000   200   300000   120000     300000       0             0 electron",
		"[  300]  1000   300   100000    20000     100000       0             0 bash",
		"oom-kill:constraint=CONSTRAINT_NONE",
	}

	consumers := parseOOMTable(lines)
	if len(consumers) != 3 {
		t.Fatalf("got %d consumers, want 3", len(consumers))
	}

	// Should be sorted by RSS descending.
	if consumers[0].name != "electron" {
		t.Errorf("top consumer = %q, want electron", consumers[0].name)
	}
	if consumers[0].pages != 120000 {
		t.Errorf("top consumer pages = %d, want 120000", consumers[0].pages)
	}
	if consumers[1].name != "firefox" {
		t.Errorf("second consumer = %q, want firefox", consumers[1].name)
	}
	if consumers[2].name != "bash" {
		t.Errorf("third consumer = %q, want bash", consumers[2].name)
	}
}

func TestParseOOMTableEmpty(t *testing.T) {
	lines := []string{
		"some random log line",
		"another line",
	}
	consumers := parseOOMTable(lines)
	if len(consumers) != 0 {
		t.Errorf("expected empty consumers, got %d", len(consumers))
	}
}

func TestParseOOMTableLine(t *testing.T) {
	tests := []struct {
		line    string
		wantOK  bool
		name    string
		pages   int64
	}{
		{"[  100]  1000   100   500000    80000     400000       0             0 firefox", true, "firefox", 80000},
		{"[  200]  1000   200   300000   120000     300000       0             0 electron", true, "electron", 120000},
		{"not a table line", false, "", 0},
		{"[incomplete", false, "", 0},
	}

	for _, tt := range tests {
		c, ok := parseOOMTableLine(tt.line)
		if ok != tt.wantOK {
			t.Errorf("parseOOMTableLine(%q): ok = %v, want %v", tt.line, ok, tt.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if c.name != tt.name {
			t.Errorf("parseOOMTableLine(%q): name = %q, want %q", tt.line, c.name, tt.name)
		}
		if c.pages != tt.pages {
			t.Errorf("parseOOMTableLine(%q): pages = %d, want %d", tt.line, c.pages, tt.pages)
		}
	}
}
