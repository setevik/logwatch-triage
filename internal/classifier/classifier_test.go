package classifier

import (
	"testing"

	"github.com/setevik/logtriage/internal/event"
	"github.com/setevik/logtriage/internal/watcher"
)

func TestClassifyOOMKill(t *testing.T) {
	c := New("testhost")

	tests := []struct {
		name    string
		entry   watcher.JournalEntry
		wantNil bool
		tier    event.Tier
		process string
		pid     int
	}{
		{
			name: "oom killed process",
			entry: watcher.JournalEntry{
				Message:           "Out of memory: Killed process 4521 (firefox) total-vm:12345kB, anon-rss:3200000kB",
				Priority:          0,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierOOMKill,
			process: "firefox",
			pid:     4521,
		},
		{
			name: "oom-kill constraint line",
			entry: watcher.JournalEntry{
				Message:           "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,task=chrome,pid=9876,uid=1000",
				Priority:          0,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierOOMKill,
			process: "chrome",
			pid:     9876,
		},
		{
			name: "invoked oom-killer",
			entry: watcher.JournalEntry{
				Message:           "electron invoked oom-killer: gfp_mask=0x100cca(GFP_HIGHUSER_MOVABLE), order=0",
				Priority:          0,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier: event.TierOOMKill,
			// No process/pid extraction from this format.
			process: "",
			pid:     0,
		},
		{
			name: "normal log line no match",
			entry: watcher.JournalEntry{
				Message:           "Started Session 3 of User user.",
				Priority:          6,
				SyslogIdentifier:  "systemd",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := c.Classify(tt.entry)

			if tt.wantNil {
				if ev != nil {
					t.Fatalf("expected nil event, got tier=%s summary=%q", ev.Tier, ev.Summary)
				}
				return
			}

			if ev == nil {
				t.Fatal("expected event, got nil")
			}
			if ev.Tier != tt.tier {
				t.Errorf("tier = %q, want %q", ev.Tier, tt.tier)
			}
			if ev.Process != tt.process {
				t.Errorf("process = %q, want %q", ev.Process, tt.process)
			}
			if ev.PID != tt.pid {
				t.Errorf("pid = %d, want %d", ev.PID, tt.pid)
			}
			if ev.InstanceID != "testhost" {
				t.Errorf("instanceID = %q, want %q", ev.InstanceID, "testhost")
			}
		})
	}
}

func TestClassifyCrash(t *testing.T) {
	c := New("testhost")

	tests := []struct {
		name    string
		entry   watcher.JournalEntry
		wantNil bool
		tier    event.Tier
		process string
		pid     int
	}{
		{
			name: "segfault",
			entry: watcher.JournalEntry{
				Message:           "app[1234]: segfault at 0000000000000010 ip 00007f1234 sp 00007ffd error 4 in libfoo.so",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierProcessCrash,
			process: "app",
			pid:     1234,
		},
		{
			name: "coredump from systemd-coredump",
			entry: watcher.JournalEntry{
				Message:           "Process 5678 (vlc) of user 1000 dumped core.",
				Priority:          2,
				SyslogIdentifier:  "systemd-coredump",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierProcessCrash,
			process: "vlc",
			pid:     5678,
		},
		{
			name: "normal error log no match",
			entry: watcher.JournalEntry{
				Message:           "Failed to connect to database",
				Priority:          3,
				SyslogIdentifier:  "myapp",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := c.Classify(tt.entry)

			if tt.wantNil {
				if ev != nil {
					t.Fatalf("expected nil event, got tier=%s summary=%q", ev.Tier, ev.Summary)
				}
				return
			}

			if ev == nil {
				t.Fatal("expected event, got nil")
			}
			if ev.Tier != tt.tier {
				t.Errorf("tier = %q, want %q", ev.Tier, tt.tier)
			}
			if ev.Process != tt.process {
				t.Errorf("process = %q, want %q", ev.Process, tt.process)
			}
			if ev.PID != tt.pid {
				t.Errorf("pid = %d, want %d", ev.PID, tt.pid)
			}
			if ev.Severity != event.SevHigh && ev.Severity != event.SevCritical {
				t.Errorf("severity = %q, expected high or critical", ev.Severity)
			}
		})
	}
}

func TestClassifyTimestampParsing(t *testing.T) {
	c := New("testhost")

	entry := watcher.JournalEntry{
		Message:           "Out of memory: Killed process 100 (test)",
		Priority:          0,
		SyslogIdentifier:  "kernel",
		RealtimeTimestamp: "1708300000000000", // microseconds since epoch
		Fields:            map[string]string{},
	}

	ev := c.Classify(entry)
	if ev == nil {
		t.Fatal("expected event")
	}

	if ev.Timestamp.Year() < 2024 {
		t.Errorf("timestamp year = %d, expected >= 2024", ev.Timestamp.Year())
	}
}
