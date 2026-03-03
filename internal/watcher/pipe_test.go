package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestParseJournalJSON(t *testing.T) {
	raw := map[string]interface{}{
		"MESSAGE":              "Out of memory: Killed process 4521 (firefox)",
		"PRIORITY":             "0",
		"SYSLOG_IDENTIFIER":   "kernel",
		"_TRANSPORT":           "kernel",
		"__REALTIME_TIMESTAMP": "1708300000000000",
		"__CURSOR":             "s=abc;i=123",
	}

	data, _ := json.Marshal(raw)
	entry, err := parseJournalJSON(data)
	if err != nil {
		t.Fatalf("parseJournalJSON error: %v", err)
	}

	if entry.Message != "Out of memory: Killed process 4521 (firefox)" {
		t.Errorf("Message = %q", entry.Message)
	}
	if entry.Priority != 0 {
		t.Errorf("Priority = %d, want 0", entry.Priority)
	}
	if entry.SyslogIdentifier != "kernel" {
		t.Errorf("SyslogIdentifier = %q", entry.SyslogIdentifier)
	}
	if entry.Transport != "kernel" {
		t.Errorf("Transport = %q", entry.Transport)
	}
	if entry.RealtimeTimestamp != "1708300000000000" {
		t.Errorf("RealtimeTimestamp = %q", entry.RealtimeTimestamp)
	}
	if entry.Cursor != "s=abc;i=123" {
		t.Errorf("Cursor = %q", entry.Cursor)
	}
}

func TestParseJournalJSONWithArrayField(t *testing.T) {
	raw := map[string]interface{}{
		"MESSAGE":            "test",
		"PRIORITY":           "3",
		"SYSLOG_IDENTIFIER":  "test",
		"_SOME_ARRAY_FIELD":  []interface{}{"first", "second"},
	}

	data, _ := json.Marshal(raw)
	entry, err := parseJournalJSON(data)
	if err != nil {
		t.Fatalf("parseJournalJSON error: %v", err)
	}

	if entry.Fields["_SOME_ARRAY_FIELD"] != "first" {
		t.Errorf("array field = %q, want %q", entry.Fields["_SOME_ARRAY_FIELD"], "first")
	}
}

func TestParseJournalJSONInvalid(t *testing.T) {
	_, err := parseJournalJSON([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseJournalJSONNumericPriority(t *testing.T) {
	// journalctl sometimes emits PRIORITY as a number rather than string.
	raw := map[string]interface{}{
		"MESSAGE":  "test",
		"PRIORITY": float64(3),
	}

	data, _ := json.Marshal(raw)
	entry, err := parseJournalJSON(data)
	if err != nil {
		t.Fatalf("parseJournalJSON error: %v", err)
	}

	if entry.Priority != 3 {
		t.Errorf("Priority = %d, want 3", entry.Priority)
	}
}

// failingSource is a JournalSource that always fails to start.
type failingSource struct{}

func (f *failingSource) Entries(ctx context.Context) (<-chan JournalEntry, error) {
	return nil, fmt.Errorf("simulated failure")
}

func (f *failingSource) Stop() {}

// TestSupervisedSourceMaxRestartsClosesChannel verifies that when a supervised
// source exhausts its maxRestarts, the output channel is closed. This is
// important because the main loop must detect this channel close and return
// an error (not nil) so systemd can restart the daemon.
func TestSupervisedSourceMaxRestartsClosesChannel(t *testing.T) {
	sup := NewSupervisedSource(
		func() JournalSource { return &failingSource{} },
		1*time.Millisecond, // minimal wait to keep test fast
		2,                  // allow 2 restarts
	)

	ctx := context.Background()
	ch, err := sup.Entries(ctx)
	if err != nil {
		t.Fatalf("Entries() error: %v", err)
	}

	// The channel should close once max restarts are exhausted.
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("expected channel to be closed, but received an entry")
		}
		// Channel closed as expected.
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for channel to close after max restarts")
	}
}

// finiteSource sends one entry then closes, simulating a source that crashes.
type finiteSource struct {
	entry JournalEntry
}

func (f *finiteSource) Entries(ctx context.Context) (<-chan JournalEntry, error) {
	ch := make(chan JournalEntry, 1)
	ch <- f.entry
	close(ch)
	return ch, nil
}

func (f *finiteSource) Stop() {}

// TestSupervisedSourceForwardsEntries verifies that entries from the underlying
// source are forwarded through the supervised channel before a restart occurs.
func TestSupervisedSourceForwardsEntries(t *testing.T) {
	entry := JournalEntry{Message: "test message"}
	callCount := 0

	sup := NewSupervisedSource(
		func() JournalSource {
			callCount++
			return &finiteSource{entry: entry}
		},
		1*time.Millisecond,
		2,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := sup.Entries(ctx)
	if err != nil {
		t.Fatalf("Entries() error: %v", err)
	}

	// Should receive at least one entry before restarts exhaust.
	select {
	case got, ok := <-ch:
		if !ok {
			t.Fatal("channel closed before receiving any entries")
		}
		if got.Message != "test message" {
			t.Errorf("Message = %q, want %q", got.Message, "test message")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for entry")
	}
}
