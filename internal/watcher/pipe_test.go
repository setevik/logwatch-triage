package watcher

import (
	"encoding/json"
	"testing"
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
