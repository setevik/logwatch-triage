package monitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/setevik/logtriage/internal/format"
)

func TestTopMemConsumers(t *testing.T) {
	// Create a fake /proc tree.
	procRoot := t.TempDir()

	// Create two fake processes.
	makeFakeProc(t, procRoot, "100", "firefox", "10000 5000 300 0 0 0 0")
	makeFakeProc(t, procRoot, "200", "electron", "20000 8000 500 0 0 0 0")
	makeFakeProc(t, procRoot, "300", "bash", "5000 1000 100 0 0 0 0")

	procs, err := topMemConsumers(procRoot, 2)
	if err != nil {
		t.Fatalf("topMemConsumers: %v", err)
	}

	if len(procs) != 2 {
		t.Fatalf("got %d procs, want 2", len(procs))
	}

	// First should be electron (highest RSS).
	if procs[0].Name != "electron" {
		t.Errorf("top process = %q, want electron", procs[0].Name)
	}
	if procs[0].PID != 200 {
		t.Errorf("top PID = %d, want 200", procs[0].PID)
	}

	// Second should be firefox.
	if procs[1].Name != "firefox" {
		t.Errorf("second process = %q, want firefox", procs[1].Name)
	}

	// RSS should be in bytes (pages * page_size).
	pageSize := int64(os.Getpagesize())
	if procs[0].RSSBytes != 8000*pageSize {
		t.Errorf("electron RSS = %d, want %d", procs[0].RSSBytes, 8000*pageSize)
	}
}

func TestFormatTopConsumers(t *testing.T) {
	consumers := []ProcMem{
		{PID: 100, Name: "firefox", RSSBytes: 3 * 1024 * 1024 * 1024},  // 3 GB
		{PID: 200, Name: "electron", RSSBytes: 512 * 1024 * 1024},       // 512 MB
	}

	out := FormatTopConsumers(consumers)
	if out == "" {
		t.Fatal("FormatTopConsumers returned empty string")
	}
	// Should contain both process names.
	if !strings.Contains(out, "firefox") || !strings.Contains(out, "electron") {
		t.Errorf("output missing process names: %s", out)
	}
	if !strings.Contains(out, "GB") {
		t.Errorf("output missing GB unit: %s", out)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{500, "500 B"},
		{2048, "2.0 KB"},
		{5 * 1024 * 1024, "5.0 MB"},
		{3 * 1024 * 1024 * 1024, "3.0 GB"},
	}
	for _, tt := range tests {
		got := format.Bytes(tt.bytes)
		if got != tt.want {
			t.Errorf("format.Bytes(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func makeFakeProc(t *testing.T, root, pid, name, statm string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(name+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "statm"), []byte(statm), 0o644); err != nil {
		t.Fatal(err)
	}
}

