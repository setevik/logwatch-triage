// Package watcher provides journal log watching via journalctl subprocess.
package watcher

import (
	"context"
)

// JournalEntry represents a parsed journal log entry.
type JournalEntry struct {
	// Fields from journalctl JSON output.
	Message           string
	Priority          int    // syslog priority (0=emerg ... 7=debug)
	SyslogIdentifier  string // e.g. "kernel", "systemd", process name
	SystemdUnit       string // e.g. "docker.service"
	PID               string
	Transport         string // e.g. "kernel", "journal", "syslog"
	Cursor            string
	RealtimeTimestamp string // microseconds since epoch as string

	// All raw fields from the JSON object.
	Fields map[string]string
}

// JournalSource is the interface for receiving journal entries.
// Implementations include the real journalctl pipe and test mocks.
type JournalSource interface {
	// Entries returns a channel of journal entries. The channel is closed
	// when the source is stopped or the context is cancelled.
	Entries(ctx context.Context) (<-chan JournalEntry, error)

	// Stop signals the source to shut down.
	Stop()
}
