// Package classifier matches journal entries to event tiers using pattern matching.
package classifier

import (
	"fmt"
	"strconv"
	"time"

	"github.com/setevik/logtriage/internal/event"
	"github.com/setevik/logtriage/internal/watcher"
)

// Classifier matches journal entries to event types.
type Classifier struct {
	instanceID string
}

// New creates a Classifier for the given instance.
func New(instanceID string) *Classifier {
	return &Classifier{instanceID: instanceID}
}

// Classify examines a journal entry and returns a classified Event, or nil
// if the entry does not match any known pattern.
func (c *Classifier) Classify(entry watcher.JournalEntry) *event.Event {
	ts := parseTimestamp(entry)

	// T1 — OOM Kill
	if ev := c.classifyOOM(entry, ts); ev != nil {
		return ev
	}

	// T2 — Process Crash
	if ev := c.classifyCrash(entry, ts); ev != nil {
		return ev
	}

	return nil
}

func (c *Classifier) classifyOOM(entry watcher.JournalEntry, ts time.Time) *event.Event {
	for _, re := range oomPatterns {
		if !re.MatchString(entry.Message) {
			continue
		}

		process, pid := extractOOMProcess(entry.Message)
		summary := "OOM Kill"
		if process != "" {
			summary = fmt.Sprintf("OOM Kill: %s (pid %d)", process, pid)
		}

		ev := event.New(c.instanceID, ts, event.TierOOMKill, event.SevCritical, summary)
		ev.Process = process
		ev.PID = pid
		ev.RawFields = entry.Fields
		return ev
	}
	return nil
}

func (c *Classifier) classifyCrash(entry watcher.JournalEntry, ts time.Time) *event.Event {
	// Check for systemd-coredump identifier.
	if crashIdentifiers[entry.SyslogIdentifier] {
		process, pid := extractCoredumpProcess(entry.Message)
		summary := "Process Crash"
		if process != "" {
			summary = fmt.Sprintf("Crash: %s (pid %d) dumped core", process, pid)
		}

		ev := event.New(c.instanceID, ts, event.TierProcessCrash, event.SevHigh, summary)
		ev.Process = process
		ev.PID = pid
		ev.RawFields = entry.Fields
		return ev
	}

	// Check message-based crash patterns.
	for _, re := range crashPatterns {
		if !re.MatchString(entry.Message) {
			continue
		}

		process, pid := extractCrashProcess(entry)
		summary := "Process Crash"
		if process != "" {
			summary = fmt.Sprintf("Crash: %s (pid %d) segfault", process, pid)
		}

		ev := event.New(c.instanceID, ts, event.TierProcessCrash, event.SevHigh, summary)
		ev.Process = process
		ev.PID = pid
		ev.RawFields = entry.Fields
		return ev
	}

	return nil
}

// extractOOMProcess pulls process name and PID from OOM kill messages.
func extractOOMProcess(msg string) (string, int) {
	if m := oomKillProcessRe.FindStringSubmatch(msg); len(m) == 3 {
		pid, _ := strconv.Atoi(m[1])
		return m[2], pid
	}
	if m := oomKillTaskRe.FindStringSubmatch(msg); len(m) == 3 {
		pid, _ := strconv.Atoi(m[2])
		return m[1], pid
	}
	return "", 0
}

// extractCoredumpProcess pulls process name and PID from coredump messages.
func extractCoredumpProcess(msg string) (string, int) {
	if m := coredumpProcessRe.FindStringSubmatch(msg); len(m) == 3 {
		pid, _ := strconv.Atoi(m[1])
		return m[2], pid
	}
	return "", 0
}

// extractCrashProcess pulls process name and PID from segfault/trap messages.
func extractCrashProcess(entry watcher.JournalEntry) (string, int) {
	if m := crashSegfaultRe.FindStringSubmatch(entry.Message); len(m) == 3 {
		pid, _ := strconv.Atoi(m[2])
		return m[1], pid
	}
	// Fall back to journal entry fields.
	if entry.SyslogIdentifier != "" {
		pid, _ := strconv.Atoi(entry.PID)
		return entry.SyslogIdentifier, pid
	}
	return "", 0
}

// parseTimestamp converts the journal entry's __REALTIME_TIMESTAMP (microseconds
// since epoch) to a time.Time. Falls back to current time.
func parseTimestamp(entry watcher.JournalEntry) time.Time {
	if entry.RealtimeTimestamp != "" {
		if usec, err := strconv.ParseInt(entry.RealtimeTimestamp, 10, 64); err == nil {
			return time.Unix(usec/1_000_000, (usec%1_000_000)*1000)
		}
	}
	return time.Now()
}
