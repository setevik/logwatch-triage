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

	// T3 — Service Failure
	if ev := c.classifyServiceFailure(entry, ts); ev != nil {
		return ev
	}

	// T4 — Kernel/HW Error
	if ev := c.classifyKernelHW(entry, ts); ev != nil {
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

func (c *Classifier) classifyServiceFailure(entry watcher.JournalEntry, ts time.Time) *event.Event {
	// Only consider messages from systemd itself.
	if !serviceIdentifiers[entry.SyslogIdentifier] {
		return nil
	}

	for _, re := range serviceFailPatterns {
		if !re.MatchString(entry.Message) {
			continue
		}

		unit := extractServiceUnit(entry)
		if unit == "" {
			// If we can't identify the unit, use the systemd unit field.
			unit = entry.SystemdUnit
		}
		if unit == "" {
			continue
		}

		exitCode := extractExitCode(entry.Message)
		summary := fmt.Sprintf("Service failed: %s", unit)
		if exitCode != "" {
			summary = fmt.Sprintf("Service failed: %s (exit %s)", unit, exitCode)
		}

		ev := event.New(c.instanceID, ts, event.TierServiceFailure, event.SevMedium, summary)
		ev.Unit = unit
		ev.RawFields = entry.Fields
		return ev
	}
	return nil
}

// extractServiceUnit pulls the unit name from a systemd failure message.
func extractServiceUnit(entry watcher.JournalEntry) string {
	if m := serviceUnitRe.FindStringSubmatch(entry.Message); len(m) >= 2 {
		return m[1]
	}
	// Fall back to journal metadata.
	if unit, ok := entry.Fields["UNIT"]; ok {
		return unit
	}
	return ""
}

// extractExitCode pulls the exit status from a failure message.
func extractExitCode(msg string) string {
	if m := serviceExitCodeRe.FindStringSubmatch(msg); len(m) == 2 {
		return m[1]
	}
	return ""
}

func (c *Classifier) classifyKernelHW(entry watcher.JournalEntry, ts time.Time) *event.Event {
	// T4 events primarily come from kernel transport.
	if !kernelHWIdentifiers[entry.SyslogIdentifier] && entry.Transport != "kernel" {
		return nil
	}

	for _, re := range kernelHWPatterns {
		if !re.MatchString(entry.Message) {
			continue
		}

		summary := extractKernelHWSummary(entry.Message)

		ev := event.New(c.instanceID, ts, event.TierKernelHW, event.SevHigh, summary)
		ev.RawFields = entry.Fields
		return ev
	}
	return nil
}

// extractKernelHWSummary tries to produce a concise summary from kernel/HW messages.
func extractKernelHWSummary(msg string) string {
	for _, sp := range kernelHWSummaryPatterns {
		m := sp.re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		if len(m) > 1 {
			return fmt.Sprintf(sp.summary, m[1])
		}
		return sp.summary
	}
	// Truncate raw message as fallback.
	if len(msg) > 80 {
		return "Kernel/HW: " + msg[:77] + "..."
	}
	return "Kernel/HW: " + msg
}

// ClassifyPSIEvent creates a T5 memory pressure event from PSI monitor data.
// This is called directly from the main pipeline, not via journal entry classification.
func (c *Classifier) ClassifyPSIEvent(someAvg10, fullAvg10 float64, detail string) *event.Event {
	summary := fmt.Sprintf("Memory pressure: some=%.1f%% full=%.1f%%", someAvg10, fullAvg10)
	ev := event.New(c.instanceID, time.Now(), event.TierMemPressure, event.SevWarning, summary)
	ev.Detail = detail
	return ev
}

// ClassifySMARTEvent creates a T4 kernel/HW event from a SMART status change.
func (c *Classifier) ClassifySMARTEvent(device, summary, detail string) *event.Event {
	ev := event.New(c.instanceID, time.Now(), event.TierKernelHW, event.SevHigh, summary)
	ev.Detail = detail
	return ev
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
