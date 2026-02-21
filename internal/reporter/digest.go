package reporter

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/setevik/logtriage/internal/event"
)

// DigestSummary holds aggregated event counts for a digest period.
type DigestSummary struct {
	InstanceID string
	Since      time.Time
	Until      time.Time

	OOMKills        int
	OOMBreakdown    map[string]int // process -> count
	Crashes         int
	CrashBreakdown  map[string]int
	ServiceFailures int
	ServiceBreakdown map[string]int // unit -> count
	KernelHWErrors  int
	KernelBreakdown []string // unique summaries
	MemPressure     int
}

// BuildDigest aggregates a list of events into a DigestSummary.
func BuildDigest(instanceID string, events []*event.Event, since, until time.Time) *DigestSummary {
	d := &DigestSummary{
		InstanceID:       instanceID,
		Since:            since,
		Until:            until,
		OOMBreakdown:     make(map[string]int),
		CrashBreakdown:   make(map[string]int),
		ServiceBreakdown: make(map[string]int),
	}

	kernelSeen := make(map[string]bool)

	for _, ev := range events {
		switch ev.Tier {
		case event.TierOOMKill:
			d.OOMKills++
			name := ev.Process
			if name == "" {
				name = "unknown"
			}
			d.OOMBreakdown[name]++
		case event.TierProcessCrash:
			d.Crashes++
			name := ev.Process
			if name == "" {
				name = "unknown"
			}
			d.CrashBreakdown[name]++
		case event.TierServiceFailure:
			d.ServiceFailures++
			unit := ev.Unit
			if unit == "" {
				unit = "unknown"
			}
			d.ServiceBreakdown[unit]++
		case event.TierKernelHW:
			d.KernelHWErrors++
			if !kernelSeen[ev.Summary] {
				kernelSeen[ev.Summary] = true
				d.KernelBreakdown = append(d.KernelBreakdown, ev.Summary)
			}
		case event.TierMemPressure:
			d.MemPressure++
		}
	}

	return d
}

// FormatDigest formats a DigestSummary as human-readable text suitable for
// ntfy or stdout output.
func FormatDigest(d *DigestSummary) string {
	var b strings.Builder

	dateRange := fmt.Sprintf("%s - %s",
		d.Since.Local().Format("Jan 02"),
		d.Until.Local().Format("Jan 02"))

	fmt.Fprintf(&b, "=== %s ===\n", d.InstanceID)
	fmt.Fprintf(&b, "Period: %s\n\n", dateRange)

	// OOM Kills
	fmt.Fprintf(&b, "OOM Kills:        %d", d.OOMKills)
	if d.OOMKills > 0 {
		fmt.Fprintf(&b, " (%s)", formatBreakdown(d.OOMBreakdown))
	}
	b.WriteString("\n")

	// Process Crashes
	fmt.Fprintf(&b, "Process Crashes:  %d", d.Crashes)
	if d.Crashes > 0 {
		fmt.Fprintf(&b, " (%s)", formatBreakdown(d.CrashBreakdown))
	}
	b.WriteString("\n")

	// Service Failures
	fmt.Fprintf(&b, "Service Failures: %d", d.ServiceFailures)
	if d.ServiceFailures > 0 {
		fmt.Fprintf(&b, " (%s)", formatBreakdown(d.ServiceBreakdown))
	}
	b.WriteString("\n")

	// HW/Kernel Errors
	fmt.Fprintf(&b, "HW/Kernel Errors: %d", d.KernelHWErrors)
	if d.KernelHWErrors > 0 && len(d.KernelBreakdown) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(d.KernelBreakdown, ", "))
	}
	b.WriteString("\n")

	// Memory Pressure
	fmt.Fprintf(&b, "Memory Pressure:  %d warning episodes\n", d.MemPressure)

	return b.String()
}

// FormatDigestTitle generates the ntfy title for a digest notification.
func FormatDigestTitle(since, until time.Time) string {
	return fmt.Sprintf("\U0001f4ca logtriage weekly digest (%s-%s)",
		since.Local().Format("Jan 02"),
		until.Local().Format("Jan 02"))
}

// formatBreakdown turns a map[string]int into "foo x2, bar x1" sorted by count desc.
func formatBreakdown(m map[string]int) string {
	type entry struct {
		name  string
		count int
	}

	entries := make([]entry, 0, len(m))
	for name, count := range m {
		entries = append(entries, entry{name, count})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = fmt.Sprintf("%s \u00d7%d", e.name, e.count)
	}
	return strings.Join(parts, ", ")
}
