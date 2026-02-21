package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ProcMem represents a process's memory usage from /proc/[pid]/statm.
type ProcMem struct {
	PID     int
	Name    string
	RSSBytes int64 // resident set size in bytes
}

// TopMemConsumers reads /proc/*/statm and returns the top N processes by RSS.
func TopMemConsumers(n int) ([]ProcMem, error) {
	return topMemConsumers("/proc", n)
}

func topMemConsumers(procRoot string, n int) ([]ProcMem, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", procRoot, err)
	}

	pageSize := int64(os.Getpagesize())
	var procs []ProcMem

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}

		rssPages, err := readStatmRSS(filepath.Join(procRoot, entry.Name(), "statm"))
		if err != nil {
			continue // process may have exited
		}

		name := readCommName(filepath.Join(procRoot, entry.Name(), "comm"))

		procs = append(procs, ProcMem{
			PID:      pid,
			Name:     name,
			RSSBytes: rssPages * pageSize,
		})
	}

	// Sort by RSS descending.
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].RSSBytes > procs[j].RSSBytes
	})

	if n > 0 && len(procs) > n {
		procs = procs[:n]
	}
	return procs, nil
}

// readStatmRSS reads the RSS field (second field) from /proc/[pid]/statm.
// The value is in pages.
func readStatmRSS(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, fmt.Errorf("unexpected statm format")
	}
	return strconv.ParseInt(fields[1], 10, 64)
}

// readCommName reads the process name from /proc/[pid]/comm.
func readCommName(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(data))
}

// FormatTopConsumers formats a list of ProcMem as human-readable lines.
func FormatTopConsumers(consumers []ProcMem) string {
	var b strings.Builder
	for i, p := range consumers {
		fmt.Fprintf(&b, "  %d. %-20s %s\n", i+1, p.Name, formatBytes(p.RSSBytes))
	}
	return b.String()
}

func formatBytes(b int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
