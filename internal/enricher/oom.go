package enricher

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/setevik/logtriage/internal/event"
)

// enrichOOM adds kernel OOM context around an OOM kill event.
// It queries kernel logs from the 60 seconds before the kill and parses
// the OOM killer's process table dump.
func enrichOOM(ctx context.Context, ev *event.Event) {
	lines, err := getKernelLogsAround(ctx)
	if err != nil {
		slog.Debug("oom enrichment: failed to get kernel logs", "error", err)
		return
	}

	var detail strings.Builder

	if ev.Process != "" {
		fmt.Fprintf(&detail, "%s was killed by OOM killer.\n", ev.Process)
	}

	// Parse the OOM killer's process table for top memory consumers.
	consumers := parseOOMTable(lines)
	if len(consumers) > 0 {
		detail.WriteString("\nTop memory consumers at time of kill:\n")
		limit := 5
		if len(consumers) < limit {
			limit = len(consumers)
		}
		for i, c := range consumers[:limit] {
			suffix := ""
			if c.name == ev.Process {
				suffix = " (killed)"
			}
			fmt.Fprintf(&detail, "  %d. %-16s %d pages%s\n", i+1, c.name, c.pages, suffix)
		}
	}

	ev.Detail = detail.String()
}

// getKernelLogsAround fetches recent kernel log entries via journalctl.
func getKernelLogsAround(ctx context.Context) ([]string, error) {
	out, err := runCommand(ctx, "journalctl", "-k", "--since", "60s ago", "-o", "json", "--no-pager")
	if err != nil {
		return nil, err
	}

	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		var entry map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if msg, ok := entry["MESSAGE"].(string); ok {
			lines = append(lines, msg)
		}
	}
	return lines, nil
}

type memConsumer struct {
	name  string
	pages int64
}

// parseOOMTable looks for OOM killer process table lines in kernel messages.
// These lines look like:
// [ pid ]   uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name
// [  123]  1000   123   123456    78901     456789       0             0 firefox
func parseOOMTable(lines []string) []memConsumer {
	var consumers []memConsumer
	inTable := false

	for _, line := range lines {
		if strings.Contains(line, "uid  tgid total_vm") || strings.Contains(line, "oom_score_adj name") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		// End of table detection
		if strings.Contains(line, "oom-kill:") || strings.Contains(line, "Out of memory") {
			break
		}

		c, ok := parseOOMTableLine(line)
		if ok {
			consumers = append(consumers, c)
		}
	}

	sort.Slice(consumers, func(i, j int) bool {
		return consumers[i].pages > consumers[j].pages
	})

	return consumers
}

// parseOOMTableLine attempts to parse a single OOM process table line.
func parseOOMTableLine(line string) (memConsumer, bool) {
	// Format: [ pid ]   uid  tgid total_vm      rss ...  name
	// The name is the last field.
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "[") {
		return memConsumer{}, false
	}

	// Find fields after the bracketed PID section.
	closeBracket := strings.Index(line, "]")
	if closeBracket < 0 || closeBracket+1 >= len(line) {
		return memConsumer{}, false
	}

	fields := strings.Fields(line[closeBracket+1:])
	// Expect: uid tgid total_vm rss pgtables_bytes swapents oom_score_adj name
	if len(fields) < 8 {
		return memConsumer{}, false
	}

	name := fields[len(fields)-1]
	var rss int64
	fmt.Sscanf(fields[3], "%d", &rss)

	return memConsumer{name: name, pages: rss}, true
}
