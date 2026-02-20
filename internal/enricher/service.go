package enricher

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/setevik/logtriage/internal/event"
)

// enrichService adds context to a service failure event by querying the
// last journal entries for the failed unit.
func enrichService(ctx context.Context, ev *event.Event) {
	if ev.Unit == "" {
		return
	}

	lines, err := getUnitLogs(ctx, ev.Unit, 10)
	if err != nil {
		slog.Debug("service enrichment: failed to get unit logs", "unit", ev.Unit, "error", err)
		return
	}

	if len(lines) == 0 {
		return
	}

	var detail strings.Builder
	fmt.Fprintf(&detail, "%s failed.\n\nLast log lines:\n", ev.Unit)
	for _, line := range lines {
		fmt.Fprintf(&detail, "  %s\n", line)
	}

	ev.Detail = detail.String()
}

// getUnitLogs fetches the last N log lines from a systemd unit via journalctl.
func getUnitLogs(ctx context.Context, unit string, n int) ([]string, error) {
	out, err := runCommand(ctx, "journalctl",
		"-u", unit,
		"-n", fmt.Sprintf("%d", n),
		"--no-pager",
		"-o", "json",
	)
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
