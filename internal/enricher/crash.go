package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/setevik/logtriage/internal/event"
	"github.com/setevik/logtriage/internal/format"
)

// enrichCrash adds coredump context to a crash event by querying coredumpctl.
func enrichCrash(ctx context.Context, ev *event.Event) {
	if ev.PID == 0 {
		return
	}

	info, err := getCoredumpInfo(ctx, ev.PID)
	if err != nil {
		slog.Debug("crash enrichment: coredumpctl query failed", "pid", ev.PID, "error", err)
		return
	}

	var detail strings.Builder

	if ev.Process != "" {
		fmt.Fprintf(&detail, "%s crashed", ev.Process)
	}
	if info.Signal != "" {
		fmt.Fprintf(&detail, " with %s", info.Signal)
	}
	detail.WriteString(".\n")

	if info.CoredumpSize > 0 {
		fmt.Fprintf(&detail, "Coredump saved (%s).\n", format.Bytes(info.CoredumpSize))
	}

	if len(info.Backtrace) > 0 {
		detail.WriteString("\nTop backtrace frames:\n")
		limit := 5
		if len(info.Backtrace) < limit {
			limit = len(info.Backtrace)
		}
		for i, frame := range info.Backtrace[:limit] {
			fmt.Fprintf(&detail, "  #%d %s\n", i, frame)
		}
	}

	ev.Detail = detail.String()
}

type coredumpInfo struct {
	Signal       string
	Executable   string
	CoredumpSize int64
	Backtrace    []string
}

// getCoredumpInfo queries coredumpctl for crash details about a given PID.
func getCoredumpInfo(ctx context.Context, pid int) (*coredumpInfo, error) {
	out, err := runCommand(ctx, "coredumpctl", "info", fmt.Sprintf("%d", pid), "--json=short", "--no-pager")
	if err != nil {
		return nil, err
	}

	// coredumpctl --json=short outputs a JSON array.
	var entries []map[string]interface{}
	if err := json.Unmarshal(out, &entries); err != nil {
		// Try single object.
		var entry map[string]interface{}
		if err2 := json.Unmarshal(out, &entry); err2 != nil {
			return nil, fmt.Errorf("parsing coredumpctl JSON: %w", err)
		}
		entries = []map[string]interface{}{entry}
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no coredump entries found for pid %d", pid)
	}

	entry := entries[len(entries)-1] // most recent
	info := &coredumpInfo{}

	if sig, ok := entry["COREDUMP_SIGNAL_NAME"].(string); ok {
		info.Signal = sig
	} else if sig, ok := entry["COREDUMP_SIGNAL"].(string); ok {
		info.Signal = "signal " + sig
	}

	if exe, ok := entry["COREDUMP_EXE"].(string); ok {
		info.Executable = exe
	}

	if size, ok := entry["COREDUMP_SIZE"].(float64); ok {
		info.CoredumpSize = int64(size)
	}

	return info, nil
}

