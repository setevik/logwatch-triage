package watcher

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"sync"
)

// PipeSource implements JournalSource by tailing journalctl --follow -o json.
type PipeSource struct {
	cursorFile string
	mu         sync.Mutex
	cmd        *exec.Cmd
	cancel     context.CancelFunc
}

// NewPipeSource creates a new PipeSource. cursorFile is the path to a file
// where journalctl stores its cursor for crash-safe resume. Pass "" to disable.
func NewPipeSource(cursorFile string) *PipeSource {
	return &PipeSource{cursorFile: cursorFile}
}

func (p *PipeSource) Entries(ctx context.Context) (<-chan JournalEntry, error) {
	ctx, cancel := context.WithCancel(ctx)
	p.mu.Lock()
	p.cancel = cancel
	p.mu.Unlock()

	args := []string{
		"--follow",
		"-o", "json",
		"--no-pager",
		"-p", "0..3", // emerg..err
	}
	if p.cursorFile != "" {
		args = append(args, "--cursor-file", p.cursorFile)
	}

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	p.mu.Lock()
	p.cmd = cmd
	p.mu.Unlock()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("starting journalctl: %w", err)
	}

	ch := make(chan JournalEntry, 64)

	go func() {
		defer close(ch)
		defer func() {
			_ = cmd.Wait()
		}()

		scanner := bufio.NewScanner(stdout)
		// Journal entries can be large; increase buffer to 1MB.
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			line := scanner.Bytes()
			entry, err := parseJournalJSON(line)
			if err != nil {
				slog.Debug("skipping unparseable journal line", "error", err)
				continue
			}

			select {
			case ch <- entry:
			case <-ctx.Done():
				return
			}
		}

		if err := scanner.Err(); err != nil {
			slog.Warn("journal scanner error", "error", err)
		}
	}()

	slog.Info("journal watcher started", "priority_filter", "0..3")
	return ch, nil
}

func (p *PipeSource) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		p.cancel()
	}
}

// parseJournalJSON parses a single JSON line from journalctl -o json.
func parseJournalJSON(data []byte) (JournalEntry, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return JournalEntry{}, err
	}

	fields := make(map[string]string, len(raw))
	for k, v := range raw {
		switch val := v.(type) {
		case string:
			fields[k] = val
		case float64:
			fields[k] = strconv.FormatFloat(val, 'f', -1, 64)
		case []interface{}:
			// journalctl may emit arrays for multi-value fields; take first.
			if len(val) > 0 {
				fields[k] = fmt.Sprintf("%v", val[0])
			}
		default:
			fields[k] = fmt.Sprintf("%v", v)
		}
	}

	priority, _ := strconv.Atoi(fields["PRIORITY"])

	return JournalEntry{
		Message:           fields["MESSAGE"],
		Priority:          priority,
		SyslogIdentifier:  fields["SYSLOG_IDENTIFIER"],
		SystemdUnit:       fields["_SYSTEMD_UNIT"],
		PID:               fields["_PID"],
		Transport:         fields["_TRANSPORT"],
		Cursor:            fields["__CURSOR"],
		RealtimeTimestamp: fields["__REALTIME_TIMESTAMP"],
		Fields:            fields,
	}, nil
}
