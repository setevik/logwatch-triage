package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SMARTStatus represents the health status of a disk.
type SMARTStatus struct {
	Device       string
	ModelName    string
	Healthy      bool
	Temperature  int
	ReallocCount int
	PendCount    int
	ErrorCount   int
}

// SMARTEvent is emitted when a disk's SMART status changes or has errors.
type SMARTEvent struct {
	Timestamp time.Time
	Status    SMARTStatus
	Changed   bool // true if status changed since last poll
}

// SMARTMonitor polls smartctl for disk health and emits events on changes.
type SMARTMonitor struct {
	pollInterval time.Duration
	lastStatus   map[string]SMARTStatus
}

// NewSMARTMonitor creates a SMART monitor with the given poll interval.
func NewSMARTMonitor(pollInterval time.Duration) *SMARTMonitor {
	return &SMARTMonitor{
		pollInterval: pollInterval,
		lastStatus:   make(map[string]SMARTStatus),
	}
}

// Events starts the SMART polling loop and returns a channel of disk events.
// Only events with status changes or errors are emitted.
func (m *SMARTMonitor) Events(ctx context.Context) <-chan SMARTEvent {
	ch := make(chan SMARTEvent, 8)
	go m.poll(ctx, ch)
	return ch
}

func (m *SMARTMonitor) poll(ctx context.Context, ch chan<- SMARTEvent) {
	defer close(ch)

	// Initial poll.
	m.checkAll(ctx, ch)

	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkAll(ctx, ch)
		}
	}
}

func (m *SMARTMonitor) checkAll(ctx context.Context, ch chan<- SMARTEvent) {
	devices, err := detectDisks()
	if err != nil {
		slog.Debug("failed to detect disks", "error", err)
		return
	}

	for _, dev := range devices {
		status, err := querySMART(ctx, dev)
		if err != nil {
			slog.Debug("smartctl query failed", "device", dev, "error", err)
			continue
		}

		prev, seen := m.lastStatus[dev]
		changed := !seen || statusChanged(prev, status)

		if changed || !status.Healthy || status.ReallocCount > 0 || status.PendCount > 0 {
			ev := SMARTEvent{
				Timestamp: time.Now(),
				Status:    status,
				Changed:   changed,
			}

			select {
			case ch <- ev:
			case <-ctx.Done():
				return
			default:
			}
		}

		m.lastStatus[dev] = status
	}
}

// detectDisks finds block devices that support SMART.
func detectDisks() ([]string, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}

	var devices []string
	for _, e := range entries {
		name := e.Name()
		// Skip loop, ram, and dm devices.
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") {
			continue
		}
		// Check if it's a real device (has a device/ subdirectory).
		if _, err := os.Stat(filepath.Join("/sys/block", name, "device")); err == nil {
			devices = append(devices, "/dev/"+name)
		}
	}
	return devices, nil
}

// querySMART runs smartctl and parses the JSON output.
func querySMART(ctx context.Context, device string) (SMARTStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "smartctl", "--json=c", "-a", device)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// smartctl exits non-zero on errors but still provides JSON output.
	_ = cmd.Run()

	if stdout.Len() == 0 {
		return SMARTStatus{}, fmt.Errorf("smartctl returned no output for %s: %s", device, stderr.String())
	}

	return parseSMARTJSON(device, stdout.Bytes())
}

// smartJSON is the subset of smartctl JSON output we care about.
type smartJSON struct {
	ModelName   string `json:"model_name"`
	SmartStatus struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature struct {
		Current int `json:"current"`
	} `json:"temperature"`
	ATASmartAttributes struct {
		Table []struct {
			ID    int    `json:"id"`
			Name  string `json:"name"`
			Value int    `json:"value"`
			Raw   struct {
				Value int `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
}

func parseSMARTJSON(device string, data []byte) (SMARTStatus, error) {
	var j smartJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return SMARTStatus{}, fmt.Errorf("parsing smartctl JSON: %w", err)
	}

	status := SMARTStatus{
		Device:      device,
		ModelName:   j.ModelName,
		Healthy:     j.SmartStatus.Passed,
		Temperature: j.Temperature.Current,
	}

	// Extract key SMART attributes.
	for _, attr := range j.ATASmartAttributes.Table {
		switch attr.ID {
		case 5: // Reallocated_Sector_Ct
			status.ReallocCount = attr.Raw.Value
		case 197: // Current_Pending_Sector
			status.PendCount = attr.Raw.Value
		case 199: // UDMA_CRC_Error_Count (or other error counts)
			status.ErrorCount = attr.Raw.Value
		}
	}

	return status, nil
}

func statusChanged(prev, curr SMARTStatus) bool {
	return prev.Healthy != curr.Healthy ||
		prev.ReallocCount != curr.ReallocCount ||
		prev.PendCount != curr.PendCount ||
		prev.ErrorCount != curr.ErrorCount
}
