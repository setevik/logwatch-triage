// Package monitor provides proactive system monitoring for memory pressure,
// disk health, and process memory usage.
package monitor

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// PSIStats holds parsed /proc/pressure/memory values.
type PSIStats struct {
	SomeAvg10  float64
	SomeAvg60  float64
	SomeAvg300 float64
	FullAvg10  float64
	FullAvg60  float64
	FullAvg300 float64
}

// PSIEvent is emitted by the PSI monitor when pressure thresholds are exceeded.
type PSIEvent struct {
	Timestamp    time.Time
	Stats        PSIStats
	TopConsumers []ProcMem // filled during high-pressure episodes
}

// PSIMonitor polls /proc/pressure/memory and emits events when thresholds
// are exceeded. Under pressure, it switches to high-frequency polling and
// captures top memory consumers.
type PSIMonitor struct {
	pollInterval  time.Duration
	warnSomeAvg10 float64
	warnFullAvg10 float64
	procPath      string // override for testing
}

// NewPSIMonitor creates a PSI monitor with the given thresholds.
func NewPSIMonitor(pollInterval time.Duration, warnSome, warnFull float64) *PSIMonitor {
	return &PSIMonitor{
		pollInterval:  pollInterval,
		warnSomeAvg10: warnSome,
		warnFullAvg10: warnFull,
		procPath:      "/proc/pressure/memory",
	}
}

// Events starts the PSI polling loop and returns a channel of pressure events.
// Only events that exceed thresholds are emitted.
func (m *PSIMonitor) Events(ctx context.Context) <-chan PSIEvent {
	ch := make(chan PSIEvent, 8)
	go m.poll(ctx, ch)
	return ch
}

func (m *PSIMonitor) poll(ctx context.Context, ch chan<- PSIEvent) {
	defer close(ch)

	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	var inPressure bool
	highFreqTicker := time.NewTicker(1 * time.Second)
	highFreqTicker.Stop() // not started yet

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.check(ctx, ch, &inPressure, ticker, highFreqTicker)
		case <-highFreqTicker.C:
			m.check(ctx, ch, &inPressure, ticker, highFreqTicker)
		}
	}
}

func (m *PSIMonitor) check(ctx context.Context, ch chan<- PSIEvent, inPressure *bool, normalTicker, highFreqTicker *time.Ticker) {
	stats, err := m.readPSI()
	if err != nil {
		slog.Debug("failed to read PSI stats", "error", err)
		return
	}

	exceeded := stats.SomeAvg10 > m.warnSomeAvg10 || stats.FullAvg10 > m.warnFullAvg10

	if exceeded && !*inPressure {
		// Transition to high-pressure mode.
		*inPressure = true
		normalTicker.Stop()
		highFreqTicker.Reset(1 * time.Second)

		slog.Info("memory pressure detected, switching to high-frequency polling",
			"some_avg10", stats.SomeAvg10,
			"full_avg10", stats.FullAvg10,
		)
	} else if !exceeded && *inPressure {
		// Transition back to normal.
		*inPressure = false
		highFreqTicker.Stop()
		normalTicker.Reset(m.pollInterval)

		slog.Info("memory pressure subsided, returning to normal polling")
	}

	if exceeded {
		ev := PSIEvent{
			Timestamp: time.Now(),
			Stats:     stats,
		}

		// Capture top memory consumers during pressure.
		if consumers, err := TopMemConsumers(5); err == nil {
			ev.TopConsumers = consumers
		}

		select {
		case ch <- ev:
		case <-ctx.Done():
			return
		default:
			// Channel full, drop event.
		}
	}
}

func (m *PSIMonitor) readPSI() (PSIStats, error) {
	return ReadPSI(m.procPath)
}

// ReadPSI parses /proc/pressure/memory (or a test file at the given path).
// Format:
//
//	some avg10=0.00 avg60=0.00 avg300=0.00 total=0
//	full avg10=0.00 avg60=0.00 avg300=0.00 total=0
func ReadPSI(path string) (PSIStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return PSIStats{}, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var stats PSIStats
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "some ") {
			stats.SomeAvg10, stats.SomeAvg60, stats.SomeAvg300 = parsePSILine(line)
		} else if strings.HasPrefix(line, "full ") {
			stats.FullAvg10, stats.FullAvg60, stats.FullAvg300 = parsePSILine(line)
		}
	}
	return stats, scanner.Err()
}

// parsePSILine parses a line like "some avg10=2.10 avg60=0.50 avg300=0.10 total=123456"
func parsePSILine(line string) (avg10, avg60, avg300 float64) {
	fields := strings.Fields(line)
	for _, f := range fields {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 {
			continue
		}
		val, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			continue
		}
		switch parts[0] {
		case "avg10":
			avg10 = val
		case "avg60":
			avg60 = val
		case "avg300":
			avg300 = val
		}
	}
	return
}
