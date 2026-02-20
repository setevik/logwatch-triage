package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/setevik/logtriage/internal/event"
)

// DedupResult describes whether an event should be alerted on.
type DedupResult struct {
	// ShouldAlert is true if this event should trigger a notification.
	ShouldAlert bool
	// RecentCount is the number of similar events within the cooldown window.
	RecentCount int
	// Aggregated is true if the alert was suppressed during cooldown but the
	// aggregate threshold was just reached, so a summary alert should fire.
	Aggregated bool
}

// CheckCooldown determines whether an event should trigger an alert based on
// how many similar events (same instance, tier, process/unit) have occurred
// within the cooldown window.
//
// Logic:
//   - If no prior events within window: alert (first occurrence).
//   - If prior events exist but count < threshold: suppress (within cooldown).
//   - If count == threshold: alert as aggregated (crash-looping summary).
//   - If count > threshold: suppress (already sent aggregate alert).
func (d *DB) CheckCooldown(ev *event.Event, window time.Duration, threshold int) (DedupResult, error) {
	since := ev.Timestamp.Add(-window).UTC().Format(time.RFC3339Nano)

	// Build dedup key: match on instance + tier + (process or unit).
	query := `SELECT COUNT(*) FROM events
		WHERE instance_id = ? AND tier = ? AND timestamp >= ?`
	args := []interface{}{ev.InstanceID, string(ev.Tier), since}

	if ev.Unit != "" {
		query += " AND unit = ?"
		args = append(args, ev.Unit)
	} else if ev.Process != "" {
		query += " AND process = ?"
		args = append(args, ev.Process)
	}

	var count int
	err := d.db.QueryRow(query, args...).Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		return DedupResult{}, fmt.Errorf("checking cooldown: %w", err)
	}

	result := DedupResult{RecentCount: count}

	switch {
	case count == 0:
		// First occurrence in the window — alert.
		result.ShouldAlert = true
	case count == threshold:
		// Hit the aggregate threshold — send a summary alert.
		result.ShouldAlert = true
		result.Aggregated = true
	default:
		// Within cooldown (either still accumulating or already aggregated).
		result.ShouldAlert = false
	}

	slog.Debug("cooldown check",
		"tier", ev.Tier,
		"process", ev.Process,
		"unit", ev.Unit,
		"recent_count", count,
		"threshold", threshold,
		"should_alert", result.ShouldAlert,
	)

	return result, nil
}
