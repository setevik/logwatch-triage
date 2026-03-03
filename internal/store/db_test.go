package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/setevik/logtriage/internal/event"
)

func testDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func makeEvent(instanceID, tier, severity, summary, process, unit string) *event.Event {
	ev := event.New(instanceID, time.Now(), event.Tier(tier), event.Severity(severity), summary)
	ev.Process = process
	ev.Unit = unit
	return ev
}

func TestInsertAndQuery(t *testing.T) {
	db := testDB(t)

	ev := makeEvent("host1", "T1", "critical", "OOM Kill: firefox", "firefox", "")
	ev.Detail = "Firefox was killed"
	ev.PID = 4521

	if err := db.Insert(ev); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	events, err := db.Query(QueryFilter{
		Since: time.Now().Add(-1 * time.Hour),
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	got := events[0]
	if got.ID != ev.ID {
		t.Errorf("ID = %q, want %q", got.ID, ev.ID)
	}
	if got.InstanceID != "host1" {
		t.Errorf("InstanceID = %q", got.InstanceID)
	}
	if got.Tier != event.TierOOMKill {
		t.Errorf("Tier = %q", got.Tier)
	}
	if got.Process != "firefox" {
		t.Errorf("Process = %q", got.Process)
	}
	if got.PID != 4521 {
		t.Errorf("PID = %d", got.PID)
	}
	if got.Detail != "Firefox was killed" {
		t.Errorf("Detail = %q", got.Detail)
	}
}

func TestQueryFilters(t *testing.T) {
	db := testDB(t)

	// Insert events with different tiers and instances.
	ev1 := makeEvent("host1", "T1", "critical", "OOM", "firefox", "")
	ev2 := makeEvent("host1", "T2", "high", "Crash", "vlc", "")
	ev3 := makeEvent("host2", "T1", "critical", "OOM", "chrome", "")
	ev4 := makeEvent("host1", "T3", "medium", "Service failed", "", "docker.service")

	for _, ev := range []*event.Event{ev1, ev2, ev3, ev4} {
		if err := db.Insert(ev); err != nil {
			t.Fatal(err)
		}
	}

	// Filter by tier.
	events, err := db.Query(QueryFilter{
		Since: time.Now().Add(-1 * time.Hour),
		Tier:  "T1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Errorf("tier filter: got %d events, want 2", len(events))
	}

	// Filter by instance.
	events, err = db.Query(QueryFilter{
		Since:      time.Now().Add(-1 * time.Hour),
		InstanceID: "host2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Errorf("instance filter: got %d events, want 1", len(events))
	}

	// Filter by limit.
	events, err = db.Query(QueryFilter{
		Since: time.Now().Add(-1 * time.Hour),
		Limit: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Errorf("limit filter: got %d events, want 2", len(events))
	}
}

func TestMarkNotified(t *testing.T) {
	db := testDB(t)

	ev := makeEvent("host1", "T1", "critical", "OOM", "firefox", "")
	if err := db.Insert(ev); err != nil {
		t.Fatal(err)
	}

	if err := db.MarkNotified(ev.ID); err != nil {
		t.Fatalf("MarkNotified: %v", err)
	}
}

func TestPurge(t *testing.T) {
	db := testDB(t)

	// Insert an old event by manipulating timestamp.
	ev := event.New("host1", time.Now().Add(-100*24*time.Hour), event.TierOOMKill, event.SevCritical, "Old OOM")
	if err := db.Insert(ev); err != nil {
		t.Fatal(err)
	}

	// Insert a recent event.
	ev2 := makeEvent("host1", "T1", "critical", "Recent OOM", "firefox", "")
	if err := db.Insert(ev2); err != nil {
		t.Fatal(err)
	}

	purged, err := db.Purge(90 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if purged != 1 {
		t.Errorf("purged %d events, want 1", purged)
	}

	events, err := db.Query(QueryFilter{Since: time.Now().Add(-365 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Errorf("after purge: %d events remain, want 1", len(events))
	}
}

func TestCount(t *testing.T) {
	db := testDB(t)

	count, err := db.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 0 {
		t.Errorf("empty db count = %d, want 0", count)
	}

	// Insert some events.
	for i := 0; i < 5; i++ {
		ev := makeEvent("host1", "T1", "critical", "OOM", "firefox", "")
		if err := db.Insert(ev); err != nil {
			t.Fatal(err)
		}
	}

	count, err = db.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 5 {
		t.Errorf("count = %d, want 5", count)
	}
}

func TestCheckCooldownFirstOccurrence(t *testing.T) {
	db := testDB(t)

	ev := makeEvent("host1", "T2", "high", "Crash: vlc", "vlc", "")

	result, err := db.CheckCooldown(ev, 5*time.Minute, 3)
	if err != nil {
		t.Fatalf("CheckCooldown: %v", err)
	}
	if !result.ShouldAlert {
		t.Error("first occurrence should alert")
	}
	if result.Aggregated {
		t.Error("first occurrence should not be aggregated")
	}
}

func TestCheckCooldownSuppression(t *testing.T) {
	db := testDB(t)

	// Insert one existing event.
	ev1 := makeEvent("host1", "T2", "high", "Crash: vlc", "vlc", "")
	if err := db.Insert(ev1); err != nil {
		t.Fatal(err)
	}

	// New event for same process+tier should be suppressed.
	ev2 := makeEvent("host1", "T2", "high", "Crash: vlc", "vlc", "")

	result, err := db.CheckCooldown(ev2, 5*time.Minute, 3)
	if err != nil {
		t.Fatalf("CheckCooldown: %v", err)
	}
	if result.ShouldAlert {
		t.Error("should be suppressed within cooldown window")
	}
	if result.RecentCount != 1 {
		t.Errorf("RecentCount = %d, want 1", result.RecentCount)
	}
}

func TestCheckCooldownAggregation(t *testing.T) {
	db := testDB(t)

	// Insert exactly threshold-count existing events.
	for i := 0; i < 3; i++ {
		ev := makeEvent("host1", "T2", "high", "Crash: vlc", "vlc", "")
		if err := db.Insert(ev); err != nil {
			t.Fatal(err)
		}
	}

	// Next event should trigger aggregate alert.
	ev := makeEvent("host1", "T2", "high", "Crash: vlc", "vlc", "")

	result, err := db.CheckCooldown(ev, 5*time.Minute, 3)
	if err != nil {
		t.Fatalf("CheckCooldown: %v", err)
	}
	if !result.ShouldAlert {
		t.Error("aggregate threshold should trigger alert")
	}
	if !result.Aggregated {
		t.Error("should be flagged as aggregated")
	}
}

func TestCheckCooldownByUnit(t *testing.T) {
	db := testDB(t)

	// Insert a service failure for docker.service.
	ev1 := makeEvent("host1", "T3", "medium", "Service failed: docker.service", "", "docker.service")
	if err := db.Insert(ev1); err != nil {
		t.Fatal(err)
	}

	// Same unit should be suppressed.
	ev2 := makeEvent("host1", "T3", "medium", "Service failed: docker.service", "", "docker.service")
	result, err := db.CheckCooldown(ev2, 5*time.Minute, 3)
	if err != nil {
		t.Fatal(err)
	}
	if result.ShouldAlert {
		t.Error("same unit within cooldown should be suppressed")
	}

	// Different unit should alert.
	ev3 := makeEvent("host1", "T3", "medium", "Service failed: nginx.service", "", "nginx.service")
	result, err = db.CheckCooldown(ev3, 5*time.Minute, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ShouldAlert {
		t.Error("different unit should alert")
	}
}

// TestCheckCooldownInsertBeforeCheckBug validates that the cooldown check must
// happen before the event is inserted. If CheckCooldown runs after Insert, the
// current event is counted against itself and the first occurrence is wrongly
// suppressed (count=1 instead of count=0).
func TestCheckCooldownInsertBeforeCheckBug(t *testing.T) {
	db := testDB(t)

	ev := makeEvent("host1", "T2", "high", "Crash: vlc", "vlc", "")

	// Simulate the OLD (buggy) order: insert first, then check.
	if err := db.Insert(ev); err != nil {
		t.Fatal(err)
	}
	result, err := db.CheckCooldown(ev, 5*time.Minute, 3)
	if err != nil {
		t.Fatal(err)
	}
	// With insert-before-check, count=1, which falls into default → suppress.
	// This is the bug: a first occurrence gets suppressed.
	if result.ShouldAlert {
		t.Error("expected insert-before-check to suppress first occurrence (demonstrating the bug)")
	}
	if result.RecentCount != 1 {
		t.Errorf("RecentCount = %d, want 1 (the just-inserted event)", result.RecentCount)
	}
}

// TestCheckCooldownCheckBeforeInsertFix validates the correct order: check
// cooldown first, then insert. The first occurrence correctly sees count=0
// and alerts.
func TestCheckCooldownCheckBeforeInsertFix(t *testing.T) {
	db := testDB(t)

	ev := makeEvent("host1", "T2", "high", "Crash: vlc", "vlc", "")

	// Correct order: check first, then insert.
	result, err := db.CheckCooldown(ev, 5*time.Minute, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ShouldAlert {
		t.Error("check-before-insert: first occurrence should alert")
	}
	if result.RecentCount != 0 {
		t.Errorf("RecentCount = %d, want 0", result.RecentCount)
	}

	// Now insert.
	if err := db.Insert(ev); err != nil {
		t.Fatal(err)
	}

	// Second event: check first, should be suppressed (count=1).
	ev2 := makeEvent("host1", "T2", "high", "Crash: vlc", "vlc", "")
	result, err = db.CheckCooldown(ev2, 5*time.Minute, 3)
	if err != nil {
		t.Fatal(err)
	}
	if result.ShouldAlert {
		t.Error("second occurrence should be suppressed")
	}
	if result.RecentCount != 1 {
		t.Errorf("RecentCount = %d, want 1", result.RecentCount)
	}
}

// TestCheckCooldownEmptyProcessUnitDifferentSummaries verifies that events
// without process or unit but with different summaries do NOT suppress each
// other. Before the fix, all T4 events with empty process/unit were grouped
// together, causing e.g. GPU errors to suppress disk I/O errors.
func TestCheckCooldownEmptyProcessUnitDifferentSummaries(t *testing.T) {
	db := testDB(t)

	// Insert a GPU error (T4, no process or unit).
	gpuErr := makeEvent("host1", "T4", "high", "NVIDIA Xid 79: GPU fallen off bus", "", "")
	if err := db.Insert(gpuErr); err != nil {
		t.Fatal(err)
	}

	// A different T4 event (disk I/O error) should still alert since it has
	// a different summary, even though tier, process, and unit match.
	diskErr := makeEvent("host1", "T4", "high", "Disk I/O error: sda", "", "")
	result, err := db.CheckCooldown(diskErr, 5*time.Minute, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ShouldAlert {
		t.Error("different T4 event with different summary should alert, not be suppressed by GPU error")
	}
	if result.RecentCount != 0 {
		t.Errorf("RecentCount = %d, want 0 (different summary)", result.RecentCount)
	}
}

// TestCheckCooldownEmptyProcessUnitSameSummary verifies that events without
// process or unit but with the same summary ARE correctly deduplicated.
func TestCheckCooldownEmptyProcessUnitSameSummary(t *testing.T) {
	db := testDB(t)

	// Insert a T4 event with no process or unit.
	ev1 := makeEvent("host1", "T4", "high", "MCE: Machine check error", "", "")
	if err := db.Insert(ev1); err != nil {
		t.Fatal(err)
	}

	// Same summary → should be suppressed.
	ev2 := makeEvent("host1", "T4", "high", "MCE: Machine check error", "", "")
	result, err := db.CheckCooldown(ev2, 5*time.Minute, 3)
	if err != nil {
		t.Fatal(err)
	}
	if result.ShouldAlert {
		t.Error("same T4 event with same summary should be suppressed")
	}
	if result.RecentCount != 1 {
		t.Errorf("RecentCount = %d, want 1", result.RecentCount)
	}
}

// TestCheckCooldownEmptyProcessUnitDoesNotMatchProcessEvent verifies that
// events with a process set are not counted when deduplicating an event that
// has no process or unit.
func TestCheckCooldownEmptyProcessUnitDoesNotMatchProcessEvent(t *testing.T) {
	db := testDB(t)

	// Insert a T4 event that has a process set.
	withProcess := makeEvent("host1", "T4", "high", "Kernel/HW: something", "kernel", "")
	if err := db.Insert(withProcess); err != nil {
		t.Fatal(err)
	}

	// A T4 event without process/unit should not count the above event,
	// even if tier matches.
	noProcess := makeEvent("host1", "T4", "high", "Kernel/HW: something", "", "")
	result, err := db.CheckCooldown(noProcess, 5*time.Minute, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ShouldAlert {
		t.Error("event without process should not be suppressed by event with process")
	}
	if result.RecentCount != 0 {
		t.Errorf("RecentCount = %d, want 0", result.RecentCount)
	}
}
