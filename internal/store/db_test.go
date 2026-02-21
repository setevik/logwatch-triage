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
