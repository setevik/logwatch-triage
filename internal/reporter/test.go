package reporter

import (
	"time"

	"github.com/setevik/logtriage/internal/event"
)

// TestEvent creates a synthetic event for testing ntfy connectivity.
type TestEvent struct {
	InstanceID string
}

// ToEvent converts a TestEvent to a real Event suitable for Report().
func (t *TestEvent) ToEvent() *event.Event {
	return &event.Event{
		ID:         "test-" + time.Now().Format("20060102-150405"),
		InstanceID: t.InstanceID,
		Timestamp:  time.Now(),
		Tier:       event.TierProcessCrash,
		Severity:   event.SevHigh,
		Summary:    "Test notification from logtriage",
		Detail:     "This is a test notification to verify ntfy connectivity.\nIf you see this, logtriage is configured correctly.",
		RawFields:  map[string]string{},
	}
}
