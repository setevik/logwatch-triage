// Package event defines the core data model for logtriage events.
package event

import (
	"time"

	"github.com/google/uuid"
)

// Tier classifies the type of system event.
type Tier string

const (
	TierOOMKill      Tier = "T1"
	TierProcessCrash Tier = "T2"
)

// Severity indicates the urgency of an event.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevWarning  Severity = "warning"
)

// Event represents a classified system event with enriched context.
type Event struct {
	ID         string
	InstanceID string
	Timestamp  time.Time
	Tier       Tier
	Severity   Severity
	Summary    string
	Process    string
	PID        int
	Unit       string
	Detail     string
	RawFields  map[string]string
}

// New creates a new Event with a generated UUID and the given timestamp.
func New(instanceID string, ts time.Time, tier Tier, sev Severity, summary string) *Event {
	return &Event{
		ID:         uuid.NewString(),
		InstanceID: instanceID,
		Timestamp:  ts,
		Tier:       tier,
		Severity:   sev,
		Summary:    summary,
		RawFields:  make(map[string]string),
	}
}

// TierLabel returns a human-readable label for the tier.
func (t Tier) Label() string {
	switch t {
	case TierOOMKill:
		return "OOM Kill"
	case TierProcessCrash:
		return "Process Crash"
	default:
		return string(t)
	}
}

// SeverityLabel returns a human-readable label for severity.
func (s Severity) Label() string {
	return string(s)
}
