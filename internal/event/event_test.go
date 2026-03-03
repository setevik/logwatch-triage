package event

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	ts := time.Date(2026, 2, 19, 14, 0, 0, 0, time.UTC)
	ev := New("myhost", ts, TierOOMKill, SevCritical, "OOM Kill: firefox")

	if ev.ID == "" {
		t.Error("ID should not be empty")
	}
	if ev.InstanceID != "myhost" {
		t.Errorf("InstanceID = %q, want %q", ev.InstanceID, "myhost")
	}
	if ev.Timestamp != ts {
		t.Errorf("Timestamp = %v, want %v", ev.Timestamp, ts)
	}
	if ev.Tier != TierOOMKill {
		t.Errorf("Tier = %q, want %q", ev.Tier, TierOOMKill)
	}
	if ev.Severity != SevCritical {
		t.Errorf("Severity = %q, want %q", ev.Severity, SevCritical)
	}
	if ev.Summary != "OOM Kill: firefox" {
		t.Errorf("Summary = %q", ev.Summary)
	}
	if ev.RawFields == nil {
		t.Error("RawFields should be initialized")
	}
}

func TestNewUniqueIDs(t *testing.T) {
	ts := time.Now()
	ev1 := New("host", ts, TierOOMKill, SevCritical, "a")
	ev2 := New("host", ts, TierOOMKill, SevCritical, "b")
	if ev1.ID == ev2.ID {
		t.Error("two events should have different IDs")
	}
}

func TestTierLabel(t *testing.T) {
	tests := []struct {
		tier  Tier
		label string
	}{
		{TierOOMKill, "OOM Kill"},
		{TierProcessCrash, "Process Crash"},
		{TierServiceFailure, "Service Failure"},
		{TierKernelHW, "Kernel/HW Error"},
		{TierMemPressure, "Memory Pressure"},
		{Tier("T99"), "T99"},
	}

	for _, tt := range tests {
		got := tt.tier.Label()
		if got != tt.label {
			t.Errorf("Tier(%q).Label() = %q, want %q", tt.tier, got, tt.label)
		}
	}
}

func TestSeverityLabel(t *testing.T) {
	tests := []struct {
		sev   Severity
		label string
	}{
		{SevCritical, "critical"},
		{SevHigh, "high"},
		{SevMedium, "medium"},
		{SevWarning, "warning"},
	}

	for _, tt := range tests {
		got := tt.sev.Label()
		if got != tt.label {
			t.Errorf("Severity(%q).Label() = %q, want %q", tt.sev, got, tt.label)
		}
	}
}
