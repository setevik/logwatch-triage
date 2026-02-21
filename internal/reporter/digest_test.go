package reporter

import (
	"strings"
	"testing"
	"time"

	"github.com/setevik/logtriage/internal/event"
)

func TestBuildDigestEmpty(t *testing.T) {
	since := time.Date(2024, 2, 10, 0, 0, 0, 0, time.UTC)
	until := time.Date(2024, 2, 17, 0, 0, 0, 0, time.UTC)

	d := BuildDigest("testhost", nil, since, until)
	if d.InstanceID != "testhost" {
		t.Errorf("InstanceID = %q, want testhost", d.InstanceID)
	}
	if d.OOMKills != 0 || d.Crashes != 0 || d.ServiceFailures != 0 || d.KernelHWErrors != 0 || d.MemPressure != 0 {
		t.Error("expected all counts to be zero for empty event list")
	}
}

func TestBuildDigestCounts(t *testing.T) {
	since := time.Date(2024, 2, 10, 0, 0, 0, 0, time.UTC)
	until := time.Date(2024, 2, 17, 0, 0, 0, 0, time.UTC)

	events := []*event.Event{
		{Tier: event.TierOOMKill, Process: "firefox"},
		{Tier: event.TierOOMKill, Process: "electron"},
		{Tier: event.TierOOMKill, Process: "firefox"},
		{Tier: event.TierProcessCrash, Process: "vlc"},
		{Tier: event.TierProcessCrash, Process: "vlc"},
		{Tier: event.TierProcessCrash, Process: "gimp"},
		{Tier: event.TierServiceFailure, Unit: "docker.service"},
		{Tier: event.TierKernelHW, Summary: "I/O error on /dev/sda"},
		{Tier: event.TierKernelHW, Summary: "I/O error on /dev/sda"},
		{Tier: event.TierKernelHW, Summary: "EXT4 error on /dev/sdb"},
		{Tier: event.TierMemPressure},
		{Tier: event.TierMemPressure},
	}

	d := BuildDigest("testhost", events, since, until)

	if d.OOMKills != 3 {
		t.Errorf("OOMKills = %d, want 3", d.OOMKills)
	}
	if d.Crashes != 3 {
		t.Errorf("Crashes = %d, want 3", d.Crashes)
	}
	if d.ServiceFailures != 1 {
		t.Errorf("ServiceFailures = %d, want 1", d.ServiceFailures)
	}
	if d.KernelHWErrors != 3 {
		t.Errorf("KernelHWErrors = %d, want 3", d.KernelHWErrors)
	}
	if d.MemPressure != 2 {
		t.Errorf("MemPressure = %d, want 2", d.MemPressure)
	}

	// Check breakdowns.
	if d.OOMBreakdown["firefox"] != 2 {
		t.Errorf("OOM firefox = %d, want 2", d.OOMBreakdown["firefox"])
	}
	if d.OOMBreakdown["electron"] != 1 {
		t.Errorf("OOM electron = %d, want 1", d.OOMBreakdown["electron"])
	}
	if d.CrashBreakdown["vlc"] != 2 {
		t.Errorf("crash vlc = %d, want 2", d.CrashBreakdown["vlc"])
	}
	if d.ServiceBreakdown["docker.service"] != 1 {
		t.Errorf("service docker = %d, want 1", d.ServiceBreakdown["docker.service"])
	}

	// Kernel breakdown should deduplicate summaries.
	if len(d.KernelBreakdown) != 2 {
		t.Errorf("KernelBreakdown len = %d, want 2", len(d.KernelBreakdown))
	}
}

func TestBuildDigestUnknownProcess(t *testing.T) {
	events := []*event.Event{
		{Tier: event.TierOOMKill, Process: ""},
		{Tier: event.TierProcessCrash, Process: ""},
		{Tier: event.TierServiceFailure, Unit: ""},
	}

	d := BuildDigest("host", events, time.Now(), time.Now())

	if d.OOMBreakdown["unknown"] != 1 {
		t.Errorf("OOM unknown = %d, want 1", d.OOMBreakdown["unknown"])
	}
	if d.CrashBreakdown["unknown"] != 1 {
		t.Errorf("crash unknown = %d, want 1", d.CrashBreakdown["unknown"])
	}
	if d.ServiceBreakdown["unknown"] != 1 {
		t.Errorf("service unknown = %d, want 1", d.ServiceBreakdown["unknown"])
	}
}

func TestFormatDigest(t *testing.T) {
	d := &DigestSummary{
		InstanceID:       "workstation",
		Since:            time.Date(2024, 2, 10, 0, 0, 0, 0, time.UTC),
		Until:            time.Date(2024, 2, 17, 0, 0, 0, 0, time.UTC),
		OOMKills:         2,
		OOMBreakdown:     map[string]int{"firefox": 1, "electron": 1},
		Crashes:          3,
		CrashBreakdown:   map[string]int{"vlc": 2, "gimp": 1},
		ServiceFailures:  1,
		ServiceBreakdown: map[string]int{"docker.service": 1},
		KernelHWErrors:   0,
		KernelBreakdown:  nil,
		MemPressure:      4,
	}

	out := FormatDigest(d)

	// Check key content is present.
	checks := []string{
		"workstation",
		"OOM Kills:        2",
		"Process Crashes:  3",
		"Service Failures: 1",
		"HW/Kernel Errors: 0",
		"Memory Pressure:  4",
		"firefox",
		"electron",
		"vlc",
		"gimp",
		"docker.service",
	}

	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("output missing %q\nfull output:\n%s", check, out)
		}
	}
}

func TestFormatDigestTitle(t *testing.T) {
	since := time.Date(2024, 2, 10, 0, 0, 0, 0, time.UTC)
	until := time.Date(2024, 2, 16, 0, 0, 0, 0, time.UTC)

	title := FormatDigestTitle(since, until)
	if !strings.Contains(title, "weekly digest") {
		t.Errorf("title missing 'weekly digest': %q", title)
	}
	if !strings.Contains(title, "Feb 10") {
		t.Errorf("title missing start date: %q", title)
	}
}

func TestFormatBreakdown(t *testing.T) {
	m := map[string]int{"firefox": 3, "chrome": 1, "vlc": 2}
	out := formatBreakdown(m)

	// Should be sorted by count desc.
	firefoxIdx := strings.Index(out, "firefox")
	vlcIdx := strings.Index(out, "vlc")
	chromeIdx := strings.Index(out, "chrome")

	if firefoxIdx == -1 || vlcIdx == -1 || chromeIdx == -1 {
		t.Fatalf("missing entries in breakdown: %q", out)
	}
	if firefoxIdx > vlcIdx || vlcIdx > chromeIdx {
		t.Errorf("breakdown not sorted by count desc: %q", out)
	}

	if !strings.Contains(out, "\u00d73") {
		t.Errorf("missing count marker: %q", out)
	}
}
