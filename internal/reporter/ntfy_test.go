package reporter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/setevik/logtriage/internal/config"
	"github.com/setevik/logtriage/internal/event"
)

func TestFormatTitle(t *testing.T) {
	ev := &event.Event{
		InstanceID: "workstation",
		Tier:       event.TierOOMKill,
		Summary:    "OOM Kill: firefox (pid 4521)",
	}

	title := FormatTitle(ev)
	if !strings.Contains(title, "[workstation]") {
		t.Errorf("title should contain instance ID, got %q", title)
	}
	if !strings.Contains(title, "OOM Kill: firefox") {
		t.Errorf("title should contain summary, got %q", title)
	}
}

func TestFormatBody(t *testing.T) {
	ev := &event.Event{
		InstanceID: "workstation",
		Timestamp:  time.Date(2026, 2, 19, 14, 32, 5, 0, time.UTC),
		Detail:     "Firefox was killed by OOM killer.\nRSS at kill: 3.2 GB",
	}

	body := FormatBody(ev)
	if !strings.Contains(body, "Host: workstation") {
		t.Errorf("body should contain host, got %q", body)
	}
	if !strings.Contains(body, "2026-02-19 14:32:05") {
		t.Errorf("body should contain formatted time, got %q", body)
	}
	if !strings.Contains(body, "Firefox was killed") {
		t.Errorf("body should contain detail, got %q", body)
	}
}

func TestTagsForTier(t *testing.T) {
	if tags := TagsForTier(event.TierOOMKill); tags != "skull,memory" {
		t.Errorf("T1 tags = %q, want %q", tags, "skull,memory")
	}
	if tags := TagsForTier(event.TierProcessCrash); tags != "warning,crash" {
		t.Errorf("T2 tags = %q, want %q", tags, "warning,crash")
	}
}

func TestNtfyReporterSend(t *testing.T) {
	var receivedTitle, receivedPriority, receivedTags, receivedBody string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTitle = r.Header.Get("Title")
		receivedPriority = r.Header.Get("Priority")
		receivedTags = r.Header.Get("Tags")

		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.Ntfy.URL = server.URL

	rep := NewNtfy(cfg)

	ev := &event.Event{
		ID:         "test-123",
		InstanceID: "testhost",
		Timestamp:  time.Date(2026, 2, 19, 14, 32, 5, 0, time.UTC),
		Tier:       event.TierOOMKill,
		Severity:   event.SevCritical,
		Summary:    "OOM Kill: firefox (pid 4521)",
		Process:    "firefox",
		PID:        4521,
		Detail:     "Firefox was killed by OOM killer.",
		RawFields:  map[string]string{},
	}

	ctx := context.Background()
	if err := rep.Report(ctx, ev); err != nil {
		t.Fatalf("Report() error: %v", err)
	}

	if !strings.Contains(receivedTitle, "OOM Kill") {
		t.Errorf("ntfy title = %q, should contain OOM Kill", receivedTitle)
	}
	if receivedPriority != "urgent" {
		t.Errorf("ntfy priority = %q, want %q", receivedPriority, "urgent")
	}
	if receivedTags != "skull,memory" {
		t.Errorf("ntfy tags = %q, want %q", receivedTags, "skull,memory")
	}
	if !strings.Contains(receivedBody, "testhost") {
		t.Errorf("ntfy body should contain host, got %q", receivedBody)
	}
}

func TestNtfyReporterSkipsNonAlertTier(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.Ntfy.URL = server.URL
	cfg.Ntfy.AlertTiers = []string{"T1"} // only T1

	rep := NewNtfy(cfg)

	ev := &event.Event{
		ID:         "test-456",
		InstanceID: "testhost",
		Timestamp:  time.Now(),
		Tier:       event.TierProcessCrash, // T2 - not in alert tiers
		Severity:   event.SevHigh,
		Summary:    "Crash: vlc",
		RawFields:  map[string]string{},
	}

	ctx := context.Background()
	if err := rep.Report(ctx, ev); err != nil {
		t.Fatalf("Report() error: %v", err)
	}

	if called {
		t.Error("ntfy should not have been called for non-alert tier")
	}
}

func TestNtfyReporterNoURL(t *testing.T) {
	cfg := config.Default()
	cfg.Ntfy.URL = "" // no URL

	rep := NewNtfy(cfg)
	ev := &event.Event{
		Tier:      event.TierOOMKill,
		Severity:  event.SevCritical,
		RawFields: map[string]string{},
	}

	if err := rep.Report(context.Background(), ev); err != nil {
		t.Fatalf("Report() with no URL should not error, got: %v", err)
	}
}
