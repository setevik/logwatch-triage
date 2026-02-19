package reporter

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/setevik/logtriage/internal/config"
	"github.com/setevik/logtriage/internal/event"
)

// NtfyReporter sends event notifications to an ntfy server.
type NtfyReporter struct {
	cfg    *config.Config
	client *http.Client
}

// NewNtfy creates a new NtfyReporter.
func NewNtfy(cfg *config.Config) *NtfyReporter {
	return &NtfyReporter{
		cfg: cfg,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Report sends an event notification to ntfy if the event's tier is in the
// configured alert tiers.
func (r *NtfyReporter) Report(ctx context.Context, ev *event.Event) error {
	if r.cfg.Ntfy.URL == "" {
		slog.Debug("ntfy URL not configured, skipping notification")
		return nil
	}

	if !r.cfg.ShouldAlert(string(ev.Tier)) {
		slog.Debug("event tier not in alert tiers, skipping", "tier", ev.Tier)
		return nil
	}

	title := FormatTitle(ev)
	body := FormatBody(ev)
	priority := r.cfg.NtfyPriority(string(ev.Severity))
	tags := TagsForTier(ev.Tier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.Ntfy.URL, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating ntfy request: %w", err)
	}

	req.Header.Set("Title", title)
	req.Header.Set("Priority", priority)
	req.Header.Set("Tags", tags)

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending ntfy notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy returned status %d", resp.StatusCode)
	}

	slog.Info("notification sent", "tier", ev.Tier, "summary", ev.Summary, "priority", priority)
	return nil
}
