package enricher

import (
	"context"
	"log/slog"

	"github.com/setevik/logtriage/internal/event"
)

// Enricher adds context to classified events via subprocess queries.
type Enricher struct{}

// New creates a new Enricher.
func New() *Enricher {
	return &Enricher{}
}

// Enrich adds detailed context to an event based on its tier.
// This may spawn short-lived subprocesses (journalctl, coredumpctl) to
// gather additional information.
func (e *Enricher) Enrich(ctx context.Context, ev *event.Event) {
	switch ev.Tier {
	case event.TierOOMKill:
		enrichOOM(ctx, ev)
	case event.TierProcessCrash:
		enrichCrash(ctx, ev)
		// Also check if this is a compositor crash (possibly GPU-related).
		enrichCompositorCrash(ctx, ev)
	case event.TierServiceFailure:
		enrichService(ctx, ev)
	case event.TierKernelHW:
		// Use GPU-specific enrichment for GPU events, disk enrichment otherwise.
		if ev.RawFields["_gpu_event"] == "true" {
			enrichGPU(ctx, ev)
		} else {
			enrichKernelHW(ctx, ev)
		}
	default:
		slog.Debug("no enrichment available for tier", "tier", ev.Tier)
	}
}
