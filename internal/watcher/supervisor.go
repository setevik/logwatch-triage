package watcher

import (
	"context"
	"log/slog"
	"time"
)

// SupervisedSource wraps a JournalSource with automatic restart on failure.
type SupervisedSource struct {
	factory     func() JournalSource
	restartWait time.Duration
	maxRestarts int
}

// NewSupervisedSource creates a supervised wrapper around a source factory.
// On source failure, it waits restartWait before creating a new source.
// maxRestarts of 0 means unlimited restarts.
func NewSupervisedSource(factory func() JournalSource, restartWait time.Duration, maxRestarts int) *SupervisedSource {
	return &SupervisedSource{
		factory:     factory,
		restartWait: restartWait,
		maxRestarts: maxRestarts,
	}
}

// Entries starts the supervised source loop. It returns a channel that receives
// entries across restarts. The channel is closed when the context is cancelled
// or max restarts are exceeded.
func (s *SupervisedSource) Entries(ctx context.Context) (<-chan JournalEntry, error) {
	out := make(chan JournalEntry, 64)

	go func() {
		defer close(out)

		restarts := 0
		for {
			if s.maxRestarts > 0 && restarts >= s.maxRestarts {
				slog.Error("journal watcher exceeded max restarts", "max", s.maxRestarts)
				return
			}

			source := s.factory()
			entries, err := source.Entries(ctx)
			if err != nil {
				slog.Error("failed to start journal source", "error", err, "restart_count", restarts)
				select {
				case <-ctx.Done():
					return
				case <-time.After(s.restartWait):
					restarts++
					continue
				}
			}

			slog.Info("journal source started", "restart_count", restarts)

			// Forward entries until the source channel closes.
			sourceDone := false
			for !sourceDone {
				select {
				case entry, ok := <-entries:
					if !ok {
						sourceDone = true
						break
					}
					select {
					case out <- entry:
					case <-ctx.Done():
						source.Stop()
						return
					}
				case <-ctx.Done():
					source.Stop()
					return
				}
			}

			slog.Warn("journal source stopped, restarting", "restart_count", restarts)
			source.Stop()
			restarts++

			select {
			case <-ctx.Done():
				return
			case <-time.After(s.restartWait):
			}
		}
	}()

	return out, nil
}

func (s *SupervisedSource) Stop() {
	// Stopping is handled via context cancellation.
}
