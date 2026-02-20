// logtriage watches system logs and detects high-severity issues
// (OOM kills, crashes, service failures), performs root cause correlation,
// and reports findings via ntfy webhook.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/setevik/logtriage/internal/classifier"
	"github.com/setevik/logtriage/internal/config"
	"github.com/setevik/logtriage/internal/enricher"
	"github.com/setevik/logtriage/internal/event"
	"github.com/setevik/logtriage/internal/reporter"
	"github.com/setevik/logtriage/internal/store"
	"github.com/setevik/logtriage/internal/watcher"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "query":
			runQuery(os.Args[2:])
			return
		case "test-ntfy":
			runTestNtfyCmd(os.Args[2:])
			return
		case "version":
			fmt.Println("logtriage", version)
			return
		}
	}

	// Default: run daemon.
	runDaemon(os.Args[1:])
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("logtriage", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config file")
	showVersion := fs.Bool("version", false, "print version and exit")
	testNtfy := fs.Bool("test-ntfy", false, "send a test notification and exit")
	fs.Parse(args)

	if *showVersion {
		fmt.Println("logtriage", version)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	setupLogging(cfg.Log.Level)

	slog.Info("logtriage starting",
		"version", version,
		"instance", cfg.Instance.ID,
		"role", cfg.Instance.Role,
	)

	if *testNtfy {
		doTestNtfy(cfg)
		return
	}

	if err := run(cfg); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Create cursor file path for journalctl resume.
	dataDir, err := dataDirectory()
	if err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}
	cursorFile := filepath.Join(dataDir, "journal-cursor")

	// Open event database.
	db, err := store.Open(cfg.DBPath())
	if err != nil {
		return fmt.Errorf("opening event database: %w", err)
	}
	defer db.Close()

	slog.Info("event database opened", "path", cfg.DBPath())

	// Run retention purge on startup.
	if cfg.DB.Retention.Duration > 0 {
		purged, err := db.Purge(cfg.DB.Retention.Duration)
		if err != nil {
			slog.Warn("failed to purge old events", "error", err)
		} else if purged > 0 {
			slog.Info("purged old events", "count", purged, "retention", cfg.DB.Retention.Duration)
		}
	}

	// Set up the pipeline: watcher -> classifier -> enricher -> store + dedup -> reporter.
	cls := classifier.New(cfg.Instance.ID)
	enr := enricher.New()
	rep := reporter.NewNtfy(cfg)

	// Create supervised journal source.
	supervised := watcher.NewSupervisedSource(
		func() watcher.JournalSource {
			return watcher.NewPipeSource(cursorFile)
		},
		5*time.Second, // restart wait
		0,             // unlimited restarts
	)

	entries, err := supervised.Entries(ctx)
	if err != nil {
		return fmt.Errorf("starting journal watcher: %w", err)
	}

	slog.Info("pipeline started, watching for events")

	for {
		select {
		case entry, ok := <-entries:
			if !ok {
				slog.Warn("journal entry channel closed")
				return nil
			}

			ev := cls.Classify(entry)
			if ev == nil {
				continue
			}

			slog.Info("event classified",
				"tier", ev.Tier,
				"severity", ev.Severity,
				"summary", ev.Summary,
			)

			enr.Enrich(ctx, ev)

			// Store event in database.
			if err := db.Insert(ev); err != nil {
				slog.Error("failed to store event", "error", err)
			}

			// Check cooldown before notifying.
			dedup, err := db.CheckCooldown(ev, cfg.Cooldown.Window.Duration, cfg.Cooldown.AggregateThreshold)
			if err != nil {
				slog.Error("cooldown check failed", "error", err)
			}

			if dedup.ShouldAlert {
				if dedup.Aggregated {
					ev.Summary = fmt.Sprintf("[x%d] %s", dedup.RecentCount, ev.Summary)
				}
				if err := rep.Report(ctx, ev); err != nil {
					slog.Error("failed to send notification", "error", err)
				} else {
					_ = db.MarkNotified(ev.ID)
				}
			} else {
				slog.Debug("notification suppressed by cooldown",
					"tier", ev.Tier,
					"recent_count", dedup.RecentCount,
				)
			}

		case sig := <-sigCh:
			slog.Info("received signal, shutting down", "signal", sig)
			cancel()
			return nil
		}
	}
}

// --- query subcommand ---

func runQuery(args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config file")
	last := fs.String("last", "24h", "time window (e.g. 24h, 7d, 30d)")
	tier := fs.String("tier", "", "filter by tier (T1, T2, T3)")
	instance := fs.String("instance", "", "filter by instance ID")
	limit := fs.Int("limit", 50, "max events to show")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	setupLogging("error") // quiet for CLI output

	db, err := store.Open(cfg.DBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	since, err := parseDuration(*last)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --last value %q: %v\n", *last, err)
		os.Exit(1)
	}

	filter := store.QueryFilter{
		Since:      time.Now().Add(-since),
		Tier:       strings.ToUpper(*tier),
		InstanceID: *instance,
		Limit:      *limit,
	}

	events, err := db.Query(filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "query error: %v\n", err)
		os.Exit(1)
	}

	if len(events) == 0 {
		fmt.Println("No events found.")
		return
	}

	printEvents(events)
}

func printEvents(events []*event.Event) {
	for _, ev := range events {
		ts := ev.Timestamp.Local().Format("2006-01-02 15:04:05")
		tierLabel := ev.Tier.Label()
		fmt.Printf("%s  [%s] %-18s %s\n", ts, ev.Tier, tierLabel, ev.Summary)
		if ev.Unit != "" {
			fmt.Printf("             Unit: %s\n", ev.Unit)
		}
		if ev.Detail != "" {
			// Print first line of detail as a brief.
			lines := strings.SplitN(ev.Detail, "\n", 2)
			fmt.Printf("             %s\n", lines[0])
		}
		fmt.Println()
	}
	fmt.Printf("Total: %d event(s)\n", len(events))
}

// parseDuration extends time.ParseDuration with support for "d" (days) suffix.
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		s = strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(s, "%d", &days); err != nil {
			return 0, fmt.Errorf("invalid days format: %s", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// --- test-ntfy subcommand ---

func runTestNtfyCmd(args []string) {
	fs := flag.NewFlagSet("test-ntfy", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config file")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	setupLogging(cfg.Log.Level)
	doTestNtfy(cfg)
}

func doTestNtfy(cfg *config.Config) {
	if cfg.Ntfy.URL == "" {
		fmt.Fprintln(os.Stderr, "error: ntfy.url not configured")
		os.Exit(1)
	}

	rep := reporter.NewNtfy(cfg)
	ev := &reporter.TestEvent{
		InstanceID: cfg.Instance.ID,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := rep.Report(ctx, ev.ToEvent()); err != nil {
		fmt.Fprintf(os.Stderr, "error sending test notification: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Test notification sent successfully.")
}

func setupLogging(level string) {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})
	slog.SetDefault(slog.New(handler))
}

func dataDirectory() (string, error) {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	dir := filepath.Join(dataHome, "logtriage")
	return dir, os.MkdirAll(dir, 0o750)
}
