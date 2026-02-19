// logtriage watches system logs and detects high-severity issues
// (OOM kills, crashes), performs root cause correlation, and reports
// findings via ntfy webhook.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/setevik/logtriage/internal/classifier"
	"github.com/setevik/logtriage/internal/config"
	"github.com/setevik/logtriage/internal/enricher"
	"github.com/setevik/logtriage/internal/reporter"
	"github.com/setevik/logtriage/internal/watcher"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to config file (default: ~/.config/logtriage/config.toml)")
	showVersion := flag.Bool("version", false, "print version and exit")
	testNtfy := flag.Bool("test-ntfy", false, "send a test notification and exit")
	flag.Parse()

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
		runTestNtfy(cfg)
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

	// Set up the pipeline: watcher -> classifier -> enricher -> reporter.
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

			if err := rep.Report(ctx, ev); err != nil {
				slog.Error("failed to send notification", "error", err)
			}

		case sig := <-sigCh:
			slog.Info("received signal, shutting down", "signal", sig)
			cancel()
			return nil
		}
	}
}

func runTestNtfy(cfg *config.Config) {
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
