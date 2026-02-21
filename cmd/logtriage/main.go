// logtriage watches system logs and detects high-severity issues
// (OOM kills, crashes, service failures), performs root cause correlation,
// and reports findings via ntfy webhook.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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
	"github.com/setevik/logtriage/internal/monitor"
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
		case "digest":
			runDigest(os.Args[2:])
			return
		case "status":
			runStatus(os.Args[2:])
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

	// Start PSI monitor if enabled.
	var psiEvents <-chan monitor.PSIEvent
	if cfg.PSI.Enabled {
		psiMon := monitor.NewPSIMonitor(
			cfg.PSI.PollInterval.Duration,
			cfg.PSI.WarnSomeAvg10,
			cfg.PSI.WarnFullAvg10,
		)
		psiEvents = psiMon.Events(ctx)
		slog.Info("PSI monitor started",
			"interval", cfg.PSI.PollInterval.Duration,
			"warn_some", cfg.PSI.WarnSomeAvg10,
			"warn_full", cfg.PSI.WarnFullAvg10,
		)
	}

	// Start SMART monitor if enabled.
	var smartEvents <-chan monitor.SMARTEvent
	if cfg.SMART.Enabled {
		smartMon := monitor.NewSMARTMonitor(cfg.SMART.PollInterval.Duration)
		smartEvents = smartMon.Events(ctx)
		slog.Info("SMART monitor started", "interval", cfg.SMART.PollInterval.Duration)
	}

	// Start GPU monitor if enabled.
	var gpuEvents <-chan monitor.GPUEvent
	if cfg.GPU.Enabled {
		gpuMon := monitor.NewGPUMonitor(
			cfg.GPU.PollInterval.Duration,
			cfg.GPU.TempWarn,
			cfg.GPU.VRAMWarnPct,
		)
		gpuEvents = gpuMon.Events(ctx)
		slog.Info("GPU monitor started",
			"interval", cfg.GPU.PollInterval.Duration,
			"temp_warn", cfg.GPU.TempWarn,
			"vram_warn_pct", cfg.GPU.VRAMWarnPct,
		)
	}

	// Notify systemd we are ready (sd_notify).
	sdNotify("READY=1")

	// Start watchdog ticker if WatchdogSec is configured.
	var watchdogTicker *time.Ticker
	if wdInterval := watchdogInterval(); wdInterval > 0 {
		// Ping at half the watchdog interval.
		watchdogTicker = time.NewTicker(wdInterval / 2)
		defer watchdogTicker.Stop()
		slog.Info("systemd watchdog enabled", "interval", wdInterval)
	}

	slog.Info("pipeline started, watching for events")

	for {
		// Watchdog channel (nil if disabled, select skips nil channels).
		var watchdogCh <-chan time.Time
		if watchdogTicker != nil {
			watchdogCh = watchdogTicker.C
		}

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

			handleEvent(ctx, ev, enr, db, rep, cfg)

		case psiEv, ok := <-psiEvents:
			if !ok {
				psiEvents = nil
				continue
			}

			// Build T5 detail with top consumers.
			detail := fmt.Sprintf("PSI some avg10=%.1f%% full avg10=%.1f%%",
				psiEv.Stats.SomeAvg10, psiEv.Stats.FullAvg10)
			if len(psiEv.TopConsumers) > 0 {
				detail += "\n\nTop memory consumers:\n"
				detail += monitor.FormatTopConsumers(psiEv.TopConsumers)
			}

			ev := cls.ClassifyPSIEvent(psiEv.Stats.SomeAvg10, psiEv.Stats.FullAvg10, detail)
			handleEvent(ctx, ev, enr, db, rep, cfg)

		case smartEv, ok := <-smartEvents:
			if !ok {
				smartEvents = nil
				continue
			}

			s := smartEv.Status
			summary := fmt.Sprintf("SMART: %s (%s)", s.Device, s.ModelName)
			if !s.Healthy {
				summary = fmt.Sprintf("SMART FAILING: %s (%s)", s.Device, s.ModelName)
			}

			var detail strings.Builder
			fmt.Fprintf(&detail, "Device: %s\nModel: %s\n", s.Device, s.ModelName)
			if !s.Healthy {
				fmt.Fprintf(&detail, "Health: FAILED\n")
			}
			if s.Temperature > 0 {
				fmt.Fprintf(&detail, "Temperature: %d°C\n", s.Temperature)
			}
			if s.ReallocCount > 0 {
				fmt.Fprintf(&detail, "Reallocated sectors: %d\n", s.ReallocCount)
			}
			if s.PendCount > 0 {
				fmt.Fprintf(&detail, "Pending sectors: %d\n", s.PendCount)
			}

			ev := cls.ClassifySMARTEvent(s.Device, summary, detail.String())
			handleEvent(ctx, ev, enr, db, rep, cfg)

		case gpuEv, ok := <-gpuEvents:
			if !ok {
				gpuEvents = nil
				continue
			}

			s := gpuEv.Status
			var summary, detail string
			switch gpuEv.Reason {
			case "thermal_warning":
				summary = fmt.Sprintf("GPU thermal warning: %s %d°C", filepath.Base(s.CardPath), s.Temperature)
				detail = monitor.FormatGPUStatus(s)
			case "vram_high":
				pct := int(s.VRAMUsed * 100 / s.VRAMTotal)
				summary = fmt.Sprintf("GPU VRAM high: %s %d%%", filepath.Base(s.CardPath), pct)
				detail = monitor.FormatGPUStatus(s)
			default:
				summary = fmt.Sprintf("GPU event: %s (%s)", filepath.Base(s.CardPath), gpuEv.Reason)
				detail = monitor.FormatGPUStatus(s)
			}

			ev := cls.ClassifyGPUEvent(filepath.Base(s.CardPath), string(s.Vendor), summary, detail)
			handleEvent(ctx, ev, enr, db, rep, cfg)

		case <-watchdogCh:
			sdNotify("WATCHDOG=1")

		case sig := <-sigCh:
			slog.Info("received signal, shutting down", "signal", sig)
			sdNotify("STOPPING=1")
			cancel()
			return nil
		}
	}
}

// handleEvent runs an event through the enrichment, storage, dedup, and notification pipeline.
func handleEvent(ctx context.Context, ev *event.Event, enr *enricher.Enricher, db *store.DB, rep *reporter.NtfyReporter, cfg *config.Config) {
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
}

// --- digest subcommand ---

func runDigest(args []string) {
	fs := flag.NewFlagSet("digest", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config file")
	send := fs.Bool("send", false, "send digest via ntfy (otherwise print to stdout)")
	last := fs.String("last", "7d", "time window for digest")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	setupLogging("error")

	db, err := store.Open(cfg.DBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	duration, err := parseDuration(*last)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --last value: %v\n", err)
		os.Exit(1)
	}

	until := time.Now()
	since := until.Add(-duration)

	events, err := db.Query(store.QueryFilter{Since: since, Until: until})
	if err != nil {
		fmt.Fprintf(os.Stderr, "query error: %v\n", err)
		os.Exit(1)
	}

	digest := reporter.BuildDigest(cfg.Instance.ID, events, since, until)
	body := reporter.FormatDigest(digest)

	if !*send {
		fmt.Print(body)
		return
	}

	// Send via ntfy.
	topic := cfg.DigestTopic()
	if topic == "" {
		fmt.Fprintln(os.Stderr, "error: no ntfy URL configured for digest")
		os.Exit(1)
	}

	title := reporter.FormatDigestTitle(since, until)
	if err := sendDigestNtfy(topic, title, body); err != nil {
		fmt.Fprintf(os.Stderr, "error sending digest: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Digest sent successfully.")
}

func sendDigestNtfy(url, title, body string) error {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", "low")
	req.Header.Set("Tags", "chart")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy returned status %d", resp.StatusCode)
	}
	return nil
}

// --- status subcommand ---

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config file")
	fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	setupLogging("error")

	fmt.Printf("Instance:     %s\n", cfg.Instance.ID)
	fmt.Printf("Role:         %s\n", cfg.Instance.Role)

	db, err := store.Open(cfg.DBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Last event.
	lastEvents, err := db.Query(store.QueryFilter{Limit: 1})
	if err == nil && len(lastEvents) > 0 {
		ev := lastEvents[0]
		ago := time.Since(ev.Timestamp).Truncate(time.Second)
		fmt.Printf("Last event:   [%s] %s — %s ago\n", ev.Tier, ev.Summary, formatDuration(ago))
	} else {
		fmt.Println("Last event:   none")
	}

	// Event counts for last 24h.
	since24h := time.Now().Add(-24 * time.Hour)
	events24h, _ := db.Query(store.QueryFilter{Since: since24h})

	var oom, crash, svcFail, kernHW, memPres int
	for _, ev := range events24h {
		switch ev.Tier {
		case event.TierOOMKill:
			oom++
		case event.TierProcessCrash:
			crash++
		case event.TierServiceFailure:
			svcFail++
		case event.TierKernelHW:
			kernHW++
		case event.TierMemPressure:
			memPres++
		}
	}
	fmt.Printf("Events (24h): %d OOM, %d crash, %d service, %d hw, %d pressure\n",
		oom, crash, svcFail, kernHW, memPres)

	// PSI snapshot.
	stats, err := monitor.ReadPSI("/proc/pressure/memory")
	if err == nil {
		status := "healthy"
		if stats.SomeAvg10 > cfg.PSI.WarnSomeAvg10 || stats.FullAvg10 > cfg.PSI.WarnFullAvg10 {
			status = "WARNING"
		}
		fmt.Printf("PSI memory:   some=%.1f%% full=%.1f%% (%s)\n",
			stats.SomeAvg10, stats.FullAvg10, status)
	}

	// GPU snapshot.
	gpus := monitor.DetectGPUs()
	for i := range gpus {
		gpu := &gpus[i]
		monitor.ReadGPUTemp(gpu)
		monitor.ReadGPUVRAM(gpu)

		info := fmt.Sprintf("%s (%s)", filepath.Base(gpu.CardPath), gpu.Vendor)
		if gpu.Temperature > 0 {
			info += fmt.Sprintf(" %d°C", gpu.Temperature)
		}
		if gpu.VRAMTotal > 0 {
			pct := gpu.VRAMUsed * 100 / gpu.VRAMTotal
			info += fmt.Sprintf(", VRAM %d%%", pct)
		}
		fmt.Printf("GPU:          %s\n", info)
	}

	// DB info.
	eventCount, _ := db.Count()
	fmt.Printf("DB events:    %d total\n", eventCount)
	fmt.Printf("DB path:      %s\n", cfg.DBPath())
}

// --- query subcommand ---

func runQuery(args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config file")
	last := fs.String("last", "24h", "time window (e.g. 24h, 7d, 30d)")
	tier := fs.String("tier", "", "filter by tier (T1, T2, T3, T4, T5)")
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

// formatDuration formats a duration in human-readable form.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		return fmt.Sprintf("%dh %dm", h, m)
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, h)
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

// --- sd_notify support ---

// sdNotify sends a notification to systemd via the NOTIFY_SOCKET.
// This is a minimal implementation that doesn't require a C dependency.
func sdNotify(state string) {
	socketAddr := os.Getenv("NOTIFY_SOCKET")
	if socketAddr == "" {
		return
	}

	conn, err := net.Dial("unixgram", socketAddr)
	if err != nil {
		slog.Debug("sd_notify: failed to connect", "error", err)
		return
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(state)); err != nil {
		slog.Debug("sd_notify: failed to send", "error", err)
	}
}

// watchdogInterval reads WATCHDOG_USEC from the environment and returns the
// watchdog interval as a time.Duration. Returns 0 if not set.
func watchdogInterval() time.Duration {
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return 0
	}
	var usec int64
	if _, err := fmt.Sscanf(usecStr, "%d", &usec); err != nil {
		return 0
	}
	return time.Duration(usec) * time.Microsecond
}

// --- utilities ---

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
