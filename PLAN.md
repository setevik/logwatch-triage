# logtriage — Linux Desktop Crash & OOM Root Cause Reporter

## Overview

A lightweight Go daemon for personal Linux workstations that watches system logs and kernel events, detects high-severity issues (OOM kills, crashes, service failures, hardware errors), performs root cause correlation, and reports findings via ntfy webhook and weekly digest.

## Design Principles

- **Single static binary** — Pure Go, no C dependencies
- **Low footprint** — Target <15 MB RSS idle, mlockall() for reliability under memory pressure
- **Zero config to start** — Sensible defaults, optional TOML config for tuning
- **Positive detection** — Match known bad patterns (not negative-filter like journalwatch)
- **Correlation over alerting** — Don't just say "OOM happened", say *why*

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  logtriage (pure Go)                     │
│                                                          │
│  ┌─────────────┐                                         │
│  │  Journal     │──┐                                     │
│  │  Watcher     │  │   ┌──────────────┐  ┌────────────┐ │
│  │  (journalctl │  ├──▶│  Classifier  │─▶│  Enricher   │ │
│  │   pipe)      │  │   │  (pattern    │  │  (subprocess│ │
│  └─────────────┘  │   │   matching)  │  │   queries)  │ │
│  ┌─────────────┐  │   └──────────────┘  └──────┬─────┘ │
│  │  PSI Monitor │──┘                            │       │
│  │  (periodic)  │                               ▼       │
│  └─────────────┘                        ┌────────────┐  │
│  ┌─────────────┐                        │  Event DB   │  │
│  │  SMART Poll  │──▶ (same pipeline)    │  (SQLite)   │  │
│  │  (hourly)    │                        └──────┬─────┘ │
│  └─────────────┘                                │       │
│                                          ┌──────▼─────┐ │
│         Subprocess calls:                │  Reporter   │ │
│         • journalctl (enrichment)        │  • ntfy     │ │
│         • coredumpctl (crash info)       │  • digest   │ │
│         • smartctl (disk health)         └────────────┘ │
└──────────────────────────────────────────────────────────┘
```

### Component Responsibilities

**Journal Watcher** — Tails journald via a long-lived `journalctl --follow -o json` subprocess. Filters server-side for priority ≤ err (3) plus kernel transport. Uses `--cursor-file` for crash-safe resume across restarts. A supervision goroutine handles process lifecycle (restart on exit, watchdog, clean shutdown). Emits parsed journal entries to the classifier.

**PSI Monitor** — Polls `/proc/pressure/memory` every 5s. When `some avg10 > 50%` or `full avg10 > 10%`, switches to high-frequency mode (1s) and begins capturing top memory consumers from `/proc/*/statm`. Feeds pressure events into the classifier to provide pre-OOM context.

**SMART Poll** — Runs `smartctl --json=c /dev/sdX` hourly for each detected disk. Only emits events on status change or new errors.

**Classifier** — Pattern-matches journal entries into event tiers:

| Tier | Patterns | Priority |
|------|----------|----------|
| T1 — OOM Kill | `oom-kill:`, `Out of memory: Killed process`, `invoked oom-killer` | critical |
| T2 — Process Crash | `segfault at`, `traps:`, `systemd-coredump`, signal entries | high |
| T3 — Service Failure | unit entering `failed` state, non-zero exit codes | medium |
| T4 — Kernel/HW | `I/O error`, `EXT4-fs error`, `GPU hang`, `MCE`, `NMI`, `EDAC` | high |
| T5 — Memory Pressure | PSI thresholds exceeded (pre-OOM warning) | warning |

**Enricher** — Adds context to classified events via short-lived subprocess queries (clean separation from the watcher's follow stream):

- **OOM events**: Spawn `journalctl -k --since "60s ago" -o json` for kernel context around the kill. Parse the OOM killer's process table dump. Cross-reference with PSI snapshot buffer and `/proc/*/statm` snapshots for the actual memory hog. Identify victim vs. cause.
- **Crashes**: Query `coredumpctl info <PID> --json=short` for backtrace summary, signal, executable path.
- **Service failures**: Spawn `journalctl -u <unit> -n 10 --no-pager -o json` for last log lines from the failed unit.
- **Kernel/HW**: Cross-reference with SMART data if disk-related.

**Event DB** — SQLite database at `~/.local/share/logtriage/events.db`. Stores classified events with metadata, used for:
- Deduplication / cooldown (don't re-alert on crash-looping service within 5min window)
- Weekly digest generation
- CLI query support (`logtriage query --last 24h`)
- Multi-instance digest aggregation (each instance writes to its own local DB; digest reads all)

**Reporter** — Two output channels:

1. **ntfy (real-time)** — HTTP POST to configured ntfy topic for T1-T2 events (critical/high). Respects cooldown windows. All notifications are prefixed with `[instance_id]` for quick identification.
2. **Weekly digest** — Timer-triggered (Sunday 9:00 or configurable). Queries event DB for the past 7 days, generates summary grouped by instance then tier, and POSTs to ntfy with lower priority.

---

## Core Data Model

### Event

```go
type Tier string

const (
    TierOOMKill        Tier = "T1"
    TierProcessCrash   Tier = "T2"
    TierServiceFailure Tier = "T3"
    TierKernelHW       Tier = "T4"
    TierMemPressure    Tier = "T5"
)

type Severity string

const (
    SevCritical Severity = "critical"
    SevHigh     Severity = "high"
    SevMedium   Severity = "medium"
    SevWarning  Severity = "warning"
)

type Event struct {
    ID         string    // UUID
    InstanceID string    // "workstation", "nas", etc.
    Timestamp  time.Time
    Tier       Tier
    Severity   Severity
    Summary    string    // One-line: "OOM Kill: firefox (pid 4521)"
    Process    string    // Affected process name (if applicable)
    PID        int       // Affected PID (if applicable)
    Unit       string    // systemd unit (if applicable)
    Detail     string    // Enriched multi-line description
    RawFields  map[string]string // Original journal fields
}
```

### DB Schema

```sql
CREATE TABLE events (
    id          TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    timestamp   DATETIME NOT NULL,
    tier        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    summary     TEXT NOT NULL,
    process     TEXT,
    pid         INTEGER,
    unit        TEXT,
    detail      TEXT,
    raw_json    TEXT,
    notified    BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_events_instance_ts ON events(instance_id, timestamp);
CREATE INDEX idx_events_tier ON events(tier, timestamp);
CREATE INDEX idx_events_dedup ON events(instance_id, tier, process, unit);
```

### Multi-Instance Digest Aggregation

Each logtriage instance writes to its own local SQLite DB. For the weekly digest, there are two approaches:

**Option A (simple, chosen for Phase 1):** Each instance sends its own partial digest to the same ntfy topic. The user sees N messages, one per instance. No coordination needed.

**Option B (future):** Instances expose their event DB via a simple HTTP endpoint or push events to a shared SQLite on a network mount. A single coordinator instance (e.g. the NAS) generates a unified digest. This requires a `[federation]` config section — defer to Phase 4+.

---

## Event Output Format

### ntfy Real-Time Alert

```
POST https://ntfy.sh/<topic>
Headers:
  Title: 🔴 [workstation] OOM Kill: firefox (pid 4521)
  Priority: urgent
  Tags: skull,memory

Body:
Host: workstation
Time: 2026-02-19 14:32:05 IST

Firefox was killed by OOM killer.
RSS at kill: 3.2 GB

Likely cause: electron (VSCode) consuming 8.1 GB RSS
Memory pressure was critical (PSI full avg10: 45%) for 23s before kill.

Top consumers at time of kill:
  1. electron    8.1 GB
  2. firefox     3.2 GB (killed)
  3. chromium    1.8 GB
```

### ntfy Crash Alert

```
POST https://ntfy.sh/<topic>
Headers:
  Title: 💥 [workstation] Crash: vlc (SIGSEGV)
  Priority: high
  Tags: warning,crash

Body:
Host: workstation
Time: 2026-02-19 16:45:12 IST

vlc crashed with SIGSEGV.
Coredump saved (312 MB).

Top backtrace frames:
  #0 libavcodec.so.60 → av_frame_unref
  #1 libvlccore.so.9 → input_DecoderDecode
  #2 libvlccore.so.9 → MainLoop

Occurred 1 time in past 24h.
```

### Weekly Digest (multi-instance)

```
POST https://ntfy.sh/<topic>
Headers:
  Title: 📊 logtriage weekly digest (Feb 10-16)
  Priority: low
  Tags: chart

Body:
=== workstation ===
OOM Kills:        2 (firefox ×1, electron ×1)
Process Crashes:  3 (vlc ×2, gimp ×1)
Service Failures: 1 (docker.service ×1)
HW/Kernel Errors: 0
Memory Pressure:  4 warning episodes (avg duration: 45s)
Top memory offender: electron (avg 6.2 GB, triggered 1 OOM)

=== nas ===
OOM Kills:        0
Process Crashes:  0
Service Failures: 2 (smbd.service ×1, zfs-scrub.service ×1)
HW/Kernel Errors: 1 (I/O error on /dev/sdc — SMART: reallocated sectors 48→52)
Memory Pressure:  0

Longest incident: [nas] zfs-scrub.service failed
  → exit code 1, scrub errors detected on pool "tank"
```

---

## Configuration

Location: `~/.config/logtriage/config.toml`

```toml
[instance]
# Human-readable name for this machine. Used in all alerts, digest, DB, CLI output.
# Falls back to os.Hostname() if not set.
id = "workstation"
# Optional: role hint for context-aware enrichment (e.g. "desktop", "nas", "server")
# Affects which detectors are enabled by default (e.g. SMART defaults on for "nas")
role = "desktop"

[ntfy]
url = "https://ntfy.sh/my-logtriage-topic"
# url = "http://localhost:8080/my-topic"  # self-hosted
priority_map = { critical = "urgent", high = "high", medium = "default" }
# Only alert on these tiers in real-time (T1, T2 by default)
alert_tiers = ["T1", "T2"]

[digest]
enabled = true
schedule = "Sun 09:00"       # cron-ish, local time
topic = ""                   # defaults to same as ntfy.url

[cooldown]
# Don't re-alert for same (unit/process, tier) within this window
window = "5m"
# For crash-looping services, aggregate into single alert after N hits
aggregate_threshold = 3

[psi]
enabled = true
poll_interval = "5s"
warn_some_avg10 = 50.0       # percent
warn_full_avg10 = 10.0       # percent

[smart]
enabled = false              # opt-in, needs smartmontools + root/disk group
poll_interval = "1h"

[db]
path = "~/.local/share/logtriage/events.db"
retention = "90d"

[log]
level = "info"               # debug, info, warn, error
```

---

## Project Structure

```
logtriage/
├── cmd/
│   └── logtriage/
│       └── main.go              # Entry point, signal handling, component wiring
├── internal/
│   ├── watcher/
│   │   ├── source.go            # JournalSource interface (for testability)
│   │   ├── pipe.go              # journalctl subprocess watcher (default)
│   │   ├── pipe_test.go
│   │   └── supervisor.go        # Process lifecycle: restart, watchdog, shutdown
│   ├── monitor/
│   │   ├── psi.go               # /proc/pressure polling
│   │   ├── psi_test.go
│   │   ├── smart.go             # smartctl polling (optional)
│   │   └── procsnap.go          # /proc/*/statm snapshot for top consumers
│   ├── classifier/
│   │   ├── classifier.go        # Pattern matching, tier assignment
│   │   ├── patterns.go          # Compiled regexes / string matchers
│   │   └── classifier_test.go
│   ├── enricher/
│   │   ├── enricher.go          # Context gathering orchestrator
│   │   ├── oom.go               # OOM-specific: journal lookback + proc table parse
│   │   ├── crash.go             # Coredump/segfault: coredumpctl subprocess
│   │   ├── service.go           # Service failure: journalctl -u subprocess
│   │   ├── query.go             # Shared subprocess helpers for journalctl queries
│   │   └── enricher_test.go
│   ├── store/
│   │   ├── db.go                # SQLite event storage
│   │   ├── dedup.go             # Cooldown / dedup logic
│   │   └── db_test.go
│   ├── reporter/
│   │   ├── ntfy.go              # ntfy HTTP client
│   │   ├── digest.go            # Weekly digest generation
│   │   ├── formatter.go         # Event → human-readable text
│   │   └── ntfy_test.go
│   ├── event/
│   │   └── event.go             # Core event types and tier definitions
│   └── config/
│       ├── config.go            # TOML config parsing + defaults
│       └── config_test.go
├── go.mod
├── go.sum
├── Makefile
├── README.md
├── logtriage.service            # systemd user unit file
└── config.example.toml
```

---

## Key Dependencies

| Dependency | Purpose |
|---|---|
| `github.com/godbus/dbus/v5` | D-Bus (optional desktop notification fallback) |
| `github.com/prometheus/procfs` | /proc parsing, PSI stats |
| `modernc.org/sqlite` | SQLite (pure Go) |
| `github.com/BurntSushi/toml` | Config parsing |

All dependencies are pure Go. Journal access and enrichment queries use `journalctl` / `coredumpctl` / `smartctl` subprocesses.

Build requirement: Go 1.22+
Runtime requirement: `systemd` (journalctl, coredumpctl), optionally `smartmontools`

---

## systemd User Service

```ini
# ~/.config/systemd/user/logtriage.service
[Unit]
Description=logtriage - crash & OOM root cause reporter
After=default.target

[Service]
Type=notify
ExecStart=%h/.local/bin/logtriage
Restart=on-failure
RestartSec=5s
# Lock memory to stay responsive under OOM pressure
LimitMEMLOCK=infinity
# Reduce own OOM score so we survive to report
OOMScoreAdjust=-900
WatchdogSec=60

[Install]
WantedBy=default.target
```

Weekly digest via systemd timer:

```ini
# ~/.config/systemd/user/logtriage-digest.timer
[Unit]
Description=logtriage weekly digest

[Timer]
OnCalendar=Sun 09:00
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# ~/.config/systemd/user/logtriage-digest.service
[Unit]
Description=logtriage weekly digest generation

[Service]
Type=oneshot
ExecStart=%h/.local/bin/logtriage digest --send
```

---

## CLI Interface

```
logtriage                           # Run daemon (foreground)
logtriage daemon                    # Run daemon (sd_notify integration)
logtriage query                     # Show recent events (last 24h)
logtriage query --last 7d           # Show events from past 7 days
logtriage query --tier T1           # Filter by tier
logtriage query --instance nas      # Filter by instance (for shared DB scenarios)
logtriage digest                    # Print weekly digest to stdout
logtriage digest --send             # Generate and send digest via ntfy
logtriage status                    # Show daemon health, instance ID, last event, PSI snapshot
logtriage test-ntfy                 # Send test notification (includes instance ID)
```

All CLI output and notifications include the instance identifier. Example:

```
$ logtriage status
Instance:     workstation
Role:         desktop
Uptime:       3d 14h 22m
Last event:   [T2] vlc crashed (SIGSEGV) — 2h ago
Events (24h): 1 crash, 0 OOM, 0 service failures
PSI memory:   some=2.1% full=0.0% (healthy)
```

---

## Implementation Phases

### Phase 1 — Core Loop (MVP)
- Journal watcher via `journalctl --follow -o json` pipe + supervisor goroutine
- `JournalSource` interface (for testability / mocking)
- T1 (OOM) and T2 (crash) classifier with pattern matching
- Basic enrichment via short-lived `journalctl` / `coredumpctl` subprocess queries
- ntfy reporter with structured text formatting
- Instance ID in config + all outputs
- Config loading with sane defaults
- Run as foreground process

### Phase 2 — Storage & Dedup
- SQLite event store
- Cooldown / dedup logic
- CLI query interface
- T3 (service failure) detection + enrichment

### Phase 3 — Proactive Monitoring
- PSI monitor with pre-OOM warnings
- Process memory snapshot buffer
- T4 (kernel/HW) detection
- SMART integration (opt-in)

### Phase 4 — Digest & Polish
- Weekly digest generation + timer
- systemd user service with sd_notify + watchdog
- `logtriage status` command
- Event retention / DB cleanup
- Man page / README

### Phase 5 — GPU Monitoring Investigation
- Research available telemetry: NVIDIA (`nvidia-smi`, NVML), AMD (`amdgpu` kernel driver, `radeontop`, `rocm-smi`), Intel (`intel_gpu_top`)
- Identify journal patterns for GPU hangs, resets, firmware errors (`amdgpu: GPU fault`, `NVRM: Xid`, `i915: GPU HANG`)
- Detect Xorg/Wayland compositor crashes related to GPU driver faults
- VRAM OOM detection (distinct from system RAM OOM)
- Thermal throttling events from GPU driver
- Evaluate whether to poll sysfs `/sys/class/drm/` or rely purely on journal patterns
- Goal: determine minimum viable GPU monitoring that works across vendors without heavy vendor-specific tooling

---

## Open Questions

1. **Digest: in-process timer vs separate systemd timer?** Spec currently uses a separate oneshot + timer, which is simpler and more unix-y. Alternative: single long-running daemon handles both.
2. **ntfy auth**: Support token-based auth for private ntfy instances? (Easy to add — just an `Authorization` header.)
3. **Multi-instance digest federation**: Option A (each sends own digest) is the Phase 1 plan. Evaluate whether Option B (coordinator aggregation) is worth the complexity for your setup.

---

## Role-Based Defaults

The `role` field in `[instance]` adjusts which detectors and patterns are active by default:

| Setting | `desktop` | `nas` | `server` |
|---|---|---|---|
| PSI monitor | on | on | on |
| SMART poll | off | **on** | off |
| T2 crash detection (coredump) | on | on | on |
| T5 memory pressure alerts | on | on | on |
| GPU/display patterns | on | off | off |
| ZFS/mdadm/RAID patterns | off | **on** | off |
| SMB/NFS service patterns | off | **on** | off |
| Docker/container patterns | on | off | on |

All overridable in config. The role just sets sensible starting points so a NAS deployment gets SMART + RAID + Samba monitoring out of the box without manual config.
