# logtriage

A lightweight Go daemon for Linux systems that watches system logs and kernel events, detects high-severity issues (OOM kills, crashes, service failures, hardware errors), performs root cause correlation, and reports findings via [ntfy](https://ntfy.sh) notifications and weekly digests.

## Features

- **OOM Kill detection (T1)** — Detects OOM kills, enriches with process table dump and top memory consumers
- **Process crash detection (T2)** — Catches segfaults and coredumps, enriches with backtrace via coredumpctl
- **Service failure detection (T3)** — Monitors systemd unit failures with last log lines
- **Kernel/HW error detection (T4)** — Disk I/O errors, filesystem errors, GPU faults (NVIDIA/AMD/Intel), MCE, NMI, EDAC, PCIe AER
- **Memory pressure monitoring (T5)** — Polls `/proc/pressure/memory` with adaptive frequency, captures top consumers
- **SMART disk health** — Periodic smartctl polling with change detection
- **GPU monitoring** — Temperature and VRAM usage via sysfs and nvidia-smi
- **Dedup/cooldown** — Suppresses duplicate alerts with configurable window and aggregate threshold
- **Weekly digest** — Summarizes events by tier with process/unit breakdowns
- **SQLite storage** — Event history with retention, CLI query support
- **systemd integration** — sd_notify ready/watchdog/stopping, service and timer units included

## Quick Start

```bash
# Build
make build

# Run with defaults (no config needed)
./logtriage

# Or install to ~/.local/bin
make install
```

## Configuration

Copy `config.example.toml` to `~/.config/logtriage/config.toml` and edit as needed. All values have sensible defaults — you only need to set what you want to change.

Key settings:

```toml
[ntfy]
url = "https://ntfy.sh/my-logtriage-topic"

[instance]
id = "workstation"
```

See `config.example.toml` for all options.

## Usage

```bash
# Run daemon (default)
logtriage

# Query recent events
logtriage query --last 24h
logtriage query --last 7d --tier T1

# Show system status
logtriage status

# Generate digest
logtriage digest --last 7d
logtriage digest --last 7d --send  # send via ntfy

# Test ntfy connectivity
logtriage test-ntfy

# Print version
logtriage version
```

## systemd Setup

```bash
# Copy service files
cp logtriage.service ~/.config/systemd/user/
cp logtriage-digest.service ~/.config/systemd/user/
cp logtriage-digest.timer ~/.config/systemd/user/

# Enable and start
systemctl --user daemon-reload
systemctl --user enable --now logtriage.service
systemctl --user enable --now logtriage-digest.timer
```

## Event Tiers

| Tier | Type | Severity | Default Alert |
|------|------|----------|---------------|
| T1 | OOM Kill | critical | yes |
| T2 | Process Crash | high | yes |
| T3 | Service Failure | medium | no |
| T4 | Kernel/HW Error | high | no |
| T5 | Memory Pressure | warning | no |

## Development

```bash
make build    # Build binary
make test     # Run tests with race detector
make lint     # Run go vet
make clean    # Remove binary
```

## Requirements

- Go 1.24+
- Linux with systemd/journald
- Optional: smartmontools (for SMART monitoring), nvidia-smi (for NVIDIA GPU monitoring)
