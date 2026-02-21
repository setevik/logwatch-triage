// Package config handles TOML configuration loading with sensible defaults.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration for logtriage.
type Config struct {
	Instance InstanceConfig `toml:"instance"`
	Ntfy     NtfyConfig     `toml:"ntfy"`
	Digest   DigestConfig   `toml:"digest"`
	Cooldown CooldownConfig `toml:"cooldown"`
	PSI      PSIConfig      `toml:"psi"`
	SMART    SMARTConfig    `toml:"smart"`
	GPU      GPUConfig      `toml:"gpu"`
	DB       DBConfig       `toml:"db"`
	Log      LogConfig      `toml:"log"`
}

// InstanceConfig identifies this machine.
type InstanceConfig struct {
	ID   string `toml:"id"`
	Role string `toml:"role"`
}

// NtfyConfig controls the ntfy notification target.
type NtfyConfig struct {
	URL         string            `toml:"url"`
	PriorityMap map[string]string `toml:"priority_map"`
	AlertTiers  []string          `toml:"alert_tiers"`
}

// DigestConfig controls weekly digest generation.
type DigestConfig struct {
	Enabled bool   `toml:"enabled"`
	Topic   string `toml:"topic"` // defaults to ntfy.url if empty
}

// CooldownConfig controls dedup/cooldown behavior.
type CooldownConfig struct {
	Window             Duration `toml:"window"`
	AggregateThreshold int      `toml:"aggregate_threshold"`
}

// PSIConfig controls the /proc/pressure memory monitor.
type PSIConfig struct {
	Enabled      bool    `toml:"enabled"`
	PollInterval Duration `toml:"poll_interval"`
	WarnSomeAvg10 float64 `toml:"warn_some_avg10"`
	WarnFullAvg10 float64 `toml:"warn_full_avg10"`
}

// SMARTConfig controls smartctl disk health polling.
type SMARTConfig struct {
	Enabled      bool     `toml:"enabled"`
	PollInterval Duration `toml:"poll_interval"`
}

// GPUConfig controls GPU monitoring via sysfs and vendor tools.
type GPUConfig struct {
	Enabled      bool     `toml:"enabled"`
	PollInterval Duration `toml:"poll_interval"`
	TempWarn     int      `toml:"temp_warn"`     // degrees C, emit warning above this
	VRAMWarnPct  int      `toml:"vram_warn_pct"` // emit warning when VRAM usage exceeds this %
}

// DBConfig controls SQLite event storage.
type DBConfig struct {
	Path      string   `toml:"path"`
	Retention Duration `toml:"retention"`
}

// LogConfig controls logging.
type LogConfig struct {
	Level string `toml:"level"`
}

// Duration wraps time.Duration for TOML string parsing (e.g. "5m", "1h", "7d").
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalText(text []byte) error {
	s := string(text)
	// Support "d" suffix for days, which time.ParseDuration does not handle.
	if strings.HasSuffix(s, "d") {
		s = strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(s, "%d", &days); err != nil {
			return fmt.Errorf("invalid days format: %s", s)
		}
		d.Duration = time.Duration(days) * 24 * time.Hour
		return nil
	}
	var err error
	d.Duration, err = time.ParseDuration(s)
	return err
}

func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.Duration.String()), nil
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	return &Config{
		Instance: InstanceConfig{
			ID:   hostname,
			Role: "desktop",
		},
		Ntfy: NtfyConfig{
			PriorityMap: map[string]string{
				"critical": "urgent",
				"high":     "high",
				"medium":   "default",
			},
			AlertTiers: []string{"T1", "T2"},
		},
		Digest: DigestConfig{
			Enabled: true,
		},
		Cooldown: CooldownConfig{
			Window:             Duration{5 * time.Minute},
			AggregateThreshold: 3,
		},
		PSI: PSIConfig{
			Enabled:       true,
			PollInterval:  Duration{5 * time.Second},
			WarnSomeAvg10: 50.0,
			WarnFullAvg10: 10.0,
		},
		SMART: SMARTConfig{
			Enabled:      false,
			PollInterval: Duration{1 * time.Hour},
		},
		GPU: GPUConfig{
			Enabled:      true,
			PollInterval: Duration{30 * time.Second},
			TempWarn:     85,
			VRAMWarnPct:  90,
		},
		DB: DBConfig{
			Path:      "", // defaults to ~/.local/share/logtriage/events.db at runtime
			Retention: Duration{90 * 24 * time.Hour},
		},
		Log: LogConfig{
			Level: "info",
		},
	}
}

// DefaultPath returns the default config file path.
func DefaultPath() string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(configDir, "logtriage", "config.toml")
}

// Load reads configuration from the given path, falling back to defaults
// for any unset fields. If the file does not exist, returns defaults.
func Load(path string) (*Config, error) {
	cfg := Default()

	if path == "" {
		path = DefaultPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	return cfg, nil
}

// ShouldAlert returns true if the given tier is in the configured alert tiers.
func (c *Config) ShouldAlert(tier string) bool {
	for _, t := range c.Ntfy.AlertTiers {
		if strings.EqualFold(t, tier) {
			return true
		}
	}
	return false
}

// DBPath returns the resolved database path. If not explicitly configured,
// it returns the default path under the XDG data directory.
func (c *Config) DBPath() string {
	if c.DB.Path != "" {
		// Expand ~ prefix.
		if strings.HasPrefix(c.DB.Path, "~/") {
			home, err := os.UserHomeDir()
			if err == nil {
				return filepath.Join(home, c.DB.Path[2:])
			}
		}
		return c.DB.Path
	}
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, _ := os.UserHomeDir()
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, "logtriage", "events.db")
}

// DigestTopic returns the ntfy URL to use for digest notifications.
// Falls back to the main ntfy URL if not explicitly set.
func (c *Config) DigestTopic() string {
	if c.Digest.Topic != "" {
		return c.Digest.Topic
	}
	return c.Ntfy.URL
}

// NtfyPriority maps a severity string to an ntfy priority string.
func (c *Config) NtfyPriority(severity string) string {
	if p, ok := c.Ntfy.PriorityMap[severity]; ok {
		return p
	}
	return "default"
}
