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
	Cooldown CooldownConfig `toml:"cooldown"`
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

// CooldownConfig controls dedup/cooldown behavior.
type CooldownConfig struct {
	Window             Duration `toml:"window"`
	AggregateThreshold int      `toml:"aggregate_threshold"`
}

// LogConfig controls logging.
type LogConfig struct {
	Level string `toml:"level"`
}

// Duration wraps time.Duration for TOML string parsing (e.g. "5m", "1h").
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
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
		Cooldown: CooldownConfig{
			Window:             Duration{5 * time.Minute},
			AggregateThreshold: 3,
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

// NtfyPriority maps a severity string to an ntfy priority string.
func (c *Config) NtfyPriority(severity string) string {
	if p, ok := c.Ntfy.PriorityMap[severity]; ok {
		return p
	}
	return "default"
}
