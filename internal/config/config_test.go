package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := Default()

	if cfg.Instance.ID == "" {
		t.Error("default instance ID should not be empty")
	}
	if cfg.Instance.Role != "desktop" {
		t.Errorf("default role = %q, want %q", cfg.Instance.Role, "desktop")
	}
	if cfg.Cooldown.Window.Duration != 5*time.Minute {
		t.Errorf("default cooldown window = %v, want %v", cfg.Cooldown.Window.Duration, 5*time.Minute)
	}
	if cfg.Cooldown.AggregateThreshold != 3 {
		t.Errorf("default aggregate threshold = %d, want 3", cfg.Cooldown.AggregateThreshold)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("default log level = %q, want %q", cfg.Log.Level, "info")
	}
	if len(cfg.Ntfy.AlertTiers) != 2 {
		t.Errorf("default alert tiers count = %d, want 2", len(cfg.Ntfy.AlertTiers))
	}
}

func TestLoadNonExistentFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.toml")
	if err != nil {
		t.Fatalf("loading nonexistent config should return defaults, got error: %v", err)
	}
	if cfg.Instance.Role != "desktop" {
		t.Errorf("role = %q, want default %q", cfg.Instance.Role, "desktop")
	}
}

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	content := `
[instance]
id = "mynas"
role = "nas"

[ntfy]
url = "https://ntfy.sh/my-topic"
alert_tiers = ["T1", "T2", "T3"]

[cooldown]
window = "10m"
aggregate_threshold = 5

[log]
level = "debug"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	if cfg.Instance.ID != "mynas" {
		t.Errorf("instance.id = %q, want %q", cfg.Instance.ID, "mynas")
	}
	if cfg.Instance.Role != "nas" {
		t.Errorf("instance.role = %q, want %q", cfg.Instance.Role, "nas")
	}
	if cfg.Ntfy.URL != "https://ntfy.sh/my-topic" {
		t.Errorf("ntfy.url = %q", cfg.Ntfy.URL)
	}
	if len(cfg.Ntfy.AlertTiers) != 3 {
		t.Errorf("alert_tiers count = %d, want 3", len(cfg.Ntfy.AlertTiers))
	}
	if cfg.Cooldown.Window.Duration != 10*time.Minute {
		t.Errorf("cooldown.window = %v, want 10m", cfg.Cooldown.Window.Duration)
	}
	if cfg.Cooldown.AggregateThreshold != 5 {
		t.Errorf("cooldown.aggregate_threshold = %d, want 5", cfg.Cooldown.AggregateThreshold)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log.level = %q, want %q", cfg.Log.Level, "debug")
	}
}

func TestLoadInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	if err := os.WriteFile(path, []byte("not valid [[[ toml"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML, got nil")
	}
}

func TestShouldAlert(t *testing.T) {
	cfg := Default()

	if !cfg.ShouldAlert("T1") {
		t.Error("T1 should be alerted by default")
	}
	if !cfg.ShouldAlert("T2") {
		t.Error("T2 should be alerted by default")
	}
	if cfg.ShouldAlert("T3") {
		t.Error("T3 should not be alerted by default")
	}
}

func TestNtfyPriority(t *testing.T) {
	cfg := Default()

	if p := cfg.NtfyPriority("critical"); p != "urgent" {
		t.Errorf("critical priority = %q, want %q", p, "urgent")
	}
	if p := cfg.NtfyPriority("high"); p != "high" {
		t.Errorf("high priority = %q, want %q", p, "high")
	}
	if p := cfg.NtfyPriority("unknown"); p != "default" {
		t.Errorf("unknown priority = %q, want %q", p, "default")
	}
}
