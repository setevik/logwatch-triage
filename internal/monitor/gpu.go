package monitor

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/setevik/logtriage/internal/format"
)

// GPUVendor identifies the GPU driver/vendor.
type GPUVendor string

const (
	GPUVendorAMD    GPUVendor = "amd"
	GPUVendorNVIDIA GPUVendor = "nvidia"
	GPUVendorIntel  GPUVendor = "intel"
)

// GPUStatus represents the current state of a GPU.
type GPUStatus struct {
	CardPath    string    // e.g., "/sys/class/drm/card0"
	Vendor      GPUVendor // detected driver vendor
	Temperature int       // degrees Celsius, 0 if unavailable
	TempCrit    int       // critical threshold, 0 if unavailable
	VRAMUsed    int64     // bytes, 0 if unavailable
	VRAMTotal   int64     // bytes, 0 if unavailable
}

// GPUEvent is emitted when GPU status crosses a threshold.
type GPUEvent struct {
	Timestamp time.Time
	Status    GPUStatus
	Reason    string // "thermal_warning", "vram_high"
}

// GPUMonitor polls GPU sysfs and optional vendor CLIs for health status.
type GPUMonitor struct {
	pollInterval time.Duration
	tempWarn     int // temperature warning threshold (degrees C)
	vramWarnPct  int // VRAM usage warning threshold (percent)
}

// NewGPUMonitor creates a GPU monitor with the given settings.
func NewGPUMonitor(pollInterval time.Duration, tempWarn, vramWarnPct int) *GPUMonitor {
	return &GPUMonitor{
		pollInterval: pollInterval,
		tempWarn:     tempWarn,
		vramWarnPct:  vramWarnPct,
	}
}

// Events starts the GPU polling loop and returns a channel of GPU events.
func (m *GPUMonitor) Events(ctx context.Context) <-chan GPUEvent {
	ch := make(chan GPUEvent, 8)
	go m.poll(ctx, ch)
	return ch
}

func (m *GPUMonitor) poll(ctx context.Context, ch chan<- GPUEvent) {
	defer close(ch)

	// Initial poll.
	m.checkAll(ctx, ch)

	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkAll(ctx, ch)
		}
	}
}

func (m *GPUMonitor) checkAll(ctx context.Context, ch chan<- GPUEvent) {
	gpus := DetectGPUs()
	if len(gpus) == 0 {
		return
	}

	for i := range gpus {
		gpu := &gpus[i]
		ReadGPUTemp(gpu)
		ReadGPUVRAM(gpu)

		// For NVIDIA, try nvidia-smi if sysfs data is missing.
		if gpu.Vendor == GPUVendorNVIDIA && gpu.Temperature == 0 {
			readNvidiaSMI(ctx, gpu)
		}

		// Emit events for thresholds.
		if gpu.Temperature > 0 && gpu.Temperature >= m.tempWarn {
			select {
			case ch <- GPUEvent{
				Timestamp: time.Now(),
				Status:    *gpu,
				Reason:    "thermal_warning",
			}:
			case <-ctx.Done():
				return
			default:
			}
		}

		if gpu.VRAMTotal > 0 && gpu.VRAMUsed > 0 {
			pct := int(gpu.VRAMUsed * 100 / gpu.VRAMTotal)
			if pct >= m.vramWarnPct {
				select {
				case ch <- GPUEvent{
					Timestamp: time.Now(),
					Status:    *gpu,
					Reason:    "vram_high",
				}:
				case <-ctx.Done():
					return
				default:
				}
			}
		}
	}
}

// DetectGPUs scans /sys/class/drm for GPU cards and identifies their vendor.
func DetectGPUs() []GPUStatus {
	entries, err := filepath.Glob("/sys/class/drm/card[0-9]*")
	if err != nil {
		return nil
	}

	var gpus []GPUStatus
	seen := make(map[string]bool)

	for _, cardPath := range entries {
		base := filepath.Base(cardPath)
		// Skip render nodes like card0-DP-1; only want card0, card1, etc.
		if strings.Contains(base, "-") {
			continue
		}
		if seen[base] {
			continue
		}
		seen[base] = true

		vendor := identifyGPUVendor(cardPath)
		if vendor == "" {
			continue
		}

		gpus = append(gpus, GPUStatus{
			CardPath: cardPath,
			Vendor:   vendor,
		})
	}
	return gpus
}

// identifyGPUVendor reads the driver symlink to determine the GPU vendor.
func identifyGPUVendor(cardPath string) GPUVendor {
	driverLink := filepath.Join(cardPath, "device", "driver")
	target, err := os.Readlink(driverLink)
	if err != nil {
		return ""
	}
	driver := filepath.Base(target)

	switch {
	case driver == "amdgpu" || driver == "radeon":
		return GPUVendorAMD
	case driver == "nvidia":
		return GPUVendorNVIDIA
	case driver == "i915" || driver == "xe":
		return GPUVendorIntel
	case driver == "nouveau":
		return GPUVendorNVIDIA // open-source NVIDIA
	}
	return ""
}

// ReadGPUTemp reads GPU temperature from hwmon sysfs.
func ReadGPUTemp(gpu *GPUStatus) {
	hwmonPath := filepath.Join(gpu.CardPath, "device", "hwmon")
	entries, err := os.ReadDir(hwmonPath)
	if err != nil {
		return
	}

	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "hwmon") {
			continue
		}
		hwmon := filepath.Join(hwmonPath, e.Name())

		// Read temperature.
		if val := readSysfsInt(filepath.Join(hwmon, "temp1_input")); val > 0 {
			gpu.Temperature = val / 1000 // millidegrees to degrees
		}

		// Read critical threshold.
		if val := readSysfsInt(filepath.Join(hwmon, "temp1_crit")); val > 0 {
			gpu.TempCrit = val / 1000
		}

		if gpu.Temperature > 0 {
			break
		}
	}
}

// ReadGPUVRAM reads VRAM usage from amdgpu sysfs.
func ReadGPUVRAM(gpu *GPUStatus) {
	if gpu.Vendor != GPUVendorAMD {
		return
	}

	devicePath := filepath.Join(gpu.CardPath, "device")
	gpu.VRAMUsed = readSysfsInt64(filepath.Join(devicePath, "mem_info_vram_used"))
	gpu.VRAMTotal = readSysfsInt64(filepath.Join(devicePath, "mem_info_vram_total"))
}

// readNvidiaSMI queries nvidia-smi for GPU temperature and VRAM usage.
func readNvidiaSMI(ctx context.Context, gpu *GPUStatus) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nvidia-smi",
		"--query-gpu=temperature.gpu,memory.used,memory.total",
		"--format=csv,noheader,nounits")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		slog.Debug("nvidia-smi query failed", "error", err)
		return
	}

	// Output: "72, 4096, 8192"
	parts := strings.Split(strings.TrimSpace(stdout.String()), ",")
	if len(parts) >= 1 {
		if v, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
			gpu.Temperature = v
		}
	}
	if len(parts) >= 2 {
		if v, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64); err == nil {
			gpu.VRAMUsed = v * 1024 * 1024 // MiB to bytes
		}
	}
	if len(parts) >= 3 {
		if v, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64); err == nil {
			gpu.VRAMTotal = v * 1024 * 1024 // MiB to bytes
		}
	}
}

// readSysfsInt reads an integer from a sysfs file.
func readSysfsInt(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	val, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return val
}

// readSysfsInt64 reads a 64-bit integer from a sysfs file.
func readSysfsInt64(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	val, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return val
}

// FormatGPUStatus returns a human-readable summary of GPU status.
func FormatGPUStatus(gpu GPUStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "GPU: %s (%s)\n", filepath.Base(gpu.CardPath), gpu.Vendor)

	if gpu.Temperature > 0 {
		tempStr := fmt.Sprintf("%d°C", gpu.Temperature)
		if gpu.TempCrit > 0 {
			tempStr += fmt.Sprintf(" (critical: %d°C)", gpu.TempCrit)
		}
		fmt.Fprintf(&b, "  Temperature: %s\n", tempStr)
	}

	if gpu.VRAMTotal > 0 {
		pct := gpu.VRAMUsed * 100 / gpu.VRAMTotal
		fmt.Fprintf(&b, "  VRAM: %s / %s (%d%%)\n",
			format.Bytes(gpu.VRAMUsed),
			format.Bytes(gpu.VRAMTotal),
			pct)
	}

	return b.String()
}

