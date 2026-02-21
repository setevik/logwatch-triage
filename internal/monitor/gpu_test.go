package monitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentifyGPUVendor(t *testing.T) {
	// Create a fake sysfs tree.
	tmpDir := t.TempDir()
	cardPath := filepath.Join(tmpDir, "card0")

	// Test AMD.
	driverDir := filepath.Join(cardPath, "device", "driver_target")
	os.MkdirAll(driverDir, 0o755)
	os.MkdirAll(filepath.Join(cardPath, "device"), 0o755)

	// Create a symlink that points to a path ending in "amdgpu".
	amdTarget := filepath.Join(tmpDir, "bus", "pci", "drivers", "amdgpu")
	os.MkdirAll(amdTarget, 0o755)
	os.Symlink(amdTarget, filepath.Join(cardPath, "device", "driver"))

	vendor := identifyGPUVendor(cardPath)
	if vendor != GPUVendorAMD {
		t.Errorf("vendor = %q, want amd", vendor)
	}

	// Test NVIDIA.
	os.Remove(filepath.Join(cardPath, "device", "driver"))
	nvTarget := filepath.Join(tmpDir, "bus", "pci", "drivers", "nvidia")
	os.MkdirAll(nvTarget, 0o755)
	os.Symlink(nvTarget, filepath.Join(cardPath, "device", "driver"))

	vendor = identifyGPUVendor(cardPath)
	if vendor != GPUVendorNVIDIA {
		t.Errorf("vendor = %q, want nvidia", vendor)
	}

	// Test Intel.
	os.Remove(filepath.Join(cardPath, "device", "driver"))
	intelTarget := filepath.Join(tmpDir, "bus", "pci", "drivers", "i915")
	os.MkdirAll(intelTarget, 0o755)
	os.Symlink(intelTarget, filepath.Join(cardPath, "device", "driver"))

	vendor = identifyGPUVendor(cardPath)
	if vendor != GPUVendorIntel {
		t.Errorf("vendor = %q, want intel", vendor)
	}

	// Test unknown driver.
	os.Remove(filepath.Join(cardPath, "device", "driver"))
	unknownTarget := filepath.Join(tmpDir, "bus", "pci", "drivers", "unknown_drv")
	os.MkdirAll(unknownTarget, 0o755)
	os.Symlink(unknownTarget, filepath.Join(cardPath, "device", "driver"))

	vendor = identifyGPUVendor(cardPath)
	if vendor != "" {
		t.Errorf("vendor = %q, want empty for unknown driver", vendor)
	}
}

func TestReadGPUTemp(t *testing.T) {
	tmpDir := t.TempDir()
	cardPath := filepath.Join(tmpDir, "card0")
	hwmonPath := filepath.Join(cardPath, "device", "hwmon", "hwmon0")
	os.MkdirAll(hwmonPath, 0o755)

	// Write temp in millidegrees.
	os.WriteFile(filepath.Join(hwmonPath, "temp1_input"), []byte("72000\n"), 0o644)
	os.WriteFile(filepath.Join(hwmonPath, "temp1_crit"), []byte("100000\n"), 0o644)

	gpu := GPUStatus{CardPath: cardPath, Vendor: GPUVendorAMD}
	readGPUTemp(&gpu)

	if gpu.Temperature != 72 {
		t.Errorf("Temperature = %d, want 72", gpu.Temperature)
	}
	if gpu.TempCrit != 100 {
		t.Errorf("TempCrit = %d, want 100", gpu.TempCrit)
	}
}

func TestReadGPUTempMissing(t *testing.T) {
	tmpDir := t.TempDir()
	cardPath := filepath.Join(tmpDir, "card0")
	os.MkdirAll(filepath.Join(cardPath, "device"), 0o755)

	gpu := GPUStatus{CardPath: cardPath, Vendor: GPUVendorAMD}
	readGPUTemp(&gpu)

	if gpu.Temperature != 0 {
		t.Errorf("Temperature = %d, want 0 for missing hwmon", gpu.Temperature)
	}
}

func TestReadGPUVRAM(t *testing.T) {
	tmpDir := t.TempDir()
	cardPath := filepath.Join(tmpDir, "card0")
	devicePath := filepath.Join(cardPath, "device")
	os.MkdirAll(devicePath, 0o755)

	os.WriteFile(filepath.Join(devicePath, "mem_info_vram_used"), []byte("4294967296\n"), 0o644)   // 4 GB
	os.WriteFile(filepath.Join(devicePath, "mem_info_vram_total"), []byte("8589934592\n"), 0o644)  // 8 GB

	gpu := GPUStatus{CardPath: cardPath, Vendor: GPUVendorAMD}
	readGPUVRAM(&gpu)

	if gpu.VRAMUsed != 4294967296 {
		t.Errorf("VRAMUsed = %d, want 4294967296", gpu.VRAMUsed)
	}
	if gpu.VRAMTotal != 8589934592 {
		t.Errorf("VRAMTotal = %d, want 8589934592", gpu.VRAMTotal)
	}
}

func TestReadGPUVRAMNonAMD(t *testing.T) {
	tmpDir := t.TempDir()
	cardPath := filepath.Join(tmpDir, "card0")
	devicePath := filepath.Join(cardPath, "device")
	os.MkdirAll(devicePath, 0o755)

	// VRAM files exist but GPU is not AMD — should not be read.
	os.WriteFile(filepath.Join(devicePath, "mem_info_vram_used"), []byte("1000\n"), 0o644)
	os.WriteFile(filepath.Join(devicePath, "mem_info_vram_total"), []byte("2000\n"), 0o644)

	gpu := GPUStatus{CardPath: cardPath, Vendor: GPUVendorNVIDIA}
	readGPUVRAM(&gpu)

	if gpu.VRAMUsed != 0 || gpu.VRAMTotal != 0 {
		t.Errorf("VRAM should be 0 for non-AMD GPU, got used=%d total=%d", gpu.VRAMUsed, gpu.VRAMTotal)
	}
}

func TestReadSysfsInt(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "value")

	os.WriteFile(path, []byte("42\n"), 0o644)
	if v := readSysfsInt(path); v != 42 {
		t.Errorf("readSysfsInt = %d, want 42", v)
	}

	// Missing file.
	if v := readSysfsInt(filepath.Join(tmpDir, "missing")); v != 0 {
		t.Errorf("readSysfsInt = %d, want 0 for missing", v)
	}

	// Invalid content.
	os.WriteFile(path, []byte("not_a_number\n"), 0o644)
	if v := readSysfsInt(path); v != 0 {
		t.Errorf("readSysfsInt = %d, want 0 for invalid", v)
	}
}

func TestFormatGPUStatus(t *testing.T) {
	gpu := GPUStatus{
		CardPath:    "/sys/class/drm/card0",
		Vendor:      GPUVendorAMD,
		Temperature: 75,
		TempCrit:    100,
		VRAMUsed:    4 * 1024 * 1024 * 1024,
		VRAMTotal:   8 * 1024 * 1024 * 1024,
	}

	out := FormatGPUStatus(gpu)
	if out == "" {
		t.Fatal("FormatGPUStatus returned empty string")
	}

	// Check key content.
	checks := []string{"card0", "amd", "75°C", "100°C", "VRAM", "50%"}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("output missing %q\nfull output:\n%s", check, out)
		}
	}
}

func TestFormatBytesGPU(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0 B"},
		{1024 * 1024, "1 MB"},
		{4 * 1024 * 1024 * 1024, "4.0 GB"},
		{int64(1.5 * 1024 * 1024 * 1024), "1.5 GB"},
	}

	for _, tt := range tests {
		got := formatBytesGPU(tt.input)
		if got != tt.expected {
			t.Errorf("formatBytesGPU(%d) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

