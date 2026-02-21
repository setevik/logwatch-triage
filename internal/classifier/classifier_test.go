package classifier

import (
	"testing"

	"github.com/setevik/logtriage/internal/event"
	"github.com/setevik/logtriage/internal/watcher"
)

func TestClassifyOOMKill(t *testing.T) {
	c := New("testhost")

	tests := []struct {
		name    string
		entry   watcher.JournalEntry
		wantNil bool
		tier    event.Tier
		process string
		pid     int
	}{
		{
			name: "oom killed process",
			entry: watcher.JournalEntry{
				Message:           "Out of memory: Killed process 4521 (firefox) total-vm:12345kB, anon-rss:3200000kB",
				Priority:          0,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierOOMKill,
			process: "firefox",
			pid:     4521,
		},
		{
			name: "oom-kill constraint line",
			entry: watcher.JournalEntry{
				Message:           "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,task=chrome,pid=9876,uid=1000",
				Priority:          0,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierOOMKill,
			process: "chrome",
			pid:     9876,
		},
		{
			name: "invoked oom-killer",
			entry: watcher.JournalEntry{
				Message:           "electron invoked oom-killer: gfp_mask=0x100cca(GFP_HIGHUSER_MOVABLE), order=0",
				Priority:          0,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier: event.TierOOMKill,
			// No process/pid extraction from this format.
			process: "",
			pid:     0,
		},
		{
			name: "normal log line no match",
			entry: watcher.JournalEntry{
				Message:           "Started Session 3 of User user.",
				Priority:          6,
				SyslogIdentifier:  "systemd",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := c.Classify(tt.entry)

			if tt.wantNil {
				if ev != nil {
					t.Fatalf("expected nil event, got tier=%s summary=%q", ev.Tier, ev.Summary)
				}
				return
			}

			if ev == nil {
				t.Fatal("expected event, got nil")
			}
			if ev.Tier != tt.tier {
				t.Errorf("tier = %q, want %q", ev.Tier, tt.tier)
			}
			if ev.Process != tt.process {
				t.Errorf("process = %q, want %q", ev.Process, tt.process)
			}
			if ev.PID != tt.pid {
				t.Errorf("pid = %d, want %d", ev.PID, tt.pid)
			}
			if ev.InstanceID != "testhost" {
				t.Errorf("instanceID = %q, want %q", ev.InstanceID, "testhost")
			}
		})
	}
}

func TestClassifyCrash(t *testing.T) {
	c := New("testhost")

	tests := []struct {
		name    string
		entry   watcher.JournalEntry
		wantNil bool
		tier    event.Tier
		process string
		pid     int
	}{
		{
			name: "segfault",
			entry: watcher.JournalEntry{
				Message:           "app[1234]: segfault at 0000000000000010 ip 00007f1234 sp 00007ffd error 4 in libfoo.so",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierProcessCrash,
			process: "app",
			pid:     1234,
		},
		{
			name: "coredump from systemd-coredump",
			entry: watcher.JournalEntry{
				Message:           "Process 5678 (vlc) of user 1000 dumped core.",
				Priority:          2,
				SyslogIdentifier:  "systemd-coredump",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierProcessCrash,
			process: "vlc",
			pid:     5678,
		},
		{
			name: "normal error log no match",
			entry: watcher.JournalEntry{
				Message:           "Failed to connect to database",
				Priority:          3,
				SyslogIdentifier:  "myapp",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := c.Classify(tt.entry)

			if tt.wantNil {
				if ev != nil {
					t.Fatalf("expected nil event, got tier=%s summary=%q", ev.Tier, ev.Summary)
				}
				return
			}

			if ev == nil {
				t.Fatal("expected event, got nil")
			}
			if ev.Tier != tt.tier {
				t.Errorf("tier = %q, want %q", ev.Tier, tt.tier)
			}
			if ev.Process != tt.process {
				t.Errorf("process = %q, want %q", ev.Process, tt.process)
			}
			if ev.PID != tt.pid {
				t.Errorf("pid = %d, want %d", ev.PID, tt.pid)
			}
			if ev.Severity != event.SevHigh && ev.Severity != event.SevCritical {
				t.Errorf("severity = %q, expected high or critical", ev.Severity)
			}
		})
	}
}

func TestClassifyServiceFailure(t *testing.T) {
	c := New("testhost")

	tests := []struct {
		name    string
		entry   watcher.JournalEntry
		wantNil bool
		tier    event.Tier
		unit    string
	}{
		{
			name: "service entered failed state",
			entry: watcher.JournalEntry{
				Message:           "docker.service entered failed state.",
				Priority:          3,
				SyslogIdentifier:  "systemd",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier: event.TierServiceFailure,
			unit: "docker.service",
		},
		{
			name: "service failed with result",
			entry: watcher.JournalEntry{
				Message:           "nginx.service: Failed with result 'exit-code'.",
				Priority:          3,
				SyslogIdentifier:  "systemd",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier: event.TierServiceFailure,
			unit: "nginx.service",
		},
		{
			name: "main process exited with non-zero",
			entry: watcher.JournalEntry{
				Message:           "myapp.service: Main process exited, code=exited, status=1/FAILURE",
				Priority:          3,
				SyslogIdentifier:  "systemd",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier: event.TierServiceFailure,
			unit: "myapp.service",
		},
		{
			name: "non-systemd identifier should not match",
			entry: watcher.JournalEntry{
				Message:           "docker.service entered failed state.",
				Priority:          3,
				SyslogIdentifier:  "docker",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			wantNil: true,
		},
		{
			name: "normal systemd message should not match",
			entry: watcher.JournalEntry{
				Message:           "Started Docker Application Container Engine.",
				Priority:          6,
				SyslogIdentifier:  "systemd",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := c.Classify(tt.entry)

			if tt.wantNil {
				if ev != nil {
					t.Fatalf("expected nil event, got tier=%s summary=%q", ev.Tier, ev.Summary)
				}
				return
			}

			if ev == nil {
				t.Fatal("expected event, got nil")
			}
			if ev.Tier != tt.tier {
				t.Errorf("tier = %q, want %q", ev.Tier, tt.tier)
			}
			if ev.Unit != tt.unit {
				t.Errorf("unit = %q, want %q", ev.Unit, tt.unit)
			}
			if ev.Severity != event.SevMedium {
				t.Errorf("severity = %q, expected medium", ev.Severity)
			}
		})
	}
}

func TestClassifyKernelHW(t *testing.T) {
	c := New("testhost")

	tests := []struct {
		name    string
		entry   watcher.JournalEntry
		wantNil bool
		tier    event.Tier
		summary string
	}{
		{
			name: "I/O error on disk",
			entry: watcher.JournalEntry{
				Message:           "blk_update_request: I/O error, dev sda, sector 12345",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "I/O error on /dev/sda",
		},
		{
			name: "EXT4 filesystem error",
			entry: watcher.JournalEntry{
				Message:           "EXT4-fs error (device sda1): ext4_journal_check_start:61: Detected aborted journal",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "EXT4 error on /dev/sda1",
		},
		{
			name: "GPU hang",
			entry: watcher.JournalEntry{
				Message:           "i915 0000:00:02.0: GPU HANG: ecode 9:1:0x00000000",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "Intel GPU hang (ecode 9:1:0x00000000)",
		},
		{
			name: "MCE hardware error",
			entry: watcher.JournalEntry{
				Message:           "mce: [Hardware Error]: Machine check events logged",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "Machine check exception",
		},
		{
			name: "NVIDIA Xid error",
			entry: watcher.JournalEntry{
				Message:           "NVRM: Xid (PCI:0000:01:00): 79, pid=1234, GPU has fallen off the bus",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "NVIDIA Xid 79: GPU has fallen off the bus",
		},
		{
			name: "non-kernel transport should not match",
			entry: watcher.JournalEntry{
				Message:           "I/O error on something",
				Priority:          3,
				SyslogIdentifier:  "myapp",
				Transport:         "stdout",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			wantNil: true,
		},
		{
			name: "normal kernel message should not match",
			entry: watcher.JournalEntry{
				Message:           "Loading kernel modules...",
				Priority:          6,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := c.Classify(tt.entry)

			if tt.wantNil {
				if ev != nil {
					t.Fatalf("expected nil event, got tier=%s summary=%q", ev.Tier, ev.Summary)
				}
				return
			}

			if ev == nil {
				t.Fatal("expected event, got nil")
			}
			if ev.Tier != tt.tier {
				t.Errorf("tier = %q, want %q", ev.Tier, tt.tier)
			}
			if ev.Summary != tt.summary {
				t.Errorf("summary = %q, want %q", ev.Summary, tt.summary)
			}
			if ev.Severity != event.SevHigh {
				t.Errorf("severity = %q, expected high", ev.Severity)
			}
		})
	}
}

func TestClassifyGPUPatterns(t *testing.T) {
	c := New("testhost")

	tests := []struct {
		name    string
		entry   watcher.JournalEntry
		tier    event.Tier
		summary string
		gpuFlag bool
	}{
		{
			name: "NVIDIA Xid 31 memory page fault",
			entry: watcher.JournalEntry{
				Message:           "NVRM: Xid (PCI:0000:04:00): 31, Ch 00000001, engmask 00000101, intr 10000000",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "NVIDIA Xid 31: GPU memory page fault",
			gpuFlag: true,
		},
		{
			name: "NVIDIA GPU fallen off bus",
			entry: watcher.JournalEntry{
				Message:           "NVRM: GPU 0000:01:00.0: GPU has fallen off the bus.",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "NVIDIA GPU fallen off bus (fatal)",
			gpuFlag: true,
		},
		{
			name: "NVIDIA VRAM out of memory",
			entry: watcher.JournalEntry{
				Message:           "NVRM: Assertion failed: Out of memory [NV_ERR_NO_MEMORY]",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "NVIDIA VRAM out of memory",
			gpuFlag: true,
		},
		{
			name: "AMD GPU reset",
			entry: watcher.JournalEntry{
				Message:           "amdgpu 0000:03:00.0: amdgpu: GPU reset(2) succeeded!",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "AMD GPU reset",
			gpuFlag: true,
		},
		{
			name: "AMD GPU ring timeout",
			entry: watcher.JournalEntry{
				Message:           "amdgpu 0000:03:00.0: amdgpu: ring gfx_0.0.0 timeout",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "AMD GPU ring gfx_0.0.0 timeout",
			gpuFlag: true,
		},
		{
			name: "AMD VRAM protection fault",
			entry: watcher.JournalEntry{
				Message:           "VM_L2_PROTECTION_FAULT_STATUS:0x00051014",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "AMD GPU VRAM protection fault",
			gpuFlag: true,
		},
		{
			name: "AMD VRAM lost",
			entry: watcher.JournalEntry{
				Message:           "[drm] VRAM is lost due to GPU reset!",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "VRAM lost after GPU reset",
			gpuFlag: true,
		},
		{
			name: "AMD GPU thermal fault",
			entry: watcher.JournalEntry{
				Message:           "amdgpu 0000:03:00.0: amdgpu: GPU SW CTF temperature reached, shutdown!",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "AMD GPU thermal fault",
			gpuFlag: true,
		},
		{
			name: "Intel i915 engine reset",
			entry: watcher.JournalEntry{
				Message:           "i915 0000:00:02.0: Resetting rcs0 for hang on rcs0",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "Intel GPU resetting rcs0: hang on rcs0",
			gpuFlag: true,
		},
		{
			name: "Intel i915 chip reset",
			entry: watcher.JournalEntry{
				Message:           "i915 0000:00:02.0: Resetting chip for GuC failed to respond",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "Intel GPU resetting chip: GuC failed to respond",
			gpuFlag: true,
		},
		{
			name: "DRM flip timeout",
			entry: watcher.JournalEntry{
				Message:           "[drm:nv_drm_atomic_commit [nvidia_drm]] *ERROR* [CRTC:71:head-0] flip_done timed out",
				Priority:          3,
				SyslogIdentifier:  "kernel",
				Transport:         "kernel",
				RealtimeTimestamp: "1708300000000000",
				Fields:            map[string]string{},
			},
			tier:    event.TierKernelHW,
			summary: "DRM flip timeout",
			gpuFlag: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := c.Classify(tt.entry)
			if ev == nil {
				t.Fatal("expected event, got nil")
			}
			if ev.Tier != tt.tier {
				t.Errorf("tier = %q, want %q", ev.Tier, tt.tier)
			}
			if ev.Summary != tt.summary {
				t.Errorf("summary = %q, want %q", ev.Summary, tt.summary)
			}
			if tt.gpuFlag && ev.RawFields["_gpu_event"] != "true" {
				t.Error("expected _gpu_event=true in RawFields")
			}
		})
	}
}

func TestClassifyGPUEvent(t *testing.T) {
	c := New("testhost")
	ev := c.ClassifyGPUEvent("card0", "amd", "GPU thermal warning: card0 92°C", "Temperature: 92°C")
	if ev == nil {
		t.Fatal("expected event")
	}
	if ev.Tier != event.TierKernelHW {
		t.Errorf("tier = %q, want T4", ev.Tier)
	}
	if ev.RawFields["_gpu_event"] != "true" {
		t.Error("expected _gpu_event=true")
	}
	if ev.RawFields["_gpu_vendor"] != "amd" {
		t.Errorf("_gpu_vendor = %q, want amd", ev.RawFields["_gpu_vendor"])
	}
}

func TestIsCompositorProcess(t *testing.T) {
	compositors := []string{"Xorg", "gnome-shell", "kwin_wayland", "sway", "Hyprland"}
	for _, p := range compositors {
		if !IsCompositorProcess(p) {
			t.Errorf("IsCompositorProcess(%q) = false, want true", p)
		}
	}
	if IsCompositorProcess("firefox") {
		t.Error("IsCompositorProcess(firefox) = true, want false")
	}
}

func TestClassifyPSIEvent(t *testing.T) {
	c := New("testhost")

	ev := c.ClassifyPSIEvent(65.2, 15.3, "PSI some avg10=65.2% full avg10=15.3%")
	if ev == nil {
		t.Fatal("expected event")
	}
	if ev.Tier != event.TierMemPressure {
		t.Errorf("tier = %q, want T5", ev.Tier)
	}
	if ev.Severity != event.SevWarning {
		t.Errorf("severity = %q, want warning", ev.Severity)
	}
	if ev.InstanceID != "testhost" {
		t.Errorf("instanceID = %q", ev.InstanceID)
	}
}

func TestClassifySMARTEvent(t *testing.T) {
	c := New("testhost")

	ev := c.ClassifySMARTEvent("/dev/sda", "SMART FAILING: /dev/sda", "Health: FAILED")
	if ev == nil {
		t.Fatal("expected event")
	}
	if ev.Tier != event.TierKernelHW {
		t.Errorf("tier = %q, want T4", ev.Tier)
	}
	if ev.Severity != event.SevHigh {
		t.Errorf("severity = %q, want high", ev.Severity)
	}
}

func TestClassifyTimestampParsing(t *testing.T) {
	c := New("testhost")

	entry := watcher.JournalEntry{
		Message:           "Out of memory: Killed process 100 (test)",
		Priority:          0,
		SyslogIdentifier:  "kernel",
		RealtimeTimestamp: "1708300000000000", // microseconds since epoch
		Fields:            map[string]string{},
	}

	ev := c.Classify(entry)
	if ev == nil {
		t.Fatal("expected event")
	}

	if ev.Timestamp.Year() < 2024 {
		t.Errorf("timestamp year = %d, expected >= 2024", ev.Timestamp.Year())
	}
}
