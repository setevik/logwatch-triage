package classifier

import "regexp"

// T1 — OOM Kill patterns
var oomPatterns = []*regexp.Regexp{
	regexp.MustCompile(`oom-kill:`),
	regexp.MustCompile(`Out of memory: Kill(ed)? process`),
	regexp.MustCompile(`invoked oom-killer`),
}

// T2 — Process Crash patterns
var crashPatterns = []*regexp.Regexp{
	regexp.MustCompile(`segfault at`),
	regexp.MustCompile(`traps:.*trap`),
	regexp.MustCompile(`Process \d+ \(.+\) of user \d+ dumped core`),
}

// crashIdentifiers are syslog identifiers that signal crash events.
var crashIdentifiers = map[string]bool{
	"systemd-coredump": true,
}

// oomProcessRe extracts the killed process name and PID from an OOM kill message.
// Examples:
//
//	"Out of memory: Killed process 4521 (firefox)"
//	"oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,oom_memcg=...,task_memcg=...,task=firefox,pid=4521,uid=1000"
var oomKillProcessRe = regexp.MustCompile(`Killed process (\d+) \(([^)]+)\)`)
var oomKillTaskRe = regexp.MustCompile(`task=([^,]+),pid=(\d+)`)

// crashSegfaultRe extracts info from segfault messages.
// Example: "app[1234]: segfault at 0000000000000010 ip ... sp ... error 4 in libfoo.so"
var crashSegfaultRe = regexp.MustCompile(`(\S+)\[(\d+)\]: segfault at`)

// coredumpRe extracts process info from systemd-coredump messages.
// Example: "Process 1234 (app) of user 1000 dumped core."
var coredumpProcessRe = regexp.MustCompile(`Process (\d+) \(([^)]+)\) of user \d+ dumped core`)

// T3 — Service Failure patterns
var serviceFailPatterns = []*regexp.Regexp{
	regexp.MustCompile(`entered failed state`),
	regexp.MustCompile(`Failed with result`),
	regexp.MustCompile(`Main process exited, code=exited, status=\d+/`),
}

// serviceIdentifiers are syslog identifiers that emit service failure messages.
var serviceIdentifiers = map[string]bool{
	"systemd": true,
}

// serviceUnitRe extracts the unit name from systemd failure messages.
// Example: "docker.service: Main process exited, code=exited, status=1/FAILURE"
// Example: "foo.service entered failed state."
// Example: "foo.service: Failed with result 'exit-code'."
var serviceUnitRe = regexp.MustCompile(`^(\S+\.service)(?::|:?\s)`)

// serviceExitCodeRe extracts exit status from failure messages.
// Example: "status=1/FAILURE"
var serviceExitCodeRe = regexp.MustCompile(`status=(\d+)/`)

// T4 — Kernel/HW Error patterns (disk, CPU, generic hardware)
var kernelHWPatterns = []*regexp.Regexp{
	regexp.MustCompile(`I/O error`),
	regexp.MustCompile(`EXT4-fs error`),
	regexp.MustCompile(`XFS .* error`),
	regexp.MustCompile(`BTRFS .* error`),
	regexp.MustCompile(`Buffer I/O error`),
	regexp.MustCompile(`blk_update_request: I/O error`),
	regexp.MustCompile(`mce: \[Hardware Error\]`),
	regexp.MustCompile(`Machine check events logged`),
	regexp.MustCompile(`MCE`),
	regexp.MustCompile(`NMI:`),
	regexp.MustCompile(`EDAC .* error`),
	regexp.MustCompile(`pcieport.*AER`),
	regexp.MustCompile(`Hardware Error`),
}

// T4 — GPU-specific kernel error patterns
var gpuPatterns = []*regexp.Regexp{
	// NVIDIA (proprietary driver)
	regexp.MustCompile(`NVRM: Xid`),
	regexp.MustCompile(`NVRM:.*GPU has fallen off the bus`),
	regexp.MustCompile(`NVRM:.*GPU crash dump`),
	regexp.MustCompile(`NVRM:.*Out of memory`),
	regexp.MustCompile(`NVRM:.*Cannot allocate sysmem`),

	// AMD (amdgpu kernel driver)
	regexp.MustCompile(`amdgpu.*GPU fault`),
	regexp.MustCompile(`amdgpu.*GPU reset`),
	regexp.MustCompile(`amdgpu.*page fault`),
	regexp.MustCompile(`amdgpu.*ring\s+\S+\s+timeout`),
	regexp.MustCompile(`(?:GCVM_L2|VM_L2)_PROTECTION_FAULT_STATUS`),
	regexp.MustCompile(`\[drm\] VRAM is lost`),
	regexp.MustCompile(`amdgpu.*GPU SW CTF`),
	regexp.MustCompile(`amdgpu.*GPU over temperature range`),

	// Intel (i915 / xe driver)
	regexp.MustCompile(`i915.*GPU HANG`),
	regexp.MustCompile(`i915.*Resetting (?:rcs|bcs|vcs|vecs|ccs)\d*`),
	regexp.MustCompile(`i915.*Resetting chip`),
	regexp.MustCompile(`GUC: Engine reset failed`),

	// Generic DRM errors
	regexp.MustCompile(`GPU hang`),
	regexp.MustCompile(`gpu\s+fault`),
	regexp.MustCompile(`\*ERROR\*.*flip_done timed out`),
	regexp.MustCompile(`\*ERROR\*.*commit wait timed out`),
}

// compositorProcesses maps compositor process names to friendly labels.
// Used to detect compositor crashes that may be GPU-driver-initiated.
var compositorProcesses = map[string]string{
	"Xorg":         "Xorg",
	"Xwayland":     "Xwayland",
	"gnome-shell":  "GNOME Shell",
	"kwin_wayland": "KWin (Wayland)",
	"kwin_x11":     "KWin (X11)",
	"sway":         "Sway",
	"Hyprland":     "Hyprland",
	"mutter":       "Mutter",
}

// kernelHWIdentifiers are transport/identifiers that commonly produce HW events.
var kernelHWIdentifiers = map[string]bool{
	"kernel": true,
}

// kernelDeviceRe extracts device names from I/O error messages.
// Example: "blk_update_request: I/O error, dev sda, sector 12345"
var kernelDeviceRe = regexp.MustCompile(`dev\s+(\w+)`)

// kernelFSDevRe extracts device from filesystem error messages.
// Example: "EXT4-fs error (device sda1): ..."
var kernelFSDevRe = regexp.MustCompile(`\(device\s+(\w+)\)`)

// nvidiaXidRe extracts the Xid error code from NVIDIA driver messages.
// Example: "NVRM: Xid (PCI:0000:01:00): 79, pid=1234, GPU has fallen off the bus"
var nvidiaXidRe = regexp.MustCompile(`NVRM: Xid \(PCI:[0-9a-f:\.]+\): (\d+),`)

// nvidiaXidDescriptions maps critical Xid codes to descriptions.
var nvidiaXidDescriptions = map[string]string{
	"13":  "Graphics exception",
	"31":  "GPU memory page fault",
	"38":  "Driver firmware error",
	"43":  "GPU stopped processing",
	"48":  "ECC double-bit error",
	"62":  "Internal micro-controller error",
	"69":  "GPU invalid page access",
	"79":  "GPU has fallen off the bus",
	"109": "Context switch timeout",
	"119": "GSP timeout",
}

// amdGPURingRe extracts the ring name from amdgpu ring timeout.
var amdGPURingRe = regexp.MustCompile(`amdgpu.*ring\s+(\S+)\s+timeout`)

// i915EcodeRe extracts the ecode from i915 GPU HANG.
var i915EcodeRe = regexp.MustCompile(`i915.*GPU HANG: ecode (\d+:\d+:(?:0x)?[0-9a-fA-F]+)`)

// i915ResetRe extracts the engine and reason from i915 reset messages.
var i915ResetRe = regexp.MustCompile(`i915.*Resetting\s+(\S+)\s+for\s+(.+)`)

// kernelHWSummaryRe tries to extract a concise error description.
var kernelHWSummaryPatterns = []struct {
	re      *regexp.Regexp
	summary string
}{
	// Disk/filesystem
	{regexp.MustCompile(`I/O error.*dev\s+(\w+)`), "I/O error on /dev/%s"},
	{regexp.MustCompile(`EXT4-fs error \(device (\w+)\)`), "EXT4 error on /dev/%s"},
	{regexp.MustCompile(`XFS.*error.*dev\s+(\w+)`), "XFS error on /dev/%s"},
	{regexp.MustCompile(`BTRFS.*error.*dev\s+(\w+)`), "BTRFS error on /dev/%s"},

	// NVIDIA GPU
	{regexp.MustCompile(`NVRM:.*GPU has fallen off the bus`), "NVIDIA GPU fallen off bus (fatal)"},
	{regexp.MustCompile(`NVRM:.*GPU crash dump`), "NVIDIA GPU crash dump"},
	{regexp.MustCompile(`NVRM:.*Out of memory`), "NVIDIA VRAM out of memory"},
	{regexp.MustCompile(`NVRM:.*Cannot allocate sysmem`), "NVIDIA sysmem allocation failed"},
	{regexp.MustCompile(`NVRM: Xid`), "NVIDIA GPU error (Xid)"},

	// AMD GPU
	{regexp.MustCompile(`amdgpu.*GPU reset`), "AMD GPU reset"},
	{regexp.MustCompile(`amdgpu.*GPU fault`), "AMD GPU fault"},
	{regexp.MustCompile(`amdgpu.*ring\s+(\S+)\s+timeout`), "AMD GPU ring %s timeout"},
	{regexp.MustCompile(`amdgpu.*page fault`), "AMD GPU page fault"},
	{regexp.MustCompile(`VM_L2_PROTECTION_FAULT`), "AMD GPU VRAM protection fault"},
	{regexp.MustCompile(`GCVM_L2_PROTECTION_FAULT`), "AMD GPU VRAM protection fault"},
	{regexp.MustCompile(`\[drm\] VRAM is lost`), "VRAM lost after GPU reset"},
	{regexp.MustCompile(`amdgpu.*GPU SW CTF`), "AMD GPU thermal fault"},
	{regexp.MustCompile(`amdgpu.*GPU over temperature`), "AMD GPU over temperature"},

	// Intel GPU
	{regexp.MustCompile(`i915.*GPU HANG`), "Intel GPU hang"},
	{regexp.MustCompile(`i915.*Resetting chip`), "Intel GPU chip reset"},
	{regexp.MustCompile(`i915.*Resetting`), "Intel GPU engine reset"},
	{regexp.MustCompile(`GUC: Engine reset failed`), "Intel GuC engine reset failed"},

	// Generic GPU/DRM
	{regexp.MustCompile(`GPU hang`), "GPU hang detected"},
	{regexp.MustCompile(`GPU fault`), "GPU fault detected"},
	{regexp.MustCompile(`flip_done timed out`), "DRM flip timeout"},
	{regexp.MustCompile(`commit wait timed out`), "DRM commit wait timeout"},

	// CPU/Memory/PCIe
	{regexp.MustCompile(`MCE|mce:.*Hardware Error`), "Machine check exception"},
	{regexp.MustCompile(`NMI:`), "NMI received"},
	{regexp.MustCompile(`EDAC`), "Memory error (EDAC)"},
	{regexp.MustCompile(`AER`), "PCIe AER error"},
}
