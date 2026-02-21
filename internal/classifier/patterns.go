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

// T4 — Kernel/HW Error patterns
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
	regexp.MustCompile(`GPU hang`),
	regexp.MustCompile(`gpu\s+fault`),
	regexp.MustCompile(`NVRM: Xid`),
	regexp.MustCompile(`i915.*GPU HANG`),
	regexp.MustCompile(`amdgpu.*GPU fault`),
	regexp.MustCompile(`pcieport.*AER`),
	regexp.MustCompile(`Hardware Error`),
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

// kernelHWSummaryRe tries to extract a concise error description.
var kernelHWSummaryPatterns = []struct {
	re      *regexp.Regexp
	summary string
}{
	{regexp.MustCompile(`I/O error.*dev\s+(\w+)`), "I/O error on /dev/%s"},
	{regexp.MustCompile(`EXT4-fs error \(device (\w+)\)`), "EXT4 error on /dev/%s"},
	{regexp.MustCompile(`XFS.*error.*dev\s+(\w+)`), "XFS error on /dev/%s"},
	{regexp.MustCompile(`BTRFS.*error.*dev\s+(\w+)`), "BTRFS error on /dev/%s"},
	{regexp.MustCompile(`GPU hang`), "GPU hang detected"},
	{regexp.MustCompile(`GPU fault`), "GPU fault detected"},
	{regexp.MustCompile(`NVRM: Xid`), "NVIDIA GPU error (Xid)"},
	{regexp.MustCompile(`i915.*GPU HANG`), "Intel GPU hang"},
	{regexp.MustCompile(`amdgpu.*GPU fault`), "AMD GPU fault"},
	{regexp.MustCompile(`MCE|mce:.*Hardware Error`), "Machine check exception"},
	{regexp.MustCompile(`NMI:`), "NMI received"},
	{regexp.MustCompile(`EDAC`), "Memory error (EDAC)"},
	{regexp.MustCompile(`AER`), "PCIe AER error"},
}
