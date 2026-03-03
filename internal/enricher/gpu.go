package enricher

import (
	"context"
	"fmt"
	"strings"

	"github.com/setevik/logtriage/internal/classifier"
	"github.com/setevik/logtriage/internal/event"
	"github.com/setevik/logtriage/internal/monitor"
)

// enrichGPU adds GPU context to T4 events that have the _gpu_event marker,
// and annotates compositor crashes (T2) with GPU status when available.
func enrichGPU(ctx context.Context, ev *event.Event) {
	gpus := monitor.DetectGPUs()
	if len(gpus) == 0 {
		return
	}

	var detail strings.Builder
	for i := range gpus {
		gpu := &gpus[i]
		monitor.ReadGPUTemp(gpu)
		monitor.ReadGPUVRAM(gpu)

		if gpu.Temperature > 0 || gpu.VRAMTotal > 0 {
			detail.WriteString(monitor.FormatGPUStatus(*gpu))
		}
	}

	if detail.Len() > 0 {
		if ev.Detail != "" {
			ev.Detail += "\n"
		}
		ev.Detail += detail.String()
	}
}

// enrichCompositorCrash annotates a compositor crash with GPU context.
func enrichCompositorCrash(ctx context.Context, ev *event.Event) {
	if ev.Process == "" {
		return
	}
	if !classifier.IsCompositorProcess(ev.Process) {
		return
	}

	label := classifier.CompositorLabel(ev.Process)

	// Check for recent GPU errors in kernel log.
	gpuLogs, err := queryRecentGPUKernelLogs(ctx)
	if err == nil && gpuLogs != "" {
		if ev.Detail != "" {
			ev.Detail += "\n"
		}
		ev.Detail += fmt.Sprintf("%s crash — recent GPU kernel messages:\n%s", label, gpuLogs)
	}

	// Add current GPU status.
	enrichGPU(ctx, ev)
}

// queryRecentGPUKernelLogs looks for GPU-related kernel messages in the last 60s.
func queryRecentGPUKernelLogs(ctx context.Context) (string, error) {
	out, err := runCommand(ctx, "journalctl", "-k", "--since", "60s ago",
		"--no-pager", "-o", "short-precise", "--grep",
		"GPU|NVRM|amdgpu|i915|drm.*ERROR")
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	// Limit to 10 most recent lines.
	if len(lines) > 10 {
		lines = lines[len(lines)-10:]
	}
	return strings.Join(lines, "\n"), nil
}
