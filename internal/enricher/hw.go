package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/setevik/logtriage/internal/event"
)

var deviceRe = regexp.MustCompile(`/dev/(\w+)`)

// enrichKernelHW adds context to kernel/hardware error events.
// For disk-related errors, it cross-references with SMART data.
func enrichKernelHW(ctx context.Context, ev *event.Event) {
	// Try to extract a device name from the summary or raw fields.
	device := extractDevice(ev)
	if device == "" {
		return
	}

	// Query SMART data for the device.
	smartDetail, err := querySMARTDetail(ctx, device)
	if err != nil {
		slog.Debug("kernel/hw enrichment: SMART query failed", "device", device, "error", err)
		return
	}

	if smartDetail != "" {
		if ev.Detail != "" {
			ev.Detail += "\n"
		}
		ev.Detail += smartDetail
	}
}

// extractDevice tries to find a block device name in the event.
func extractDevice(ev *event.Event) string {
	// Check summary for /dev/xxx references.
	if m := deviceRe.FindStringSubmatch(ev.Summary); len(m) == 2 {
		return "/dev/" + m[1]
	}
	// Check detail.
	if m := deviceRe.FindStringSubmatch(ev.Detail); len(m) == 2 {
		return "/dev/" + m[1]
	}
	return ""
}

// querySMARTDetail runs smartctl and returns a brief status summary.
func querySMARTDetail(ctx context.Context, device string) (string, error) {
	out, err := runCommand(ctx, "smartctl", "--json=c", "-a", device)
	if err != nil {
		return "", err
	}

	var j struct {
		SmartStatus struct {
			Passed bool `json:"passed"`
		} `json:"smart_status"`
		Temperature struct {
			Current int `json:"current"`
		} `json:"temperature"`
		ATASmartAttributes struct {
			Table []struct {
				Name string `json:"name"`
				Raw  struct {
					Value int `json:"value"`
				} `json:"raw"`
			} `json:"table"`
		} `json:"ata_smart_attributes"`
	}

	if err := json.Unmarshal(out, &j); err != nil {
		return "", fmt.Errorf("parsing smartctl JSON: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "SMART status for %s:\n", device)

	status := "PASSED"
	if !j.SmartStatus.Passed {
		status = "FAILED"
	}
	fmt.Fprintf(&b, "  Health: %s\n", status)

	if j.Temperature.Current > 0 {
		fmt.Fprintf(&b, "  Temperature: %d°C\n", j.Temperature.Current)
	}

	for _, attr := range j.ATASmartAttributes.Table {
		switch attr.Name {
		case "Reallocated_Sector_Ct":
			if attr.Raw.Value > 0 {
				fmt.Fprintf(&b, "  Reallocated sectors: %d\n", attr.Raw.Value)
			}
		case "Current_Pending_Sector":
			if attr.Raw.Value > 0 {
				fmt.Fprintf(&b, "  Pending sectors: %d\n", attr.Raw.Value)
			}
		}
	}

	return b.String(), nil
}
