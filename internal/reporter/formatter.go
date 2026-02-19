package reporter

import (
	"fmt"
	"strings"

	"github.com/setevik/logtriage/internal/event"
)

// tierEmoji maps event tiers to display emojis for ntfy titles.
var tierEmoji = map[event.Tier]string{
	event.TierOOMKill:      "\U0001f534", // red circle
	event.TierProcessCrash: "\U0001f4a5", // collision/crash
}

// tierTags maps event tiers to ntfy tag names.
var tierTags = map[event.Tier]string{
	event.TierOOMKill:      "skull,memory",
	event.TierProcessCrash: "warning,crash",
}

// FormatTitle builds the ntfy notification title for an event.
func FormatTitle(ev *event.Event) string {
	emoji := tierEmoji[ev.Tier]
	if emoji == "" {
		emoji = "\u2757" // exclamation mark
	}
	return fmt.Sprintf("%s [%s] %s", emoji, ev.InstanceID, ev.Summary)
}

// FormatBody builds the ntfy notification body for an event.
func FormatBody(ev *event.Event) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Host: %s\n", ev.InstanceID)
	fmt.Fprintf(&b, "Time: %s\n", ev.Timestamp.Format("2006-01-02 15:04:05 MST"))

	if ev.Detail != "" {
		b.WriteString("\n")
		b.WriteString(ev.Detail)
	}

	return b.String()
}

// TagsForTier returns the ntfy tags string for an event tier.
func TagsForTier(tier event.Tier) string {
	if tags, ok := tierTags[tier]; ok {
		return tags
	}
	return "warning"
}
