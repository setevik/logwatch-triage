// Package format provides shared formatting utilities.
package format

import "fmt"

const (
	KB = 1024
	MB = KB * 1024
	GB = MB * 1024
)

// Bytes formats a byte count as a human-readable string (e.g., "3.0 GB", "512.0 MB").
func Bytes(b int64) string {
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
