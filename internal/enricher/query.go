// Package enricher adds context to classified events via subprocess queries.
package enricher

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

const queryTimeout = 10 * time.Second

// runCommand executes a command with a timeout and returns its stdout.
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %v: %w (stderr: %s)", name, args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}
