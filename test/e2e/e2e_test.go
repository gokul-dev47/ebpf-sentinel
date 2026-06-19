// Package e2e provides end-to-end tests for eBPF Sentinel.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sentinelBinary = "../../bin/sentinel"

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "e2e tests require root, skipping")
		os.Exit(0)
	}
	if _, err := os.Stat(sentinelBinary); err != nil {
		fmt.Fprintf(os.Stderr, "sentinel binary not found at %s, run 'make build' first\n", sentinelBinary)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestScanCleanSystem(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, sentinelBinary, "scan", "--json", "--timeout", "60")
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			t.Logf("scan found threats (exit 1) - validating JSON output")
		} else {
			require.NoError(t, err, "scan should not fail with exit code 2+")
		}
	}

	var results map[string]interface{}
	require.NoError(t, json.Unmarshal(out, &results), "output must be valid JSON")
	assert.Contains(t, results, "scan_id")
	assert.Contains(t, results, "risk_level")
	assert.Contains(t, results, "findings")
}

func TestScanOutputFileCreated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	outFile := t.TempDir() + "/scan_result.json"
	cmd := exec.CommandContext(ctx, sentinelBinary, "scan",
		"--checks", "syscall",
		"--output", outFile,
		"--timeout", "30")
	cmd.Run() //nolint:errcheck

	_, err := os.Stat(outFile)
	assert.NoError(t, err, "output file should be created")

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var results map[string]interface{}
	assert.NoError(t, json.Unmarshal(data, &results))
}

func TestStatusCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, sentinelBinary, "status", "--json").Output()
	require.NoError(t, err, "status should succeed")
	assert.NotEmpty(t, out)
}

func TestScanIndividualChecks(t *testing.T) {
	checks := []string{"syscall", "ebpf", "memory"}
	for _, check := range checks {
		t.Run(check, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, sentinelBinary, "scan",
				"--checks", check, "--json", "--timeout", "30")
			out, err := cmd.Output()
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
					// Threats found - still validate JSON
				} else {
					t.Fatalf("scan --checks %s failed: %v", check, err)
				}
			}
			var results map[string]interface{}
			assert.NoError(t, json.Unmarshal(out, &results),
				"output for check=%s should be valid JSON", check)
		})
	}
}

func TestRemediateDryRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, sentinelBinary, "remediate", "--dry-run")
	out, _ := cmd.CombinedOutput()
	assert.NotContains(t, string(out), "panic", "should not panic")
}
