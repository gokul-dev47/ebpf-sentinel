// Package integration provides integration tests for eBPF Sentinel.
package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/gokul-dev47/ebpf-sentinel/pkg/detector"
	"github.com/gokul-dev47/ebpf-sentinel/pkg/loader"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "integration tests require root, skipping")
		os.Exit(0)
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		fmt.Fprintln(os.Stderr, "BTF not available, skipping")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func newTestLoader(t *testing.T) *loader.Loader {
	t.Helper()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	ldr, err := loader.New(log)
	require.NoError(t, err)
	return ldr
}

func TestCleanSystemProducesNoCriticalFindings(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	ldr := newTestLoader(t)
	defer ldr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	require.NoError(t, ldr.Load(ctx))

	eng := detector.NewEngine(detector.EngineConfig{
		Loader: ldr, Logger: log, Checks: []string{"all"},
	})
	results, err := eng.Scan(ctx)
	require.NoError(t, err)

	for _, f := range results.Findings {
		assert.NotEqual(t, detector.RiskCritical, f.Risk,
			"unexpected CRITICAL finding on clean system: %s", f.Title)
	}
}

func TestSyscallHookDetectorRuns(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	ldr := newTestLoader(t)
	defer ldr.Close()

	ctx := context.Background()
	det := detector.NewSyscallHookDetector(log, ldr)
	results := &detector.ScanResults{}
	assert.NoError(t, det.Run(ctx, results))
}

func TestHiddenProcessDetectorRuns(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	ldr := newTestLoader(t)
	defer ldr.Close()

	ctx := context.Background()
	det := detector.NewHiddenProcessDetector(log, ldr)
	results := &detector.ScanResults{}
	assert.NoError(t, det.Run(ctx, results))

	selfPID := os.Getpid()
	_, err := os.Stat(fmt.Sprintf("/proc/%d", selfPID))
	assert.NoError(t, err, "self process should be visible in /proc")
}

func TestEBPFScannerRuns(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scanner := detector.NewEBPFScanner(log)
	results := &detector.ScanResults{}
	assert.NoError(t, scanner.Run(ctx, results))
}

func TestMemoryScannerRuns(t *testing.T) {
	log := logrus.New()
	scanner := detector.NewMemoryScanner(log)
	ctx := context.Background()
	results := &detector.ScanResults{}
	assert.NoError(t, scanner.Run(ctx, results))
}

func TestScanResultsSerializeToJSON(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	ldr := newTestLoader(t)
	defer ldr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	require.NoError(t, ldr.Load(ctx))

	eng := detector.NewEngine(detector.EngineConfig{
		Loader:  ldr,
		Logger:  log,
		Checks:  []string{"syscall"},
		JSONOut: true,
	})
	results, err := eng.Scan(ctx)
	require.NoError(t, err)

	data, err := results.MarshalJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "scan_id")
}

func TestScanRespectsContextTimeout(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	ldr := newTestLoader(t)
	defer ldr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	eng := detector.NewEngine(detector.EngineConfig{
		Loader: ldr, Logger: log, Checks: []string{"all"},
	})
	// Should not hang or panic
	_, _ = eng.Scan(ctx)
}

func TestMITREMappingsPresent(t *testing.T) {
	findings := []detector.FindingType{
		detector.FindingSyscallHook,
		detector.FindingHiddenProcess,
		detector.FindingSuspiciousBPF,
		detector.FindingMemoryPatch,
		detector.FindingHiddenModule,
		detector.FindingBehavioral,
	}
	for _, ft := range findings {
		mappings := detector.MITREMappings(ft)
		assert.NotEmpty(t, mappings, "expected MITRE mappings for %s", ft)
		for _, m := range mappings {
			assert.NotEmpty(t, m.TechniqueID)
			assert.NotEmpty(t, m.Name)
		}
	}
}
