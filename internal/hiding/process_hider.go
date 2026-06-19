// Package hiding provides DETECTION-side analysis of process-hiding techniques.
// This package contains NO hiding logic whatsoever.
package hiding

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// HidingIndicator describes evidence that a process-hiding technique is active.
type HidingIndicator struct {
	Technique   string    `json:"technique"`
	Evidence    string    `json:"evidence"`
	AffectedPID int       `json:"affected_pid,omitempty"`
	Confidence  float64   `json:"confidence"`
	Timestamp   time.Time `json:"timestamp"`
}

// ProcessHidingDetector detects active process-hiding techniques.
type ProcessHidingDetector struct {
	mu       sync.Mutex
	log      *logrus.Logger
	findings []HidingIndicator
}

// NewProcessHidingDetector creates a new detector.
func NewProcessHidingDetector(log *logrus.Logger) *ProcessHidingDetector {
	return &ProcessHidingDetector{log: log}
}

// DetectGetdentsInconsistency checks for inconsistency between two
// independent /proc enumerations performed milliseconds apart.
func (d *ProcessHidingDetector) DetectGetdentsInconsistency() ([]HidingIndicator, error) {
	scan1, err := d.quickProcScan()
	if err != nil {
		return nil, fmt.Errorf("first proc scan: %w", err)
	}
	time.Sleep(50 * time.Millisecond)
	scan2, err := d.quickProcScan()
	if err != nil {
		return nil, fmt.Errorf("second proc scan: %w", err)
	}
	var indicators []HidingIndicator
	now := time.Now()
	for pid := range scan1 {
		if _, ok := scan2[pid]; !ok {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
				continue
			}
			indicators = append(indicators, HidingIndicator{
				Technique:   "getdents_filtering",
				Evidence:    fmt.Sprintf("PID %d present via stat() but absent from getdents64()", pid),
				AffectedPID: pid,
				Confidence:  0.80,
				Timestamp:   now,
			})
		}
	}
	d.mu.Lock()
	d.findings = append(d.findings, indicators...)
	d.mu.Unlock()
	return indicators, nil
}

// DetectProcStatAnomalies checks for processes where /proc/<pid>/stat
// exists but the PID does not appear in the /proc directory listing.
func (d *ProcessHidingDetector) DetectProcStatAnomalies(knownPIDs []int) ([]HidingIndicator, error) {
	procPIDs, err := d.quickProcScan()
	if err != nil {
		return nil, err
	}
	var indicators []HidingIndicator
	now := time.Now()
	for _, pid := range knownPIDs {
		if _, visible := procPIDs[pid]; visible {
			continue
		}
		statPath := fmt.Sprintf("/proc/%d/stat", pid)
		if data, err := os.ReadFile(statPath); err == nil {
			comm := extractComm(string(data))
			indicators = append(indicators, HidingIndicator{
				Technique: "proc_stat_accessible_but_hidden",
				Evidence: fmt.Sprintf("PID %d (%s): /proc/%d/stat readable but PID absent from /proc listing",
					pid, comm, pid),
				AffectedPID: pid,
				Confidence:  0.90,
				Timestamp:   now,
			})
		}
	}
	return indicators, nil
}

// GetFindings returns all detected hiding indicators.
func (d *ProcessHidingDetector) GetFindings() []HidingIndicator {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]HidingIndicator, len(d.findings))
	copy(out, d.findings)
	return out
}

func (d *ProcessHidingDetector) quickProcScan() (map[int]string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("reading /proc: %w", err)
	}
	pids := make(map[int]string, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm := ""
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
			comm = strings.TrimSpace(string(data))
		}
		pids[pid] = comm
	}
	return pids, nil
}

func extractComm(stat string) string {
	start := strings.IndexByte(stat, '(')
	end := strings.LastIndexByte(stat, ')')
	if start < 0 || end < 0 || end <= start {
		return "unknown"
	}
	return stat[start+1 : end]
}
