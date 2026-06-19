// Package tracker maintains state snapshots across detection scans.
package tracker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ProcessSnapshot is a point-in-time capture of running processes.
type ProcessSnapshot struct {
	Timestamp time.Time      `json:"timestamp"`
	PIDs      map[int]string `json:"pids"`
}

// ModuleSnapshot captures loaded kernel modules at a point in time.
type ModuleSnapshot struct {
	Timestamp time.Time         `json:"timestamp"`
	Modules   map[string]string `json:"modules"`
}

// Delta describes changes between two snapshots.
type Delta struct {
	Type      string    `json:"type"`
	Change    string    `json:"change"`
	Item      string    `json:"item"`
	Timestamp time.Time `json:"timestamp"`
}

// Tracker maintains baseline snapshots and computes deltas.
type Tracker struct {
	mu              sync.RWMutex
	log             *logrus.Logger
	processBaseline *ProcessSnapshot
	moduleBaseline  *ModuleSnapshot
	stateFile       string
}

// NewTracker creates a new state tracker.
func NewTracker(log *logrus.Logger, stateFile string) *Tracker {
	return &Tracker{log: log, stateFile: stateFile}
}

// CaptureProcessBaseline takes a snapshot of currently running processes.
func (t *Tracker) CaptureProcessBaseline(_ context.Context) error {
	snapshot := &ProcessSnapshot{Timestamp: time.Now(), PIDs: make(map[int]string)}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("reading /proc: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		snapshot.PIDs[pid] = strings.TrimSpace(string(data))
	}
	t.mu.Lock()
	t.processBaseline = snapshot
	t.mu.Unlock()
	t.log.Debugf("process baseline: %d processes", len(snapshot.PIDs))
	return nil
}

// DiffProcesses returns deltas between baseline and current /proc state.
func (t *Tracker) DiffProcesses(_ context.Context) ([]Delta, error) {
	t.mu.RLock()
	baseline := t.processBaseline
	t.mu.RUnlock()
	if baseline == nil {
		return nil, fmt.Errorf("no baseline; call CaptureProcessBaseline first")
	}
	current := make(map[int]string)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("reading /proc: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		current[pid] = strings.TrimSpace(string(data))
	}
	var deltas []Delta
	now := time.Now()
	for pid, comm := range current {
		if _, existed := baseline.PIDs[pid]; !existed {
			deltas = append(deltas, Delta{
				Type: "process", Change: "added",
				Item: fmt.Sprintf("PID %d (%s)", pid, comm), Timestamp: now,
			})
		}
	}
	for pid, comm := range baseline.PIDs {
		if _, exists := current[pid]; !exists {
			deltas = append(deltas, Delta{
				Type: "process", Change: "removed",
				Item: fmt.Sprintf("PID %d (%s)", pid, comm), Timestamp: now,
			})
		}
	}
	return deltas, nil
}

// CaptureModuleBaseline takes a snapshot of loaded kernel modules.
func (t *Tracker) CaptureModuleBaseline(_ context.Context) error {
	modules, err := readModulesMap()
	if err != nil {
		return fmt.Errorf("reading modules: %w", err)
	}
	t.mu.Lock()
	t.moduleBaseline = &ModuleSnapshot{Timestamp: time.Now(), Modules: modules}
	t.mu.Unlock()
	t.log.Debugf("module baseline: %d modules", len(modules))
	return nil
}

// DiffModules returns modules added or removed since baseline.
func (t *Tracker) DiffModules(_ context.Context) ([]Delta, error) {
	t.mu.RLock()
	baseline := t.moduleBaseline
	t.mu.RUnlock()
	if baseline == nil {
		return nil, fmt.Errorf("no module baseline; call CaptureModuleBaseline first")
	}
	current, err := readModulesMap()
	if err != nil {
		return nil, fmt.Errorf("reading current modules: %w", err)
	}
	var deltas []Delta
	now := time.Now()
	for name := range current {
		if _, existed := baseline.Modules[name]; !existed {
			deltas = append(deltas, Delta{Type: "module", Change: "added", Item: name, Timestamp: now})
		}
	}
	for name := range baseline.Modules {
		if _, exists := current[name]; !exists {
			deltas = append(deltas, Delta{Type: "module", Change: "removed", Item: name, Timestamp: now})
		}
	}
	return deltas, nil
}

// SaveState persists current baselines to the state file.
func (t *Tracker) SaveState() error {
	if t.stateFile == "" {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	state := map[string]interface{}{
		"process_baseline": t.processBaseline,
		"module_baseline":  t.moduleBaseline,
		"saved_at":         time.Now(),
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}
	return os.WriteFile(t.stateFile, data, 0600)
}

// LoadState restores baselines from the state file.
func (t *Tracker) LoadState() error {
	if t.stateFile == "" {
		return nil
	}
	data, err := os.ReadFile(t.stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading state file: %w", err)
	}
	var state struct {
		ProcessBaseline *ProcessSnapshot `json:"process_baseline"`
		ModuleBaseline  *ModuleSnapshot  `json:"module_baseline"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parsing state: %w", err)
	}
	t.mu.Lock()
	t.processBaseline = state.ProcessBaseline
	t.moduleBaseline = state.ModuleBaseline
	t.mu.Unlock()
	return nil
}

func readModulesMap() (map[string]string, error) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, err
	}
	mods := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			mods[fields[0]] = fields[4]
		} else if len(fields) >= 1 {
			mods[fields[0]] = "live"
		}
	}
	return mods, nil
}
