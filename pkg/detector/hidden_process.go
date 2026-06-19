// Package detector - hidden process detection module.
package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/gokul-dev47/ebpf-sentinel/pkg/loader"
	"github.com/sirupsen/logrus"
)

// ProcessEntry holds metadata about a single process.
type ProcessEntry struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	Comm string `json:"comm"`
	UID  int    `json:"uid"`
}

// wsl2HostProcesses lists process name patterns that run in the WSL2 host
// namespace and legitimately don't appear in WSL2's /proc view.
// These are NOT rootkits - they are Windows/Docker host processes.
var wsl2HostProcessPatterns = []string{
	"docker-desktop",
	"docker",
	"wsl-pro-service",
	"wslservice",
	"wsl",
	"wslhost",
	"plan9",
	"init",
	"SessionLeader",
	"ShimV2",
	"containerd",
	"vpnkit",
	"com.docker",
	"hyperv",
	"vmmem",
	"MicrosoftEdge",
	"msrpc",
	"svchost",
	"lsass",
	"wininit",
	"csrss",
	"smss",
	"services",
	"sentinel", // our own process
}

// isWSL2HostProcess returns true if the process comm matches a known WSL2 host pattern.
func isWSL2HostProcess(comm string) bool {
	commLower := strings.ToLower(comm)
	for _, pattern := range wsl2HostProcessPatterns {
		if strings.Contains(commLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// isWSL2Environment detects if we are running inside WSL2.
func isWSL2Environment() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	v := strings.ToLower(string(data))
	return strings.Contains(v, "microsoft") || strings.Contains(v, "wsl")
}

// HiddenProcessDetector finds processes visible in the kernel task list
// but absent from /proc.
type HiddenProcessDetector struct {
	log    *logrus.Logger
	loader *loader.Loader
	isWSL2 bool
}

// NewHiddenProcessDetector creates a new hidden process detector.
func NewHiddenProcessDetector(log *logrus.Logger, ldr *loader.Loader) *HiddenProcessDetector {
	return &HiddenProcessDetector{
		log:    log,
		loader: ldr,
		isWSL2: isWSL2Environment(),
	}
}

// Name returns the module identifier.
func (d *HiddenProcessDetector) Name() string { return "HiddenProcessDetector" }

// Run executes hidden process detection.
func (d *HiddenProcessDetector) Run(ctx context.Context, results *ScanResults) error {
	d.log.Debug("starting hidden process detection")

	if d.isWSL2 {
		d.log.Debug("WSL2 environment detected - enabling host process filtering")
	}

	procPIDs, err := d.enumerateProc()
	if err != nil {
		return fmt.Errorf("enumerating /proc: %w", err)
	}
	d.log.Debugf("found %d processes via /proc", len(procPIDs))

	bpfPIDs, err := d.enumerateBPFCache()
	if err != nil {
		d.log.WithError(err).Debug("BPF cache unavailable, using brute force")
		bpfPIDs, err = d.bruteForcePIDs()
		if err != nil {
			d.log.WithError(err).Debug("brute force also failed, skipping process detection")
			return nil
		}
	}
	d.log.Debugf("found %d processes via BPF/brute-force cache", len(bpfPIDs))

	schedPIDs, _ := d.enumerateSchedDebug()

	hidden := d.findHiddenPIDs(procPIDs, bpfPIDs, schedPIDs)

	reported := 0
	for _, pid := range hidden {
		comm := "unknown"
		if e, ok := bpfPIDs[pid]; ok && e.Comm != "" {
			comm = e.Comm
		}

		// Filter WSL2 host processes - they appear hidden but are NOT rootkits
		if d.isWSL2 && isWSL2HostProcess(comm) {
			d.log.Debugf("skipping WSL2 host process: PID=%d comm=%s", pid, comm)
			continue
		}

		// Filter kernel threads (PID 2 and its children often appear hidden)
		if pid <= 3 {
			continue
		}

		// Additional sanity check: verify PID is not accessible at all
		// (true hidden processes won't be accessible via any /proc path)
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
			// Process IS accessible via /proc - not actually hidden, just
			// a race condition between our two scans
			d.log.Debugf("PID %d appeared hidden but /proc/%d exists - race condition, skipping", pid, pid)
			continue
		}

		ev, _ := json.Marshal(map[string]interface{}{
			"hidden_pid":      pid,
			"comm":            comm,
			"visible_in_bpf":  true,
			"visible_in_proc": false,
			"is_wsl2":         d.isWSL2,
		})
		results.AddFinding(&Finding{
			Type: FindingHiddenProcess, Risk: RiskCritical,
			Title: fmt.Sprintf("Hidden process detected: PID %d (%s)", pid, comm),
			Description: fmt.Sprintf(
				"Process PID %d (comm: %s) is present in the kernel task list "+
					"but absent from /proc. Definitive indicator of a process-hiding rootkit.",
				pid, comm),
			Evidence: ev, Confidence: 0.95,
			Remediation: fmt.Sprintf(
				"kill -9 %d (may fail if rootkit protects it). Reboot to clean state.", pid),
			MITRE: MITREMappings(FindingHiddenProcess),
		})
		d.log.Warnf("hidden process: PID=%d comm=%s", pid, comm)
		reported++
	}

	d.log.Debugf("hidden process scan complete: %d suspicious (filtered %d WSL2/race)",
		reported, len(hidden)-reported)
	return nil
}

// Remediate implements DetectionModule.
func (d *HiddenProcessDetector) Remediate(_ context.Context, findings []*Finding, dryRun bool) ([]string, error) {
	var actions []string
	for _, f := range findings {
		var ev map[string]interface{}
		if err := json.Unmarshal(f.Evidence, &ev); err != nil {
			continue
		}
		pid := int(ev["hidden_pid"].(float64))
		actions = append(actions, fmt.Sprintf("kill -9 %d (hidden process)", pid))
		if !dryRun {
			proc, err := os.FindProcess(pid)
			if err == nil {
				if err := proc.Kill(); err != nil {
					d.log.WithError(err).Warnf("could not kill hidden PID %d", pid)
				}
			}
		}
	}
	return actions, nil
}

func (d *HiddenProcessDetector) enumerateProc() (map[int]*ProcessEntry, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("reading /proc: %w", err)
	}
	pids := make(map[int]*ProcessEntry)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		proc := &ProcessEntry{PID: pid}
		d.enrichFromStatus(pid, proc)
		pids[pid] = proc
	}
	return pids, nil
}

func (d *HiddenProcessDetector) enrichFromStatus(pid int, entry *ProcessEntry) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch k {
		case "Name":
			entry.Comm = v
		case "PPid":
			entry.PPID, _ = strconv.Atoi(v)
		case "Uid":
			f := strings.Fields(v)
			if len(f) > 0 {
				entry.UID, _ = strconv.Atoi(f[0])
			}
		}
	}
}

func (d *HiddenProcessDetector) enumerateBPFCache() (map[int]*ProcessEntry, error) {
	m, err := d.loader.GetMap("process_cache")
	if err != nil {
		return nil, fmt.Errorf("getting process_cache: %w", err)
	}
	type bpfProc struct {
		PID, TGID, PPID, UID, GID uint32
		Comm                       [16]byte
		StartTime                  uint64
		Flags                      uint8
		Pad                        [3]uint8
	}
	pids := make(map[int]*ProcessEntry)
	var key uint32
	var val bpfProc
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		comm := strings.TrimRight(string(val.Comm[:]), "\x00")
		pids[int(val.PID)] = &ProcessEntry{
			PID: int(val.PID), PPID: int(val.PPID),
			Comm: comm, UID: int(val.UID),
		}
	}
	if err := iter.Err(); err != nil && err != ebpf.ErrIterationAborted {
		return pids, fmt.Errorf("iterating process_cache: %w", err)
	}
	return pids, nil
}

func (d *HiddenProcessDetector) bruteForcePIDs() (map[int]*ProcessEntry, error) {
	pids := make(map[int]*ProcessEntry)
	maxPID := 32768
	if data, err := os.ReadFile("/proc/sys/kernel/pid_max"); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			maxPID = v
		}
	}
	// Cap at 65535 to avoid very long scans
	if maxPID > 65535 {
		maxPID = 65535
	}
	for pid := 1; pid <= maxPID; pid++ {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d/task/%d", pid, pid)); err == nil {
			entry := &ProcessEntry{PID: pid}
			d.enrichFromStatus(pid, entry)
			pids[pid] = entry
		}
	}
	return pids, nil
}

func (d *HiddenProcessDetector) enumerateSchedDebug() (map[int]bool, error) {
	data, err := os.ReadFile("/proc/sched_debug")
	if err != nil {
		return nil, err
	}
	pids := make(map[int]bool)
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		for _, field := range strings.Fields(line) {
			parts := strings.Split(field, "/")
			if pid, err := strconv.Atoi(parts[0]); err == nil && pid > 0 && pid < 4194304 {
				pids[pid] = true
				break
			}
		}
	}
	return pids, nil
}

func (d *HiddenProcessDetector) findHiddenPIDs(
	procPIDs map[int]*ProcessEntry,
	bpfPIDs map[int]*ProcessEntry,
	schedPIDs map[int]bool,
) []int {
	seen := make(map[int]bool)
	var hidden []int
	for pid := range bpfPIDs {
		if pid <= 2 {
			continue
		}
		if _, inProc := procPIDs[pid]; !inProc && !seen[pid] {
			seen[pid] = true
			hidden = append(hidden, pid)
		}
	}
	for pid := range schedPIDs {
		if pid <= 2 {
			continue
		}
		if _, inProc := procPIDs[pid]; !inProc {
			if _, inBPF := bpfPIDs[pid]; inBPF && !seen[pid] {
				seen[pid] = true
				hidden = append(hidden, pid)
			}
		}
	}
	return hidden
}
