// Package detector - behavioral anomaly detection module.
package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gokul-dev47/ebpf-sentinel/pkg/loader"
	"github.com/sirupsen/logrus"
)

// SyscallLatencyStats holds per-syscall statistics.
type SyscallLatencyStats struct {
	SyscallNr   int     `json:"syscall_nr"`
	SyscallName string  `json:"syscall_name"`
	Count       uint64  `json:"count"`
	MeanNs      float64 `json:"mean_ns"`
	StdDevNs    float64 `json:"std_dev_ns"`
	MaxNs       uint64  `json:"max_ns"`
	MinNs       uint64  `json:"min_ns"`
}

// AnomalyEvent represents a single detected behavioral anomaly.
type AnomalyEvent struct {
	SyscallNr   int       `json:"syscall_nr"`
	SyscallName string    `json:"syscall_name"`
	LatencyNs   uint64    `json:"latency_ns"`
	MeanNs      float64   `json:"mean_ns"`
	StdDevNs    float64   `json:"std_dev_ns"`
	ZScore      float64   `json:"z_score"`
	Timestamp   time.Time `json:"timestamp"`
}

// empiricalBaselines maps syscall numbers to expected mean latency in ns.
var empiricalBaselines = map[int]uint64{
	0: 300, 1: 200, 2: 1500, 3: 100, 4: 400,
	9: 800, 21: 600, 257: 1800, 59: 50000,
}

// BehavioralDetector analyzes syscall patterns for anomalies.
type BehavioralDetector struct {
	log    *logrus.Logger
	loader *loader.Loader
	mu     sync.Mutex
}

// NewBehavioralDetector creates a new behavioral anomaly detector.
func NewBehavioralDetector(log *logrus.Logger, ldr *loader.Loader) *BehavioralDetector {
	return &BehavioralDetector{log: log, loader: ldr}
}

// Name returns the module identifier.
func (d *BehavioralDetector) Name() string { return "BehavioralDetector" }

// Run performs behavioral analysis on BPF-collected syscall data.
func (d *BehavioralDetector) Run(ctx context.Context, results *ScanResults) error {
	d.log.Debug("starting behavioral analysis")

	// Skip if BPF not available
	if !d.loader.BPFAvailable() {
		d.log.Debug("BPF not available, skipping behavioral analysis")
		return nil
	}

	stats, err := d.readSyscallBaseline()
	if err != nil {
		d.log.WithError(err).Debug("could not read syscall baseline")
		return nil
	}
	if len(stats) == 0 {
		d.log.Debug("no syscall baseline data yet (system just started)")
		return nil
	}
	d.log.Debugf("read stats for %d syscalls", len(stats))

	anomalies := d.detectAnomalies(stats)
	for _, a := range anomalies {
		ev, _ := json.Marshal(a)
		results.AddFinding(&Finding{
			Type: FindingBehavioral,
			Risk: riskFromZScore(a.ZScore),
			Title: fmt.Sprintf("Syscall latency anomaly: %s (z=%.1f)", a.SyscallName, a.ZScore),
			Description: fmt.Sprintf(
				"Syscall %s (nr=%d) shows anomalous latency: %dns vs baseline "+
					"mean %.0fns±%.0fns (z=%.2f). May indicate rootkit interception overhead.",
				a.SyscallName, a.SyscallNr, a.LatencyNs, a.MeanNs, a.StdDevNs, a.ZScore),
			Evidence:   ev,
			Confidence: math.Min(0.3+a.ZScore/20.0, 0.85),
			MITRE:      MITREMappings(FindingBehavioral),
		})
	}

	if err := d.detectSuspiciousSequences(ctx, results); err != nil {
		d.log.WithError(err).Debug("sequence detection failed")
	}
	return nil
}

// Remediate implements DetectionModule.
func (d *BehavioralDetector) Remediate(_ context.Context, _ []*Finding, _ bool) ([]string, error) {
	return []string{
		"[INFO] Behavioral anomalies suggest active syscall interception",
		"[MANUAL] Verify: cat /proc/kallsyms | grep sys_call_table",
	}, nil
}

type bpfSyscallStats struct {
	Count, TotalNs, MaxNs, MinNs, LastNs, MeanNs, VarianceNs uint64
}

func (d *BehavioralDetector) readSyscallBaseline() ([]*SyscallLatencyStats, error) {
	m, err := d.loader.GetMap("syscall_baseline")
	if err != nil {
		return nil, fmt.Errorf("getting syscall_baseline map: %w", err)
	}
	var stats []*SyscallLatencyStats
	for nr := 0; nr < 512; nr++ {
		key := uint32(nr)
		var val bpfSyscallStats
		if err := m.Lookup(&key, &val); err != nil {
			if err == ebpf.ErrKeyNotExist {
				continue
			}
			continue
		}
		if val.Count < 100 {
			continue
		}
		name := syscallNames[nr]
		if name == "" {
			name = fmt.Sprintf("syscall_%d", nr)
		}
		stats = append(stats, &SyscallLatencyStats{
			SyscallNr:   nr,
			SyscallName: name,
			Count:       val.Count,
			MeanNs:      float64(val.MeanNs),
			StdDevNs:    math.Sqrt(float64(val.VarianceNs)),
			MaxNs:       val.MaxNs,
			MinNs:       val.MinNs,
		})
	}
	return stats, nil
}

func (d *BehavioralDetector) detectAnomalies(stats []*SyscallLatencyStats) []AnomalyEvent {
	var anomalies []AnomalyEvent
	for _, s := range stats {
		if s.StdDevNs == 0 || s.Count < 100 {
			continue
		}
		z := (float64(s.MaxNs) - s.MeanNs) / s.StdDevNs
		if z > 5.0 {
			anomalies = append(anomalies, AnomalyEvent{
				SyscallNr: s.SyscallNr, SyscallName: s.SyscallName,
				LatencyNs: s.MaxNs, MeanNs: s.MeanNs,
				StdDevNs: s.StdDevNs, ZScore: z, Timestamp: time.Now(),
			})
		}
		if baseline, ok := empiricalBaselines[s.SyscallNr]; ok && s.MeanNs > float64(baseline)*5.0 {
			z2 := s.MeanNs / float64(baseline)
			anomalies = append(anomalies, AnomalyEvent{
				SyscallNr: s.SyscallNr, SyscallName: s.SyscallName,
				LatencyNs: uint64(s.MeanNs), MeanNs: s.MeanNs,
				StdDevNs: s.StdDevNs, ZScore: z2, Timestamp: time.Now(),
			})
		}
	}
	return anomalies
}

func (d *BehavioralDetector) detectSuspiciousSequences(ctx context.Context, results *ScanResults) error {
	m, err := d.loader.GetMap("getdents_count")
	if err != nil {
		return nil
	}
	var pid uint32
	var count uint64
	iter := m.Iterate()
	for iter.Next(&pid, &count) {
		if count > 10*1024*1024 {
			ev, _ := json.Marshal(map[string]interface{}{"pid": pid, "bytes": count})
			results.AddFinding(&Finding{
				Type:  FindingBehavioral, Risk: RiskMedium,
				Title: fmt.Sprintf("Unusual getdents64 volume from PID %d", pid),
				Description: fmt.Sprintf(
					"PID %d read %d bytes via getdents64. May indicate rootkit probing /proc.",
					pid, count),
				Evidence: ev, Confidence: 0.45,
				MITRE:    MITREMappings(FindingBehavioral),
			})
		}
	}
	return nil
}

func riskFromZScore(z float64) RiskLevel {
	switch {
	case z > 10:
		return RiskCritical
	case z > 7:
		return RiskHigh
	case z > 5:
		return RiskMedium
	default:
		return RiskLow
	}
}
