// Package detector implements the core detection engine.
package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/gokul-dev47/ebpf-sentinel/pkg/loader"
	sentinelmetrics "github.com/gokul-dev47/ebpf-sentinel/pkg/prometheus"
	"github.com/gokul-dev47/ebpf-sentinel/pkg/storage"
	"github.com/sirupsen/logrus"
)

// RiskLevel represents the severity of detected threats.
type RiskLevel string

const (
	RiskNone     RiskLevel = "NONE"
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// Finding represents a single detected threat or anomaly.
type Finding struct {
	Type        FindingType      `json:"type"`
	Risk        RiskLevel        `json:"risk"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Evidence    json.RawMessage  `json:"evidence,omitempty"`
	MITRE       []MITRETechnique `json:"mitre,omitempty"`
	Timestamp   time.Time        `json:"timestamp"`
	Remediation string           `json:"remediation,omitempty"`
	Confidence  float64          `json:"confidence"`
}

// ScanResults aggregates all findings from a single scan run.
type ScanResults struct {
	ScanID    string        `json:"scan_id"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration_ns"`
	RiskLevel RiskLevel     `json:"risk_level"`
	Findings  []*Finding    `json:"findings"`
	Hostname  string        `json:"hostname"`
	Kernel    string        `json:"kernel"`
	mu        sync.Mutex
}

// AddFinding appends a finding thread-safely.
func (r *ScanResults) AddFinding(f *Finding) {
	f.Timestamp = time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Findings = append(r.Findings, f)
	r.updateRiskLevel(f.Risk)
}

// HasThreats returns true if any findings were recorded.
func (r *ScanResults) HasThreats() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Findings) > 0
}

// MarshalJSON serializes ScanResults to JSON.
func (r *ScanResults) MarshalJSON() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	type Alias ScanResults
	return json.Marshal((*Alias)(r))
}

// GetFindings returns a copy of the findings slice.
func (r *ScanResults) GetFindings() []*Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Finding, len(r.Findings))
	copy(out, r.Findings)
	return out
}

func (r *ScanResults) updateRiskLevel(f RiskLevel) {
	order := map[RiskLevel]int{
		RiskNone: 0, RiskLow: 1, RiskMedium: 2, RiskHigh: 3, RiskCritical: 4,
	}
	if order[f] > order[r.RiskLevel] {
		r.RiskLevel = f
	}
}

// EngineConfig holds configuration for the detection engine.
type EngineConfig struct {
	Loader  *loader.Loader
	Store   *storage.PostgresStore
	Logger  *logrus.Logger
	Metrics *sentinelmetrics.Metrics
	Checks  []string
	JSONOut bool
}

// DetectionModule is the interface all detector implementations satisfy.
type DetectionModule interface {
	Name() string
	Run(ctx context.Context, results *ScanResults) error
	Remediate(ctx context.Context, findings []*Finding, dryRun bool) ([]string, error)
}

// Engine orchestrates all detection modules in parallel.
type Engine struct {
	cfg     EngineConfig
	log     *logrus.Logger
	modules []DetectionModule
}

// NewEngine creates a new Engine with all modules registered.
func NewEngine(cfg EngineConfig) *Engine {
	e := &Engine{cfg: cfg, log: cfg.Logger}
	e.registerModules()
	return e
}

func (e *Engine) registerModules() {
	all := []DetectionModule{
		NewSyscallHookDetector(e.log, e.cfg.Loader),
		NewHiddenProcessDetector(e.log, e.cfg.Loader),
		NewEBPFScanner(e.log),
		NewMemoryScanner(e.log),
		NewBehavioralDetector(e.log, e.cfg.Loader),
	}
	checkSet := make(map[string]bool)
	for _, c := range e.cfg.Checks {
		checkSet[c] = true
	}
	if checkSet["all"] {
		e.modules = all
		return
	}
	checkMap := map[string]string{
		"syscall": "SyscallHookDetector", "process": "HiddenProcessDetector",
		"ebpf": "EBPFScanner", "memory": "MemoryScanner", "behavioral": "BehavioralDetector",
	}
	for _, mod := range all {
		for k, n := range checkMap {
			if checkSet[k] && mod.Name() == n {
				e.modules = append(e.modules, mod)
			}
		}
	}
}

// Scan runs all detection modules in parallel.
func (e *Engine) Scan(ctx context.Context) (*ScanResults, error) {
	hostname, _ := os.Hostname()
	status, _ := e.cfg.Loader.Status(ctx)
	results := &ScanResults{
		ScanID:    fmt.Sprintf("%d", time.Now().UnixNano()%100000000),
		StartTime: time.Now(),
		RiskLevel: RiskNone,
		Hostname:  hostname,
	}
	if status != nil {
		results.Kernel = status.Kernel
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(e.modules))
	for _, mod := range e.modules {
		mod := mod
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := mod.Run(ctx, results); err != nil {
				e.log.WithError(err).WithField("module", mod.Name()).Warn("module error")
				errCh <- fmt.Errorf("%s: %w", mod.Name(), err)
			}
		}()
	}
	wg.Wait()
	close(errCh)

	results.EndTime = time.Now()
	results.Duration = results.EndTime.Sub(results.StartTime)

	if e.cfg.Store != nil {
		if err := e.cfg.Store.SaveScanResults(ctx, results); err != nil {
			e.log.WithError(err).Warn("failed to persist results")
		}
	}
	if e.cfg.Metrics != nil {
		e.cfg.Metrics.RecordScan(results.Duration, results)
	}

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	if len(errs) > 0 && len(errs) == len(e.modules) {
		return results, fmt.Errorf("all modules failed: %w", errs[0])
	}
	return results, nil
}

// GetStatus returns current loader status.
func (e *Engine) GetStatus(ctx context.Context) (*loader.Status, error) {
	return e.cfg.Loader.Status(ctx)
}

// Remediate applies fixes for detected threats.
func (e *Engine) Remediate(ctx context.Context, results *ScanResults, dryRun bool) error {
	findings := results.GetFindings()
	var allActions []string
	for _, mod := range e.modules {
		var mf []*Finding
		for _, f := range findings {
			if moduleOwns(mod, f) {
				mf = append(mf, f)
			}
		}
		if len(mf) == 0 {
			continue
		}
		taken, err := mod.Remediate(ctx, mf, dryRun)
		if err != nil {
			e.log.WithError(err).Warnf("remediation error in %s", mod.Name())
		}
		allActions = append(allActions, taken...)
	}
	prefix := ""
	if dryRun {
		prefix = "[DRY RUN] "
	}
	fmt.Printf("\n\033[36m╔══════════════════════════════════════╗\033[0m\n")
	fmt.Printf("\033[36m║       REMEDIATION ACTIONS             ║\033[0m\n")
	fmt.Printf("\033[36m╚══════════════════════════════════════╝\033[0m\n")
	for _, a := range allActions {
		fmt.Printf("  %s→ %s\n", prefix, a)
	}
	if len(allActions) == 0 {
		fmt.Println("  No automated remediations available. Manual investigation required.")
	}
	return nil
}

func moduleOwns(mod DetectionModule, f *Finding) bool {
	switch mod.Name() {
	case "SyscallHookDetector":
		return f.Type == FindingSyscallHook
	case "HiddenProcessDetector":
		return f.Type == FindingHiddenProcess
	case "EBPFScanner":
		return f.Type == FindingSuspiciousBPF
	case "MemoryScanner":
		return f.Type == FindingMemoryPatch || f.Type == FindingHiddenModule
	case "BehavioralDetector":
		return f.Type == FindingBehavioral
	}
	return false
}

// Renderer handles output formatting.
type Renderer struct{ jsonMode bool }

// NewRenderer creates a new result renderer.
func NewRenderer(jsonMode bool) *Renderer { return &Renderer{jsonMode: jsonMode} }

// Render writes scan results to w.
func (r *Renderer) Render(results *ScanResults, w io.Writer) error {
	if r.jsonMode {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "\033[36m╔══════════════════════════════════════════════════════╗\033[0m\n")
	fmt.Fprintf(w, "\033[36m║          eBPF SENTINEL SCAN RESULTS                  ║\033[0m\n")
	fmt.Fprintf(w, "\033[36m╠══════════════════════════════════════════════════════╣\033[0m\n")
	fmt.Fprintf(w, "\033[36m║\033[0m  Scan ID:  %-41s \033[36m║\033[0m\n", results.ScanID)
	fmt.Fprintf(w, "\033[36m║\033[0m  Host:     %-41s \033[36m║\033[0m\n", results.Hostname)
	fmt.Fprintf(w, "\033[36m║\033[0m  Duration: %-41s \033[36m║\033[0m\n", fmt.Sprintf("%.2fs", results.Duration.Seconds()))
	fmt.Fprintf(w, "\033[36m║\033[0m  Findings: %-41d \033[36m║\033[0m\n", len(results.Findings))
	fmt.Fprintf(w, "\033[36m╚══════════════════════════════════════════════════════╝\033[0m\n")
	if !results.HasThreats() {
		fmt.Fprintf(w, "\n\033[32m╔══════════════════════════════════════════════════════╗\033[0m\n")
		fmt.Fprintf(w, "\033[32m║  ✅  SYSTEM CLEAN - No rootkit indicators detected   ║\033[0m\n")
		fmt.Fprintf(w, "\033[32m╚══════════════════════════════════════════════════════╝\033[0m\n\n")
		return nil
	}
	rc := riskColor(results.RiskLevel)
	fmt.Fprintf(w, "\n%s╔══════════════════════════════════════════════════════╗\033[0m\n", rc)
	fmt.Fprintf(w, "%s║  🔴  ROOTKIT INDICATORS DETECTED  RISK: %-11s ║\033[0m\n", rc, string(results.RiskLevel))
	fmt.Fprintf(w, "%s╚══════════════════════════════════════════════════════╝\033[0m\n\n", rc)
	for i, f := range results.Findings {
		fc := riskColor(f.Risk)
		fmt.Fprintf(w, "%s┌─ Finding #%d: %s\033[0m\n", fc, i+1, f.Title)
		fmt.Fprintf(w, "%s│  Type:        %s\033[0m\n", fc, string(f.Type))
		fmt.Fprintf(w, "%s│  Risk:        %s\033[0m\n", fc, string(f.Risk))
		fmt.Fprintf(w, "%s│  Confidence:  %.0f%%\033[0m\n", fc, f.Confidence*100)
		fmt.Fprintf(w, "%s│  Description: %s\033[0m\n", fc, f.Description)
		if len(f.MITRE) > 0 {
			fmt.Fprintf(w, "%s│  MITRE ATT&CK:\033[0m\n", fc)
			for _, m := range f.MITRE {
				fmt.Fprintf(w, "%s│    %-12s %s\033[0m\n", fc, m.TechniqueID, m.Name)
			}
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "%s│  Remediation: %s\033[0m\n", fc, f.Remediation)
		}
		fmt.Fprintf(w, "%s└──────────────────────────────────────────────────────\033[0m\n\n", fc)
	}
	return nil
}

// RenderStatus writes loader status to w.
func (r *Renderer) RenderStatus(status *loader.Status, w io.Writer) error {
	if r.jsonMode {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(status)
	}
	fmt.Fprintf(w, "\033[36m╔══════════════════════════════════════╗\033[0m\n")
	fmt.Fprintf(w, "\033[36m║         SENTINEL STATUS               ║\033[0m\n")
	fmt.Fprintf(w, "\033[36m╠══════════════════════════════════════╣\033[0m\n")
	fmt.Fprintf(w, "\033[36m║\033[0m  Kernel:   %-27s \033[36m║\033[0m\n", truncate(status.Kernel, 26))
	fmt.Fprintf(w, "\033[36m║\033[0m  Arch:     %-27s \033[36m║\033[0m\n", status.Arch)
	fmt.Fprintf(w, "\033[36m║\033[0m  Programs: %-27d \033[36m║\033[0m\n", len(status.Programs))
	fmt.Fprintf(w, "\033[36m║\033[0m  Maps:     %-27d \033[36m║\033[0m\n", len(status.Maps))
	fmt.Fprintf(w, "\033[36m╚══════════════════════════════════════╝\033[0m\n\n")
	for _, p := range status.Programs {
		fmt.Fprintf(w, "  \033[32m✓\033[0m %-30s type=%s\n", p.Name, p.Type)
	}
	return nil
}

// RenderHistory writes stored scan history to w.
func (r *Renderer) RenderHistory(scans []*storage.ScanRecord, w io.Writer) error {
	if r.jsonMode {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(scans)
	}
	fmt.Fprintf(w, "\033[36m╔══════════╦════════════════╦═══════════╦═══════════╦══════════╗\033[0m\n")
	fmt.Fprintf(w, "\033[36m║ SCAN ID  ║ TIMESTAMP      ║ DURATION  ║ FINDINGS  ║ RISK     ║\033[0m\n")
	fmt.Fprintf(w, "\033[36m╠══════════╬════════════════╬═══════════╬═══════════╬══════════╣\033[0m\n")
	for _, s := range scans {
		rc := riskColor(RiskLevel(s.RiskLevel))
		fmt.Fprintf(w, "\033[36m║\033[0m %-8s \033[36m║\033[0m %-14s \033[36m║\033[0m %-9s \033[36m║\033[0m %-9d \033[36m║\033[0m %s%-8s\033[0m \033[36m║\033[0m\n",
			truncate(s.ScanID, 8), s.StartTime.Format("01-02 15:04:05"),
			fmt.Sprintf("%.1fs", s.Duration.Seconds()), s.FindingCount, rc, s.RiskLevel)
	}
	fmt.Fprintf(w, "\033[36m╚══════════╩════════════════╩═══════════╩═══════════╩══════════╝\033[0m\n")
	return nil
}

func riskColor(r RiskLevel) string {
	switch r {
	case RiskCritical:
		return "\033[31m"
	case RiskHigh, RiskMedium:
		return "\033[33m"
	case RiskLow:
		return "\033[36m"
	default:
		return "\033[32m"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
