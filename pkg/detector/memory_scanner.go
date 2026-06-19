// Package detector - kernel memory scanner module.
package detector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// ModuleInfo represents a loaded kernel module.
type ModuleInfo struct {
	Name     string   `json:"name"`
	Size     int64    `json:"size"`
	RefCount int      `json:"ref_count"`
	UsedBy   []string `json:"used_by"`
	State    string   `json:"state"`
}

var knownRootkitSignatures = []struct {
	Name    string
	Pattern []byte
}{
	{Name: "Diamorphine", Pattern: []byte("diamorphine")},
	{Name: "Reptile", Pattern: []byte("reptile_hide")},
	{Name: "beurk", Pattern: []byte("beurk_module")},
	{Name: "Azazel", Pattern: []byte("azazel_so")},
}

// builtinModules lists modules that appear in kallsyms but not /proc/modules
// on certain kernels (WSL2, some embedded kernels). These are NOT rootkits.
var builtinModules = map[string]bool{
	"bpf":               true,
	"__builtin__ftrace": true,
	"pci_stub":          true,
	"virtio":            true,
	"9p":                true,
	"hv_vmbus":          true,
	"hv_storvsc":        true,
	"hv_netvsc":         true,
	"hv_utils":          true,
	"hyperv_keyboard":   true,
	"dxgkrnl":           true,
}

// MemoryScanner checks kernel memory for rootkit indicators.
type MemoryScanner struct{ log *logrus.Logger }

// NewMemoryScanner creates a new memory scanner.
func NewMemoryScanner(log *logrus.Logger) *MemoryScanner { return &MemoryScanner{log: log} }

// Name returns the module identifier.
func (s *MemoryScanner) Name() string { return "MemoryScanner" }

// Run performs all memory-based rootkit checks.
func (s *MemoryScanner) Run(ctx context.Context, results *ScanResults) error {
	s.log.Debug("starting memory scanner")
	if err := s.checkModuleConsistency(ctx, results); err != nil {
		s.log.WithError(err).Warn("module consistency check failed")
	}
	if err := s.checkSysFSModules(ctx, results); err != nil {
		s.log.WithError(err).Warn("sysfs module check failed")
	}
	if err := s.scanKcoreSignatures(ctx, results); err != nil {
		s.log.WithError(err).Debug("kcore scan unavailable (needs CAP_SYS_RAWIO)")
	}
	return nil
}

// Remediate implements DetectionModule.
func (s *MemoryScanner) Remediate(_ context.Context, findings []*Finding, dryRun bool) ([]string, error) {
	var actions []string
	for _, f := range findings {
		if f.Type != FindingHiddenModule {
			continue
		}
		var ev map[string]interface{}
		if err := json.Unmarshal(f.Evidence, &ev); err != nil {
			continue
		}
		if name, ok := ev["module_name"].(string); ok {
			actions = append(actions, fmt.Sprintf("rmmod %s (suspicious/hidden module)", name))
			if !dryRun {
				s.log.Warnf("rmmod %s - manual intervention required", name)
			}
		}
	}
	return actions, nil
}

func (s *MemoryScanner) checkModuleConsistency(ctx context.Context, results *ScanResults) error {
	procMods, err := s.readProcModules()
	if err != nil {
		return fmt.Errorf("reading /proc/modules: %w", err)
	}
	kallsymsMods, err := s.readKallsymsModules()
	if err != nil {
		return fmt.Errorf("reading kallsyms modules: %w", err)
	}
	for modName := range kallsymsMods {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Skip known built-in modules (WSL2, embedded kernels)
		if builtinModules[modName] {
			s.log.Debugf("skipping known builtin module: %s", modName)
			continue
		}
		if _, exists := procMods[modName]; !exists {
			ev, _ := json.Marshal(map[string]interface{}{
				"module_name":     modName,
				"in_kallsyms":     true,
				"in_proc_modules": false,
			})
			results.AddFinding(&Finding{
				Type:  FindingHiddenModule, Risk: RiskCritical,
				Title: fmt.Sprintf("Hidden kernel module: %s", modName),
				Description: fmt.Sprintf(
					"Module %q has symbols in /proc/kallsyms but is absent from /proc/modules. "+
						"Strong indicator of a module hiding itself from userspace.",
					modName),
				Evidence: ev, Confidence: 0.90,
				Remediation: fmt.Sprintf("rmmod %s. If protected: reboot.", modName),
				MITRE:       MITREMappings(FindingHiddenModule),
			})
		}
	}
	return nil
}

func (s *MemoryScanner) checkSysFSModules(ctx context.Context, results *ScanResults) error {
	procMods, err := s.readProcModules()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir("/sys/module")
	if err != nil {
		return fmt.Errorf("reading /sys/module: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || ctx.Err() != nil {
			continue
		}
		modName := entry.Name()
		if builtinModules[modName] {
			continue
		}
		normalized := strings.ReplaceAll(modName, "-", "_")
		if _, exists := procMods[normalized]; exists {
			continue
		}
		taintPath := fmt.Sprintf("/sys/module/%s/taint", modName)
		if _, err := os.Stat(taintPath); err == nil {
			ev, _ := json.Marshal(map[string]interface{}{
				"module_name":     modName,
				"in_sysfs":        true,
				"in_proc_modules": false,
			})
			results.AddFinding(&Finding{
				Type:  FindingHiddenModule, Risk: RiskHigh,
				Title: fmt.Sprintf("OOT module hidden from /proc/modules: %s", modName),
				Description: fmt.Sprintf(
					"Module %q in /sys/module with taint file but not in /proc/modules.", modName),
				Evidence: ev, Confidence: 0.75,
				Remediation: fmt.Sprintf("Investigate: cat /sys/module/%s/taint", modName),
				MITRE:       MITREMappings(FindingHiddenModule),
			})
		}
	}
	return nil
}

func (s *MemoryScanner) scanKcoreSignatures(ctx context.Context, results *ScanResults) error {
	f, err := os.Open("/proc/kcore")
	if err != nil {
		return fmt.Errorf("opening /proc/kcore: %w", err)
	}
	defer f.Close()

	ident := make([]byte, 64)
	if _, err := f.ReadAt(ident, 0); err != nil {
		return err
	}
	if string(ident[1:4]) != "ELF" {
		return fmt.Errorf("not ELF")
	}

	phoff := readLE64(ident, 32)
	phentsize := readLE16(ident, 54)
	phnum := readLE16(ident, 56)

	const pageSize = 4096
	buf := make([]byte, pageSize)
	phdr := make([]byte, phentsize)

	for i := uint16(0); i < phnum; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := f.ReadAt(phdr, int64(phoff)+int64(i)*int64(phentsize)); err != nil {
			continue
		}
		if readLE32(phdr, 0) != 1 {
			continue
		}
		pOffset := readLE64(phdr, 8)
		pFilesz := readLE64(phdr, 32)

		var pageOff uint64
		for pageOff < pFilesz {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			sz := pageSize
			if pageOff+uint64(sz) > pFilesz {
				sz = int(pFilesz - pageOff)
			}
			n, err := f.ReadAt(buf[:sz], int64(pOffset+pageOff))
			if err != nil || n == 0 {
				break
			}
			for _, sig := range knownRootkitSignatures {
				if idx := bytesIndex(buf[:n], sig.Pattern); idx >= 0 {
					vaddr := readLE64(phdr, 16) + pageOff + uint64(idx)
					ev, _ := json.Marshal(map[string]interface{}{
						"signature":       sig.Name,
						"virtual_address": fmt.Sprintf("0x%x", vaddr),
					})
					results.AddFinding(&Finding{
						Type:  FindingMemoryPatch, Risk: RiskCritical,
						Title: fmt.Sprintf("Rootkit signature in kernel memory: %s", sig.Name),
						Description: fmt.Sprintf(
							"Found %s signature at kernel VA 0x%x.", sig.Name, vaddr),
						Evidence: ev, Confidence: 0.85,
						MITRE:    MITREMappings(FindingMemoryPatch),
					})
				}
			}
			pageOff += uint64(n)
		}
	}
	return nil
}

func (s *MemoryScanner) readProcModules() (map[string]*ModuleInfo, error) {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	mods := make(map[string]*ModuleInfo)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 1 {
			continue
		}
		mods[parts[0]] = &ModuleInfo{Name: parts[0], State: "live"}
	}
	return mods, scanner.Err()
}

func (s *MemoryScanner) readKallsymsModules() (map[string]bool, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	mods := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 4 {
			continue
		}
		mod := strings.Trim(parts[3], "[]")
		if mod != "" {
			mods[mod] = true
		}
	}
	return mods, scanner.Err()
}

func bytesIndex(haystack, needle []byte) int {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		found := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				found = false
				break
			}
		}
		if found {
			return i
		}
	}
	return -1
}
