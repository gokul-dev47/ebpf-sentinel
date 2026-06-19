// Package detector - syscall hook detection module.
package detector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gokul-dev47/ebpf-sentinel/pkg/loader"
	"github.com/sirupsen/logrus"
)

var syscallNames = map[int]string{
	0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
	5: "fstat", 9: "mmap", 21: "access", 39: "getpid", 56: "clone",
	57: "fork", 59: "execve", 60: "exit", 62: "kill", 105: "setuid",
	106: "getuid", 157: "prctl", 231: "exit_group", 257: "openat",
}

// KallsymsEntry represents a symbol from /proc/kallsyms.
type KallsymsEntry struct {
	Address uint64
	Type    string
	Name    string
	Module  string
}

// SyscallTableEntry represents a single syscall handler mapping.
type SyscallTableEntry struct {
	SyscallNr    int    `json:"syscall_nr"`
	SyscallName  string `json:"syscall_name"`
	ExpectedSym  string `json:"expected_symbol"`
	ExpectedAddr uint64 `json:"expected_addr"`
	ActualAddr   uint64 `json:"actual_addr"`
	Hooked       bool   `json:"hooked"`
	HookTarget   string `json:"hook_target,omitempty"`
}

// SyscallHookDetector detects patched syscall table entries.
type SyscallHookDetector struct {
	log    *logrus.Logger
	loader *loader.Loader
}

// NewSyscallHookDetector creates a new syscall hook detector.
func NewSyscallHookDetector(log *logrus.Logger, ldr *loader.Loader) *SyscallHookDetector {
	return &SyscallHookDetector{log: log, loader: ldr}
}

// Name returns the module identifier.
func (d *SyscallHookDetector) Name() string { return "SyscallHookDetector" }

// Run executes syscall table integrity checks.
func (d *SyscallHookDetector) Run(ctx context.Context, results *ScanResults) error {
	d.log.Debug("starting syscall hook detection")
	syms, err := d.readKallsyms()
	if err != nil {
		return fmt.Errorf("reading kallsyms: %w", err)
	}
	symByName := make(map[string]*KallsymsEntry, len(syms))
	for i := range syms {
		symByName[syms[i].Name] = &syms[i]
	}
	hooks, err := d.checkSyscallTable(ctx, symByName)
	if err != nil {
		d.log.WithError(err).Warn("syscall table check failed")
	}
	inlineHooks, err := d.detectInlineHooks(symByName)
	if err != nil {
		d.log.WithError(err).Debug("inline hook detection unavailable")
	}
	all := append(hooks, inlineHooks...)
	for _, h := range all {
		if !h.Hooked {
			continue
		}
		ev, _ := json.Marshal(h)
		results.AddFinding(&Finding{
			Type:  FindingSyscallHook,
			Risk:  RiskCritical,
			Title: fmt.Sprintf("Syscall %d (%s) appears hooked", h.SyscallNr, h.SyscallName),
			Description: fmt.Sprintf(
				"Syscall handler at 0x%x resolves to unexpected target 0x%x (%s). "+
					"Strong indicator of syscall table modification by a rootkit.",
				h.ExpectedAddr, h.ActualAddr, h.HookTarget),
			Evidence:    ev,
			Confidence:  0.90,
			Remediation: "Reboot into a known-clean kernel. Investigate loaded kernel modules.",
			MITRE:       MITREMappings(FindingSyscallHook),
		})
	}
	return nil
}

// Remediate implements DetectionModule.
func (d *SyscallHookDetector) Remediate(_ context.Context, _ []*Finding, _ bool) ([]string, error) {
	return []string{
		"[MANUAL] Check 'lsmod' for unfamiliar modules",
		"[MANUAL] Reboot into clean kernel to restore syscall table",
	}, nil
}

func (d *SyscallHookDetector) readKallsyms() ([]KallsymsEntry, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("opening /proc/kallsyms: %w", err)
	}
	defer f.Close()
	var entries []KallsymsEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}
		e := KallsymsEntry{Address: addr, Type: parts[1], Name: parts[2]}
		if len(parts) >= 4 {
			e.Module = strings.Trim(parts[3], "[]")
		}
		entries = append(entries, e)
	}
	return entries, scanner.Err()
}

func (d *SyscallHookDetector) checkSyscallTable(ctx context.Context, symByName map[string]*KallsymsEntry) ([]SyscallTableEntry, error) {
	var entries []SyscallTableEntry
	for nr, name := range syscallNames {
		if err := ctx.Err(); err != nil {
			return entries, err
		}
		expectedSym := "__x64_sys_" + name
		sym := symByName[expectedSym]
		if sym == nil {
			expectedSym = "sys_" + name
			sym = symByName[expectedSym]
		}
		if sym == nil {
			continue
		}
		entry := SyscallTableEntry{
			SyscallNr: nr, SyscallName: name,
			ExpectedSym: expectedSym, ExpectedAddr: sym.Address, ActualAddr: sym.Address,
		}
		if sym.Module != "" {
			entry.Hooked = true
			entry.HookTarget = fmt.Sprintf("module:%s", sym.Module)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (d *SyscallHookDetector) detectInlineHooks(symByName map[string]*KallsymsEntry) ([]SyscallTableEntry, error) {
	f, err := os.Open("/proc/kcore")
	if err != nil {
		d.log.Debug("/proc/kcore not accessible, skipping inline hook detection")
		return nil, nil
	}
	defer f.Close()
	criticals := []string{
		"__x64_sys_kill", "__x64_sys_getdents64", "__x64_sys_read",
		"__x64_sys_write", "__x64_sys_openat", "__x64_sys_execve",
	}
	var entries []SyscallTableEntry
	for _, symName := range criticals {
		sym := symByName[symName]
		if sym == nil || sym.Address == 0 {
			continue
		}
		buf, err := readKcoreVA(f, sym.Address, 16)
		if err != nil {
			continue
		}
		entry := SyscallTableEntry{SyscallName: symName, ExpectedSym: symName,
			ExpectedAddr: sym.Address, ActualAddr: sym.Address}
		if len(buf) >= 5 && buf[0] == 0xE9 {
			rel := int32(buf[1]) | int32(buf[2])<<8 | int32(buf[3])<<16 | int32(buf[4])<<24
			target := sym.Address + 5 + uint64(rel)
			entry.Hooked = true
			entry.ActualAddr = target
			entry.HookTarget = fmt.Sprintf("jmp->0x%x", target)
		}
		if len(buf) >= 12 && buf[0] == 0x48 && buf[1] == 0xB8 {
			target := uint64(buf[2]) | uint64(buf[3])<<8 | uint64(buf[4])<<16 |
				uint64(buf[5])<<24 | uint64(buf[6])<<32 | uint64(buf[7])<<40 |
				uint64(buf[8])<<48 | uint64(buf[9])<<56
			if buf[10] == 0xFF && buf[11] == 0xE0 {
				entry.Hooked = true
				entry.ActualAddr = target
				entry.HookTarget = fmt.Sprintf("movabs+jmp->0x%x", target)
			}
		}
		if entry.Hooked {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func readKcoreVA(f *os.File, va uint64, n int) ([]byte, error) {
	ident := make([]byte, 64)
	if _, err := f.ReadAt(ident, 0); err != nil {
		return nil, err
	}
	if string(ident[1:4]) != "ELF" {
		return nil, fmt.Errorf("not ELF")
	}
	phoff := readLE64(ident, 32)
	phentsize := readLE16(ident, 54)
	phnum := readLE16(ident, 56)
	phdr := make([]byte, phentsize)
	for i := uint16(0); i < phnum; i++ {
		if _, err := f.ReadAt(phdr, int64(phoff)+int64(i)*int64(phentsize)); err != nil {
			continue
		}
		if readLE32(phdr, 0) != 1 {
			continue
		}
		pVaddr := readLE64(phdr, 16)
		pFilesz := readLE64(phdr, 32)
		pOffset := readLE64(phdr, 8)
		if va >= pVaddr && va+uint64(n) <= pVaddr+pFilesz {
			buf := make([]byte, n)
			if _, err := f.ReadAt(buf, int64(pOffset)+int64(va-pVaddr)); err != nil {
				return nil, err
			}
			return buf, nil
		}
	}
	return nil, fmt.Errorf("VA 0x%x not found in kcore", va)
}

func readLE64(b []byte, off int) uint64 {
	return uint64(b[off]) | uint64(b[off+1])<<8 | uint64(b[off+2])<<16 |
		uint64(b[off+3])<<24 | uint64(b[off+4])<<32 | uint64(b[off+5])<<40 |
		uint64(b[off+6])<<48 | uint64(b[off+7])<<56
}
func readLE32(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}
func readLE16(b []byte, off int) uint16 {
	return uint16(b[off]) | uint16(b[off+1])<<8
}
