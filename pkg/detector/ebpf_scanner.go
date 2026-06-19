// Package detector - eBPF program audit scanner.
package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// BPFProgInfo holds metadata about a loaded BPF program.
type BPFProgInfo struct {
	ID       uint32    `json:"id"`
	Type     uint32    `json:"type"`
	TypeName string    `json:"type_name"`
	Name     string    `json:"name"`
	Tag      string    `json:"tag"`
	LoadedAt time.Time `json:"loaded_at"`
	UID      uint32    `json:"uid"`
}

type bpftoolProg struct {
	ID       uint32   `json:"id"`
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	Tag      string   `json:"tag"`
	LoadedAt int64    `json:"loaded_at"`
	UID      uint32   `json:"uid"`
	MapIDs   []uint32 `json:"map_ids,omitempty"`
}

var suspiciousTypes = []struct{ name, reason string }{
	{"kprobe", "Can intercept arbitrary kernel functions"},
	{"raw_tracepoint", "Access to all syscall arguments"},
	{"lsm", "Intercepts security-critical kernel operations"},
	{"kretprobe", "Can observe and modify syscall return values"},
}

var knownBenign = map[string]string{
	"sentinel":          "eBPF Sentinel (self)",
	"cilium":            "Cilium CNI",
	"falco":             "Falco security",
	"tetragon":          "Tetragon",
	"handle_sched_pr":   "WSL2 kernel scheduler",
	"handle_sched_fo":   "WSL2 kernel scheduler",
	"kprobe__oom_kil":   "WSL2 OOM killer monitor",
	"kprobe__":          "WSL2 kernel probe",
	"tracepoint__":      "WSL2 kernel tracepoint",
	"raw_tracepoint__":  "WSL2 raw tracepoint",
	"perf_event":        "WSL2 perf event",
	"hv_":               "Hyper-V driver",
}

// EBPFScanner enumerates and audits loaded BPF programs.
type EBPFScanner struct{ log *logrus.Logger }

// NewEBPFScanner creates a new eBPF program scanner.
func NewEBPFScanner(log *logrus.Logger) *EBPFScanner { return &EBPFScanner{log: log} }

// Name returns the module identifier.
func (s *EBPFScanner) Name() string { return "EBPFScanner" }

// Run enumerates BPF programs and flags suspicious ones.
func (s *EBPFScanner) Run(ctx context.Context, results *ScanResults) error {
	s.log.Debug("starting BPF program audit")
	progs, err := s.enumerateViaSyscall(ctx)
	if err != nil {
		progs, err = s.enumerateViaBpftool(ctx)
		if err != nil {
			return fmt.Errorf("BPF program enumeration failed: %w", err)
		}
	}
	s.log.Debugf("found %d BPF programs", len(progs))
	for _, prog := range progs {
		risk, reason := s.assessProgram(&prog)
		if risk == RiskNone {
			continue
		}
		ev, _ := json.Marshal(prog)
		results.AddFinding(&Finding{
			Type:  FindingSuspiciousBPF,
			Risk:  risk,
			Title: fmt.Sprintf("Suspicious BPF program: %q (ID=%d, type=%s)", prog.Name, prog.ID, prog.TypeName),
			Description: fmt.Sprintf("BPF program ID=%d name=%q type=%s tag=%s loaded by UID=%d. Reason: %s",
				prog.ID, prog.Name, prog.TypeName, prog.Tag, prog.UID, reason),
			Evidence: ev, Confidence: riskToConfidence(risk),
			Remediation: fmt.Sprintf("bpftool prog dump id %d. Unload if malicious.", prog.ID),
			MITRE:       MITREMappings(FindingSuspiciousBPF),
		})
	}
	return nil
}

// Remediate implements DetectionModule.
func (s *EBPFScanner) Remediate(_ context.Context, findings []*Finding, _ bool) ([]string, error) {
	var actions []string
	for _, f := range findings {
		var ev BPFProgInfo
		if err := json.Unmarshal(f.Evidence, &ev); err != nil {
			continue
		}
		actions = append(actions, fmt.Sprintf("bpftool prog detach id %d (suspicious)", ev.ID))
	}
	return actions, nil
}

func (s *EBPFScanner) enumerateViaSyscall(ctx context.Context) ([]BPFProgInfo, error) {
	var progs []BPFProgInfo
	var id uint32
	for {
		if ctx.Err() != nil {
			return progs, nil
		}
		nextID, err := bpfProgGetNextID(id)
		if err != nil {
			break
		}
		id = nextID
		info, err := bpfProgGetInfoByFD(id)
		if err != nil {
			continue
		}
		progs = append(progs, *info)
	}
	return progs, nil
}

func (s *EBPFScanner) enumerateViaBpftool(ctx context.Context) ([]BPFProgInfo, error) {
	out, err := exec.CommandContext(ctx, "bpftool", "prog", "list", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("bpftool failed: %w", err)
	}
	var raw []bpftoolProg
	if err := json.NewDecoder(bytes.NewReader(out)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("parsing bpftool output: %w", err)
	}
	progs := make([]BPFProgInfo, 0, len(raw))
	for _, r := range raw {
		info := BPFProgInfo{ID: r.ID, TypeName: r.Type, Name: r.Name, Tag: r.Tag, UID: r.UID}
		if r.LoadedAt > 0 {
			info.LoadedAt = time.Unix(r.LoadedAt, 0)
		}
		progs = append(progs, info)
	}
	return progs, nil
}

func (s *EBPFScanner) assessProgram(prog *BPFProgInfo) (RiskLevel, string) {
	for prefix, tool := range knownBenign {
		if strings.Contains(strings.ToLower(prog.Name), prefix) {
			s.log.Debugf("program %q matched benign pattern (%s)", prog.Name, tool)
			return RiskNone, ""
		}
	}
	if prog.Name == "" && prog.UID != 0 {
		return RiskHigh, "anonymous BPF program loaded by non-root"
	}
	for _, p := range suspiciousTypes {
		if strings.EqualFold(prog.TypeName, p.name) {
			if prog.UID != 0 {
				return RiskHigh, fmt.Sprintf("non-root UID %d loaded %s program: %s", prog.UID, prog.TypeName, p.reason)
			}
			if isMaliciousName(prog.Name) {
				return RiskHigh, fmt.Sprintf("name matches malicious pattern: %s", prog.Name)
			}
			return RiskMedium, p.reason
		}
	}
	if looksObfuscated(prog.Name) {
		return RiskMedium, "program name appears obfuscated"
	}
	return RiskNone, ""
}

func isMaliciousName(name string) bool {
	for _, p := range []string{"hide", "rootkit", "rkit", "backdoor", "diamorphine", "reptile"} {
		if strings.Contains(strings.ToLower(name), p) {
			return true
		}
	}
	return false
}

func looksObfuscated(name string) bool {
	if len(name) < 8 {
		return false
	}
	for _, c := range name {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func riskToConfidence(r RiskLevel) float64 {
	switch r {
	case RiskCritical:
		return 0.95
	case RiskHigh:
		return 0.80
	case RiskMedium:
		return 0.60
	default:
		return 0.40
	}
}

// BPF syscall wrappers
func bpfProgGetNextID(startID uint32) (uint32, error) {
	type attr struct{ StartID, NextID, OpenFlags uint32 }
	a := attr{StartID: startID}
	_, _, errno := unix.Syscall(unix.SYS_BPF, 11,
		uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
	if errno != 0 {
		return 0, errno
	}
	return a.NextID, nil
}

func bpfProgGetInfoByFD(progID uint32) (*BPFProgInfo, error) {
	type getFDAttr struct{ ID, NextID, OpenFlags uint32 }
	fa := getFDAttr{ID: progID}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, 13,
		uintptr(unsafe.Pointer(&fa)), unsafe.Sizeof(fa))
	if errno != 0 {
		return nil, errno
	}
	defer unix.Close(int(fd))

	type kernelInfo struct {
		ProgType, ID    uint32
		Tag             [8]byte
		JitedLen        uint32
		XlatedLen       uint32
		JitedInsns      uint64
		XlatedInsns     uint64
		LoadTime        uint64
		CreatedByUID    uint32
		NrMapIDs        uint32
		MapIDs          uint64
		Name            [16]byte
		IfIndex         uint32
		NetnsIno        uint64
		NrJitedKsyms    uint32
		NrJitedFuncLens uint32
	}
	type infoAttr struct {
		BpfFD, InfoLen uint32
		Info           uint64
	}
	ki := &kernelInfo{}
	ia := infoAttr{
		BpfFD:   uint32(fd),
		InfoLen: uint32(unsafe.Sizeof(*ki)),
		Info:    uint64(uintptr(unsafe.Pointer(ki))),
	}
	_, _, errno = unix.Syscall(unix.SYS_BPF, 15,
		uintptr(unsafe.Pointer(&ia)), unsafe.Sizeof(ia))
	if errno != 0 {
		return nil, errno
	}
	name := strings.TrimRight(string(ki.Name[:]), "\x00")
	info := &BPFProgInfo{
		ID: ki.ID, Type: ki.ProgType,
		TypeName: bpfTypeName(ki.ProgType),
		Name: name, Tag: fmt.Sprintf("%x", ki.Tag), UID: ki.CreatedByUID,
	}
	if ki.LoadTime > 0 {
		info.LoadedAt = time.Unix(int64(ki.LoadTime/1e9), int64(ki.LoadTime%1e9))
	}
	return info, nil
}

func bpfTypeName(t uint32) string {
	names := map[uint32]string{
		1: "socket_filter", 2: "kprobe", 3: "sched_cls", 5: "tracepoint",
		6: "xdp", 7: "perf_event", 13: "sock_ops", 17: "raw_tracepoint",
		26: "tracing", 29: "lsm", 30: "sk_lookup",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return strconv.Itoa(int(t))
}
