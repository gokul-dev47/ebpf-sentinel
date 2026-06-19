// Package loader handles loading and attaching BPF programs.
package loader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
)

const (
	BPFPinPath = "/sys/fs/bpf/sentinel"
	BPFObjPath = "/usr/lib/sentinel/bpf"
)

// LoadedProgram represents a successfully loaded and attached BPF program.
type LoadedProgram struct {
	Name string
	Type ebpf.ProgramType
	Tag  string
	Link link.Link
}

// MapStatus represents a loaded BPF map's metadata.
type MapStatus struct {
	Name    string
	Type    ebpf.MapType
	Entries uint32
}

// Status holds the current state of all loaded programs and maps.
type Status struct {
	Programs []LoadedProgram
	Maps     []MapStatus
	Kernel   string
	Arch     string
}

// Loader manages the BPF object lifecycle.
type Loader struct {
	log      *logrus.Logger
	objs     map[string]*ebpf.Collection
	links    []link.Link
	programs []*LoadedProgram
	bpfAvail bool
}

// New creates a new Loader. Gracefully handles environments without BPF support.
func New(log *logrus.Logger) (*Loader, error) {
	// Try to remove memlock rlimit but don't fail if we can't
	if err := rlimit.RemoveMemlock(); err != nil {
		log.WithError(err).Debug("could not remove memlock rlimit (BPF may be limited)")
	}
	return &Loader{
		log:  log,
		objs: make(map[string]*ebpf.Collection),
	}, nil
}

// Load discovers and loads BPF object files. Gracefully skips if unavailable.
func (l *Loader) Load(ctx context.Context) error {
	objPath := BPFObjPath
	if p := os.Getenv("SENTINEL_BPF_PATH"); p != "" {
		objPath = p
	}

	// Check BTF availability
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		l.log.Warn("BTF not available (/sys/kernel/btf/vmlinux missing) - running in Go-only mode")
		l.bpfAvail = false
		return nil
	}

	// Find BPF object files
	files, err := filepath.Glob(filepath.Join(objPath, "*.bpf.o"))
	if err != nil {
		l.log.WithError(err).Warn("error searching for BPF objects - running in Go-only mode")
		l.bpfAvail = false
		return nil
	}
	if len(files) == 0 {
		l.log.Warnf("no BPF object files found in %s - running in Go-only mode", objPath)
		l.log.Info("Go-only detectors active: syscall hooks, hidden processes, memory scanner, eBPF audit")
		l.bpfAvail = false
		return nil
	}

	l.bpfAvail = true
	for _, f := range files {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := l.loadObject(f); err != nil {
			l.log.WithError(err).Warnf("failed to load %s", filepath.Base(f))
		}
	}
	return nil
}

func (l *Loader) loadObject(path string) error {
	l.log.Debugf("loading BPF object: %s", path)
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return fmt.Errorf("loading spec from %s: %w", path, err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction},
	})
	if err != nil {
		return fmt.Errorf("creating collection from %s: %w", path, err)
	}
	name := filepath.Base(path)
	l.objs[name] = coll
	for progName, prog := range coll.Programs {
		lnk, err := l.attachProgram(progName, prog)
		if err != nil {
			l.log.WithError(err).Warnf("could not attach %s in %s", progName, name)
			continue
		}
		info, _ := prog.Info()
		loaded := &LoadedProgram{Name: progName, Type: prog.Type(), Link: lnk}
		if info != nil {
			loaded.Tag = fmt.Sprintf("%x", info.Tag)
		}
		l.programs = append(l.programs, loaded)
		l.log.Debugf("attached: %s (type=%s)", progName, prog.Type())
	}
	return nil
}

func (l *Loader) attachProgram(name string, prog *ebpf.Program) (link.Link, error) {
	switch prog.Type() {
	case ebpf.TracePoint:
		lnk, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			return nil, fmt.Errorf("attaching tracepoint %s: %w", name, err)
		}
		l.links = append(l.links, lnk)
		return lnk, nil
	case ebpf.Kprobe:
		var symbol string
		var isReturn bool
		if len(name) > 10 && name[:10] == "kretprobe_" {
			symbol, isReturn = name[10:], true
		} else if len(name) > 7 && name[:7] == "kprobe_" {
			symbol = name[7:]
		} else {
			return nil, fmt.Errorf("cannot infer symbol from %s", name)
		}
		var lnk link.Link
		var err error
		if isReturn {
			lnk, err = link.Kretprobe(symbol, prog, nil)
		} else {
			lnk, err = link.Kprobe(symbol, prog, nil)
		}
		if err != nil {
			return nil, fmt.Errorf("attaching kprobe %s: %w", symbol, err)
		}
		l.links = append(l.links, lnk)
		return lnk, nil
	case ebpf.RawTracepoint:
		event := name
		if len(name) > 7 && name[:7] == "raw_tp_" {
			event = name[7:]
		}
		lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name: event, Program: prog,
		})
		if err != nil {
			return nil, fmt.Errorf("attaching raw tracepoint %s: %w", event, err)
		}
		l.links = append(l.links, lnk)
		return lnk, nil
	default:
		return nil, fmt.Errorf("unsupported type %s for auto-attach", prog.Type())
	}
}

// GetMap retrieves a loaded BPF map by name. Returns a stub map if BPF unavailable.
func (l *Loader) GetMap(name string) (*ebpf.Map, error) {
	for _, coll := range l.objs {
		if m, ok := coll.Maps[name]; ok {
			return m, nil
		}
	}
	return nil, fmt.Errorf("BPF map %q not found (BPF available: %v)", name, l.bpfAvail)
}

// BPFAvailable returns true if BPF programs were successfully loaded.
func (l *Loader) BPFAvailable() bool {
	return l.bpfAvail
}

// Status returns current loader status.
func (l *Loader) Status(_ context.Context) (*Status, error) {
	s := &Status{Kernel: kernelVersion(), Arch: runtime.GOARCH}
	for _, p := range l.programs {
		s.Programs = append(s.Programs, *p)
	}
	for _, coll := range l.objs {
		for mapName, m := range coll.Maps {
			info, err := m.Info()
			ms := MapStatus{Name: mapName, Type: m.Type()}
			if err == nil && info != nil {
				ms.Entries = info.MaxEntries
			}
			s.Maps = append(s.Maps, ms)
		}
	}
	return s, nil
}

// Close detaches all programs and releases resources.
func (l *Loader) Close() {
	for i := len(l.links) - 1; i >= 0; i-- {
		if err := l.links[i].Close(); err != nil {
			l.log.WithError(err).Debug("error closing BPF link")
		}
	}
	for name, coll := range l.objs {
		coll.Close()
		l.log.Debugf("closed BPF collection: %s", name)
	}
}

func kernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	s := string(data)
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}
