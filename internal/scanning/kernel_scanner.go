// Package scanning provides kernel memory scanning utilities.
package scanning

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// ScanResult describes a single finding from a kernel memory scan.
type ScanResult struct {
	Type        string
	VirtualAddr uint64
	Description string
	Severity    string
}

// KcoreSegment represents a PT_LOAD segment from /proc/kcore.
type KcoreSegment struct {
	VAddr, FileOff, FileSize, MemSize uint64
}

// KernelScanner scans kernel memory via /proc/kcore for anomalies.
type KernelScanner struct{ log *logrus.Logger }

// NewKernelScanner creates a new KernelScanner.
func NewKernelScanner(log *logrus.Logger) *KernelScanner { return &KernelScanner{log: log} }

// ParseKcoreSegments parses all PT_LOAD segments from /proc/kcore.
func (s *KernelScanner) ParseKcoreSegments() ([]KcoreSegment, error) {
	f, err := os.Open("/proc/kcore")
	if err != nil {
		return nil, fmt.Errorf("opening /proc/kcore: %w", err)
	}
	defer f.Close()

	var ehdr [64]byte
	if _, err := io.ReadFull(f, ehdr[:]); err != nil {
		return nil, fmt.Errorf("reading ELF header: %w", err)
	}
	if string(ehdr[1:4]) != "ELF" {
		return nil, fmt.Errorf("not an ELF file")
	}
	if ehdr[4] != 2 {
		return nil, fmt.Errorf("only ELF64 supported")
	}

	var order binary.ByteOrder = binary.LittleEndian
	if ehdr[5] == 2 {
		order = binary.BigEndian
	}

	phoff := order.Uint64(ehdr[32:40])
	phentsize := order.Uint16(ehdr[54:56])
	phnum := order.Uint16(ehdr[56:58])

	segs := make([]KcoreSegment, 0, phnum)
	phdr := make([]byte, phentsize)
	for i := uint16(0); i < phnum; i++ {
		if _, err := f.ReadAt(phdr, int64(phoff)+int64(i)*int64(phentsize)); err != nil {
			continue
		}
		if order.Uint32(phdr[0:4]) != 1 { // PT_LOAD
			continue
		}
		segs = append(segs, KcoreSegment{
			FileOff:  order.Uint64(phdr[8:16]),
			VAddr:    order.Uint64(phdr[16:24]),
			FileSize: order.Uint64(phdr[32:40]),
			MemSize:  order.Uint64(phdr[40:48]),
		})
	}
	return segs, nil
}

// ReadVirtualAddress reads n bytes at virtual address va from /proc/kcore.
func (s *KernelScanner) ReadVirtualAddress(va uint64, n int) ([]byte, error) {
	f, err := os.Open("/proc/kcore")
	if err != nil {
		return nil, fmt.Errorf("opening /proc/kcore: %w", err)
	}
	defer f.Close()

	segs, err := s.ParseKcoreSegments()
	if err != nil {
		return nil, err
	}
	for _, seg := range segs {
		if va >= seg.VAddr && va+uint64(n) <= seg.VAddr+seg.FileSize {
			buf := make([]byte, n)
			if _, err := f.ReadAt(buf, int64(seg.FileOff)+int64(va-seg.VAddr)); err != nil {
				return nil, fmt.Errorf("reading kcore at 0x%x: %w", va, err)
			}
			return buf, nil
		}
	}
	return nil, fmt.Errorf("VA 0x%x not found in kcore", va)
}

// ScanForSignatures scans the kernel .text section for known byte patterns.
func (s *KernelScanner) ScanForSignatures(patterns [][]byte) ([]ScanResult, error) {
	start, end, err := s.resolveTextBounds()
	if err != nil {
		return nil, fmt.Errorf("resolving .text bounds: %w", err)
	}
	s.log.Debugf("scanning .text 0x%x–0x%x", start, end)
	return s.scanRegion(start, end, patterns)
}

func (s *KernelScanner) resolveTextBounds() (uint64, uint64, error) {
	kver := kernelRelease()
	for _, path := range []string{
		"/boot/vmlinux-" + kver,
		"/usr/lib/debug/boot/vmlinux-" + kver,
		fmt.Sprintf("/usr/lib/debug/lib/modules/%s/vmlinux", kver),
	} {
		if start, end, err := textBoundsFromELF(path); err == nil {
			return start, end, nil
		}
	}
	return textBoundsFromKallsyms()
}

func textBoundsFromELF(path string) (uint64, uint64, error) {
	ef, err := elf.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer ef.Close()
	for _, sec := range ef.Sections {
		if sec.Name == ".text" {
			return sec.Addr, sec.Addr + sec.Size, nil
		}
	}
	return 0, 0, fmt.Errorf(".text not found in %s", path)
}

func textBoundsFromKallsyms() (uint64, uint64, error) {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return 0, 0, fmt.Errorf("reading kallsyms: %w", err)
	}
	var stext, etext uint64
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		switch parts[2] {
		case "_stext", "__stext":
			stext = parseHex(parts[0])
		case "_etext", "__etext":
			etext = parseHex(parts[0])
		}
		if stext != 0 && etext != 0 {
			break
		}
	}
	if stext == 0 || etext == 0 {
		return 0, 0, fmt.Errorf("_stext/_etext not found (run as root)")
	}
	return stext, etext, nil
}

func (s *KernelScanner) scanRegion(start, end uint64, patterns [][]byte) ([]ScanResult, error) {
	if end <= start {
		return nil, fmt.Errorf("invalid region")
	}
	f, err := os.Open("/proc/kcore")
	if err != nil {
		return nil, fmt.Errorf("opening /proc/kcore: %w", err)
	}
	defer f.Close()

	segs, err := s.ParseKcoreSegments()
	if err != nil {
		return nil, err
	}

	const pageSize = 4096
	buf := make([]byte, pageSize)
	var results []ScanResult

	for _, seg := range segs {
		scanStart := maxU64(start, seg.VAddr)
		scanEnd := minU64(end, seg.VAddr+seg.FileSize)
		if scanStart >= scanEnd {
			continue
		}
		for va := scanStart; va < scanEnd; va += uint64(pageSize) {
			end := minU64(va+uint64(pageSize), scanEnd)
			sz := int(end - va)
			n, err := f.ReadAt(buf[:sz], int64(seg.FileOff)+int64(va-seg.VAddr))
			if err != nil || n == 0 {
				continue
			}
			for _, pat := range patterns {
				if idx := bytesFind(buf[:n], pat); idx >= 0 {
					results = append(results, ScanResult{
						Type:        "SIGNATURE",
						VirtualAddr: va + uint64(idx),
						Description: fmt.Sprintf("pattern %q at 0x%x", string(pat), va+uint64(idx)),
						Severity:    "HIGH",
					})
				}
			}
		}
	}
	return results, nil
}

func kernelRelease() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func parseHex(s string) uint64 {
	var v uint64
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= uint64(c-'A') + 10
		}
	}
	return v
}

func bytesFind(haystack, needle []byte) int {
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

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
