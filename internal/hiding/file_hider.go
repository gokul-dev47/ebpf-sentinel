// Package hiding - file hiding DETECTION utilities.
// Detects when file-hiding techniques are active. Contains NO hiding logic.
package hiding

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// FileHidingIndicator describes evidence of active file hiding.
type FileHidingIndicator struct {
	Path       string    `json:"path"`
	Technique  string    `json:"technique"`
	Evidence   string    `json:"evidence"`
	Confidence float64   `json:"confidence"`
	Timestamp  time.Time `json:"timestamp"`
}

// FileHidingDetector detects filesystem-level hiding techniques.
type FileHidingDetector struct{ log *logrus.Logger }

// NewFileHidingDetector creates a new file hiding detector.
func NewFileHidingDetector(log *logrus.Logger) *FileHidingDetector {
	return &FileHidingDetector{log: log}
}

// DetectStatVsGetdentsMismatch checks a directory for files visible via
// stat() but absent from getdents64() (readdir).
func (d *FileHidingDetector) DetectStatVsGetdentsMismatch(dir string) ([]FileHidingIndicator, error) {
	getdentsEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("ReadDir %s: %w", dir, err)
	}
	getdentsSet := make(map[string]bool, len(getdentsEntries))
	for _, e := range getdentsEntries {
		getdentsSet[e.Name()] = true
	}

	var indicators []FileHidingIndicator
	if dir == "/proc" || dir == "/proc/" {
		indicators = append(indicators, d.checkProcStatAccess(getdentsSet)...)
	}
	indicators = append(indicators, d.probeKnownArtifacts(dir, getdentsSet)...)
	return indicators, nil
}

func (d *FileHidingDetector) checkProcStatAccess(visible map[string]bool) []FileHidingIndicator {
	var indicators []FileHidingIndicator
	now := time.Now()
	for pid := 2; pid <= 65535; pid++ {
		name := fmt.Sprintf("%d", pid)
		if visible[name] {
			continue
		}
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
			comm := ""
			if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
				comm = strings.TrimSpace(string(data))
			}
			indicators = append(indicators, FileHidingIndicator{
				Path:      fmt.Sprintf("/proc/%d", pid),
				Technique: "getdents_filtering_proc",
				Evidence: fmt.Sprintf("/proc/%d stat-accessible (comm=%s) but absent from /proc listing",
					pid, comm),
				Confidence: 0.88, Timestamp: now,
			})
		}
		if len(indicators) >= 10 {
			break
		}
	}
	return indicators
}

func (d *FileHidingDetector) probeKnownArtifacts(dir string, visible map[string]bool) []FileHidingIndicator {
	// Known rootkit artifact filenames from published rootkit source code
	artifacts := []string{
		".diamorphine", ".reptile", "reptile_module",
		"diamorphine.ko", ".beurk", "beurk.so", ".azazel",
	}
	var indicators []FileHidingIndicator
	now := time.Now()
	for _, artifact := range artifacts {
		fullPath := filepath.Join(dir, artifact)
		if visible[artifact] {
			indicators = append(indicators, FileHidingIndicator{
				Path:      fullPath,
				Technique: "known_artifact_visible",
				Evidence:  fmt.Sprintf("file %q matches known rootkit artifact name", artifact),
				Confidence: 0.70, Timestamp: now,
			})
			continue
		}
		if _, err := os.Stat(fullPath); err == nil {
			indicators = append(indicators, FileHidingIndicator{
				Path:      fullPath,
				Technique: "getdents_filtering_artifact",
				Evidence: fmt.Sprintf("rootkit artifact %q stat-accessible but hidden from directory listing",
					artifact),
				Confidence: 0.92, Timestamp: now,
			})
		}
	}
	return indicators
}

// ScanProcForHiddenMaps checks /proc/<pid>/maps for memory-mapped files
// that no longer exist on disk (deleted-after-load technique).
func (d *FileHidingDetector) ScanProcForHiddenMaps(pid int) ([]FileHidingIndicator, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, fmt.Errorf("reading maps: %w", err)
	}
	var indicators []FileHidingIndicator
	now := time.Now()
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}
		mappedFile := parts[5]
		if mappedFile == "" || strings.HasPrefix(mappedFile, "[") {
			continue
		}
		if _, err := os.Stat(mappedFile); os.IsNotExist(err) {
			indicators = append(indicators, FileHidingIndicator{
				Path:      mappedFile,
				Technique: "deleted_mapped_file",
				Evidence: fmt.Sprintf("PID %d maps %s which no longer exists on disk",
					pid, mappedFile),
				Confidence: 0.55, Timestamp: now,
			})
		}
	}
	return indicators, nil
}
