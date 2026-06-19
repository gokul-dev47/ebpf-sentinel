// Package prometheus implements Prometheus metric collection.
package prometheus

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metric collectors.
type Metrics struct {
	scansTotal           prometheus.Counter
	scanErrors           prometheus.Counter
	scanDuration         prometheus.Histogram
	detectionsByType     *prometheus.CounterVec
	riskLevelGauge       prometheus.Gauge
	syscallHooksGauge    prometheus.Gauge
	hiddenProcessesGauge prometheus.Gauge
	suspiciousBPFGauge   prometheus.Gauge
	memoryAnomalies      prometheus.Gauge
	ebpfProgramsTotal    prometheus.Gauge
	lastScanTimestamp    prometheus.Gauge
}

// NewMetrics creates and registers all Prometheus metrics.
func NewMetrics() *Metrics {
	m := &Metrics{}
	m.scansTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "ebpf_sentinel", Name: "scans_total",
		Help: "Total number of detection scans executed",
	})
	m.scanErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "ebpf_sentinel", Name: "scan_errors_total",
		Help: "Total number of failed scans",
	})
	m.scanDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "ebpf_sentinel", Name: "scan_duration_seconds",
		Help:    "Duration of detection scans in seconds",
		Buckets: []float64{1, 5, 10, 15, 30, 60, 120},
	})
	m.detectionsByType = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "ebpf_sentinel", Name: "detections_total",
		Help: "Total detections broken down by finding type",
	}, []string{"type", "risk"})
	m.riskLevelGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "ebpf_sentinel", Name: "current_risk_level",
		Help: "Current system risk level (0=none,1=low,2=medium,3=high,4=critical)",
	})
	m.syscallHooksGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "ebpf_sentinel", Name: "syscall_hooks_count",
		Help: "Number of potentially hooked syscalls detected",
	})
	m.hiddenProcessesGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "ebpf_sentinel", Name: "hidden_processes_count",
		Help: "Number of potentially hidden processes detected",
	})
	m.suspiciousBPFGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "ebpf_sentinel", Name: "suspicious_bpf_programs_count",
		Help: "Number of suspicious BPF programs detected",
	})
	m.memoryAnomalies = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "ebpf_sentinel", Name: "memory_anomalies_count",
		Help: "Number of kernel memory anomalies detected",
	})
	m.ebpfProgramsTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "ebpf_sentinel", Name: "ebpf_programs_total",
		Help: "Total number of loaded BPF programs on the system",
	})
	m.lastScanTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "ebpf_sentinel", Name: "last_scan_timestamp_seconds",
		Help: "Unix timestamp of the last completed scan",
	})
	return m
}

// RecordScan updates metrics after a completed scan.
func (m *Metrics) RecordScan(duration time.Duration, results interface{}) {
	m.scansTotal.Inc()
	m.scanDuration.Observe(duration.Seconds())
	m.lastScanTimestamp.SetToCurrentTime()
}

// RecordScanError increments the scan error counter.
func (m *Metrics) RecordScanError() { m.scanErrors.Inc() }

// RecordDetection increments the detection counter.
func (m *Metrics) RecordDetection(findingType, risk string) {
	m.detectionsByType.WithLabelValues(findingType, risk).Inc()
}

// UpdateGauges updates all gauge metrics with current values.
func (m *Metrics) UpdateGauges(riskLevel, syscallHooks, hiddenProcs, suspBPF, memAnomalies, totalBPF int) {
	m.riskLevelGauge.Set(float64(riskLevel))
	m.syscallHooksGauge.Set(float64(syscallHooks))
	m.hiddenProcessesGauge.Set(float64(hiddenProcs))
	m.suspiciousBPFGauge.Set(float64(suspBPF))
	m.memoryAnomalies.Set(float64(memAnomalies))
	m.ebpfProgramsTotal.Set(float64(totalBPF))
}

// Summary returns a map of current metric names for JSON export.
func (m *Metrics) Summary() map[string]interface{} {
	return map[string]interface{}{
		"note": "Use /metrics endpoint for full Prometheus-format output",
	}
}
