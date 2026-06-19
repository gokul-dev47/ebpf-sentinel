// Package main implements the eBPF Sentinel long-running daemon agent.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gokul-dev47/ebpf-sentinel/pkg/api"
	"github.com/gokul-dev47/ebpf-sentinel/pkg/detector"
	"github.com/gokul-dev47/ebpf-sentinel/pkg/loader"
	sentinelmetrics "github.com/gokul-dev47/ebpf-sentinel/pkg/prometheus"
	"github.com/gokul-dev47/ebpf-sentinel/pkg/storage"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// AgentConfig holds all runtime configuration for the daemon.
type AgentConfig struct {
	ScanInterval    time.Duration
	DatabaseDSN     string
	RedisDSN        string
	APIAddr         string
	MetricsAddr     string
	AlertWebhookURL string
	LogLevel        string
	LogFormat       string
}

var log = logrus.New()

func main() {
	cfg := &AgentConfig{}
	root := &cobra.Command{
		Use:   "sentinel-agent",
		Short: "eBPF Sentinel daemon agent",
		RunE:  func(cmd *cobra.Command, args []string) error { return runAgent(cmd.Context(), cfg) },
	}
	root.Flags().DurationVar(&cfg.ScanInterval, "scan-interval", 5*time.Minute, "Interval between scans")
	root.Flags().StringVar(&cfg.DatabaseDSN, "db", envOr("SENTINEL_DB_DSN", ""), "PostgreSQL DSN")
	root.Flags().StringVar(&cfg.RedisDSN, "redis", envOr("SENTINEL_REDIS_DSN", ""), "Redis DSN")
	root.Flags().StringVar(&cfg.APIAddr, "api-addr", ":8080", "REST API listen address")
	root.Flags().StringVar(&cfg.MetricsAddr, "metrics-addr", ":9090", "Prometheus metrics address")
	root.Flags().StringVar(&cfg.AlertWebhookURL, "webhook", envOr("SENTINEL_WEBHOOK_URL", ""), "Alert webhook URL")
	root.Flags().StringVar(&cfg.LogLevel, "log-level", "info", "Log level: debug,info,warn,error")
	root.Flags().StringVar(&cfg.LogFormat, "log-format", "text", "Log format: text,json")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runAgent(ctx context.Context, cfg *AgentConfig) error {
	if err := configureLogging(cfg); err != nil {
		return fmt.Errorf("configuring logging: %w", err)
	}
	log.WithFields(logrus.Fields{
		"scan_interval": cfg.ScanInterval,
		"api_addr":      cfg.APIAddr,
		"metrics_addr":  cfg.MetricsAddr,
	}).Info("starting eBPF Sentinel agent")

	metrics := sentinelmetrics.NewMetrics()

	var pgStore *storage.PostgresStore
	if cfg.DatabaseDSN != "" {
		var err error
		pgStore, err = storage.NewPostgresStore(cfg.DatabaseDSN)
		if err != nil {
			log.WithError(err).Warn("PostgreSQL unavailable")
		} else {
			defer pgStore.Close()
			log.Info("connected to PostgreSQL")
		}
	}

	ldr, err := loader.New(log)
	if err != nil {
		return fmt.Errorf("initializing BPF loader: %w", err)
	}
	defer ldr.Close()
	if err := ldr.Load(ctx); err != nil {
		return fmt.Errorf("loading BPF programs: %w", err)
	}
	log.Info("BPF programs loaded successfully")

	eng := detector.NewEngine(detector.EngineConfig{
		Loader:  ldr,
		Store:   pgStore,
		Logger:  log,
		Metrics: metrics,
		Checks:  []string{"all"},
	})

	// Start REST API server
	apiServer := api.NewServer(api.ServerConfig{
		Addr: cfg.APIAddr, Engine: eng, Store: pgStore,
		Metrics: metrics, Logger: log,
	})
	go func() {
		log.Infof("REST API listening on %s", cfg.APIAddr)
		if err := apiServer.Run(ctx); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Error("API server error")
		}
	}()

	// Start Prometheus metrics server
	go func() {
		log.Infof("Prometheus metrics on %s/metrics", cfg.MetricsAddr)
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ok")
		})
		srv := &http.Server{Addr: cfg.MetricsAddr, Handler: mux,
			ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
		go func() {
			<-ctx.Done()
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			srv.Shutdown(shutCtx) //nolint:errcheck
		}()
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Error("metrics server error")
		}
	}()

	// Main scan loop
	ticker := time.NewTicker(cfg.ScanInterval)
	defer ticker.Stop()
	scanCount := 0
	runScan(ctx, eng, metrics, cfg, &scanCount) // First scan immediately

	for {
		select {
		case <-ctx.Done():
			log.Info("agent shutting down gracefully")
			return nil
		case <-ticker.C:
			runScan(ctx, eng, metrics, cfg, &scanCount)
		}
	}
}

func runScan(ctx context.Context, eng *detector.Engine,
	metrics *sentinelmetrics.Metrics, cfg *AgentConfig, count *int) {
	*count++
	n := *count
	start := time.Now()
	log.Infof("starting scan #%d", n)

	scanCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	results, err := eng.Scan(scanCtx)
	elapsed := time.Since(start)
	if err != nil {
		log.WithError(err).Errorf("scan #%d failed after %s", n, elapsed)
		metrics.RecordScanError()
		return
	}
	metrics.RecordScan(elapsed, results)
	log.WithFields(logrus.Fields{
		"scan": n, "duration": elapsed,
		"threats": len(results.Findings), "risk": results.RiskLevel,
	}).Infof("scan #%d complete", n)

	if results.HasThreats() {
		log.Warnf("🔴 %d threat(s) detected in scan #%d", len(results.Findings), n)
		if cfg.AlertWebhookURL != "" {
			if err := sendWebhook(cfg.AlertWebhookURL, results); err != nil {
				log.WithError(err).Warn("failed to send webhook alert")
			}
		}
	}
}

func sendWebhook(url string, results interface{}) error {
	type marshalable interface{ MarshalJSON() ([]byte, error) }
	m, ok := results.(marshalable)
	if !ok {
		return fmt.Errorf("results not marshalable")
	}
	payload, err := m.MarshalJSON()
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json",
		newBytesReader(payload))
	if err != nil {
		return fmt.Errorf("posting webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook HTTP %d", resp.StatusCode)
	}
	return nil
}

func configureLogging(cfg *AgentConfig) error {
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("invalid log level %q: %w", cfg.LogLevel, err)
	}
	log.SetLevel(level)
	switch cfg.LogFormat {
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{TimestampFormat: time.RFC3339Nano})
	default:
		log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true, ForceColors: true})
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type bytesReader struct{ data []byte; pos int }
func newBytesReader(b []byte) *bytesReader { return &bytesReader{data: b} }
func (b *bytesReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) { return 0, fmt.Errorf("EOF") }
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}
func (b *bytesReader) Close() error { return nil }
