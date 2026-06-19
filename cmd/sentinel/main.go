// Package main is the entry point for the eBPF Sentinel CLI.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gokul-dev47/ebpf-sentinel/pkg/detector"
	"github.com/gokul-dev47/ebpf-sentinel/pkg/loader"
	"github.com/gokul-dev47/ebpf-sentinel/pkg/storage"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	Version = "dev"
	Build   = "unknown"
	log     = logrus.New()
	jsonOut bool
	verbose bool
	dbDSN   string
)

const banner = "\033[32m╔═══════════════════════════════════════════════════╗\n║       eBPF SENTINEL - Rootkit Detection Engine    ║\n║       Version: %-8s  Build: %-10s      ║\n╚═══════════════════════════════════════════════════╝\033[0m\n"

func main() {
	if err := buildRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func buildRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "sentinel",
		Short:   "eBPF Sentinel - Kernel rootkit detection",
		Version: fmt.Sprintf("%s (%s)", Version, Build),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if verbose {
				log.SetLevel(logrus.DebugLevel)
			}
			if jsonOut {
				log.SetFormatter(&logrus.JSONFormatter{})
			} else {
				log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true, ForceColors: true})
				fmt.Printf(banner, Version, Build)
			}
		},
	}
	root.PersistentFlags().BoolVarP(&jsonOut, "json", "j", false, "JSON output")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose logging")
	root.PersistentFlags().StringVar(&dbDSN, "db", "", "PostgreSQL DSN (optional)")
	root.AddCommand(buildScanCmd(), buildWatchCmd(), buildStatusCmd(), buildReportCmd(), buildRemediateCmd())
	return root
}

func buildScanCmd() *cobra.Command {
	var checks []string
	var timeout int
	var outFile string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a one-shot detection scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), checks, time.Duration(timeout)*time.Second, outFile)
		},
	}
	cmd.Flags().StringSliceVar(&checks, "checks", []string{"all"}, "Checks: all,syscall,process,ebpf,memory,behavioral")
	cmd.Flags().IntVar(&timeout, "timeout", 60, "Timeout in seconds")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "Write JSON results to file")
	return cmd
}

func buildWatchCmd() *cobra.Command {
	var intervalSec int
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Continuous monitoring mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWatch(cmd.Context(), time.Duration(intervalSec)*time.Second)
		},
	}
	cmd.Flags().IntVarP(&intervalSec, "interval", "i", 300, "Scan interval in seconds")
	return cmd
}

func buildStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show detector status",
		RunE:  func(cmd *cobra.Command, args []string) error { return runStatus(cmd.Context()) },
	}
}

func buildReportCmd() *cobra.Command {
	var lastN int
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate report from stored scan history",
		RunE:  func(cmd *cobra.Command, args []string) error { return runReport(cmd.Context(), lastN) },
	}
	cmd.Flags().IntVarP(&lastN, "last", "n", 10, "Show last N scans")
	return cmd
}

func buildRemediateCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "remediate",
		Short: "Attempt auto-remediation of detected threats",
		RunE:  func(cmd *cobra.Command, args []string) error { return runRemediate(cmd.Context(), dryRun) },
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without doing it")
	return cmd
}

func newEngine(ldr *loader.Loader, checks []string) *detector.Engine {
	var store *storage.PostgresStore
	if dbDSN != "" {
		var err error
		store, err = storage.NewPostgresStore(dbDSN)
		if err != nil {
			log.WithError(err).Warn("PostgreSQL unavailable")
		}
	}
	return detector.NewEngine(detector.EngineConfig{
		Loader: ldr, Store: store, Logger: log, Checks: checks, JSONOut: jsonOut,
	})
}

func runScan(ctx context.Context, checks []string, timeout time.Duration, outFile string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ldr, err := loader.New(log)
	if err != nil {
		return fmt.Errorf("initializing loader: %w", err)
	}
	defer ldr.Close()
	if err := ldr.Load(ctx); err != nil {
		return fmt.Errorf("loading BPF programs: %w", err)
	}
	eng := newEngine(ldr, checks)
	results, err := eng.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	rdr := detector.NewRenderer(jsonOut)
	if err := rdr.Render(results, os.Stdout); err != nil {
		return err
	}
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		if err := detector.NewRenderer(true).Render(results, f); err != nil {
			return err
		}
		log.Infof("Results written to %s", outFile)
	}
	if results.HasThreats() {
		os.Exit(1)
	}
	return nil
}

func runWatch(ctx context.Context, interval time.Duration) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ldr, err := loader.New(log)
	if err != nil {
		return fmt.Errorf("initializing loader: %w", err)
	}
	defer ldr.Close()
	if err := ldr.Load(ctx); err != nil {
		return fmt.Errorf("loading BPF programs: %w", err)
	}
	eng := newEngine(ldr, []string{"all"})
	log.Infof("Watch mode: scanning every %s. Ctrl+C to stop.", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	count := 0
	for {
		select {
		case <-ctx.Done():
			log.Info("Shutting down watch mode")
			return nil
		case <-ticker.C:
			count++
			log.Infof("Starting scan #%d", count)
			sctx, scanCancel := context.WithTimeout(ctx, 60*time.Second)
			results, err := eng.Scan(sctx)
			scanCancel()
			if err != nil {
				log.WithError(err).Error("scan failed")
				continue
			}
			detector.NewRenderer(jsonOut).Render(results, os.Stdout) //nolint:errcheck
			if results.HasThreats() {
				log.Warn("⚠️  Threats detected")
			}
		}
	}
}

func runStatus(ctx context.Context) error {
	ldr, err := loader.New(log)
	if err != nil {
		return fmt.Errorf("creating loader: %w", err)
	}
	defer ldr.Close()
	status, err := ldr.Status(ctx)
	if err != nil {
		return fmt.Errorf("getting status: %w", err)
	}
	return detector.NewRenderer(jsonOut).RenderStatus(status, os.Stdout)
}

func runReport(ctx context.Context, lastN int) error {
	if dbDSN == "" {
		return fmt.Errorf("--db required for report command")
	}
	store, err := storage.NewPostgresStore(dbDSN)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer store.Close()
	scans, err := store.GetRecentScans(ctx, lastN)
	if err != nil {
		return fmt.Errorf("fetching scans: %w", err)
	}
	return detector.NewRenderer(jsonOut).RenderHistory(scans, os.Stdout)
}

func runRemediate(ctx context.Context, dryRun bool) error {
	ldr, err := loader.New(log)
	if err != nil {
		return fmt.Errorf("initializing loader: %w", err)
	}
	defer ldr.Close()
	if err := ldr.Load(ctx); err != nil {
		return fmt.Errorf("loading BPF programs: %w", err)
	}
	eng := newEngine(ldr, []string{"all"})
	results, err := eng.Scan(ctx)
	if err != nil {
		return fmt.Errorf("pre-remediation scan failed: %w", err)
	}
	if !results.HasThreats() {
		fmt.Println("\033[32m✅ No threats found. No remediation needed.\033[0m")
		return nil
	}
	return eng.Remediate(ctx, results, dryRun)
}
