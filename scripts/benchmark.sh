#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENTINEL="$PROJECT_ROOT/bin/sentinel"
RESULTS_DIR="$PROJECT_ROOT/benchmark_results"
mkdir -p "$RESULTS_DIR"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

spawn_processes() {
    local n=$1
    local pids=()
    for ((i=0; i<n; i++)); do
        sleep 3600 &
        pids+=($!)
    done
    echo "${pids[@]}"
}

kill_processes() { kill "$@" 2>/dev/null || true; }

benchmark_scan() {
    local label=$1 process_count=$2
    log "Benchmarking with $process_count processes..."
    local -a pids
    IFS=' ' read -r -a pids <<< "$(spawn_processes "$process_count")"
    sleep 1

    local start_ms end_ms elapsed_ms rss
    start_ms=$(date +%s%3N)
    "$SENTINEL" scan --checks all --timeout 60 --json \
        > "$RESULTS_DIR/${label}.json" 2>/dev/null || true
    end_ms=$(date +%s%3N)
    elapsed_ms=$(( end_ms - start_ms ))
    rss=$(grep VmRSS /proc/$$/status 2>/dev/null | awk '{print $2}' || echo "0")

    kill_processes "${pids[@]}"

    echo "$label,$process_count,${elapsed_ms}ms,${rss}KB" >> "$RESULTS_DIR/results.csv"
    log "  [$label] Time: ${elapsed_ms}ms RSS: ${rss}KB"
}

main() {
    if [[ $EUID -ne 0 ]]; then echo "Benchmark requires root" >&2; exit 1; fi
    if [[ ! -x "$SENTINEL" ]]; then echo "Run 'make build' first" >&2; exit 1; fi

    echo "label,process_count,scan_time,rss_kb" > "$RESULTS_DIR/results.csv"
    benchmark_scan "baseline_100"  100
    benchmark_scan "baseline_500"  500
    benchmark_scan "baseline_1000" 1000
    benchmark_scan "baseline_2000" 2000
    benchmark_scan "baseline_5000" 5000

    log "Results:"
    column -t -s, "$RESULTS_DIR/results.csv"
    log "Full results in $RESULTS_DIR/"
}
main "$@"
