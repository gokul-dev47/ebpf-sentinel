#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COVERAGE_DIR="$PROJECT_ROOT/coverage"
mkdir -p "$COVERAGE_DIR"

GREEN='\033[32m'; CYAN='\033[36m'; RESET='\033[0m'
info() { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()   { echo -e "${GREEN}[OK]${RESET}    $*"; }

run_unit() {
    info "Running unit tests..."
    cd "$PROJECT_ROOT"
    go test -v -race -count=1 \
        -coverprofile="$COVERAGE_DIR/unit.out" \
        -covermode=atomic \
        ./pkg/... ./cmd/... ./internal/...
    ok "Unit tests complete"
}

run_integration() {
    info "Running integration tests (requires root)..."
    if [[ $EUID -ne 0 ]]; then
        info "Not root - skipping integration tests"
        return 0
    fi
    cd "$PROJECT_ROOT"
    go test -v -count=1 -timeout=120s \
        -coverprofile="$COVERAGE_DIR/integration.out" \
        ./test/integration/...
    ok "Integration tests complete"
}

generate_coverage() {
    info "Generating coverage report..."
    cd "$PROJECT_ROOT"
    go tool cover -func="$COVERAGE_DIR/unit.out" | tail -1
    go tool cover -html="$COVERAGE_DIR/unit.out" \
        -o "$COVERAGE_DIR/coverage.html" 2>/dev/null || true
    ok "Coverage report: $COVERAGE_DIR/coverage.html"
}

run_gosec() {
    info "Running gosec security scan..."
    if ! command -v gosec &>/dev/null; then
        info "gosec not installed, skipping"
        return 0
    fi
    cd "$PROJECT_ROOT"
    gosec -fmt=text -severity=medium ./... 2>&1 | tee "$COVERAGE_DIR/gosec.log" || true
    ok "gosec complete"
}

main() {
    case "${1:-all}" in
        unit)        run_unit ;;
        integration) run_integration ;;
        coverage)    run_unit && run_integration && generate_coverage ;;
        security)    run_gosec ;;
        all)         run_unit && run_integration && generate_coverage && run_gosec ;;
        *)           echo "Usage: $0 [unit|integration|coverage|security|all]"; exit 1 ;;
    esac
    ok "Done. Reports in $COVERAGE_DIR/"
}
main "$@"
