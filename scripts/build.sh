#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/bin"
BPF_BUILD_DIR="$PROJECT_ROOT/build/bpf"

RED='\033[31m'; GREEN='\033[32m'; CYAN='\033[36m'; RESET='\033[0m'
info() { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()   { echo -e "${GREEN}[OK]${RESET}    $*"; }
err()  { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

check_deps() {
    local missing=()
    for tool in clang llvm-strip go make; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Missing: ${missing[*]}"
        err "Install: apt-get install clang llvm golang-1.21 make"
        exit 1
    fi
}

build_bpf() {
    info "Building BPF programs..."
    mkdir -p "$BPF_BUILD_DIR"
    make -C "$PROJECT_ROOT/bpf/detector" \
        OUTPUT_DIR="$(realpath "$BPF_BUILD_DIR")" \
        CLANG="${CLANG:-clang}" \
        LLC="${LLC:-llc}" \
        STRIP="${STRIP:-llvm-strip}" \
        BPFTOOL="${BPFTOOL:-bpftool}"
    ok "BPF objects: $(ls "$BPF_BUILD_DIR"/*.bpf.o 2>/dev/null | wc -l) files"
}

build_go() {
    info "Building Go binaries..."
    mkdir -p "$BUILD_DIR"
    local VERSION BUILD LDFLAGS
    VERSION=$(git -C "$PROJECT_ROOT" describe --tags --always --dirty 2>/dev/null || echo "dev")
    BUILD=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    LDFLAGS="-s -w -X main.Version=${VERSION} -X main.Build=${BUILD}"

    CGO_ENABLED=0 go build -ldflags "$LDFLAGS" \
        -o "$BUILD_DIR/sentinel" "$PROJECT_ROOT/cmd/sentinel"
    CGO_ENABLED=0 go build -ldflags "$LDFLAGS" \
        -o "$BUILD_DIR/sentinel-agent" "$PROJECT_ROOT/cmd/agent"
    ok "Binaries built in $BUILD_DIR/"
}

install_bpf() {
    local DEST="/usr/lib/sentinel/bpf"
    info "Installing BPF objects to $DEST..."
    mkdir -p "$DEST"
    cp "$BPF_BUILD_DIR"/*.bpf.o "$DEST/"
    ok "BPF objects installed to $DEST"
}

main() {
    cd "$PROJECT_ROOT"
    check_deps
    case "${1:-all}" in
        bpf)     build_bpf ;;
        go)      build_go ;;
        install) build_bpf && build_go && install_bpf ;;
        all)     build_bpf && build_go ;;
        *)       err "Usage: $0 [bpf|go|install|all]"; exit 1 ;;
    esac
    ok "Build complete"
}
main "$@"
