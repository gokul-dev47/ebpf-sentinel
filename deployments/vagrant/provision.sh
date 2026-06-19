#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

log() { echo "[$(date '+%H:%M:%S')] [PROVISION] $*"; }
ok()  { echo "[$(date '+%H:%M:%S')] [OK]        $*"; }

DISTRO="unknown"
[[ -f /etc/os-release ]] && source /etc/os-release && DISTRO="${ID:-unknown}"
log "Distro: $DISTRO  Kernel: $(uname -r)"

install_deps_debian() {
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        build-essential clang llvm libbpf-dev \
        linux-headers-$(uname -r) linux-tools-common \
        git curl wget ca-certificates jq 2>/dev/null || \
    apt-get install -y --no-install-recommends \
        build-essential clang llvm libbpf-dev \
        linux-headers-generic linux-tools-common \
        git curl wget ca-certificates jq
    apt-get install -y bpftool 2>/dev/null || true
}

install_deps_fedora() {
    dnf install -y clang llvm libbpf-devel \
        kernel-headers bpftool git curl wget make gcc
}

case "$DISTRO" in
    ubuntu|debian) install_deps_debian ;;
    fedora|rhel)   install_deps_fedora ;;
    *)             install_deps_debian || true ;;
esac
ok "System dependencies installed"

GO_VERSION="1.21.5"
if ! command -v go &>/dev/null || ! go version 2>/dev/null | grep -q "go1.2[1-9]"; then
    log "Installing Go ${GO_VERSION}..."
    ARCH=$(uname -m); [[ "$ARCH" == "aarch64" ]] && GOARCH="arm64" || GOARCH="amd64"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    cat > /etc/profile.d/golang.sh << 'GOEOF'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=/root/go
export PATH=$PATH:$GOPATH/bin
GOEOF
    export PATH=$PATH:/usr/local/go/bin
fi
ok "Go $(go version)"

mount -t bpf bpf /sys/fs/bpf 2>/dev/null && log "Mounted /sys/fs/bpf" || true

PROJECT_DIR="/vagrant/ebpf-sentinel"
VMLINUX_H="$PROJECT_DIR/bpf/common/vmlinux.h"
if [[ -f /sys/kernel/btf/vmlinux ]] && command -v bpftool &>/dev/null; then
    log "Generating vmlinux.h..."
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX_H" 2>/dev/null \
        && ok "vmlinux.h generated" || log "BTF dump failed (non-fatal)"
fi

if [[ -d "$PROJECT_DIR" ]]; then
    cd "$PROJECT_DIR"
    log "Downloading Go modules..."
    go mod download 2>&1 | tail -3 || true
    log "Building eBPF Sentinel..."
    make build 2>&1 | tail -10 && ok "Build successful" || log "Build failed"
    log "Running unit tests..."
    go test ./pkg/... ./cmd/... 2>&1 | tail -5 || true
fi

cat > /etc/profile.d/sentinel.sh << 'EOF2'
alias sentinel='sudo /vagrant/ebpf-sentinel/bin/sentinel'
alias sentinel-scan='sudo /vagrant/ebpf-sentinel/bin/sentinel scan'
alias bpfls='sudo bpftool prog list'
EOF2

ok "Provisioning complete!"
log "Usage: vagrant ssh <vm> -- sudo /vagrant/ebpf-sentinel/bin/sentinel scan"
