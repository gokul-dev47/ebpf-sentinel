```
███████╗██████╗ ███████╗███████╗    ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔══██╗██╔════╝██╔════╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
█████╗  ██████╔╝█████╗  ███████╗    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
██╔══╝  ██╔══██╗██╔══╝  ╚════██║    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████╗██████╔╝██║     ███████║    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚═════╝ ╚═╝     ╚══════╝    ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

![Build](https://github.com/gokul-dev47/ebpf-sentinel/actions/workflows/build.yaml/badge.svg)
![Go Version](https://img.shields.io/badge/go-1.21+-blue)
![Kernel](https://img.shields.io/badge/kernel-5.4%20%7C%205.15%20%7C%206.1%20%7C%206.6-blue)
![License](https://img.shields.io/badge/license-GPLv2-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2-lightgrey)

> **⚠️ LEGAL DISCLAIMER:** This tool is designed exclusively for **defensive security monitoring**.
> Deploy only on systems you own or have explicit written authorization to monitor.

---

## What is eBPF Sentinel?

eBPF Sentinel is a production-grade Linux rootkit detector built in Go. It uses multiple
kernel-level detection techniques to find active rootkits, hidden processes, hooked syscalls,
and suspicious kernel modifications.

---

## Features

| Detection Module | What It Finds | Status |
|---|---|---|
| **Syscall Hook Detection** | Patched syscall table, inline JMP hooks | ✅ Active |
| **Hidden Process Detection** | Processes hidden from /proc | ✅ Active |
| **eBPF Program Audit** | Suspicious BPF programs | ✅ Active |
| **Kernel Memory Scanner** | Rootkit signatures, hidden LKMs | ✅ Active |
| **Behavioral Analysis** | Syscall latency anomalies | ✅ Active (with BPF) |

---

## Quick Start

```bash
# Clone
git clone https://github.com/gokul-dev47/ebpf-sentinel
cd ebpf-sentinel

# Build (Go 1.21+ required)
go mod tidy
mkdir -p bin
CGO_ENABLED=0 go build -o bin/sentinel ./cmd/sentinel
CGO_ENABLED=0 go build -o bin/sentinel-agent ./cmd/agent

# Run scan
sudo ./bin/sentinel scan --verbose

# JSON output
sudo ./bin/sentinel scan --json

# Watch mode
sudo ./bin/sentinel watch --interval 300
```

---

## CLI Output

### Clean System
```
╔══════════════════════════════════════════════════════╗
║          eBPF SENTINEL SCAN RESULTS                  ║
╠══════════════════════════════════════════════════════╣
║  Scan ID:  68211824                                  ║
║  Host:     production-server-01                      ║
║  Duration: 3.21s                                     ║
║  Findings: 0                                         ║
╚══════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════╗
║  ✅  SYSTEM CLEAN - No rootkit indicators detected   ║
╚══════════════════════════════════════════════════════╝
```

### Rootkit Detected
```
╔══════════════════════════════════════════════════════╗
║  🔴  ROOTKIT INDICATORS DETECTED  RISK: CRITICAL    ║
╚══════════════════════════════════════════════════════╝

┌─ Finding #1: Hidden kernel module: diamorphine
│  Type:        HIDDEN_KERNEL_MODULE
│  Risk:        CRITICAL
│  Confidence:  90%
│  MITRE ATT&CK:
│    T1014        Rootkit
│    T1547.006    Boot or Logon Autostart: Kernel Modules
│  Remediation: rmmod diamorphine. If protected: reboot.
└──────────────────────────────────────────────────────
```

---

## Available Commands

```bash
sentinel scan                          # One-shot scan (all checks)
sentinel scan --checks syscall         # Syscall hooks only
sentinel scan --checks memory          # Memory/module scan only
sentinel scan --checks ebpf            # BPF program audit only
sentinel scan --checks process         # Hidden process detection only
sentinel scan --json                   # JSON output
sentinel scan --json -o results.json   # Save to file
sentinel watch --interval 300          # Scan every 5 minutes
sentinel status                        # Show loader status
sentinel remediate --dry-run           # Preview remediations
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Detection Method |
|---|---|---|
| Rootkit | T1014 | All modules |
| Process Discovery | T1057 | Hidden Process Detector |
| Hide Artifacts | T1564.001 | Memory Scanner |
| Boot/Logon Autostart: Kernel Modules | T1547.006 | Memory Scanner |
| Modify System Image | T1601 | Syscall Hook Detector |
| Non-Standard Port | T1571 | Network Monitor |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                eBPF Sentinel Architecture            │
├─────────────────────┬───────────────────────────────┤
│  KERNEL SPACE       │  USER SPACE (Go)              │
│  (BPF Programs)     │                               │
│                     │  Detection Engine             │
│  syscall_monitor ───┼─▶ SyscallHookDetector        │
│  process_scanner ───┼─▶ HiddenProcessDetector      │
│  file_monitor    ───┼─▶ MemoryScanner              │
│  network_monitor ───┼─▶ EBPFScanner                │
│  ebpf_audit      ───┼─▶ BehavioralDetector         │
│  memory_scanner  ───┼─▶                            │
│                     │  Storage & API               │
│  BPF Maps:          │  ├── PostgreSQL (optional)   │
│  ring_events     ───┼─▶ ├── Redis (optional)       │
│  process_cache      │  ├── REST API :8080          │
│  syscall_baseline   │  └── Prometheus :9090        │
└─────────────────────┴───────────────────────────────┘
```

---

## Requirements

| Component | Minimum |
|---|---|
| Go | 1.21+ |
| Linux Kernel | 5.4+ (for BPF mode) |
| Privileges | root or CAP_SYS_ADMIN |
| BTF | `/sys/kernel/btf/vmlinux` (for BPF mode) |

**WSL2 / Go-only mode:** Works without BPF. Runs syscall hook, hidden process, memory, and eBPF audit checks using pure Go kernel interfaces.

---

## Docker

```bash
docker compose -f deployments/docker/docker-compose.yaml up -d
docker exec ebpf-sentinel-sentinel-1 sentinel scan --verbose
```

---

## Performance

| Processes | Scan Time | CPU | Memory |
|---|---|---|---|
| 100 | ~0.5s | <5% | ~80MB |
| 500 | ~2s | <8% | ~110MB |
| 1000 | ~5s | <12% | ~145MB |
| 2000 | ~10s | <15% | ~185MB |

---

## Project Structure

```
ebpf-sentinel/
├── bpf/detector/          # BPF C programs (kernel space)
├── cmd/sentinel/          # CLI entry point
├── cmd/agent/             # Daemon entry point
├── pkg/detector/          # Detection modules (Go)
├── pkg/loader/            # BPF program loader
├── pkg/storage/           # PostgreSQL + Redis
├── pkg/api/               # REST API server
├── pkg/prometheus/        # Metrics
├── internal/scanning/     # Kernel memory scanner
├── internal/hiding/       # Hiding detection utilities
├── deployments/           # Docker, K8s, Vagrant
├── scripts/               # Build, test, benchmark
└── test/                  # Integration + e2e tests
```

---

## License

GNU General Public License v2. See [LICENSE](LICENSE).

Built by [@gokul-dev47](https://github.com/gokul-dev47) as a cybersecurity portfolio project.
