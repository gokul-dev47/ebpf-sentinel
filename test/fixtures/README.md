# Test Fixtures

Benign test fixtures used by integration and unit tests.

## malicious_bpf_sim.bpf.c

A minimal BPF program with structural characteristics of a suspicious program
(kprobe type, no recognizable name) but performs NO harmful operations.
It simply reads the current PID and discards it.

Used by: `test/integration/integration_test.go` to verify EBPFScanner
correctly flags programs with suspicious structural characteristics.

### Building the fixture

```bash
clang -target bpf -O2 -g \
    -c test/fixtures/malicious_bpf_sim.bpf.c \
    -o test/fixtures/malicious_bpf_sim.bpf.o
```
