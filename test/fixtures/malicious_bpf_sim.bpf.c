// SPDX-License-Identifier: GPL-2.0
/*
 * TEST FIXTURE - Simulated Suspicious BPF Program
 *
 * BENIGN test fixture that mimics structural characteristics of a suspicious
 * BPF program WITHOUT performing any harmful operations.
 *
 * Purpose: verify EBPFScanner correctly flags programs with suspicious
 * structural properties (kprobe type, no recognizable name).
 *
 * What this does: attaches a kprobe to sys_getpid, reads current PID,
 * and immediately returns 0. No data exfiltration. No modifications.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/__x64_sys_getpid")
int test_fixture_kprobe(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    (void)pid_tgid;
    return 0;
}
