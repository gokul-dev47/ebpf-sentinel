// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../common/maps.h"
#include "../common/helpers.h"
#include "../common/ringbuf.h"

char LICENSE[] SEC("license") = "GPL";

#define BASELINE_MIN_SAMPLES 100
#define ANOMALY_THRESHOLD_STD 3

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct syscall_enter_ctx);
} in_flight SEC(".maps");

static __always_inline int is_anomalous(struct syscall_stats *s, u64 sample)
{
    if (s->count < BASELINE_MIN_SAMPLES) return 0;
    if (sample <= s->mean_ns) return 0;
    u64 stddev = isqrt_u64(s->variance_ns);
    return sample > (s->mean_ns + ANOMALY_THRESHOLD_STD * stddev) ? 1 : 0;
}

SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    u32 pid = get_current_pid();
    u64 nr  = ctx->args[1];
    if (nr >= MAX_SYSCALLS) return 0;
    struct syscall_enter_ctx ec = { .start_ns = now_ns(), .syscall_nr = (u32)nr };
    bpf_map_update_elem(&in_flight, &pid, &ec, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int trace_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    u32 pid = get_current_pid();
    struct syscall_enter_ctx *ec = bpf_map_lookup_elem(&in_flight, &pid);
    if (!ec) return 0;
    u64 latency    = now_ns() - ec->start_ns;
    u32 syscall_nr = ec->syscall_nr;
    bpf_map_delete_elem(&in_flight, &pid);
    if (syscall_nr >= MAX_SYSCALLS) return 0;
    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_baseline, &syscall_nr);
    if (!stats) return 0;
    if (stats->count == 0 || latency < stats->min_latency_ns) stats->min_latency_ns = latency;
    if (latency > stats->max_latency_ns) stats->max_latency_ns = latency;
    stats->total_latency_ns += latency;
    stats->last_seen_ns = now_ns();
    int anomaly = is_anomalous(stats, latency);
    welford_update(stats, latency);
    if (anomaly) {
        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(comm, sizeof(comm));
        rb_emit_syscall_anomaly(syscall_nr, latency, pid, comm);
    }
    return 0;
}
