/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __HELPERS_H__
#define __HELPERS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed int         s32;
typedef signed long long   s64;

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static __always_inline u64 isqrt_u64(u64 n)
{
    if (n == 0) return 0;
    u64 x = n;
    u64 y = (x + 1) >> 1;
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (y >= x) break;
        x = y;
        y = (x + n / x) >> 1;
    }
    return x;
}

static __always_inline u32 get_current_pid(void)
{
    return (u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
}

static __always_inline u32 get_current_tgid(void)
{
    return (u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline u32 get_current_uid(void)
{
    return (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
}

static __always_inline u32 get_current_gid(void)
{
    return (u32)(bpf_get_current_uid_gid() >> 32);
}

static __always_inline u32 get_ppid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (!parent) return 0;
    return BPF_CORE_READ(parent, tgid);
}

static __always_inline u64 now_ns(void) { return bpf_ktime_get_ns(); }
static __always_inline u64 ns_to_us(u64 ns) { return ns / 1000ULL; }
static __always_inline u64 ns_to_ms(u64 ns) { return ns / 1000000ULL; }

static __always_inline void welford_update(struct syscall_stats *stats, u64 sample)
{
    stats->count++;
    if (stats->count == 1) { stats->mean_ns = sample; stats->variance_ns = 0; return; }
    s64 delta = (s64)sample - (s64)stats->mean_ns;
    stats->mean_ns = (u64)((s64)stats->mean_ns + delta / (s64)stats->count);
    s64 delta2 = (s64)sample - (s64)stats->mean_ns;
    u64 m2 = stats->variance_ns * (stats->count - 1);
    m2 += (u64)(delta < 0 ? -delta : delta) * (u64)(delta2 < 0 ? -delta2 : delta2);
    stats->variance_ns = (stats->count > 1) ? m2 / stats->count : 0;
}

#endif /* __HELPERS_H__ */
