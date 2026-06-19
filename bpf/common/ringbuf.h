/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __RINGBUF_H__
#define __RINGBUF_H__

#include <bpf/bpf_helpers.h>
#include "maps.h"
#include "helpers.h"

static __always_inline int rb_emit_process(struct process_info *info)
{
    struct ring_event *ev = bpf_ringbuf_reserve(&ring_events, sizeof(*ev), 0);
    if (!ev) return -1;
    ev->type = EVENT_HIDDEN_PROCESS;
    ev->cpu  = bpf_get_smp_processor_id();
    ev->timestamp_ns = now_ns();
    __builtin_memcpy(&ev->data.proc, info, sizeof(*info));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

static __always_inline int rb_emit_file(struct file_access_event *fa)
{
    struct ring_event *ev = bpf_ringbuf_reserve(&ring_events, sizeof(*ev), 0);
    if (!ev) return -1;
    ev->type = EVENT_SUSPICIOUS_FILE;
    ev->cpu  = bpf_get_smp_processor_id();
    ev->timestamp_ns = now_ns();
    __builtin_memcpy(&ev->data.file, fa, sizeof(*fa));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

static __always_inline int rb_emit_network(struct network_event *ne)
{
    struct ring_event *ev = bpf_ringbuf_reserve(&ring_events, sizeof(*ev), 0);
    if (!ev) return -1;
    ev->type = EVENT_NETWORK_ANOMALY;
    ev->cpu  = bpf_get_smp_processor_id();
    ev->timestamp_ns = now_ns();
    __builtin_memcpy(&ev->data.net, ne, sizeof(*ne));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

static __always_inline int rb_emit_syscall_anomaly(u32 syscall_nr, u64 latency_ns,
                                                    u32 pid, const char *comm)
{
    struct ring_event *ev = bpf_ringbuf_reserve(&ring_events, sizeof(*ev), 0);
    if (!ev) return -1;
    ev->type = EVENT_SYSCALL_ANOMALY;
    ev->cpu  = bpf_get_smp_processor_id();
    ev->timestamp_ns = now_ns();
    ev->data.proc.pid        = pid;
    ev->data.proc.start_time = latency_ns;
    ev->data.proc.flags      = (u8)(syscall_nr & 0xFF);
    ev->data.proc.gid        = syscall_nr;
    if (comm) __builtin_memcpy(ev->data.proc.comm, comm, TASK_COMM_LEN);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

#endif /* __RINGBUF_H__ */
