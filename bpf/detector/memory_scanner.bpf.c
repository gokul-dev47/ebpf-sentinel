// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../common/maps.h"
#include "../common/helpers.h"
#include "../common/ringbuf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/kallsyms_lookup_name")
int kprobe_kallsyms_lookup(struct pt_regs *ctx)
{
    const char *sym = (const char *)PT_REGS_PARM1(ctx);
    if (!sym) return 0;
    char buf[64] = {};
    bpf_probe_read_kernel_str(buf, sizeof(buf), sym);
    int suspicious = 0;
    if (buf[0]=='s'&&buf[1]=='y'&&buf[2]=='s'&&buf[3]=='_'&&buf[4]=='c') suspicious = 1;
    if (buf[0]=='c'&&buf[1]=='o'&&buf[2]=='m'&&buf[3]=='m'&&buf[4]=='i') suspicious = 1;
    if (buf[0]=='p'&&buf[1]=='r'&&buf[2]=='e'&&buf[3]=='p'&&buf[4]=='a') suspicious = 1;
    if (!suspicious) return 0;
    struct ring_event *ev = bpf_ringbuf_reserve(&ring_events, sizeof(*ev), 0);
    if (!ev) return 0;
    ev->type = EVENT_MEMORY_ANOMALY;
    ev->cpu  = bpf_get_smp_processor_id();
    ev->timestamp_ns = now_ns();
    ev->data.proc.pid = get_current_tgid();
    bpf_get_current_comm(ev->data.proc.comm, sizeof(ev->data.proc.comm));
    __builtin_memcpy(ev->data.file.path, buf, 64);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/__request_module")
int kprobe_request_module(struct pt_regs *ctx)
{
    struct ring_event *ev = bpf_ringbuf_reserve(&ring_events, sizeof(*ev), 0);
    if (!ev) return 0;
    ev->type = EVENT_MEMORY_ANOMALY;
    ev->cpu  = bpf_get_smp_processor_id();
    ev->timestamp_ns = now_ns();
    ev->data.proc.pid   = get_current_tgid();
    ev->data.proc.flags = 0xAB;
    bpf_get_current_comm(ev->data.proc.comm, sizeof(ev->data.proc.comm));
    bpf_ringbuf_submit(ev, 0);
    return 0;
}
