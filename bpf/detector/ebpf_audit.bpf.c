// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../common/maps.h"
#include "../common/helpers.h"
#include "../common/ringbuf.h"

char LICENSE[] SEC("license") = "GPL";

#define BPF_PROG_LOAD 5

struct bpf_load_ctx {
    __u32 prog_type;
    char  prog_name[BPF_OBJ_NAME_LEN];
    __u32 loader_pid;
    __u32 loader_uid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, struct bpf_load_ctx);
} bpf_load_scratch SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf_enter(struct trace_event_raw_sys_enter *ctx)
{
    if ((u32)ctx->args[0] != BPF_PROG_LOAD) return 0;
    union bpf_attr __user *uattr = (union bpf_attr __user *)ctx->args[1];
    if (!uattr) return 0;
    u32 pid = get_current_tgid();
    struct bpf_load_ctx lctx = {};
    lctx.loader_pid = pid;
    lctx.loader_uid = get_current_uid();
    bpf_probe_read_user(&lctx.prog_type, sizeof(lctx.prog_type), &uattr->prog_type);
    bpf_probe_read_user_str(lctx.prog_name, sizeof(lctx.prog_name), uattr->prog_name);
    bpf_map_update_elem(&bpf_load_scratch, &pid, &lctx, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_bpf")
int trace_bpf_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (ctx->ret <= 0) return 0;
    u32 pid = get_current_tgid();
    struct bpf_load_ctx *lctx = bpf_map_lookup_elem(&bpf_load_scratch, &pid);
    if (!lctx) return 0;
    struct ring_event *ev = bpf_ringbuf_reserve(&ring_events, sizeof(*ev), 0);
    if (!ev) { bpf_map_delete_elem(&bpf_load_scratch, &pid); return 0; }
    ev->type = EVENT_BPF_AUDIT;
    ev->cpu  = bpf_get_smp_processor_id();
    ev->timestamp_ns = now_ns();
    ev->data.bpf_prog.prog_type = lctx->prog_type;
    ev->data.bpf_prog.load_time = ev->timestamp_ns;
    ev->data.bpf_prog.prog_id   = (u32)ctx->ret;
    __builtin_memcpy(ev->data.bpf_prog.name, lctx->prog_name, sizeof(ev->data.bpf_prog.name));
    bpf_ringbuf_submit(ev, 0);
    bpf_map_delete_elem(&bpf_load_scratch, &pid);
    return 0;
}
