// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../common/maps.h"
#include "../common/helpers.h"
#include "../common/ringbuf.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, u64);
} getdents_count SEC(".maps");

static __always_inline int is_suspicious_path(const char *path)
{
    char buf[32] = {};
    bpf_probe_read_user_str(buf, sizeof(buf), path);
    if (buf[0]=='/'&&buf[1]=='d'&&buf[2]=='e'&&buf[3]=='v'&&buf[4]=='/'&&buf[5]=='m') return 1;
    if (buf[0]=='/'&&buf[1]=='p'&&buf[2]=='r'&&buf[3]=='o'&&buf[4]=='c'&&buf[5]=='/'&&buf[6]=='k') return 1;
    if (buf[0]=='/'&&buf[1]=='s'&&buf[2]=='y'&&buf[3]=='s'&&buf[4]=='/'&&buf[5]=='m') return 1;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    const char __user *filename = (const char __user *)ctx->args[1];
    if (!filename || !is_suspicious_path(filename)) return 0;
    struct file_access_event fa = {};
    fa.pid = get_current_pid(); fa.uid = get_current_uid();
    fa.timestamp_ns = now_ns(); fa.flags = (u32)ctx->args[2];
    bpf_get_current_comm(fa.comm, sizeof(fa.comm));
    bpf_probe_read_user_str(fa.path, sizeof(fa.path), filename);
    rb_emit_file(&fa);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open_enter(struct trace_event_raw_sys_enter *ctx)
{
    const char __user *filename = (const char __user *)ctx->args[0];
    if (!filename || !is_suspicious_path(filename)) return 0;
    struct file_access_event fa = {};
    fa.pid = get_current_pid(); fa.uid = get_current_uid();
    fa.timestamp_ns = now_ns(); fa.flags = (u32)ctx->args[1];
    bpf_get_current_comm(fa.comm, sizeof(fa.comm));
    bpf_probe_read_user_str(fa.path, sizeof(fa.path), filename);
    rb_emit_file(&fa);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int trace_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = get_current_pid();
    u64 zero = 0;
    bpf_map_update_elem(&getdents_count, &pid, &zero, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int trace_getdents_exit(struct trace_event_raw_sys_exit *ctx)
{
    u32 pid = get_current_pid();
    s64 ret = ctx->ret;
    if (ret <= 0) { bpf_map_delete_elem(&getdents_count, &pid); return 0; }
    u64 *prev = bpf_map_lookup_elem(&getdents_count, &pid);
    if (!prev) return 0;
    __sync_fetch_and_add(prev, (u64)ret);
    return 0;
}

SEC("kprobe/security_kernel_module_request")
int kprobe_module_request(struct pt_regs *ctx)
{
    struct file_access_event fa = {};
    fa.pid = get_current_pid(); fa.uid = get_current_uid();
    fa.timestamp_ns = now_ns(); fa.flags = 0xDEAD;
    bpf_get_current_comm(fa.comm, sizeof(fa.comm));
    const char *name = (const char *)PT_REGS_PARM1(ctx);
    if (name) bpf_probe_read_kernel_str(fa.path, sizeof(fa.path), name);
    rb_emit_file(&fa);
    return 0;
}
