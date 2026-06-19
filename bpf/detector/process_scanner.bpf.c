// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../common/maps.h"
#include "../common/helpers.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    u32 child_pid = ctx->child_pid;
    struct process_info info = {};
    info.pid        = child_pid;
    info.tgid       = child_pid;
    info.ppid       = ctx->parent_pid;
    info.uid        = get_current_uid();
    info.gid        = get_current_gid();
    info.start_time = now_ns();
    __builtin_memcpy(info.comm, ctx->child_comm, TASK_COMM_LEN);
    bpf_map_update_elem(&process_cache, &child_pid, &info, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    u32 pid = get_current_pid();
    struct process_info *info = bpf_map_lookup_elem(&process_cache, &pid);
    if (!info) {
        struct process_info new_info = {};
        new_info.pid        = pid;
        new_info.tgid       = get_current_tgid();
        new_info.ppid       = get_ppid();
        new_info.uid        = get_current_uid();
        new_info.gid        = get_current_gid();
        new_info.start_time = now_ns();
        bpf_get_current_comm(new_info.comm, sizeof(new_info.comm));
        bpf_map_update_elem(&process_cache, &pid, &new_info, BPF_ANY);
        return 0;
    }
    bpf_get_current_comm(info->comm, sizeof(info->comm));
    info->tgid = get_current_tgid();
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
    u32 pid = get_current_pid();
    bpf_map_delete_elem(&process_cache, &pid);
    return 0;
}

SEC("kprobe/wake_up_new_task")
int kprobe_wake_up_new_task(struct pt_regs *ctx)
{
    struct task_struct *task = (struct task_struct *)PT_REGS_PARM1(ctx);
    if (!task) return 0;
    u32 pid  = BPF_CORE_READ(task, pid);
    u32 tgid = BPF_CORE_READ(task, tgid);
    if (bpf_map_lookup_elem(&process_cache, &pid)) return 0;
    struct process_info info = {};
    info.pid        = pid;
    info.tgid       = tgid;
    info.uid        = BPF_CORE_READ(task, cred, uid.val);
    info.start_time = now_ns();
    BPF_CORE_READ_STR_INTO(&info.comm, task, comm);
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (parent) info.ppid = BPF_CORE_READ(parent, tgid);
    bpf_map_update_elem(&process_cache, &pid, &info, BPF_NOEXIST);
    return 0;
}
