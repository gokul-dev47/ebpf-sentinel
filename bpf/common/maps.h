/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MAPS_H__
#define __MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES        65536
#define MAX_PROC_ENTRIES   4096
#define RINGBUF_SIZE       (4 * 1024 * 1024)
#define TASK_COMM_LEN      16
#define MAX_PATH_LEN       256
#define MAX_SYSCALLS       512
#define MAX_CONN_ENTRIES   1024

#define EVENT_SYSCALL_ANOMALY   1
#define EVENT_HIDDEN_PROCESS    2
#define EVENT_SUSPICIOUS_FILE   3
#define EVENT_NETWORK_ANOMALY   4
#define EVENT_BPF_AUDIT         5
#define EVENT_MEMORY_ANOMALY    6

struct process_info {
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char  comm[TASK_COMM_LEN];
    __u64 start_time;
    __u8  flags;
    __u8  pad[3];
};

struct syscall_stats {
    __u64 count;
    __u64 total_latency_ns;
    __u64 max_latency_ns;
    __u64 min_latency_ns;
    __u64 last_seen_ns;
    __u64 mean_ns;
    __u64 variance_ns;
};

struct syscall_enter_ctx {
    __u64 start_ns;
    __u32 syscall_nr;
    __u32 pad;
};

struct file_access_event {
    __u32 pid;
    __u32 uid;
    char  comm[TASK_COMM_LEN];
    char  path[MAX_PATH_LEN];
    __u64 timestamp_ns;
    __u32 flags;
    __u32 pad;
};

struct network_event {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 timestamp_ns;
    char  comm[TASK_COMM_LEN];
    __u8  proto;
    __u8  pad[3];
};

struct bpf_prog_info_event {
    __u32 prog_id;
    __u32 prog_type;
    __u64 load_time;
    char  name[BPF_OBJ_NAME_LEN];
    __u8  tag[BPF_TAG_SIZE];
};

struct ring_event {
    __u32 type;
    __u32 cpu;
    __u64 timestamp_ns;
    union {
        struct process_info      proc;
        struct file_access_event file;
        struct network_event     net;
        struct bpf_prog_info_event bpf_prog;
    } data;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} ring_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROC_ENTRIES);
    __type(key, __u32);
    __type(value, struct process_info);
} process_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SYSCALLS);
    __type(key, __u32);
    __type(value, struct syscall_stats);
} syscall_baseline SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_SYSCALLS);
    __type(key, __u32);
    __type(value, struct syscall_enter_ctx);
} syscall_enter_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONN_ENTRIES);
    __type(key, __u64);
    __type(value, struct network_event);
} connection_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

#endif /* __MAPS_H__ */
