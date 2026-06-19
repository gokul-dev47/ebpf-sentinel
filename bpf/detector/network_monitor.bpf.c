// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/in.h>
#include <net/sock.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "../common/maps.h"
#include "../common/helpers.h"
#include "../common/ringbuf.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, u32);
    __type(value, struct network_event);
} connect_in_progress SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} c2_ip_list SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;
    u32 pid = get_current_tgid();
    struct network_event ne = {};
    ne.pid = pid; ne.timestamp_ns = now_ns(); ne.proto = 6;
    ne.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ne.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    ne.sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    ne.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    bpf_get_current_comm(ne.comm, sizeof(ne.comm));
    bpf_map_update_elem(&connect_in_progress, &pid, &ne, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe_tcp_connect(struct pt_regs *ctx)
{
    if ((int)PT_REGS_RC(ctx) != 0) return 0;
    u32 pid = get_current_tgid();
    struct network_event *ne = bpf_map_lookup_elem(&connect_in_progress, &pid);
    if (!ne) return 0;
    u64 key = ((u64)pid << 16) | ne->dport;
    bpf_map_update_elem(&connection_cache, &key, ne, BPF_ANY);
    u8 *is_c2 = bpf_map_lookup_elem(&c2_ip_list, &ne->daddr);
    if (is_c2 && *is_c2) rb_emit_network(ne);
    bpf_map_delete_elem(&connect_in_progress, &pid);
    return 0;
}

SEC("kprobe/inet_listen")
int kprobe_inet_listen(struct pt_regs *ctx)
{
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    if (!sock) return 0;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) return 0;
    struct network_event ne = {};
    ne.pid = get_current_tgid(); ne.timestamp_ns = now_ns(); ne.proto = 6;
    ne.sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    ne.dport = 0xFFFD;
    bpf_get_current_comm(ne.comm, sizeof(ne.comm));
    rb_emit_network(&ne);
    return 0;
}
