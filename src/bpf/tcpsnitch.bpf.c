// SPDX-License-Identifier: GPL-2.0
/**
 * @file tcpsnitch.bpf.c
 * @brief Kernel-side eBPF programs for TCP retransmission and socket lifecycle tracing.
 * * Compiles into CO-RE (Compile Once - Run Everywhere) BPF bytecode.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_shared_maps.h"

/* ── Maps Definitions ────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fd_key);
    __type(value, __u64);
    __uint(max_entries, BPF_FD_MAP_MAX_ENTRIES);
} fd_to_session_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,  __u16);  //port
    __type(value, __u64); //session_id
} sport_to_session SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, BPF_RINGBUF_SIZE);
} events SEC(".maps");

/* ── Internal Helpers ────────────────────────────────────────────────────── */

static __always_inline __u64 lookup_session(__u32 pid, __s32 fd)
{
    struct fd_key key = { .pid = pid, .fd = fd };
    __u64 *val = bpf_map_lookup_elem(&fd_to_session_map, &key);
    return val ? *val : 0;
}

static __always_inline struct ebpf_event *
emit_event(__u64 session_id, EbpfEventType type, __u32 pid)
{
    struct ebpf_event *ev = bpf_ringbuf_reserve(&events, sizeof(struct ebpf_event), 0);
    if (!ev) return NULL;

    __builtin_memset(ev, 0, sizeof(*ev));

    ev->session_id   = session_id;
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->type         = type;
    ev->pid          = pid;
    return ev;
}

/* ── Program 1: TCP Retransmissions ───────────────────────────────────── */

struct trace_event_raw_tcp_event_sk_skb {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;

    const void    *skbaddr;
    const void    *skaddr;
    int            state;
    __u16          sport;
    __u16          dport;
    __u16          family;
    __u8           saddr[4];
    __u8           daddr[4];
    __u8           saddr_v6[16];
    __u8           daddr_v6[16];
};

SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retransmit(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Lookup session via source port (sport) 
    __u16 sport      = ctx->sport;
    __u64 *sk_val    = bpf_map_lookup_elem(&sport_to_session, &sport);
    
    // Fallback to 9999 if not found (untracked socket) 
    __u64 session_id = sk_val ? *sk_val : 9999;

    struct ebpf_event *ev = emit_event(session_id, EBPF_EV_TCP_RETRANSMIT, pid);
    if (!ev) return 0;

    const struct sock *sk = (const struct sock *)ctx->skaddr;
    const struct tcp_sock *tp = (const struct tcp_sock *)sk;

    // Capture TCP Congestion metrics using CO-RE
    ev->tcp_retransmit.snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);
    ev->tcp_retransmit.srtt_us  = BPF_CORE_READ(tp, srtt_us) >> 3;
    ev->tcp_retransmit.seq      = BPF_CORE_READ(tp, snd_una);  

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── Program 2: io_uring Completions ──────────────────────────────────── */

SEC("tracepoint/io_uring/io_uring_complete")
int trace_iouring_complete(struct trace_event_raw_io_uring_complete *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 user_data = 0;

    bpf_probe_read_kernel(&user_data, sizeof(user_data), &ctx->user_data);

    __s32 fd = (__s32)user_data;
    __u64 session_id = lookup_session(pid, fd);

    struct ebpf_event *ev = emit_event(session_id, EBPF_EV_IOURING_COMPLETE, pid);
    if (!ev) return 0;

    ev->iouring_complete.user_data = user_data;
    ev->iouring_complete.res       = ctx->res;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── Program 3: MPTCP Subflows ────────────────────────────────────────── */

struct trace_event_raw_mptcp_subflow_create {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;

    __u32 token;
    __u8  family;
    __u8  backup;
    __u16 sport;
    __u16 dport;
};

SEC("tracepoint/mptcp/mptcp_subflow_create")
int trace_mptcp_subflow(struct trace_event_raw_mptcp_subflow_create *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct ebpf_event *ev = emit_event(0, EBPF_EV_MPTCP_SUBFLOW, pid);
    if (!ev) return 0;

    ev->mptcp_subflow.token     = ctx->token;
    ev->mptcp_subflow.family    = ctx->family;
    ev->mptcp_subflow.is_backup = ctx->backup;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── Lifecycle Management ────────────────────────────────────────────────── */


SEC("tp/tcp/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) 
{
    // TCP_CLOSE = 7, TCP_CLOSE_WAIT = 8 
    if (ctx->newstate == 7 || ctx->newstate == 8) {
        __u16 sport = ctx->sport;
        bpf_map_delete_elem(&sport_to_session, &sport);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";