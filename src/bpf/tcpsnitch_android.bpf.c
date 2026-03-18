#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ── Shared structures (miroir de bpf_shared_maps.h) ─────────────────────── */

#define EBPF_EV_TCP_RETRANSMIT  1

struct ebpf_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u8   type;
    __u8   pad[3];
    __u64  session_id;

    union {
        struct {
            __u16 sport;
            __u16 dport;
            __u8  saddr[4];
            __u8  daddr[4];
            __u8  saddr_v6[16];
            __u8  daddr_v6[16];
            __u32 snd_cwnd;
        } tcp_retransmit;
    };
};

/* ── Maps ────────────────────────────────────────────────────────────────── */

struct {
    __uint(type,        BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size,    sizeof(__u32));
    __uint(value_size,  sizeof(__u32));
    __uint(max_entries, 64);
} events SEC(".maps");


struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(key_size,    sizeof(__u16));
    __uint(value_size,  sizeof(__u64));
    __uint(max_entries, 4096);
} sport_to_session SEC(".maps");

/* ── Tracepoint tcp_retransmit_skb ───────────────────────────────────────── */

struct trace_tcp_retransmit_skb {
    /* common fields (8 bytes header) */
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;

    /* event fields */
    __u64 skbaddr;       /* offset 8  */
    __u64 skaddr;        /* offset 16 — pointeur vers struct sock */
    __u16 sport;         /* offset 24 */
    __u16 dport;         /* offset 26 */
    __u8  saddr[4];      /* offset 28 */
    __u8  daddr[4];      /* offset 32 */
    __u8  saddr_v6[16];  /* offset 36 */
    __u8  daddr_v6[16];  /* offset 52 */
};

#define TCP_SOCK_SND_CWND_OFFSET 844

SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retransmit(struct trace_tcp_retransmit_skb *ctx)
{
    struct ebpf_event ev = {};

    /* Timestamp en nanosecondes */
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid          = bpf_get_current_pid_tgid() >> 32;
    ev.type         = EBPF_EV_TCP_RETRANSMIT;

    /* Champs du tracepoint — lecture directe depuis ctx */
    ev.tcp_retransmit.sport = ctx->sport;
    ev.tcp_retransmit.dport = ctx->dport;

    /* saddr / daddr */
    bpf_probe_read(ev.tcp_retransmit.saddr,
                   sizeof(ev.tcp_retransmit.saddr),
                   ctx->saddr);
    bpf_probe_read(ev.tcp_retransmit.daddr,
                   sizeof(ev.tcp_retransmit.daddr),
                   ctx->daddr);
    bpf_probe_read(ev.tcp_retransmit.saddr_v6,
                   sizeof(ev.tcp_retransmit.saddr_v6),
                   ctx->saddr_v6);
    bpf_probe_read(ev.tcp_retransmit.daddr_v6,
                   sizeof(ev.tcp_retransmit.daddr_v6),
                   ctx->daddr_v6);

    /* snd_cwnd depuis struct sock via skaddr */
    if (ctx->skaddr) {
        __u32 cwnd = 0;
        bpf_probe_read(&cwnd, sizeof(cwnd),
                       (void *)(ctx->skaddr + TCP_SOCK_SND_CWND_OFFSET));
        ev.tcp_retransmit.snd_cwnd = cwnd;
    }

    /* Résolution session_id depuis sport */
    __u16 sport = ctx->sport;
    __u64 *sid = bpf_map_lookup_elem(&sport_to_session, &sport);
    ev.session_id = sid ? *sid : 0;

    /* Émettre vers userspace via perf event */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &ev, sizeof(ev));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";