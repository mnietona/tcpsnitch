#ifndef BPF_SHARED_MAPS_H
#define BPF_SHARED_MAPS_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/**
 * @brief Lookup key for the BPF hash map mapping open FDs to tcpsnitch
 * sessions.
 */
struct fd_key {
    __u32 pid;
    __s32 fd;
};

/**
 * @brief Identifiers for events dispatched via the eBPF ring buffer.
 */
typedef enum {
    EBPF_EV_TCP_RETRANSMIT = 0,
    EBPF_EV_IOURING_COMPLETE = 1,
} EbpfEventType;

/**
 * @brief Standardized event payload sent from the kernel to the user-space
 * collector.
 */
struct ebpf_event {
    __u64 session_id;
    __u64 timestamp_ns;
    EbpfEventType type;
    __u32 pid;

    union {
        /** * @brief Payload for EBPF_EV_TCP_RETRANSMIT
         * Captured at tcp_retransmit_skb tracepoint.
         */
        struct {
            __u32 seq;
            __u32 snd_cwnd;
            __u32 srtt_us;
        } tcp_retransmit;

        /** * @brief Payload for EBPF_EV_IOURING_COMPLETE
         */
        struct {
            __u64 user_data;
            __s32 res;
        } iouring_complete;

        
    };
};

/* --- BPF Map Tuning Constants --- */

// Maximum number of concurrently tracked File Descriptors in the hash map.
#define BPF_FD_MAP_MAX_ENTRIES 65536

// Size of the eBPF ring buffer (4 MB) to prevent drops under heavy network
// load.
#define BPF_RINGBUF_SIZE (4 * 1024 * 1024)

#endif /* BPF_SHARED_MAPS_H */