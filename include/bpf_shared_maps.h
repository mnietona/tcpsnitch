#ifndef BPF_SHARED_MAPS_H
#define BPF_SHARED_MAPS_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/**
 * @brief Clé pour identifier de manière 
 * unique une ressource de fichier (file descriptor)
 */
struct fd_key {
    __u32 pid;
    __s32 fd;
};

/**
 * @brief Types d'événements pouvant
 *  être envoyés du kernel vers le collecteur en user-space.
 */
typedef enum {
    EBPF_EV_TCP_RETRANSMIT = 0,
    EBPF_EV_IOURING_COMPLETE = 1,
} EbpfEventType;


struct ebpf_event {
    __u64 session_id;
    __u64 timestamp_ns;
    EbpfEventType type;
    __u32 pid;

    union {
        /** * @brief Payload pour EBPF_EV_TCP_RETRANSMIT
         */
        struct {
            __u32 seq;
            __u32 snd_cwnd;
            __u32 srtt_us;
        } tcp_retransmit;

        /** * @brief Payload pour EBPF_EV_IOURING_COMPLETE
         */
        struct {
            __u64 user_data;
            __s32 res;
        } iouring_complete;

        
    };
};


// MAx de FD
#define BPF_FD_MAP_MAX_ENTRIES 65536

// Taille du buffer
#define BPF_RINGBUF_SIZE (4 * 1024 * 1024)

#endif /* BPF_SHARED_MAPS_H */