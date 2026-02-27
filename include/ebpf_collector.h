#ifndef EBPF_COLLECTOR_H
#define EBPF_COLLECTOR_H

#include <stdbool.h>
#include <stdint.h>

/* ── Lifecycle Management ────────────────────────────────────────────────── */

int ebpf_collector_init(const char *output_dir);
int ebpf_collector_start(void);
void ebpf_collector_stop(void);

/* ── File Descriptor Lifecycle (BPF Map Sync) ────────────────────────────── */

void ebpf_collector_register_fd(int fd, uint64_t session_id);
void ebpf_collector_unregister_fd(int fd);
void ebpf_collector_dup_fd(int old_fd, int new_fd);
void ebpf_collector_register_sport(uint16_t sport, uint64_t session_id);
void ebpf_collector_unregister_sport(uint16_t sport);

/* ── State Inquiries ─────────────────────────────────────────────────────── */

bool ebpf_collector_is_active(void);

#endif /* EBPF_COLLECTOR_H */