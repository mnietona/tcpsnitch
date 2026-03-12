/*
 * ebpf_collector_android.c
 *
 * Stub no-op implementation of the eBPF collector for Android.
 *
 * Rationale: the Pixel 4a runs kernel 4.19 which does NOT support
 * libbpf CO-RE (BPF Type Format requires kernel >= 5.8).
 * All functions are safe no-ops — the rest of tcpsnitch continues
 * to function normally (LD_PRELOAD + Netlink layers are unaffected).
 *
 * Compiled instead of ebpf_collector.c when building the Android target.
 */

#ifdef __ANDROID__

#include "ebpf_collector.h"
#include <stdbool.h>
#include <stdint.h>

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

int ebpf_collector_init(const char *output_dir) {
        (void)output_dir;
        /* eBPF not supported on Android (kernel 4.19, no libbpf CO-RE). */
        return 0;
}

int ebpf_collector_start(void) {
        return 0;
}

void ebpf_collector_stop(void) {
        /* no-op */
}

/* ── State ───────────────────────────────────────────────────────────────── */

bool ebpf_collector_is_active(void) {
        return false;
}

/* ── FD / sport lifecycle (called from libc_overrides.c) ────────────────── */

void ebpf_collector_register_fd(int fd, uint64_t session_id) {
        (void)fd;
        (void)session_id;
}

void ebpf_collector_unregister_fd(int fd) {
        (void)fd;
}

void ebpf_collector_dup_fd(int old_fd, int new_fd) {
        (void)old_fd;
        (void)new_fd;
}

void ebpf_collector_register_sport(uint16_t sport, uint64_t session_id) {
        (void)sport;
        (void)session_id;
}

void ebpf_collector_unregister_sport(uint16_t sport) {
        (void)sport;
}

#endif /* __ANDROID__ */
