// Code ebpf pour smartphone non supporté, implémentation de stub pour éviter les erreurs de compilation
#ifdef __ANDROID__

#include "ebpf_collector.h"
#include <stdbool.h>
#include <stdint.h>


int ebpf_collector_init(const char *output_dir) {
    (void)output_dir;
    return 0;
}

int ebpf_collector_start(void) {
    return 0;
}

void ebpf_collector_stop(void) {
    /* no-op */
}


bool ebpf_collector_is_active(void) {
    return false;
}


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
