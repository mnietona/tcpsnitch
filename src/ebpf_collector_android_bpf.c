// Code ebpf pour android 
// meme logique que ebpf_collector.c mais avec des adaptations pour android

#ifdef TCPSNITCH_EBPF_ANDROID

#include "ebpf_collector.h"
#include "bpf_shared_maps.h"
#include "logger.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

// Chemin de l'objet BPF pré-compilé
#define BPF_OBJ_PATH "/data/tcpsnitch_android.bpf.o"


static struct {
    struct bpf_object   *obj;
    struct ring_buffer  *rb;
    int                  map_fd;
    int                  sport_map_fd;
    FILE                *jsonl_fp;
    pthread_t            thread;
    bool                 active;
    bool                 stop_flag;
    pthread_mutex_t      file_mutex;
    struct bpf_link     *link_retransmit;
    struct bpf_link     *link_iouring;
    struct bpf_link     *link_inet_state;
} g_col = {
    .obj            = NULL,
    .rb             = NULL,
    .map_fd         = -1,
    .sport_map_fd   = -1,
    .jsonl_fp       = NULL,
    .active         = false,
    .stop_flag      = false,
    .file_mutex     = PTHREAD_MUTEX_INITIALIZER,
    .link_retransmit = NULL,
    .link_iouring    = NULL,
    .link_inet_state = NULL,
};

static void write_event_jsonl(const struct ebpf_event *ev)
{
    if (!g_col.jsonl_fp)
        return;

    const char *type_str;
    switch (ev->type) {
    case EBPF_EV_TCP_RETRANSMIT:   type_str = "tcp_retransmit";   break;
    case EBPF_EV_IOURING_COMPLETE: type_str = "iouring_complete"; break;
    default:                        type_str = "unknown";           break;
    }

    pthread_mutex_lock(&g_col.file_mutex);

    fprintf(g_col.jsonl_fp,
            "{\"source\":\"ebpf\","
            "\"type\":\"%s\","
            "\"session_id\":%" PRIu64 ","
            "\"timestamp_ns\":%" PRIu64 ","
            "\"pid\":%" PRIu32 ",",
            type_str,
            (uint64_t)ev->session_id,
            (uint64_t)ev->timestamp_ns,
            (uint32_t)ev->pid);

    switch (ev->type) {
    case EBPF_EV_TCP_RETRANSMIT:
        fprintf(g_col.jsonl_fp,
                "\"seq\":%" PRIu32 ","
                "\"snd_cwnd\":%" PRIu32 ","
                "\"srtt_us\":%" PRIu32,
                (uint32_t)ev->tcp_retransmit.seq,
                (uint32_t)ev->tcp_retransmit.snd_cwnd,
                (uint32_t)ev->tcp_retransmit.srtt_us);
        break;
    case EBPF_EV_IOURING_COMPLETE:
        fprintf(g_col.jsonl_fp,
                "\"user_data\":%" PRIu64 ","
                "\"res\":%" PRId32,
                (uint64_t)ev->iouring_complete.user_data,
                (int32_t)ev->iouring_complete.res);
        break;
    }

    fprintf(g_col.jsonl_fp, "}\n");
    pthread_mutex_unlock(&g_col.file_mutex);
}

        break;
    }

    fprintf(g_col.jsonl_fp, "}\n");
    pthread_mutex_unlock(&g_col.file_mutex);
}


static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx; (void)data_sz;
    const struct ebpf_event *ev = (const struct ebpf_event *)data;
    if (ev->session_id == 9999)
        return 0;
    write_event_jsonl(ev);
    return 0;
}

static void *polling_thread(void *arg)
{
    (void)arg;
    LOG(INFO, "eBPF Android collector polling thread started.");
    while (!g_col.stop_flag) {
        int n = ring_buffer__poll(g_col.rb, 100 /* ms */);
        if (n < 0 && n != -EINTR) {
            LOG(ERROR, "ring_buffer__poll() failed: %s", strerror(-n));
            break;
        }
    }
    pthread_mutex_lock(&g_col.file_mutex);
    if (g_col.jsonl_fp)
        fflush(g_col.jsonl_fp);
    pthread_mutex_unlock(&g_col.file_mutex);
    LOG(INFO, "eBPF Android collector polling thread stopped.");
    return NULL;
}

static struct bpf_link *attach_prog(const char *name, bool warn)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(g_col.obj, name);
    if (!prog) {
        if (warn) {
            LOG(WARN, "eBPF Android: program '%s' not found in object.", name);
        } else {
            LOG(INFO, "eBPF Android: program '%s' absent (normal).", name);
        }
        return NULL;
    }
    struct bpf_link *lnk = bpf_program__attach(prog);
    if (!lnk) {
        LOG(WARN, "eBPF Android: attach '%s' failed: %s", name, strerror(errno));
    } else {
        LOG(INFO, "eBPF Android: attached '%s'.", name);
    }
    return lnk;
}

int ebpf_collector_init(const char *output_dir)
{
    /* 1. Open output JSONL */
    char jsonl_path[512];
    snprintf(jsonl_path, sizeof(jsonl_path), "%s/ebpf_events.jsonl", output_dir);
    g_col.jsonl_fp = fopen(jsonl_path, "w");
    if (!g_col.jsonl_fp) {
        LOG(ERROR, "eBPF Android: fopen(%s): %s", jsonl_path, strerror(errno));
        return -1;
    }

    /* 2. Open the BPF object from disk */
    g_col.obj = bpf_object__open_file(BPF_OBJ_PATH, NULL);
    if (!g_col.obj) {
        LOG(ERROR, "eBPF Android: bpf_object__open_file(%s) failed: %s",
            BPF_OBJ_PATH, strerror(errno));
        goto err_close_file;
    }

    /* 3. Load (verifies + uploads to kernel) */
    int ret = bpf_object__load(g_col.obj);
    if (ret) {
        LOG(ERROR, "eBPF Android: bpf_object__load() failed: %s", strerror(-ret));
        goto err_close_obj;
    }

    /* 4. Attach programs — failures are non-fatal except if ALL fail */
    int attached = 0;

    g_col.link_retransmit = attach_prog("trace_tcp_retransmit", true);
    if (g_col.link_retransmit) attached++;

    g_col.link_iouring    = attach_prog("trace_iouring_complete", false);
    if (g_col.link_iouring)    attached++;

    g_col.link_inet_state = attach_prog("trace_inet_sock_set_state", true);
    if (g_col.link_inet_state) attached++;

    if (attached == 0) {
        LOG(ERROR, "eBPF Android: no programs attached — eBPF disabled.");
        ret = -ENOENT;
        goto err_close_obj;
    }

    /* 5. Get map FDs */
    struct bpf_map *m;

    m = bpf_object__find_map_by_name(g_col.obj, "sport_to_session");
    if (!m) { LOG(ERROR, "eBPF Android: map sport_to_session not found."); goto err_close_obj; }
    g_col.sport_map_fd = bpf_map__fd(m);

    m = bpf_object__find_map_by_name(g_col.obj, "fd_to_session_map");
    if (!m) { LOG(ERROR, "eBPF Android: map fd_to_session_map not found."); goto err_close_obj; }
    g_col.map_fd = bpf_map__fd(m);

    m = bpf_object__find_map_by_name(g_col.obj, "events");
    if (!m) { LOG(ERROR, "eBPF Android: map events not found."); goto err_close_obj; }

    /* 6. Setup ring buffer */
    g_col.rb = ring_buffer__new(bpf_map__fd(m), handle_event, NULL, NULL);
    if (!g_col.rb) {
        LOG(ERROR, "eBPF Android: ring_buffer__new() failed.");
        goto err_close_obj;
    }

    LOG(INFO, "eBPF Android collector initialized. Output: %s", jsonl_path);
    return 0;

err_close_obj:
    bpf_object__close(g_col.obj);
    g_col.obj = NULL;
err_close_file:
    fclose(g_col.jsonl_fp);
    g_col.jsonl_fp = NULL;
    return -1;
}

int ebpf_collector_start(void)
{
    if (!g_col.obj || !g_col.rb) {
        LOG(WARN, "ebpf_collector_start: not initialized.");
        return -1;
    }
    g_col.stop_flag = false;
    int ret = pthread_create(&g_col.thread, NULL, polling_thread, NULL);
    if (ret) {
        LOG(ERROR, "ebpf_collector_start: pthread_create: %s", strerror(ret));
        return -1;
    }
    g_col.active = true;
    LOG(INFO, "eBPF Android collector thread started.");
    return 0;
}

void ebpf_collector_stop(void)
{
    if (!g_col.active)
        return;
    g_col.stop_flag = true;
    pthread_join(g_col.thread, NULL);
    g_col.active = false;

    if (g_col.rb)             { ring_buffer__free(g_col.rb); g_col.rb = NULL; }
    if (g_col.link_retransmit){ bpf_link__destroy(g_col.link_retransmit); g_col.link_retransmit = NULL; }
    if (g_col.link_iouring)   { bpf_link__destroy(g_col.link_iouring);    g_col.link_iouring    = NULL; }
    if (g_col.link_inet_state){ bpf_link__destroy(g_col.link_inet_state); g_col.link_inet_state = NULL; }
    if (g_col.obj)            { bpf_object__close(g_col.obj);              g_col.obj             = NULL; }

    pthread_mutex_lock(&g_col.file_mutex);
    if (g_col.jsonl_fp) { fflush(g_col.jsonl_fp); fclose(g_col.jsonl_fp); g_col.jsonl_fp = NULL; }
    pthread_mutex_unlock(&g_col.file_mutex);

    LOG(INFO, "eBPF Android collector stopped.");
}

bool ebpf_collector_is_active(void) { return g_col.active; }

void ebpf_collector_register_fd(int fd, uint64_t session_id)
{
    if (g_col.map_fd < 0) return;
    struct fd_key key = { .pid = (uint32_t)getpid(), .fd = (int32_t)fd };
    if (bpf_map_update_elem(g_col.map_fd, &key, &session_id, BPF_ANY))
        LOG(WARN, "register_fd(%d) failed: %s", fd, strerror(errno));
}

void ebpf_collector_unregister_fd(int fd)
{
    if (g_col.map_fd < 0) return;
    struct fd_key key = { .pid = (uint32_t)getpid(), .fd = (int32_t)fd };
    int r = bpf_map_delete_elem(g_col.map_fd, &key);
    if (r && errno != ENOENT)
        LOG(WARN, "unregister_fd(%d) failed: %s", fd, strerror(errno));
}

void ebpf_collector_dup_fd(int old_fd, int new_fd)
{
    if (g_col.map_fd < 0) return;
    uint32_t pid = (uint32_t)getpid();
    struct fd_key ok = { .pid = pid, .fd = (int32_t)old_fd };
    uint64_t sid = 0;
    if (bpf_map_lookup_elem(g_col.map_fd, &ok, &sid)) return;
    struct fd_key nk = { .pid = pid, .fd = (int32_t)new_fd };
    if (bpf_map_update_elem(g_col.map_fd, &nk, &sid, BPF_ANY))
        LOG(WARN, "dup_fd(%d→%d) failed: %s", old_fd, new_fd, strerror(errno));
}

void ebpf_collector_register_sport(uint16_t sport, uint64_t session_id)
{
    if (g_col.sport_map_fd < 0) return;
    if (bpf_map_update_elem(g_col.sport_map_fd, &sport, &session_id, BPF_ANY))
        LOG(WARN, "register_sport(%u) failed: %s", sport, strerror(errno));
}

void ebpf_collector_unregister_sport(uint16_t sport)
{
    if (g_col.sport_map_fd < 0) return;
    bpf_map_delete_elem(g_col.sport_map_fd, &sport);
}

#endif /* TCPSNITCH_EBPF_ANDROID */