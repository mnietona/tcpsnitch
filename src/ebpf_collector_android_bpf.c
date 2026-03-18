#if defined(__ANDROID__) && defined(TCPSNITCH_EBPF_ANDROID)

#include "ebpf_collector.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>

#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <asm/unistd.h>

#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* ── Constantes ──────────────────────────────────────────────────────────── */

#define MAX_CPUS         8
#define PERF_PAGES       8
#define PERF_PAGE_SIZE   4096
#define PERF_MMAP_SIZE   (PERF_PAGE_SIZE * (PERF_PAGES + 1))
#define BPF_OBJ_PATH     "/data/tcpsnitch_android.bpf.o"
#define MAX_SPORT_ENTRIES 4096

/* ── Structures miroir de tcpsnitch_android.bpf.c ────────────────────────── */

#define EBPF_EV_TCP_RETRANSMIT 1

struct ebpf_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint8_t  type;
    uint8_t  pad[3];
    uint64_t session_id;

    union {
        struct {
            uint16_t sport;
            uint16_t dport;
            uint8_t  saddr[4];
            uint8_t  daddr[4];
            uint8_t  saddr_v6[16];
            uint8_t  daddr_v6[16];
            uint32_t snd_cwnd;
        } tcp_retransmit;
    };
};

/* ── ELF loader minimal ──────────────────────────────────────────────────── */

#include <elf.h>

typedef struct {
    uint8_t  *data;
    size_t    size;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdrs;
    char      *shstrtab;
} BpfElf;

static BpfElf g_elf = {0};

/* Map fds extraits du BPF object */
static int g_map_events_fd      = -1;
static int g_map_sport_fd       = -1;
static int g_prog_fd            = -1;

/* Perf event fds par CPU */
static int g_perf_fds[MAX_CPUS];
static void *g_perf_mmaps[MAX_CPUS];
static int g_ncpus = 0;

/* Thread de lecture */
static pthread_t g_thread;
static volatile bool g_running = false;
static bool g_initialized = false;

/* Fichier de sortie JSON */
static FILE *g_output_fp = NULL;

/* ── Wrappers syscall ────────────────────────────────────────────────────── */

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return (int)syscall(__NR_bpf, cmd, attr, size);
}

static int sys_perf_event_open(struct perf_event_attr *attr,
                                pid_t pid, int cpu, int group_fd,
                                unsigned long flags)
{
    return (int)syscall(__NR_perf_event_open, attr, pid, cpu,
                        group_fd, flags);
}

/* ── ELF loader ──────────────────────────────────────────────────────────── */

static int load_bpf_elf(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        LOG(ERROR, "ebpf_android: open(%s) failed: %s", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }

    g_elf.size = (size_t)st.st_size;
    g_elf.data = malloc(g_elf.size);
    if (!g_elf.data) { close(fd); return -1; }

    if (read(fd, g_elf.data, g_elf.size) != (ssize_t)g_elf.size) {
        close(fd); free(g_elf.data); g_elf.data = NULL; return -1;
    }
    close(fd);

    g_elf.ehdr    = (Elf64_Ehdr *)g_elf.data;
    g_elf.shdrs   = (Elf64_Shdr *)(g_elf.data + g_elf.ehdr->e_shoff);
    g_elf.shstrtab = (char *)(g_elf.data +
                     g_elf.shdrs[g_elf.ehdr->e_shstrndx].sh_offset);
    return 0;
}

static Elf64_Shdr *find_section(const char *name)
{
    for (int i = 0; i < g_elf.ehdr->e_shnum; i++) {
        const char *sname = g_elf.shstrtab + g_elf.shdrs[i].sh_name;
        if (strcmp(sname, name) == 0)
            return &g_elf.shdrs[i];
    }
    return NULL;
}

/* ── Création des maps BPF ───────────────────────────────────────────────── */

static int create_maps(void)
{
    /* Map 1 : events (PERF_EVENT_ARRAY) */
    union bpf_attr attr_events = {};
    attr_events.map_type    = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
    attr_events.key_size    = sizeof(uint32_t);
    attr_events.value_size  = sizeof(uint32_t);
    attr_events.max_entries = MAX_CPUS;

    g_map_events_fd = sys_bpf(BPF_MAP_CREATE, &attr_events, sizeof(attr_events));
    if (g_map_events_fd < 0) {
        LOG(ERROR, "ebpf_android: BPF_MAP_CREATE events failed: %s", strerror(errno));
        return -1;
    }

    /* Map 2 : sport_to_session (HASH) */
    union bpf_attr attr_sport = {};
    attr_sport.map_type    = BPF_MAP_TYPE_HASH;
    attr_sport.key_size    = sizeof(uint16_t);
    attr_sport.value_size  = sizeof(uint64_t);
    attr_sport.max_entries = MAX_SPORT_ENTRIES;

    g_map_sport_fd = sys_bpf(BPF_MAP_CREATE, &attr_sport, sizeof(attr_sport));
    if (g_map_sport_fd < 0) {
        LOG(ERROR, "ebpf_android: BPF_MAP_CREATE sport failed: %s", strerror(errno));
        return -1;
    }

    LOG(INFO, "ebpf_android: maps created (events_fd=%d sport_fd=%d)",
        g_map_events_fd, g_map_sport_fd);
    return 0;
}

/* ── Chargement du programme BPF ─────────────────────────────────────────── */

static int apply_relocations(Elf64_Shdr *prog_shdr, uint8_t *insns,
                              size_t insns_size)
{
    /* Chercher la section de relocation correspondante */
    char rel_name[128];
    const char *prog_name = g_elf.shstrtab + prog_shdr->sh_name;
    snprintf(rel_name, sizeof(rel_name), ".rel%s", prog_name);

    Elf64_Shdr *rel_shdr = find_section(rel_name);
    if (!rel_shdr) {
        /* Pas de relocations = programme simple, OK */
        return 0;
    }

    /* Table des symboles */
    Elf64_Shdr *sym_shdr = NULL;
    for (int i = 0; i < g_elf.ehdr->e_shnum; i++) {
        if (g_elf.shdrs[i].sh_type == SHT_SYMTAB) {
            sym_shdr = &g_elf.shdrs[i];
            break;
        }
    }
    if (!sym_shdr) return -1;

    Elf64_Sym  *syms    = (Elf64_Sym *)(g_elf.data + sym_shdr->sh_offset);
    char       *strtab  = (char *)(g_elf.data +
                           g_elf.shdrs[sym_shdr->sh_link].sh_offset);
    Elf64_Rel  *rels    = (Elf64_Rel *)(g_elf.data + rel_shdr->sh_offset);
    size_t      nrels   = rel_shdr->sh_size / sizeof(Elf64_Rel);

    for (size_t i = 0; i < nrels; i++) {
        uint32_t sym_idx = ELF64_R_SYM(rels[i].r_info);
        Elf64_Sym *sym   = &syms[sym_idx];
        const char *name = strtab + sym->st_name;

        /* Trouver le fd de la map correspondante */
        int map_fd = -1;
        if (strstr(name, "events"))
            map_fd = g_map_events_fd;
        else if (strstr(name, "sport_to_session"))
            map_fd = g_map_sport_fd;

        if (map_fd < 0) {
            LOG(WARN, "ebpf_android: unknown map '%s' in relocation", name);
            continue;
        }

        /* Patcher l'instruction BPF à l'offset de relocation */
        size_t insn_off = rels[i].r_offset;
        if (insn_off + 8 > insns_size) continue;

        /* BPF_LD_MAP_FD instruction = two 8-byte insns
         * insn[0].imm = map_fd
         * insn[1].imm = 0 (upper 32 bits) */
        struct bpf_insn *insn = (struct bpf_insn *)(insns + insn_off);
        insn[0].imm = map_fd;
        insn[1].imm = 0;
    }

    return 0;
}

static int load_program(void)
{
    /* Chercher la section tracepoint */
    Elf64_Shdr *prog_shdr = NULL;
    for (int i = 0; i < g_elf.ehdr->e_shnum; i++) {
        const char *name = g_elf.shstrtab + g_elf.shdrs[i].sh_name;
        if (strncmp(name, "tracepoint/tcp/tcp_retransmit_skb",
                    strlen("tracepoint/tcp/tcp_retransmit_skb")) == 0) {
            prog_shdr = &g_elf.shdrs[i];
            break;
        }
    }

    if (!prog_shdr) {
        LOG(ERROR, "ebpf_android: tracepoint section not found in ELF");
        return -1;
    }

    uint8_t *insns     = g_elf.data + prog_shdr->sh_offset;
    size_t   insns_size = prog_shdr->sh_size;

    /* Appliquer les relocations (patch map fds) */
    if (apply_relocations(prog_shdr, insns, insns_size) < 0) {
        LOG(ERROR, "ebpf_android: relocation failed");
        return -1;
    }

    /* Buffer pour les messages de vérification BPF */
    char log_buf[4096] = {0};

    union bpf_attr attr = {};
    attr.prog_type  = BPF_PROG_TYPE_TRACEPOINT;
    attr.insns      = (uint64_t)(uintptr_t)insns;
    attr.insn_cnt   = (uint32_t)(insns_size / 8);
    attr.license    = (uint64_t)(uintptr_t)"GPL";
    attr.log_buf    = (uint64_t)(uintptr_t)log_buf;
    attr.log_size   = sizeof(log_buf);
    attr.log_level  = 1;

    g_prog_fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (g_prog_fd < 0) {
        LOG(ERROR, "ebpf_android: BPF_PROG_LOAD failed: %s", strerror(errno));
        if (log_buf[0]) {
            LOG(ERROR, "Verifier: %.400s", log_buf);
        }
        return -1;
    }

    LOG(INFO, "ebpf_android: program loaded (fd=%d, %zu insns)",
        g_prog_fd, insns_size / 8);
    return 0;
}

/* ── Attachement au tracepoint via perf_event_open ───────────────────────── */

static int attach_tracepoint(void)
{
    /* Lire l'ID du tracepoint tcp_retransmit_skb */
    const char *id_path =
        "/sys/kernel/tracing/events/tcp/tcp_retransmit_skb/id";
    FILE *f = fopen(id_path, "r");
    if (!f) {
        /* Fallback debugfs */
        id_path = "/sys/kernel/debug/tracing/events/tcp/tcp_retransmit_skb/id";
        f = fopen(id_path, "r");
    }
    if (!f) {
        LOG(ERROR, "ebpf_android: cannot read tracepoint id");
        return -1;
    }

    int tp_id = 0;
    fscanf(f, "%d", &tp_id);
    fclose(f);

    LOG(INFO, "ebpf_android: tcp_retransmit_skb id=%d", tp_id);

    /* Attacher sur chaque CPU */
    g_ncpus = 0;

    for (int cpu = 0; cpu < MAX_CPUS; cpu++) {
        struct perf_event_attr pe = {};
        pe.type          = PERF_TYPE_TRACEPOINT;
        pe.size          = sizeof(pe);
        pe.config        = tp_id;
        pe.sample_type   = PERF_SAMPLE_RAW;
        pe.sample_period = 1;
        pe.wakeup_events = 1;

        int pfd = sys_perf_event_open(&pe, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (pfd < 0) {
            /* CPU hors ligne — normal sur certains kernels */
            g_perf_fds[cpu] = -1;
            g_perf_mmaps[cpu] = NULL;
            continue;
        }

        /* Attacher le programme BPF à ce perf event */
        if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, g_prog_fd) < 0) {
            LOG(ERROR, "ebpf_android: PERF_EVENT_IOC_SET_BPF cpu=%d: %s",
                cpu, strerror(errno));
            close(pfd);
            g_perf_fds[cpu] = -1;
            continue;
        }

        /* Mmap le ring buffer perf */
        void *mmap_base = mmap(NULL, PERF_MMAP_SIZE,
                               PROT_READ | PROT_WRITE,
                               MAP_SHARED, pfd, 0);
        if (mmap_base == MAP_FAILED) {
            LOG(ERROR, "ebpf_android: mmap cpu=%d failed: %s",
                cpu, strerror(errno));
            close(pfd);
            g_perf_fds[cpu] = -1;
            continue;
        }

        /* Activer le perf event */
        ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);

        g_perf_fds[cpu]   = pfd;
        g_perf_mmaps[cpu] = mmap_base;
        g_ncpus++;

        LOG(INFO, "ebpf_android: attached cpu=%d pfd=%d", cpu, pfd);
    }

    if (g_ncpus == 0) {
        LOG(ERROR, "ebpf_android: no CPUs attached");
        return -1;
    }

    LOG(INFO, "ebpf_android: attached to %d CPUs", g_ncpus);
    return 0;
}

/* ── Thread de lecture des événements perf ───────────────────────────────── */

static void write_event_jsonl(const struct ebpf_event *ev)
{
    if (!g_output_fp) return;

    char saddr_str[INET6_ADDRSTRLEN] = {0};
    char daddr_str[INET6_ADDRSTRLEN] = {0};

    /* IPv4 simple */
    snprintf(saddr_str, sizeof(saddr_str), "%u.%u.%u.%u",
             ev->tcp_retransmit.saddr[0], ev->tcp_retransmit.saddr[1],
             ev->tcp_retransmit.saddr[2], ev->tcp_retransmit.saddr[3]);
    snprintf(daddr_str, sizeof(daddr_str), "%u.%u.%u.%u",
             ev->tcp_retransmit.daddr[0], ev->tcp_retransmit.daddr[1],
             ev->tcp_retransmit.daddr[2], ev->tcp_retransmit.daddr[3]);

    uint64_t ts_usec = ev->timestamp_ns / 1000;

    fprintf(g_output_fp,
        "{\"source\":\"ebpf\","
        "\"type\":\"tcp_retransmit\","
        "\"timestamp_usec\":%lu,"
        "\"pid\":%u,"
        "\"session_id\":%lu,"
        "\"details\":{"
            "\"sport\":%u,"
            "\"dport\":%u,"
            "\"saddr\":\"%s\","
            "\"daddr\":\"%s\","
            "\"snd_cwnd\":%u"
        "}}\n",
        (unsigned long)ts_usec,
        ev->pid,
        (unsigned long)ev->session_id,
        ev->tcp_retransmit.sport,
        ev->tcp_retransmit.dport,
        saddr_str,
        daddr_str,
        ev->tcp_retransmit.snd_cwnd);

    fflush(g_output_fp);
}

static void read_perf_cpu(int cpu)
{
    struct perf_event_mmap_page *header =
        (struct perf_event_mmap_page *)g_perf_mmaps[cpu];

    uint64_t data_head = __atomic_load_n(&header->data_head, __ATOMIC_ACQUIRE);
    uint64_t data_tail = header->data_tail;

    uint8_t *base = (uint8_t *)g_perf_mmaps[cpu] + PERF_PAGE_SIZE;
    uint64_t size  = (uint64_t)(PERF_PAGES * PERF_PAGE_SIZE);

    while (data_tail < data_head) {
        struct perf_event_header *ehdr =
            (struct perf_event_header *)(base + (data_tail % size));

        if (ehdr->type == PERF_RECORD_SAMPLE) {
            /*
             * Format PERF_SAMPLE_RAW :
             *   u32 size
             *   u8  data[size]
             */
            uint8_t *payload = (uint8_t *)(ehdr + 1);
            uint32_t raw_size = *(uint32_t *)payload;
            payload += sizeof(uint32_t);

            if (raw_size == sizeof(struct ebpf_event)) {
                write_event_jsonl((const struct ebpf_event *)payload);
            }
        }

        data_tail += ehdr->size;
    }

    /* Mettre à jour le tail pour libérer le buffer */
    __atomic_store_n(&header->data_tail, data_tail, __ATOMIC_RELEASE);
}

static void *perf_reader_thread(void *arg)
{
    (void)arg;
    LOG(INFO, "ebpf_android: perf reader thread started");

    struct pollfd fds[MAX_CPUS];
    int nfds = 0;

    for (int cpu = 0; cpu < MAX_CPUS; cpu++) {
        if (g_perf_fds[cpu] >= 0) {
            fds[nfds].fd     = g_perf_fds[cpu];
            fds[nfds].events = POLLIN;
            nfds++;
        }
    }

    while (g_running) {
        int ret = poll(fds, nfds, 100); /* timeout 100ms */
        if (ret <= 0) continue;

        for (int cpu = 0; cpu < MAX_CPUS; cpu++) {
            if (g_perf_fds[cpu] >= 0)
                read_perf_cpu(cpu);
        }
    }

    /* Dernière lecture après arrêt */
    for (int cpu = 0; cpu < MAX_CPUS; cpu++) {
        if (g_perf_fds[cpu] >= 0)
            read_perf_cpu(cpu);
    }

    LOG(INFO, "ebpf_android: perf reader thread stopped");
    return NULL;
}

/* ── API publique (ebpf_collector.h) ─────────────────────────────────────── */

int ebpf_collector_init(const char *output_dir)
{
    /* Ouvrir le fichier de sortie */
    char path[512];
    snprintf(path, sizeof(path), "%s/ebpf_events.jsonl", output_dir);
    g_output_fp = fopen(path, "w");
    if (!g_output_fp) {
        LOG(ERROR, "ebpf_android: fopen(%s) failed: %s", path, strerror(errno));
        return -1;
    }

    /* 1. Charger l'ELF BPF */
    if (load_bpf_elf(BPF_OBJ_PATH) < 0) return -1;

    /* 2. Créer les maps */
    if (create_maps() < 0) return -1;

    /* 3. Charger le programme */
    if (load_program() < 0) return -1;

    /* 4. Attacher au tracepoint */
    if (attach_tracepoint() < 0) return -1;

    g_initialized = true;
    LOG(INFO, "ebpf_android: initialized → %s", path);
    return 0;
}

int ebpf_collector_start(void)
{
    if (!g_initialized) {
        LOG(WARN, "ebpf_android: not initialized, skipping start");
        return 0;
    }

    g_running = true;
    if (pthread_create(&g_thread, NULL, perf_reader_thread, NULL) != 0) {
        LOG(ERROR, "ebpf_android: pthread_create failed: %s", strerror(errno));
        g_running = false;
        return -1;
    }

    LOG(INFO, "ebpf_android: reader thread started");
    return 0;
}

void ebpf_collector_stop(void)
{
    if (!g_initialized) return;

    g_running = false;
    pthread_join(g_thread, NULL);

    /* Désactiver et fermer les perf fds */
    for (int cpu = 0; cpu < MAX_CPUS; cpu++) {
        if (g_perf_fds[cpu] >= 0) {
            ioctl(g_perf_fds[cpu], PERF_EVENT_IOC_DISABLE, 0);
            if (g_perf_mmaps[cpu])
                munmap(g_perf_mmaps[cpu], PERF_MMAP_SIZE);
            close(g_perf_fds[cpu]);
            g_perf_fds[cpu]   = -1;
            g_perf_mmaps[cpu] = NULL;
        }
    }

    if (g_prog_fd >= 0)       { close(g_prog_fd);       g_prog_fd = -1; }
    if (g_map_events_fd >= 0) { close(g_map_events_fd); g_map_events_fd = -1; }
    if (g_map_sport_fd >= 0)  { close(g_map_sport_fd);  g_map_sport_fd = -1; }

    if (g_elf.data) { free(g_elf.data); g_elf.data = NULL; }
    if (g_output_fp) { fclose(g_output_fp); g_output_fp = NULL; }

    g_initialized = false;
    LOG(INFO, "ebpf_android: stopped");
}

bool ebpf_collector_is_active(void)
{
    return g_initialized && g_running;
}

void ebpf_collector_register_fd(int fd, uint64_t session_id)
{
    (void)fd; (void)session_id;
    /* Corrélation via sport uniquement sur Android */
}

void ebpf_collector_unregister_fd(int fd)
{
    (void)fd;
}

void ebpf_collector_dup_fd(int old_fd, int new_fd)
{
    (void)old_fd; (void)new_fd;
}

void ebpf_collector_register_sport(uint16_t sport, uint64_t session_id)
{
    if (g_map_sport_fd < 0) return;

    union bpf_attr attr = {};
    attr.map_fd  = (uint32_t)g_map_sport_fd;
    attr.key     = (uint64_t)(uintptr_t)&sport;
    attr.value   = (uint64_t)(uintptr_t)&session_id;
    attr.flags   = BPF_ANY;

    if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0) {
        LOG(WARN, "ebpf_android: register_sport(%u) failed: %s",
            sport, strerror(errno));
    }
}

void ebpf_collector_unregister_sport(uint16_t sport)
{
    if (g_map_sport_fd < 0) return;

    union bpf_attr attr = {};
    attr.map_fd = (uint32_t)g_map_sport_fd;
    attr.key    = (uint64_t)(uintptr_t)&sport;

    sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

void ebpf_collector_unregister_sport_by_fd(int fd)
{
    (void)fd;
}

#endif /* __ANDROID__ && TCPSNITCH_EBPF_ANDROID */