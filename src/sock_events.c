#include "sock_events.h"
#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#ifndef __ANDROID__
#include <pcap/pcap.h>
#endif
#include "constants.h"
#include "init.h"
#include "json_builder.h"
#include "lib.h"
#include "logger.h"
#include "packet_sniffer.h"
#include "resizable_array.h"
#include "string_builders.h"
#include "verbose_mode.h"
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __ANDROID__
#define MUTEX_ERRORCHECK PTHREAD_MUTEX_INITIALIZER
#else
#define MUTEX_ERRORCHECK PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#endif

void sock_ev_forked_socket(int fd, const SockInfo *sock_info);
void sock_ev_ghost_socket(int fd);
static void dump_events_as_json(Socket *sock);

static pthread_mutex_t connections_count_mutex = MUTEX_ERRORCHECK;
static int connections_count = 0;

/* Private functions */

static Socket *alloc_socket(int fd) {
    Socket *sock = (Socket *)my_calloc(sizeof(Socket));
    mutex_lock(&connections_count_mutex);
    sock->id = connections_count;
    connections_count++;
    mutex_unlock(&connections_count_mutex);
    sock->fd = fd;
    return sock;
}

#define CASE_EV(ev_type_cons, ev_type, err_val)                                \
    case ev_type_cons:                                                         \
        ev = (SockEvent *)my_calloc(sizeof(ev_type));                          \
        success = (return_value != err_val);                                   \
        break;

static SockEvent *alloc_event(SockEventType type, int return_value, int err,
                              int id) {
    bool success;
    SockEvent *ev;
    switch (type) {
        CASE_EV(SOCK_EV_SOCKET, SockEvSocket, 0);
        CASE_EV(SOCK_EV_FORKED_SOCKET, SockEvForkedSocket, -1);
        CASE_EV(SOCK_EV_GHOST_SOCKET, SockEvGhostSocket, -1);
        CASE_EV(SOCK_EV_BIND, SockEvBind, -1);
        CASE_EV(SOCK_EV_CONNECT, SockEvConnect, -1);
        CASE_EV(SOCK_EV_SHUTDOWN, SockEvShutdown, -1);
        CASE_EV(SOCK_EV_LISTEN, SockEvListen, -1);
        CASE_EV(SOCK_EV_ACCEPT, SockEvAccept, -1);
        CASE_EV(SOCK_EV_ACCEPT4, SockEvAccept4, -1);
        CASE_EV(SOCK_EV_GETSOCKOPT, SockEvGetsockopt, -1);
        CASE_EV(SOCK_EV_SETSOCKOPT, SockEvSetsockopt, -1);
        CASE_EV(SOCK_EV_SEND, SockEvSend, -1);
        CASE_EV(SOCK_EV_RECV, SockEvRecv, -1);
        CASE_EV(SOCK_EV_SENDTO, SockEvSendto, -1);
        CASE_EV(SOCK_EV_RECVFROM, SockEvRecvfrom, -1);
        CASE_EV(SOCK_EV_SENDMSG, SockEvSendmsg, -1);
        CASE_EV(SOCK_EV_RECVMSG, SockEvRecvmsg, -1);
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
        CASE_EV(SOCK_EV_SENDMMSG, SockEvSendmmsg, -1);
        CASE_EV(SOCK_EV_RECVMMSG, SockEvRecvmmsg, -1);
#endif
        CASE_EV(SOCK_EV_GETSOCKNAME, SockEvGetsockname, -1);
        CASE_EV(SOCK_EV_GETPEERNAME, SockEvGetpeername, -1);
        CASE_EV(SOCK_EV_SOCKATMARK, SockEvSockatmark, -1);
        CASE_EV(SOCK_EV_ISFDTYPE, SockEvIsfdtype, -1);
        CASE_EV(SOCK_EV_WRITE, SockEvWrite, -1);
        CASE_EV(SOCK_EV_READ, SockEvRead, -1);
        CASE_EV(SOCK_EV_CLOSE, SockEvClose, -1);
        CASE_EV(SOCK_EV_DUP, SockEvDup, -1);
        CASE_EV(SOCK_EV_DUP2, SockEvDup2, -1);
        CASE_EV(SOCK_EV_DUP3, SockEvDup3, -1);
        CASE_EV(SOCK_EV_WRITEV, SockEvWritev, -1);
        CASE_EV(SOCK_EV_READV, SockEvReadv, -1);
        CASE_EV(SOCK_EV_IOCTL, SockEvIoctl, -1);
        CASE_EV(SOCK_EV_SENDFILE, SockEvSendfile, -1);
        CASE_EV(SOCK_EV_POLL, SockEvPoll, -1);
        CASE_EV(SOCK_EV_PPOLL, SockEvPpoll, -1);
        CASE_EV(SOCK_EV_SELECT, SockEvSelect, -1);
        CASE_EV(SOCK_EV_PSELECT, SockEvPselect, -1);
        CASE_EV(SOCK_EV_FCNTL, SockEvFcntl, -1);
        CASE_EV(SOCK_EV_EPOLL_CTL, SockEvEpollCtl, -1);
        CASE_EV(SOCK_EV_EPOLL_WAIT, SockEvEpollWait, -1);
        CASE_EV(SOCK_EV_EPOLL_PWAIT, SockEvEpollPwait, -1);
        CASE_EV(SOCK_EV_FDOPEN, SockEvFdopen, 0);
        CASE_EV(SOCK_EV_SPLICE, SockEvSplice, -1);
        CASE_EV(SOCK_EV_NETLINK, SockEvNetlink, -1);
        CASE_EV(SOCK_EV_TCP_INFO, SockEvTcpInfo, -1);
    }
    ev->timestamp_usec = get_time_micros();
    ev->type = type;
    ev->return_value = return_value;
    ev->success = success;
    ev->err = err;
    ev->id = id;
    ev->repeat_count = 1;
#ifdef SYS_gettid
    ev->thread_id = syscall(SYS_gettid);
#else
    ev->thread_id = getpid(); // Fallback si gettid n'existe pas
#endif
    return ev;
}

static bool is_spammy_event(const SockEvent *ev) {
    // Poll qui ne retourne rien (timeout)
    if (ev->type == SOCK_EV_POLL && ev->return_value == 0)
        return true;
    // Recv ou Send qui bloquent (EAGAIN / EWOULDBLOCK)
    if ((ev->type == SOCK_EV_RECV || ev->type == SOCK_EV_SEND) &&
        ev->return_value == -1 && (ev->err == EAGAIN || ev->err == EWOULDBLOCK))
        return true;
    return false;
}

static bool try_agglomerate(Socket *sock, SockEvent *ev) {
    if (!sock->tail)
        return false;
    SockEvent *last = sock->tail->data;

    // Si l'événement précédent est identique et qu'il fait partie des
    // événements considérés comme "spammants"
    if (last->type == ev->type && last->return_value == ev->return_value &&
        last->err == ev->err && is_spammy_event(ev)) {
        last->repeat_count++;
        last->timestamp_usec = ev->timestamp_usec; // Met à jour avec l'heure de
                                                   // la dernière occurrence
        return true;
    }
    return false;
}

static void free_event(SockEvent *ev) {
    switch (ev->type) {
    case SOCK_EV_NETLINK:
        free(((SockEvNetlink *)ev)->ip_address);
        break;

    case SOCK_EV_GETSOCKOPT:
        free(((SockEvGetsockopt *)ev)->sockopt.optval);
        break;
    case SOCK_EV_SETSOCKOPT:
        free(((SockEvSetsockopt *)ev)->sockopt.optval);
        break;
    case SOCK_EV_READV:
        free(((SockEvReadv *)ev)->iovec.iovec_sizes);
        break;
    case SOCK_EV_WRITEV:
        free(((SockEvWritev *)ev)->iovec.iovec_sizes);
        break;
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
    case SOCK_EV_SENDMMSG:
        free(((SockEvSendmmsg *)ev)->mmsghdr_vec);
        break;
    case SOCK_EV_RECVMMSG:
        free(((SockEvRecvmmsg *)ev)->mmsghdr_vec);
        break;
#endif
    case SOCK_EV_FDOPEN:
        free(((SockEvFdopen *)ev)->mode);
        break;
    default:
        break;
    }
    free(ev);
}

static void free_events_list(SockEventNode *head) {
    SockEventNode *tmp;
    while (head != NULL) {
        free_event(head->data);
        tmp = head;
        head = head->next;
        free(tmp);
    }
}

#define MAX_EVENTS_BEFORE_FLUSH 2000 // Sécurité mémoire

static void push_event(Socket *sock, SockEvent *ev) {

    if (try_agglomerate(sock, ev)) {
        free_event(ev); // Détruit le duplicata non nécessaire
        return;
    }

    SockEventNode *node = (SockEventNode *)my_malloc(sizeof(SockEventNode));
    node->data = ev;
    node->next = NULL;

    if (!sock->head)
        sock->head = node;
    else
        sock->tail->next = node;

    sock->tail = node;
    sock->events_count++;
    sock->pending_events++;

    // Sécurité en cas de surcharge (Fall-back synchrone forcé si le thread est
    // trop lent)
    if (sock->pending_events >= MAX_EVENTS_BEFORE_FLUSH) {
        dump_events_as_json(sock);
    }
}

#define SOCK_TYPE_MASK 0b1111
static void fill_sock_info(SockInfo *si, int domain, int type, int protocol) {
    si->domain = domain;
    si->type = type & SOCK_TYPE_MASK;
    si->protocol = protocol;
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
    si->sock_cloexec = type & SOCK_CLOEXEC;
    si->sock_nonblock = type & SOCK_NONBLOCK;
#else
    si->sock_cloexec = false;
    si->sock_nonblock = false;
#endif
    si->filled = true;
}

static void fill_sock_info_from_fd(SockInfo *si, int fd) {
    int type;
    socklen_t optlen = sizeof(int);
    my_getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &si->domain, &optlen);
    optlen = sizeof(int);
    my_getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &si->protocol, &optlen);
    optlen = sizeof(int);
    my_getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &optlen);
    si->type = type & SOCK_TYPE_MASK;
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
    si->sock_cloexec = type & SOCK_CLOEXEC;
    si->sock_nonblock = type & SOCK_NONBLOCK;
#else
    si->sock_cloexec = false;
    si->sock_nonblock = false;
#endif
    si->filled = true;
    return;
}

static void fill_addr(Addr *a, const struct sockaddr *addr, socklen_t len) {
    memcpy(&a->sockaddr_sto, addr, len);
    a->len = len;
}

static void fill_poll_events(PollEvents *pe, int events) {
    pe->pollin = (events & POLLIN);
    pe->pollpri = (events & POLLPRI);
    pe->pollout = (events & POLLOUT);
    pe->pollrdhup = (events & POLLRDHUP);
    pe->pollerr = (events & POLLERR);
    pe->pollhup = (events & POLLHUP);
    pe->pollnval = (events & POLLNVAL);
}

static socklen_t fill_iovec(Iovec *iov1, const struct iovec *iov2,
                            int iovec_count) {
    iov1->iovec_count = iovec_count;
    if (iovec_count <= 0)
        return 0;

    iov1->iovec_sizes = (size_t *)my_malloc(sizeof(size_t *) * iovec_count);
    socklen_t bytes = 0;
    for (int i = 0; i < iovec_count; i++) {
        if (iov1->iovec_sizes)
            iov1->iovec_sizes[i] = iov2[i].iov_len;
        bytes += iov2[i].iov_len;
    }
    return bytes;
}

static socklen_t fill_msghdr(Msghdr *m1, const struct msghdr *m2) {
    // We copy the msg_control fields of the "struct msghdr" to another
    // such struct, since we must have such a struct available later to
    // use the CMSG macros for extracting the ancillary data.

    // Msg name
    if (m2->msg_name)
        memcpy(&m1->addr, m2->msg_name, m2->msg_namelen);

    // Control data (ancillary data)
    m1->msghdr = my_calloc(sizeof(struct msghdr));
    m1->msghdr->msg_controllen = m2->msg_controllen;
    if (m2->msg_controllen)
        m1->msghdr->msg_control = my_malloc(m2->msg_controllen);
    memcpy(m1->msghdr->msg_control, m2->msg_control, m2->msg_controllen);

    // Flags
    m1->flags = m2->msg_flags;

    // Iovec
    return fill_iovec(&m1->iovec, m2->msg_iov, m2->msg_iovlen);
}

static unsigned int fill_mmsghdr_vec(Mmsghdr *mmsghdr_vec1,
                                     const struct mmsghdr *mmsghdr_vec2,
                                     unsigned int vlen) {
    unsigned int bytes = 0;
    for (unsigned int i = 0; i < vlen; i++) {
        const struct mmsghdr *mmsghdr2 = (mmsghdr_vec2 + i);
        Mmsghdr *mmsghdr1 = (mmsghdr_vec1 + i);
        mmsghdr1->bytes_transmitted = mmsghdr2->msg_len;
        bytes += fill_msghdr(&mmsghdr1->msghdr, &mmsghdr2->msg_hdr);
    }
    return bytes;
}

static void fill_sockopt(Sockopt *sockopt, int level, int optname,
                         const void *optval, socklen_t optlen, bool getsockopt,
                         int fd) {
    sockopt->level = level;
    sockopt->optname = optname;
    sockopt->optlen = optlen;
    sockopt->optval = my_malloc(optlen);
    memcpy(sockopt->optval, optval, optlen);
    sockopt->getsockopt = getsockopt;
    sockopt->fd = fd;
    return;
}

typedef int (*orig_bind_type)(int fd, const struct sockaddr *addr,
                              socklen_t len);
static orig_bind_type orig_bind;

#define MIN_PORT 32768 // cat /proc/sys/net/ipv4/ip_local_port_range
#define MAX_PORT 60999
static int force_bind(int fd, const Socket *sock, bool IPV6) {
    LOG(INFO, "Forcing bind on connection %d.", sock->id);
    LOG_FUNC_INFO;
    if (!orig_bind)
        orig_bind = (orig_bind_type)dlsym(RTLD_NEXT, "bind");

    for (int port = MIN_PORT; port <= MAX_PORT; port++) {
        int rc;
        if (IPV6) {
            struct sockaddr_in6 a;
            a.sin6_family = AF_INET6;
            a.sin6_port = htons(port); // Any port
            a.sin6_addr = in6addr_any;
            rc = orig_bind(fd, (struct sockaddr *)&a, sizeof(a));
        } else {
            struct sockaddr_in a;
            a.sin_family = AF_INET;
            a.sin_port = htons(port);
            a.sin_addr.s_addr = INADDR_ANY;
            rc = orig_bind(fd, (struct sockaddr *)&a, sizeof(a));
        }
        if (rc == 0)
            return 0; // Sucessfull bind. Stop.
        if (errno != EADDRINUSE)
            goto error1; // Unexpected error.
                         // Expected error EADDRINUSE. Try next port.
    }
    // Could not bind if we reach this point.
    goto error_out;
error1:
    LOG(ERROR, "bind() failed. %s.", strerror(errno));
    goto error_out;
error_out:
    LOG_FUNC_ERROR;
    LOG(INFO, "Packet capture filter on dest IP/PORT only.");
    return -1;
}

static void dump_events_as_json(Socket *sock) {
    if (conf_opt_d == NULL || sock->head == NULL)
        return;
    LOG_FUNC_INFO;

    SockEventNode *list_to_dump = sock->head;
    sock->head = NULL;
    sock->tail = NULL;
    sock->pending_events = 0;

    if (!sock->json_fp) {
        char *json_file_str = alloc_json_path_str(sock);
        if (json_file_str) {
            sock->json_fp = fopen(json_file_str, "a");
            free(json_file_str);
        }
    }

    if (!sock->json_fp) {
        LOG_FUNC_ERROR;
        // En cas d'erreur de disque, on doit quand même free la mémoire
        SockEventNode *tmp, *cur = list_to_dump;
        while (cur) {
            tmp = cur;
            cur = cur->next;
            free_event(tmp->data);
            free(tmp);
        }
        return;
    }

    SockEventNode *tmp, *cur = list_to_dump;
    while (cur != NULL) {
        char *json_str = alloc_sock_ev_json(cur->data);
        if (json_str) {
            my_fputs(json_str, sock->json_fp);
            my_fputs("\n", sock->json_fp);
            // fflush(sock->json_fp);
            free(json_str);
        }
        free_event(cur->data);
        tmp = cur;
        cur = cur->next;
        free(tmp);
    }
}

static void tcp_dump_tcp_info(int fd) {
    struct tcp_info *info =
        (struct tcp_info *)my_malloc(sizeof(struct tcp_info));
    int ret = fill_tcp_info(fd, info);
    int err = errno;
    sock_ev_tcp_info(fd, ret, err, info);
}

static bool should_dump_tcp_info(const Socket *sock) {
    if (!is_tcp_socket(sock->fd))
        return false;

    if (conf_opt_u > 0) {
        long cur_time = get_time_micros();
        long time_elasped = cur_time - sock->last_info_dump_micros;
        if (time_elasped > conf_opt_u)
            return true;
    }

    if (conf_opt_b > 0) {
        long cur_bytes = sock->bytes_sent + sock->bytes_received;
        long bytes_elapsed = cur_bytes - sock->last_info_dump_bytes;
        if (bytes_elapsed > conf_opt_b)
            return true;
    }

    return false;
}

/* Public functions */

void free_socket(Socket *sock) {
    if (!sock)
        return; // NULL
    free_events_list(sock->head);
    free(sock);
}

// Used for any event that duplicates a socket, such as dup() or accept().
void sock_start_capture(int fd, const struct sockaddr *addr_to) {
    Socket *sock = ra_get_and_lock_elem(fd);
    if (!sock)
        goto error_out;

    if (sock->capture_switch != NULL) {
        ra_unlock_elem(fd);
        return;
    }

    LOG(INFO, "Starting packet capture.");
    LOG_FUNC_INFO;

    if (!sock->bound) {
        force_bind(fd, sock, addr_to->sa_family == AF_INET6);

        sock->bound = true;

        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        if (getsockname(fd, (struct sockaddr *)&ss, &slen) == 0) {
            memcpy(&sock->bound_addr, &ss, slen);
        }
    }

#ifndef __ANDROID__
    // Build pcap file path
    char *pcap_file_path = alloc_pcap_path_str(sock);
    if (!pcap_file_path)
        goto error_out;

    // Build capture filter
    const struct sockaddr *addr_from =
        (sock->bound) ? (const struct sockaddr *)&sock->bound_addr : NULL;

    const char *capture_filter = alloc_capture_filter(addr_from, addr_to);
    if (!capture_filter)
        goto error1;
    // See deadlock note in is_inet_socket.
    sock->capture_switch = start_capture(capture_filter, pcap_file_path);

    free(pcap_file_path);
    ra_unlock_elem(fd);
    return;
error1:
    free(pcap_file_path);
error_out:
#else
error_out:
#endif
    ra_unlock_elem(fd);
    LOG_FUNC_ERROR;
    return;
}

void log_event(LogLevel lvl, int ev_type_cons, int fd, int con_id) {
    const char *ev_name = string_from_sock_event_type(ev_type_cons);
    LOG(lvl, "%s on connection %d (fd %d).", ev_name, con_id, fd);
}

void free_and_dump_socket(int fd) {
    Socket *sock = ra_remove_elem(fd);
#ifndef __ANDROID__
    if (sock->capture_switch != NULL)
        stop_capture(sock->capture_switch, sock->rtt * 2);
#endif

    dump_events_as_json(sock);

    if (sock->json_fp) {
        fclose(sock->json_fp);
        sock->json_fp = NULL;
    }

    free_socket(sock);
}

// Used for any event that duplicates a socket, such as dup() or accept().
// We don't have a regular socket() call but we still need to know about the
// type of socket we are dealing with in the trace. To this purpose, we copy
// the sock_info of the original socket to the new event & socket.
#define DUP_SOCKET(ev_type_cons, ev_type)                                      \
    {                                                                          \
        Socket *new_sock = alloc_socket(ret);                                  \
        memcpy(&new_sock->sock_info, &sock->sock_info, sizeof(SockInfo));      \
        log_event(INFO, ev_type_cons, ret, new_sock->id);                      \
        ev_type *new_ev = (ev_type *)alloc_event(ev_type_cons, ret, err, 0);   \
        memcpy(new_ev, ev, sizeof(ev_type));                                   \
        memcpy(&new_ev->sock_info, &sock->sock_info, sizeof(SockInfo));        \
        push_event(new_sock, (SockEvent *)new_ev);                             \
        ra_unlock_elem(fd);                                                    \
        ra_put_elem(ret, new_sock);                                            \
        sock = ra_get_and_lock_elem(fd);                                       \
    }

#define SOCK_EV_PRELUDE(ev_type_cons, ev_type)                                 \
    init_tcpsnitch();                                                          \
    if (!ra_is_present(fd))                                                    \
        sock_ev_ghost_socket(fd);                                              \
    Socket *sock = ra_get_and_lock_elem(fd);                                   \
    log_event(INFO, ev_type_cons, fd, sock->id);                               \
    ev_type *ev =                                                              \
        (ev_type *)alloc_event(ev_type_cons, ret, err, sock->events_count);

#define SOCK_EV_POSTLUDE(ev_type_cons)                                         \
    /* 1. Capturer l'état avant de libérer le verrou */                      \
    bool dump_tcp_info =                                                       \
        should_dump_tcp_info(sock) && ev_type_cons != SOCK_EV_TCP_INFO;        \
    /* 2. Output + push AVANT unlock pour éviter la race condition */        \
    output_event((SockEvent *)ev);                                             \
    push_event(sock, (SockEvent *)ev);                                         \
    /* 3. Libérer le verrou */                                               \
    ra_unlock_elem(fd);                                                        \
    /* 4. Action secondaire post-verrou */                                     \
    if (dump_tcp_info)                                                         \
        tcp_dump_tcp_info(fd);

const char *string_from_sock_event_type(SockEventType type) {
    static const char *strings[] = {
        "socket",      "forked_socket", "ghost_socket", "bind",
        "connect",     "shutdown",      "listen",       "accept",
        "accept4",     "getsockopt",    "setsockopt",   "send",
        "recv",        "sendto",        "recvfrom",     "sendmsg",
        "recvmsg",
#if !defined(__ANDROID__) || __ANDROID_API__ >= 21
        "sendmmsg",    "recvmmsg",
#endif
        "getsockname", "getpeername",   "sockatmark",   "isfdtype",
        "write",       "read",          "close",        "dup",
        "dup2",        "dup3",          "writev",       "readv",
        "ioctl",       "sendfile",      "poll",         "ppoll",
        "select",      "pselect",       "fcntl",        "epoll_ctl",
        "epoll_wait",  "epoll_pwait",   "fdopen",       "splice",
        "netlink",     "tcp_info"};
    assert(sizeof(strings) / sizeof(char *) == SOCK_EV_TCP_INFO + 1);
    return strings[type];
}

void sock_ev_socket(int fd, int domain, int type, int protocol) {
    init_tcpsnitch();
    if (ra_is_present(fd)) {
        LOG(WARN, "Unclosed socket");
        free_and_dump_socket(fd);
    }

    Socket *sock = alloc_socket(fd);
    SockEvSocket *ev = (SockEvSocket *)alloc_event(SOCK_EV_SOCKET, fd, 0, 0);

    // We duplicate the sock_info on the Socket itself, as the socket event
    // will be freed as soon as events are dumped to JSON. Placing a copy
    // on the Socket itself is thus convenient to keep track of it.
    fill_sock_info(&ev->sock_info, domain, type, protocol);
    fill_sock_info(&sock->sock_info, domain, type, protocol);
    log_event(INFO, SOCK_EV_SOCKET, fd, sock->id);

    push_event(sock, (SockEvent *)ev);
    ra_put_elem(fd, sock);
}

void sock_ev_forked_socket(int fd, const SockInfo *sock_info) {
    Socket *forked_sock = alloc_socket(fd);
    SockEvForkedSocket *ev =
        (SockEvForkedSocket *)alloc_event(SOCK_EV_FORKED_SOCKET, 0, 0, 0);

    memcpy(&forked_sock->sock_info, sock_info, sizeof(SockInfo));
    memcpy(&ev->sock_info, sock_info, sizeof(SockInfo));
    log_event(INFO, SOCK_EV_FORKED_SOCKET, fd, forked_sock->id);

    push_event(forked_sock, (SockEvent *)ev);
    ra_put_elem(fd, forked_sock);
}

void sock_ev_ghost_socket(int fd) {
    Socket *ghost_sock = alloc_socket(fd);
    SockEvGhostSocket *ev =
        (SockEvGhostSocket *)alloc_event(SOCK_EV_GHOST_SOCKET, 0, 0, 0);
    fill_sock_info_from_fd(&ev->sock_info, fd);
    memcpy(&ghost_sock->sock_info, &ev->sock_info, sizeof(SockInfo));
    log_event(WARN, SOCK_EV_GHOST_SOCKET, fd, ghost_sock->id);
    push_event(ghost_sock, (SockEvent *)ev);
    ra_put_elem(fd, ghost_sock);
}

void sock_ev_bind(int fd, int ret, int err, const struct sockaddr *addr,
                  socklen_t len) {
    // Inst. local vars Socket *sock & SockEvBind *ev
    SOCK_EV_PRELUDE(SOCK_EV_BIND, SockEvBind);

    fill_addr(&(ev->addr), addr, len);
    if (!ret) {
        // Save bound addr as we will later use it for capture filter.
        sock->bound = true;
        memcpy(&sock->bound_addr, &ev->addr.sockaddr_sto, ev->addr.len);
    }

    SOCK_EV_POSTLUDE(SOCK_EV_BIND);
}

void sock_ev_connect(int fd, int ret, int err, const struct sockaddr *addr,
                     socklen_t len) {
    // Inst. local vars Socket *sock & SockEvConnect *ev
    SOCK_EV_PRELUDE(SOCK_EV_CONNECT, SockEvConnect);

    fill_addr(&(ev->addr), addr, len);

    SOCK_EV_POSTLUDE(SOCK_EV_CONNECT);
}

void sock_ev_shutdown(int fd, int ret, int err, int how) {
    // Inst. local vars Socket *sock & SockEvShutdown *ev
    SOCK_EV_PRELUDE(SOCK_EV_SHUTDOWN, SockEvShutdown);

    ev->shut_rd = (how == SHUT_RD) || (how == SHUT_RDWR);
    ev->shut_wr = (how == SHUT_WR) || (how == SHUT_RDWR);

    SOCK_EV_POSTLUDE(SOCK_EV_SHUTDOWN);
}

void sock_ev_listen(int fd, int ret, int err, int backlog) {
    // Inst. local vars Socket *sock & SockEvListen *ev
    SOCK_EV_PRELUDE(SOCK_EV_LISTEN, SockEvListen);

    ev->backlog = backlog;

    SOCK_EV_POSTLUDE(SOCK_EV_LISTEN);
}

void sock_ev_accept(int fd, int ret, int err, const struct sockaddr *addr,
                    socklen_t *addr_len) {
    // Inst. local vars Socket *sock & SockEvAccept *ev
    SOCK_EV_PRELUDE(SOCK_EV_ACCEPT, SockEvAccept);

    if (ret != -1 && addr)
        fill_addr(&(ev->addr), addr, *addr_len);
    if (ret != -1)
        DUP_SOCKET(SOCK_EV_ACCEPT, SockEvAccept);

    SOCK_EV_POSTLUDE(SOCK_EV_ACCEPT);
}

void sock_ev_accept4(int fd, int ret, int err, const struct sockaddr *addr,
                     socklen_t *addr_len, int flags) {
    // Inst. local vars Socket *sock & SockEvAccept4 *ev
    SOCK_EV_PRELUDE(SOCK_EV_ACCEPT4, SockEvAccept4);

    if (ret != -1 && addr)
        fill_addr(&(ev->addr), addr, *addr_len);
    ev->flags = flags;
    if (ret != -1)
        DUP_SOCKET(SOCK_EV_ACCEPT4, SockEvAccept4);

    SOCK_EV_POSTLUDE(SOCK_EV_ACCEPT4);
}

void sock_ev_getsockopt(int fd, int ret, int err, int level, int optname,
                        const void *optval, socklen_t *optlen) {
    // Inst. local vars Socket *sock & SockEvGetsockopt *ev
    SOCK_EV_PRELUDE(SOCK_EV_GETSOCKOPT, SockEvGetsockopt);

    fill_sockopt(&ev->sockopt, level, optname, optval, *optlen, true, fd);

    SOCK_EV_POSTLUDE(SOCK_EV_GETSOCKOPT)
}

void sock_ev_setsockopt(int fd, int ret, int err, int level, int optname,
                        const void *optval, socklen_t optlen) {
    // Inst. local vars Socket *sock & SockEvSetsockopt *ev
    SOCK_EV_PRELUDE(SOCK_EV_SETSOCKOPT, SockEvSetsockopt);

    fill_sockopt(&ev->sockopt, level, optname, optval, optlen, false, fd);

    SOCK_EV_POSTLUDE(SOCK_EV_SETSOCKOPT);
}

void sock_ev_send(int fd, int ret, int err, const void *buf, size_t bytes,
                  int flags) {
    // Inst. local vars Socket *sock & SockEvSend *ev
    SOCK_EV_PRELUDE(SOCK_EV_SEND, SockEvSend);
    UNUSED(buf);

    ev->bytes = bytes;
    ev->flags = flags;
    sock->bytes_sent += bytes;

    SOCK_EV_POSTLUDE(SOCK_EV_SEND);
}

void sock_ev_recv(int fd, int ret, int err, void *buf, size_t bytes,
                  int flags) {
    // Inst. local vars Socket *sock & SockEvRecv *ev
    SOCK_EV_PRELUDE(SOCK_EV_RECV, SockEvRecv);
    UNUSED(buf);

    ev->bytes = bytes;
    ev->flags = flags;
    sock->bytes_received += bytes;

    SOCK_EV_POSTLUDE(SOCK_EV_RECV);
}

void sock_ev_sendto(int fd, int ret, int err, const void *buf, size_t bytes,
                    int flags, const struct sockaddr *addr, socklen_t len) {
    // Inst. local vars Socket *sock & SockEvSendto *ev
    SOCK_EV_PRELUDE(SOCK_EV_SENDTO, SockEvSendto);
    UNUSED(buf);

    ev->bytes = bytes;
    ev->flags = flags;
    sock->bytes_sent += bytes;
    if (addr)
        fill_addr(&(ev->addr), addr, len);

    SOCK_EV_POSTLUDE(SOCK_EV_SENDTO);
}

void sock_ev_recvfrom(int fd, int ret, int err, void *buf, size_t bytes,
                      int flags, const struct sockaddr *addr, socklen_t *len) {
    // Inst. local vars Socket *sock & SockEvRecvfrom *ev
    SOCK_EV_PRELUDE(SOCK_EV_RECVFROM, SockEvRecvfrom);
    UNUSED(buf);

    ev->bytes = bytes;
    ev->flags = flags;
    sock->bytes_received += bytes;
    if (ret != -1 && addr)
        fill_addr(&(ev->addr), addr, *len);

    SOCK_EV_POSTLUDE(SOCK_EV_RECVFROM);
}

void sock_ev_sendmsg(int fd, int ret, int err, const struct msghdr *msg,
                     int flags) {
    // Inst. local vars Socket *sock & SockEvSendmsg *ev
    SOCK_EV_PRELUDE(SOCK_EV_SENDMSG, SockEvSendmsg); // CORRECTED TYPO

    ev->bytes = fill_msghdr(&ev->msghdr, msg);
    ev->flags = flags;
    sock->bytes_sent += ev->bytes;

    SOCK_EV_POSTLUDE(SOCK_EV_SENDMSG);
}

void sock_ev_recvmsg(int fd, int ret, int err, const struct msghdr *msg,
                     int flags) {
    // Inst. local vars Socket *sock & SockEvRecvmsg *ev
    SOCK_EV_PRELUDE(SOCK_EV_RECVMSG, SockEvRecvmsg);

    ev->bytes = fill_msghdr(&ev->msghdr, msg);
    ev->flags = flags;
    sock->bytes_received += ev->bytes;

    SOCK_EV_POSTLUDE(SOCK_EV_RECVMSG);
}

#if !defined(__ANDROID__) || __ANDROID_API__ >= 21

void sock_ev_sendmmsg(int fd, int ret, int err, const struct mmsghdr *vmessages,
                      unsigned int vlen, int flags) {
    // Inst. local vars Socket *sock & SockEvSendmmsg *ev
    SOCK_EV_PRELUDE(SOCK_EV_SENDMMSG, SockEvSendmmsg);

    ev->flags = flags;

    ev->mmsghdr_count = vlen;
    ev->mmsghdr_vec = (Mmsghdr *)my_malloc(vlen * sizeof(Mmsghdr));
    ev->bytes = fill_mmsghdr_vec(ev->mmsghdr_vec, vmessages, vlen);

    sock->bytes_sent += ev->bytes;
    SOCK_EV_POSTLUDE(SOCK_EV_SENDMMSG);
}

void sock_ev_recvmmsg(int fd, int ret, int err, const struct mmsghdr *vmessages,
                      unsigned int vlen, int flags,
                      const struct timespec *tmo) {
    // Inst. local vars Socket *sock & SockEvRecvmmsg *ev
    SOCK_EV_PRELUDE(SOCK_EV_RECVMMSG, SockEvRecvmmsg);

    ev->flags = flags;
    ev->timeout.seconds = tmo ? tmo->tv_sec : 0;
    ev->timeout.nanoseconds = tmo ? tmo->tv_nsec : 0;

    ev->mmsghdr_count = vlen;
    ev->mmsghdr_vec = (Mmsghdr *)my_malloc(vlen * sizeof(Mmsghdr));
    ev->bytes = fill_mmsghdr_vec(ev->mmsghdr_vec, vmessages, vlen);

    sock->bytes_received += ev->bytes;
    SOCK_EV_POSTLUDE(SOCK_EV_RECVMMSG);
}

#endif // #if !defined(__ANDROID__) || __ANDROID_API__ >= 21

void sock_ev_getsockname(int fd, int ret, int err, struct sockaddr *addr,
                         socklen_t *addrlen) {
    // Inst. local vars Socket *sock & SockEvGetsockname *ev
    SOCK_EV_PRELUDE(SOCK_EV_GETSOCKNAME, SockEvGetsockname);

    if (ret != -1)
        fill_addr(&(ev->addr), addr, *addrlen);

    SOCK_EV_POSTLUDE(SOCK_EV_GETSOCKNAME);
}

void sock_ev_getpeername(int fd, int ret, int err, struct sockaddr *addr,
                         socklen_t *addrlen) {
    // Inst. local vars Socket *sock & SockEvGetpeername *ev
    SOCK_EV_PRELUDE(SOCK_EV_GETPEERNAME, SockEvGetpeername);

    if (ret != -1)
        fill_addr(&(ev->addr), addr, *addrlen);

    SOCK_EV_POSTLUDE(SOCK_EV_GETPEERNAME);
}

void sock_ev_sockatmark(int fd, int ret, int err) {
    // Inst. local vars Socket *sock & SockEvSockatmark *ev
    SOCK_EV_PRELUDE(SOCK_EV_SOCKATMARK, SockEvSockatmark);
    SOCK_EV_POSTLUDE(SOCK_EV_SOCKATMARK);
}

void sock_ev_isfdtype(int fd, int ret, int err, int fdtype) {
    // Inst. local vars Socket *sock & SockEvIsfdtype *ev
    SOCK_EV_PRELUDE(SOCK_EV_ISFDTYPE, SockEvIsfdtype);

    ev->fdtype = fdtype;

    SOCK_EV_POSTLUDE(SOCK_EV_ISFDTYPE);
}

void sock_ev_write(int fd, int ret, int err, const void *buf, size_t bytes) {
    // Inst. local vars Socket *sock & SockEvWrite *ev
    SOCK_EV_PRELUDE(SOCK_EV_WRITE, SockEvWrite);
    UNUSED(buf);

    ev->bytes = bytes;
    sock->bytes_sent += bytes;

    SOCK_EV_POSTLUDE(SOCK_EV_WRITE);
}

void sock_ev_read(int fd, int ret, int err, void *buf, size_t bytes) {
    // Inst. local vars Socket *sock & SockEvRead *ev
    SOCK_EV_PRELUDE(SOCK_EV_READ, SockEvRead);
    UNUSED(buf);

    ev->bytes = bytes;
    sock->bytes_received += bytes;

    SOCK_EV_POSTLUDE(SOCK_EV_READ);
}

void sock_ev_close(int fd, int ret, int err) {
    // Inst. local vars Socket *sock & SockEvClose *ev
    SOCK_EV_PRELUDE(SOCK_EV_CLOSE, SockEvClose);
    SOCK_EV_POSTLUDE(SOCK_EV_CLOSE);
    free_and_dump_socket(fd);
}

void sock_ev_dup(int fd, int ret, int err) {
    // Inst. local vars Socket *sock & SockEvDup *ev
    SOCK_EV_PRELUDE(SOCK_EV_DUP, SockEvDup);

    if (ret != -1)
        DUP_SOCKET(SOCK_EV_DUP, SockEvDup);

    SOCK_EV_POSTLUDE(SOCK_EV_DUP);
}

void sock_ev_dup2(int fd, int ret, int err, int newfd) {
    // Inst. local vars Socket *sock & SockEvDup2 *ev
    SOCK_EV_PRELUDE(SOCK_EV_DUP2, SockEvDup2);

    ev->newfd = newfd;
    if (ret != -1)
        DUP_SOCKET(SOCK_EV_DUP2, SockEvDup2);

    SOCK_EV_POSTLUDE(SOCK_EV_DUP2);
}

void sock_ev_dup3(int fd, int ret, int err, int newfd, int flags) {
    // Inst. local vars Socket *sock & SockEvDup3 *ev
    SOCK_EV_PRELUDE(SOCK_EV_DUP3, SockEvDup3);

    ev->newfd = newfd;
    ev->o_cloexec = (flags == O_CLOEXEC);
    if (ret != -1)
        DUP_SOCKET(SOCK_EV_DUP3, SockEvDup3);

    SOCK_EV_POSTLUDE(SOCK_EV_DUP3);
}

void sock_ev_writev(int fd, int ret, int err, const struct iovec *iovec,
                    int iovec_count) {
    // Inst. local vars Socket *sock & SockEvWritev *ev
    SOCK_EV_PRELUDE(SOCK_EV_WRITEV, SockEvWritev);

    ev->bytes = fill_iovec(&ev->iovec, iovec, iovec_count);
    sock->bytes_sent += ev->bytes;

    SOCK_EV_POSTLUDE(SOCK_EV_WRITEV);
}

void sock_ev_readv(int fd, int ret, int err, const struct iovec *iovec,
                   int iovec_count) {
    // Inst. local vars Socket *sock & SockEvReadv *ev
    SOCK_EV_PRELUDE(SOCK_EV_READV, SockEvReadv);

    ev->bytes = fill_iovec(&ev->iovec, iovec, iovec_count);
    sock->bytes_received += ev->bytes;

    SOCK_EV_POSTLUDE(SOCK_EV_READV);
}

#ifdef __ANDROID__
void sock_ev_ioctl(int fd, int ret, int err, int request) {
#else
void sock_ev_ioctl(int fd, int ret, int err, unsigned long int request) {
#endif
    // Inst. local vars Socket *sock & SockEvIoctl *ev
    SOCK_EV_PRELUDE(SOCK_EV_IOCTL, SockEvIoctl);

    ev->request = request;

    SOCK_EV_POSTLUDE(SOCK_EV_IOCTL);
}

void sock_ev_sendfile(int fd, int ret, int err, int in_fd, off_t *offset,
                      size_t bytes) {
    // Inst. local vars Socket *sock & SockEvSendfile *ev
    SOCK_EV_PRELUDE(SOCK_EV_SENDFILE, SockEvSendfile);
    UNUSED(in_fd);
    UNUSED(offset);

    ev->bytes = bytes;
    sock->bytes_sent += ev->bytes;

    SOCK_EV_POSTLUDE(SOCK_EV_SENDFILE);
}

void sock_ev_poll(int fd, int ret, int err, short requested_events,
                  short returned_events, int timeout) {
    // Inst. local vars Socket *sock & SockEvPoll *ev
    SOCK_EV_PRELUDE(SOCK_EV_POLL, SockEvPoll);

    // Correction du calcul (on nettoie les lignes en double)
    ev->timeout.seconds = (timeout / 1000);
    ev->timeout.nanoseconds = (long)((timeout % 1000) * 1000);

    // On s'assure que les paramètres sont bien utilisés ici
    fill_poll_events(&ev->requested_events, (int)requested_events);
    fill_poll_events(&ev->returned_events, (int)returned_events);

    SOCK_EV_POSTLUDE(SOCK_EV_POLL);
}

void sock_ev_ppoll(int fd, int ret, int err, short requested_events,
                   short returned_events, const struct timespec *timeout) {
    // Inst. local vars Socket *sock & SockEvPpoll *ev
    SOCK_EV_PRELUDE(SOCK_EV_PPOLL, SockEvPpoll);

    ev->timeout.seconds = timeout ? timeout->tv_sec : 0;
    ev->timeout.nanoseconds = timeout ? timeout->tv_nsec : 0;
    fill_poll_events(&ev->requested_events, requested_events);
    fill_poll_events(&ev->returned_events, returned_events);

    SOCK_EV_POSTLUDE(SOCK_EV_PPOLL);
}

void sock_ev_select(int fd, int ret, int err, bool req_read, bool req_write,
                    bool req_except, bool ret_read, bool ret_write,
                    bool ret_except, struct timeval *timeout) {
    // Inst. local vars Socket *sock & SockEvSelect *ev
    SOCK_EV_PRELUDE(SOCK_EV_SELECT, SockEvSelect);

    ev->timeout.seconds = timeout ? timeout->tv_sec : 0;
    ev->timeout.nanoseconds = timeout ? timeout->tv_usec * 1000 : 0;
    ev->requested_events.read = req_read;
    ev->requested_events.write = req_write;
    ev->requested_events.except = req_except;
    ev->returned_events.read = ret_read;
    ev->returned_events.write = ret_write;
    ev->returned_events.except = ret_except;

    SOCK_EV_POSTLUDE(SOCK_EV_SELECT);
}

void sock_ev_pselect(int fd, int ret, int err, bool req_read, bool req_write,
                     bool req_except, bool ret_read, bool ret_write,
                     bool ret_except, const struct timespec *timeout) {
    // Inst. local vars Socket *sock & SockEvPselect *ev
    SOCK_EV_PRELUDE(SOCK_EV_PSELECT, SockEvPselect);

    ev->timeout.seconds = timeout ? timeout->tv_sec : 0;
    ev->timeout.nanoseconds = timeout ? timeout->tv_nsec : 0;
    ev->requested_events.read = req_read;
    ev->requested_events.write = req_write;
    ev->requested_events.except = req_except;
    ev->returned_events.read = ret_read;
    ev->returned_events.write = ret_write;
    ev->returned_events.except = ret_except;

    SOCK_EV_POSTLUDE(SOCK_EV_PSELECT);
}

void sock_ev_fcntl(int fd, int ret, int err, int cmd, ...) {
    // Inst. local vars Socket *sock & SockEvFcntl *ev
    SOCK_EV_PRELUDE(SOCK_EV_FCNTL, SockEvFcntl);

    ev->cmd = cmd;

    switch (cmd) {
    case F_GETFD:
    case F_GETFL:
    case F_GETOWN:
    case F_GETSIG:
    case F_GETLEASE:
    case F_GETPIPE_SZ:
        break; // Arg: void
    case F_DUPFD:
    case F_DUPFD_CLOEXEC:
    case F_SETFD:
    case F_SETFL:
    case F_SETOWN:
    case F_SETSIG:
    case F_SETLEASE:
    case F_NOTIFY:
    case F_SETPIPE_SZ: {
        // Arg: int
        va_list argp;
        int arg;
        va_start(argp, cmd);
        arg = va_arg(argp, int);
        va_end(argp);
        ev->arg = arg;

        if (cmd == F_SETFL && ret != -1) {
            bool is_nonblock = (arg & O_NONBLOCK) != 0;
            /* Mise à jour de l'événement fcntl */
            ev->sock_info.sock_nonblock = is_nonblock;
            ev->sock_info.filled = true;
            /* Mise à jour persistante du socket lui-même */
            sock->sock_info.sock_nonblock = is_nonblock;

            LOG(INFO,
                "fcntl(F_SETFL) fd=%d → O_NONBLOCK=%s "
                "(sock_info mis à jour)",
                fd, is_nonblock ? "true" : "false");
        }
        break;
    }

    case F_SETLK:
    case F_SETLKW:
    case F_GETLK:
#if defined(F_GETLK64) && (F_GETLK64 != F_GETLK)
    case F_GETLK64:
    case F_SETLK64:
    case F_SETLKW64:
#endif
#if defined(F_OFD_GETLK) && !defined(__ANDROID__)
    case F_OFD_SETLK:
    case F_OFD_SETLKW:
    case F_OFD_GETLK:
#endif
        // Arg: struct flock *
        break;

    case F_GETOWN_EX:
    case F_SETOWN_EX:
        // Arg: struct f_owner_ex *
        break;

    default:
        LOG(WARN, "cmd unknown: %d - fcntl dropped", cmd);
    }

    bool dup = (ev->cmd == F_DUPFD || ev->cmd == F_DUPFD_CLOEXEC);
    if (dup && ret != -1)
        DUP_SOCKET(SOCK_EV_FCNTL, SockEvFcntl);
    SOCK_EV_POSTLUDE(SOCK_EV_FCNTL);
}

void sock_ev_epoll_ctl(int fd, int ret, int err, int op,
                       uint32_t requested_events) {
    // Inst. local vars Socket *sock & SockEvEpollCtl *ev
    SOCK_EV_PRELUDE(SOCK_EV_EPOLL_CTL, SockEvEpollCtl);

    ev->op = op;
    ev->requested_events = requested_events;

    SOCK_EV_POSTLUDE(SOCK_EV_EPOLL_CTL);
}

void sock_ev_epoll_wait(int fd, int ret, int err, int timeout,
                        uint32_t returned_events) {
    // Inst. local vars Socket *sock & SockEvEpollWait *ev
    SOCK_EV_PRELUDE(SOCK_EV_EPOLL_WAIT, SockEvEpollWait);

    ev->returned_events = returned_events;
    ev->timeout = timeout;

    SOCK_EV_POSTLUDE(SOCK_EV_EPOLL_WAIT);
}

void sock_ev_epoll_pwait(int fd, int ret, int err, int timeout,
                         uint32_t returned_events) {
    // Inst. local vars Socket *sock & SockEvEpollPwait *ev
    SOCK_EV_PRELUDE(SOCK_EV_EPOLL_PWAIT, SockEvEpollPwait);

    ev->returned_events = returned_events;
    ev->timeout = timeout;

    SOCK_EV_POSTLUDE(SOCK_EV_EPOLL_PWAIT);
}

void sock_ev_fdopen(int fd, FILE *_ret, int err, const char *mode) {
    int ret = (_ret != NULL);
    // Inst. local vars Socket *sock & SockEvFdopen *ev
    SOCK_EV_PRELUDE(SOCK_EV_FDOPEN, SockEvFdopen);

    int n = strlen(mode) + 1;
    ev->mode = (char *)my_malloc(sizeof(char) * n);
    strncpy(ev->mode, mode, n);

    SOCK_EV_POSTLUDE(SOCK_EV_FDOPEN);
}

void sock_ev_tcp_info(int fd, int ret, int err, struct tcp_info *info) {
    // Inst. local vars Socket *sock & SockEvTcpInfo *ev
    SOCK_EV_PRELUDE(SOCK_EV_TCP_INFO, SockEvTcpInfo);
    LOG_FUNC_INFO;

    memcpy(&(ev->info), info, sizeof(struct tcp_info));
    sock->last_info_dump_bytes = sock->bytes_sent + sock->bytes_received;
    sock->last_info_dump_micros = get_time_micros();
    sock->rtt = info->tcpi_rtt;
    free(info);

    SOCK_EV_POSTLUDE(SOCK_EV_TCP_INFO);
}

void sock_ev_splice(int ret, int err, int fd_in, loff_t *off_in, int fd_out,
                    loff_t *off_out, size_t len, unsigned int flags) {
    UNUSED(off_in);
    UNUSED(off_out);
    init_tcpsnitch();

    int target_fd = -1;
    if (is_inet_socket(fd_out))
        target_fd = fd_out;
    else if (is_inet_socket(fd_in))
        target_fd = fd_in;

    if (target_fd == -1)
        return;

    if (!ra_is_present(target_fd))
        sock_ev_ghost_socket(target_fd);
    Socket *sock = ra_get_and_lock_elem(target_fd);

    log_event(INFO, SOCK_EV_SPLICE, target_fd, sock->id);
    SockEvSplice *ev = (SockEvSplice *)alloc_event(SOCK_EV_SPLICE, ret, err,
                                                   sock->events_count);

    ev->fd_in = fd_in;
    ev->fd_out = fd_out;
    ev->len = len;
    ev->flags = flags;

    if (ret > 0) {
        if (target_fd == fd_out)
            sock->bytes_sent += ret;
        if (target_fd == fd_in)
            sock->bytes_received += ret;
    }

    output_event((SockEvent *)ev);
    push_event(sock, (SockEvent *)ev);

    // On capture l'info AVANT le unlock
    bool dump_tcp_info = should_dump_tcp_info(sock);
    ra_unlock_elem(target_fd);

    if (dump_tcp_info)
        tcp_dump_tcp_info(target_fd);
}

void dump_all_sock_events(void) {
    LOG_FUNC_INFO;
    for (long i = 0; i < ra_get_size(); i++) {
        if (!ra_is_present(i))
            continue;

        Socket *socket = ra_get_and_lock_elem(i);
        if (!socket || socket->head == NULL) {
            if (socket)
                ra_unlock_elem(i);
            continue;
        }

        dump_events_as_json(socket);

        ra_unlock_elem(i);
    }
}

void sock_ev_reset(void) {
    mutex_init(&connections_count_mutex);
    connections_count = 0;
    for (long i = 0; i < ra_get_size(); i++) {
        if (!ra_is_present(i))
            continue;
        Socket *sock = ra_remove_elem(i);
        sock_ev_forked_socket(i, &sock->sock_info);
        free_socket(sock);
    }
}

void sock_ev_netlink(int fd, int msg_type, int if_index, int family,
                     const char *ip) {
    if (!ra_is_present(fd))
        return;

    Socket *sock = ra_get_and_lock_elem(fd);
    SockEvNetlink *ev =
        (SockEvNetlink *)alloc_event(SOCK_EV_NETLINK, 0, 0, sock->events_count);

    ev->netlink_msg_type = msg_type;
    ev->if_index = if_index;
    ev->family = family;

    if (ip) {
        int len = strlen(ip) + 1;
        ev->ip_address = (char *)my_malloc(len);
        strncpy(ev->ip_address, ip, len);
    } else {
        ev->ip_address = NULL;
    }

    push_event(sock, (SockEvent *)ev);

    // On force l'écriture immédiate dans le fichier pour ne rien perdre
    dump_events_as_json(sock);

    ra_unlock_elem(fd);
}

uint64_t sock_get_session_id(int fd) {
    Socket *sock = ra_get_and_lock_elem(fd);
    if (!sock)
        return (uint64_t)fd;
    uint64_t id = (uint64_t)sock->id;
    ra_unlock_elem(fd);
    return id;
}