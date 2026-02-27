/**
 * @file libc_overrides.c
 * @author Gregory Vander Schueren
 * @brief LD_PRELOAD overrides for tracking socket lifecycle and establishing eBPF correlation.
 * @date October, 2016 (Updated: 2026 - eBPF FD lifecycle hooks)
 */

#include "lib.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "ebpf_collector.h"
#include "init.h"
#include "logger.h"
#include "sock_events.h"
#include "string_builders.h"

#define EXPORT __attribute__((visibility("default")))
#define LIBC_VERSION (__GLIBC__ * 100 + __GLIBC_MINOR__)

#define arg2 a
#define arg3 arg2, b
#define arg4 arg3, c
#define arg5 arg4, d
#define arg6 arg5, e

#define override(FUNCTION, RETURN_TYPE, ARGS_COUNT, ...)                   \
        typedef RETURN_TYPE (*FUNCTION##_type)(int fd, __VA_ARGS__);       \
        FUNCTION##_type orig_##FUNCTION;                                   \
                                                                           \
        EXPORT RETURN_TYPE FUNCTION(int fd, __VA_ARGS__) {                 \
                if (!orig_##FUNCTION)                                      \
                        orig_##FUNCTION =                                  \
                            (FUNCTION##_type)dlsym(RTLD_NEXT, #FUNCTION);  \
                RETURN_TYPE ret = orig_##FUNCTION(fd, arg##ARGS_COUNT);    \
                int err = errno;                                           \
                if (is_inet_socket(fd))                                    \
                        sock_ev_##FUNCTION(fd, ret, err, arg##ARGS_COUNT); \
                errno = err;                                               \
                return ret;                                                \
        }

#define override_1arg(FUNCTION, RETURN_TYPE)                               \
        typedef RETURN_TYPE (*FUNCTION##_type)(int fd);                    \
        FUNCTION##_type orig_##FUNCTION;                                   \
                                                                           \
        EXPORT RETURN_TYPE FUNCTION(int fd) {                              \
                if (!orig_##FUNCTION)                                      \
                        orig_##FUNCTION =                                  \
                            (FUNCTION##_type)dlsym(RTLD_NEXT, #FUNCTION);  \
                RETURN_TYPE ret = orig_##FUNCTION(fd);                     \
                int err = errno;                                           \
                if (is_inet_socket(fd)) sock_ev_##FUNCTION(fd, ret, err);  \
                errno = err;                                               \
                return ret;                                                \
        }

/**
 * @brief Intercepts socket() creation.
 * * eBPF Injection Point #1: After a successful socket() call, we register the FD in the BPF map:
 * {pid, fd} -> session_id. The session_id is tcpsnitch's internal socket identifier (sock->id).
 * We use the FD as a provisional correlation ID until merge_sessions.py resolves it.
 */
typedef int (*socket_type)(int domain, int type, int protocol);
socket_type orig_socket;

EXPORT int socket(int domain, int type, int protocol) {
        if (!orig_socket)
                orig_socket = (socket_type)dlsym(RTLD_NEXT, "socket");

        int fd = orig_socket(domain, type, protocol);

        if (is_inet_socket(fd)) {
                sock_ev_socket(fd, domain, type, protocol);

                if (ebpf_collector_is_active()) {
                        ebpf_collector_register_fd(fd, sock_get_session_id(fd));
                }
        }

        return fd;
}

/* Pre-declarations for getsockname used in eBPF correlation */
typedef int (*getsockname_type)(int fd, struct sockaddr *addr, socklen_t *len);
extern getsockname_type orig_getsockname;

/**
 * @brief Intercepts connect() to handle Double Endianness for eBPF correlation.
 * * Registers the source port in the eBPF map. To ensure the kernel tracepoint
 * (tcp_retransmit_skb) matches the port regardless of how the kernel structures
 * were compiled, we employ a "Double Endianness" strategy: we register both 
 * the Network Byte Order and Host Byte Order versions of the port.
 */
typedef int (*connect_type)(int fd, const struct sockaddr *addr, socklen_t len);
connect_type orig_connect;

EXPORT int connect(int fd, const struct sockaddr *addr, socklen_t len) {
        if (!orig_connect)
                orig_connect = (connect_type)dlsym(RTLD_NEXT, "connect");

        if (is_inet_socket(fd) && conf_opt_c && addr) 
                sock_start_capture(fd, addr);
        
        int ret = orig_connect(fd, addr, len);
        int err = errno;

        if (is_inet_socket(fd)) {
                sock_ev_connect(fd, ret, err, addr, len);

                if (ebpf_collector_is_active() && (ret == 0 || (ret == -1 && err == EINPROGRESS))) {
                        
                        if (!orig_getsockname)
                                orig_getsockname = (getsockname_type)dlsym(RTLD_NEXT, "getsockname");

                        if (orig_getsockname) {
                                struct sockaddr_storage local_addr;
                                socklen_t addrlen = sizeof(local_addr);
                                if (orig_getsockname(fd, (struct sockaddr *)&local_addr, &addrlen) == 0) {
                                        uint16_t sport_net = 0;
                                        if (local_addr.ss_family == AF_INET)
                                                sport_net = ((struct sockaddr_in *)&local_addr)->sin_port;
                                        else if (local_addr.ss_family == AF_INET6)
                                                sport_net = ((struct sockaddr_in6 *)&local_addr)->sin6_port;
                                        
                                        if (sport_net > 0) {
                                                uint64_t session_id = sock_get_session_id(fd);
                                                uint16_t sport_host = ntohs(sport_net);
                                                
                                                /* Double Endianness registration */
                                                ebpf_collector_register_sport(sport_host, session_id);
                                                ebpf_collector_register_sport(sport_net, session_id);
                                        }
                                }
                        }
                }
        }

        errno = err;
        return ret;
}

override(bind, int, 3, const struct sockaddr *a, socklen_t b);
override(shutdown, int, 2, int a) override(listen, int, 2, int a);
override(accept, int, 3, struct sockaddr *a, socklen_t *b);
override(accept4, int, 4, struct sockaddr *a, socklen_t *b, int c);
override(getsockopt, int, 5, int a, int b, void *c, socklen_t *d);
override(setsockopt, int, 5, int a, int b, const void *c, socklen_t d);

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
override(send, ssize_t, 4, const void *a, size_t b, unsigned int c);
override(recv, ssize_t, 4, void *a, size_t b, unsigned int c);
#else
override(send, ssize_t, 4, const void *a, size_t b, int c);
override(recv, ssize_t, 4, void *a, size_t b, int c);
#endif

typedef ssize_t (*sendto_type)(int fd, const void *buf, size_t len, int flags,
                               const struct sockaddr *dest_addr,
                               socklen_t addrlen);
sendto_type orig_sendto;

EXPORT ssize_t sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen) {
        if (!orig_sendto)
                orig_sendto = (sendto_type)dlsym(RTLD_NEXT, "sendto");

        if (is_inet_socket(fd) && conf_opt_c && dest_addr)
                sock_start_capture(fd, dest_addr);

        ssize_t ret = orig_sendto(fd, buf, len, flags, dest_addr, addrlen);
        int err = errno;

        if (is_inet_socket(fd))
                sock_ev_sendto(fd, ret, err, buf, len, flags, dest_addr, addrlen);

        errno = err;
        return ret;
}

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
override(recvfrom, ssize_t, 6, void *a, size_t b, unsigned int c,
         const struct sockaddr *d, socklen_t *e);
#elif defined(__ANDROID__)
override(recvfrom, ssize_t, 6, void *a, size_t b, int c,
         const struct sockaddr *d, socklen_t *e);
#else
override(recvfrom, ssize_t, 6, void *a, size_t b, int c, struct sockaddr *d,
         socklen_t *e);
#endif

#if defined(__ANDROID__) && __ANDROID_API__ <= 19
override(sendmsg, ssize_t, 3, const struct msghdr *a, unsigned int b);
override(recvmsg, ssize_t, 3, struct msghdr *a, unsigned int b);
#else
override(sendmsg, ssize_t, 3, const struct msghdr *a, int b);
override(recvmsg, ssize_t, 3, struct msghdr *a, int b);
#endif
override(sendmmsg, int, 4, struct mmsghdr *a, unsigned int b, int c);
override(recvmmsg, int, 5, struct mmsghdr *a, unsigned int b, int c,
         struct timespec *d);

override(getsockname, int, 3, struct sockaddr *a, socklen_t *b);
override(getpeername, int, 3, struct sockaddr *a, socklen_t *b);
override_1arg(sockatmark, int);
override(isfdtype, int, 2, int a);

/* ── IO Operations ───────────────────────────────────────────────────────── */

override(write, ssize_t, 3, const void *a, size_t b);
override(read, ssize_t, 3, void *a, size_t b);

/**
 * @brief Intercepts close() to maintain eBPF mapping consistency.
 * * eBPF Injection Point #2: Unregisters {pid, fd} from the BPF map BEFORE calling orig_close().
 * Ordering is crucial here: if we unregistered after orig_close(), the OS could recycle the 
 * FD in a different thread, opening a race condition window leading to map corruption.
 */
typedef int (*close_type)(int fd);
close_type orig_close;

EXPORT int close(int fd) {
        if (!orig_close)
                orig_close = (close_type)dlsym(RTLD_NEXT, "close");

        bool is_inet = is_inet_socket(fd);

        if (is_inet && ebpf_collector_is_active()) {
                ebpf_collector_unregister_fd(fd);
                
                if (!orig_getsockname)
                        orig_getsockname = (getsockname_type)dlsym(RTLD_NEXT, "getsockname");

                if (orig_getsockname) {
                        struct sockaddr_storage local_addr;
                        socklen_t addrlen = sizeof(local_addr);
                        if (orig_getsockname(fd, (struct sockaddr *)&local_addr, &addrlen) == 0) {
                                uint16_t sport_net = 0;
                                if (local_addr.ss_family == AF_INET)
                                        sport_net = ((struct sockaddr_in *)&local_addr)->sin_port;
                                else if (local_addr.ss_family == AF_INET6)
                                        sport_net = ((struct sockaddr_in6 *)&local_addr)->sin6_port;
                                
                                if (sport_net > 0) {
                                        uint16_t sport_host = ntohs(sport_net);
                                        /* Clean up both formats for double endianness */
                                        ebpf_collector_unregister_sport(sport_host);
                                        ebpf_collector_unregister_sport(sport_net);
                                }
                        }
                }
        }

        int ret = orig_close(fd);
        int err = errno;
        if (is_inet) sock_ev_close(fd, ret, err);

        errno = err;
        return ret;
}

/**
 * @brief Intercepts close_range() to prevent undetected FD leaks.
 * * Iterates through the given range to proactively clean up eBPF map entries
 * before the kernel performs a mass closure. Caps iteration at 4096 to prevent 
 * performance stalls if UINT_MAX is passed.
 */
typedef int (*close_range_type)(unsigned int fd, unsigned int max_fd, int flags);
close_range_type orig_close_range;

EXPORT int close_range(unsigned int fd, unsigned int max_fd, int flags) {
        if (!orig_close_range)
                orig_close_range =
                    (close_range_type)dlsym(RTLD_NEXT, "close_range");

#ifdef CLOSE_RANGE_CLOEXEC
        /* CLOSE_RANGE_CLOEXEC just sets the flag, FDs remain open. No BPF updates needed. */
        if (flags & CLOSE_RANGE_CLOEXEC)
                return orig_close_range(fd, max_fd, flags);
#endif

        /* Cap maximum range iteration to 4096 to prevent excessive loops. */
        unsigned int cap = (max_fd > 4096) ? 4096 : max_fd;

        /* Step 1: Unregister from eBPF first (prevent FD recycling bug) */
        if (ebpf_collector_is_active()) {
                for (unsigned int i = fd; i <= cap; i++) {
                        if (is_inet_socket((int)i))
                                ebpf_collector_unregister_fd((int)i);
                }
        }

        /* Step 2: Snapshot INET status before closing */
        bool is_inet[cap - fd + 1];
        for (unsigned int i = fd; i <= cap; i++)
                is_inet[i - fd] = is_inet_socket((int)i);

        /* Step 3: Real syscall */
        int ret = orig_close_range(fd, max_fd, flags);
        int err = errno;

        /* Step 4: Log ev_close for each INET socket */
        for (unsigned int i = fd; i <= cap; i++) {
                if (is_inet[i - fd])
                        sock_ev_close((int)i, ret, err);
        }

        errno = err;
        return ret;
}

/**
 * @brief Intercepts dup() to track FD inheritance in eBPF.
 */
typedef int (*dup_type)(int fd);
dup_type orig_dup;

EXPORT int dup(int fd) {
        if (!orig_dup)
                orig_dup = (dup_type)dlsym(RTLD_NEXT, "dup");

        int ret = orig_dup(fd);
        int err = errno;

        if (is_inet_socket(fd)) {
                sock_ev_dup(fd, ret, err);
                if (ret != -1 && ebpf_collector_is_active())
                        ebpf_collector_dup_fd(fd, ret);
        }

        errno = err;
        return ret;
}

/**
 * @brief Intercepts dup2() / dup3().
 * * Safely unregisters 'newfd' if it already exists, as dup2/dup3 will implicitly close it.
 */
typedef int (*dup2_type)(int fd, int newfd);
dup2_type orig_dup2;

EXPORT int dup2(int fd, int newfd) {
        if (!orig_dup2)
                orig_dup2 = (dup2_type)dlsym(RTLD_NEXT, "dup2");

        if (ebpf_collector_is_active() && is_inet_socket(newfd))
                ebpf_collector_unregister_fd(newfd);

        int ret = orig_dup2(fd, newfd);
        int err = errno;

        if (is_inet_socket(fd)) {
                sock_ev_dup2(fd, ret, err, newfd);
                if (ret != -1 && ebpf_collector_is_active())
                        ebpf_collector_dup_fd(fd, ret);
        }

        errno = err;
        return ret;
}

typedef int (*dup3_type)(int fd, int newfd, int flags);
dup3_type orig_dup3;

EXPORT int dup3(int fd, int newfd, int flags) {
        if (!orig_dup3)
                orig_dup3 = (dup3_type)dlsym(RTLD_NEXT, "dup3");

        if (ebpf_collector_is_active() && is_inet_socket(newfd))
                ebpf_collector_unregister_fd(newfd);

        int ret = orig_dup3(fd, newfd, flags);
        int err = errno;

        if (is_inet_socket(fd)) {
                sock_ev_dup3(fd, ret, err, newfd, flags);
                if (ret != -1 && ebpf_collector_is_active())
                        ebpf_collector_dup_fd(fd, ret);
        }

        errno = err;
        return ret;
}

/* ── fork() ─────────────────────────────────────────────────────────────────── */

typedef pid_t (*fork_type)(void);
fork_type orig_fork;

EXPORT pid_t fork(void) {
        if (!orig_fork)
                orig_fork = (fork_type)dlsym(RTLD_NEXT, "fork");
        LOG(INFO, "fork() called.");

        pid_t ret = orig_fork();
        int err = errno;
        if (ret == 0) reset_tcpsnitch();

        errno = err;
        return ret;
}

/* ── writev() / readv() ─────────────────────────────────────────────────────── */

override(writev, ssize_t, 3, const struct iovec *a, int b);
override(readv, ssize_t, 3, const struct iovec *a, int b);

/* ── ioctl() ────────────────────────────────────────────────────────────────── */

#ifdef __ANDROID__
typedef int (*ioctl_type)(int fd, int request, ...);
#else
typedef int (*ioctl_type)(int fd, unsigned long int request, ...);
#endif

ioctl_type orig_ioctl;

#ifdef __ANDROID__
EXPORT int ioctl(int fd, int request, ...) {
#else
EXPORT int ioctl(int fd, unsigned long int request, ...) {
#endif
        va_list argp;
        va_start(argp, request);
        void *value = va_arg(argp, void *);
        va_end(argp);

        if (!orig_ioctl)
                orig_ioctl = (ioctl_type)dlsym(RTLD_NEXT, "ioctl");

        int ret = orig_ioctl(fd, request, value);
        int err = errno;
        if (is_inet_socket(fd)) sock_ev_ioctl(fd, ret, err, request);

        errno = err;
        return ret;
}

/* ── sendfile() ─────────────────────────────────────────────────────────────── */

override(sendfile, ssize_t, 4, int a, off_t *b, size_t c);

/* ── poll() / ppoll() ───────────────────────────────────────────────────────── */

typedef int (*poll_type)(struct pollfd *fds, nfds_t nfds, int timeout);
poll_type orig_poll;

EXPORT int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
        if (!orig_poll)
                orig_poll = (poll_type)dlsym(RTLD_NEXT, "poll");

        int ret = orig_poll(fds, nfds, timeout);
        int err = errno;
        unsigned long i;
        for (i = 0; i < nfds; i++) {
                struct pollfd pollfd = fds[i];
                if (is_inet_socket(pollfd.fd))
                        sock_ev_poll(pollfd.fd, ret, err, pollfd.events,
                                     pollfd.revents, timeout);
        }

        errno = err;
        return ret;
}

typedef int (*ppoll_type)(struct pollfd *fds, nfds_t nfds,
                          const struct timespec *tmo_p,
                          const sigset_t *sigmask);
ppoll_type orig_ppoll;

EXPORT int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p,
                 const sigset_t *sigmask) {
        if (!orig_ppoll)
                orig_ppoll = (ppoll_type)dlsym(RTLD_NEXT, "ppoll");

        int ret = orig_ppoll(fds, nfds, tmo_p, sigmask);
        int err = errno;
        unsigned long i;
        for (i = 0; i < nfds; i++) {
                struct pollfd pollfd = fds[i];
                if (is_inet_socket(pollfd.fd))
                        sock_ev_ppoll(pollfd.fd, ret, err, pollfd.events,
                                      pollfd.revents, tmo_p);
        }

        errno = err;
        return ret;
}

/* ── select() / pselect() ───────────────────────────────────────────────────── */

typedef int (*select_type)(int nfds, fd_set *readfds, fd_set *writefds,
                           fd_set *exceptfds, struct timeval *timeout);
select_type orig_select;

#define READ_FLAG   0b1
#define WRITE_FLAG  0b10
#define EXCEPT_FLAG 0b100

EXPORT int select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout) {
        if (!orig_select)
                orig_select = (select_type)dlsym(RTLD_NEXT, "select");

        short req_ev[nfds];
        memset(req_ev, 0, sizeof(req_ev));

        int fd;
        for (fd = 0; fd < nfds; fd++) {
                if (is_inet_socket(fd)) {
                        if (readfds && FD_ISSET(fd, readfds))
                                req_ev[fd] = req_ev[fd] | READ_FLAG;
                        if (writefds && FD_ISSET(fd, writefds))
                                req_ev[fd] = req_ev[fd] | WRITE_FLAG;
                        if (exceptfds && FD_ISSET(fd, exceptfds))
                                req_ev[fd] = req_ev[fd] | EXCEPT_FLAG;
                }
        }

        int ret = orig_select(nfds, readfds, writefds, exceptfds, timeout);
        int err = errno;

        for (fd = 0; fd < nfds; fd++) {
                if (is_inet_socket(fd) && req_ev[fd]) {
                        sock_ev_select(fd, ret, err,
                                       (req_ev[fd] & READ_FLAG),
                                       (req_ev[fd] & WRITE_FLAG),
                                       (req_ev[fd] & EXCEPT_FLAG),
                                       readfds  && FD_ISSET(fd, readfds),
                                       writefds && FD_ISSET(fd, writefds),
                                       exceptfds && FD_ISSET(fd, exceptfds),
                                       timeout);
                }
        }

        errno = err;
        return ret;
}

typedef int (*pselect_type)(int nfds, fd_set *readfds, fd_set *writefds,
                            fd_set *exceptfds, const struct timespec *timeout,
                            const sigset_t *sigmask);
pselect_type orig_pselect;

EXPORT int pselect(int nfds, fd_set *readfds, fd_set *writefds,
                   fd_set *exceptfds, const struct timespec *timeout,
                   const sigset_t *sigmask) {
        if (!orig_pselect)
                orig_pselect = (pselect_type)dlsym(RTLD_NEXT, "pselect");

        short req_ev[nfds];
        memset(req_ev, 0, sizeof(req_ev));

        int fd;
        for (fd = 0; fd < nfds; fd++) {
                if (is_inet_socket(fd)) {
                        if (readfds && FD_ISSET(fd, readfds))
                                req_ev[fd] = req_ev[fd] | READ_FLAG;
                        if (writefds && FD_ISSET(fd, writefds))
                                req_ev[fd] = req_ev[fd] | WRITE_FLAG;
                        if (exceptfds && FD_ISSET(fd, exceptfds))
                                req_ev[fd] = req_ev[fd] | EXCEPT_FLAG;
                }
        }

        int ret = orig_pselect(nfds, readfds, writefds, exceptfds,
                               timeout, sigmask);
        int err = errno;

        for (fd = 0; fd < nfds; fd++) {
                if (is_inet_socket(fd) && req_ev[fd]) {
                        sock_ev_pselect(fd, ret, err,
                                        (req_ev[fd] & READ_FLAG),
                                        (req_ev[fd] & WRITE_FLAG),
                                        (req_ev[fd] & EXCEPT_FLAG),
                                        readfds  && FD_ISSET(fd, readfds),
                                        writefds && FD_ISSET(fd, writefds),
                                        exceptfds && FD_ISSET(fd, exceptfds),
                                        timeout);
                }
        }

        errno = err;
        return ret;
}

/* ── fcntl() ────────────────────────────────────────────────────────────────── */

typedef int (*fcntl_type)(int fd, int cmd, ...);
fcntl_type orig_fcntl;

EXPORT int fcntl(int fd, int cmd, ...) {
        if (!orig_fcntl)
                orig_fcntl = (fcntl_type)dlsym(RTLD_NEXT, "fcntl");

        va_list argp;
        void *arg;
        va_start(argp, cmd);
        arg = va_arg(argp, void *);
        va_end(argp);

        int ret = orig_fcntl(fd, cmd, arg);
        int err = errno;

        if (is_inet_socket(fd)) {
                sock_ev_fcntl(fd, ret, err, cmd, arg);

                if ((cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) &&
                    ret != -1 && ebpf_collector_is_active())
                        ebpf_collector_dup_fd(fd, ret);
        }

        errno = err;
        return ret;
}

/* ── epoll_ctl() / epoll_wait() / epoll_pwait() ────────────────────────────── */

typedef int (*epoll_ctl_type)(int epfd, int op, int fd,
                              struct epoll_event *event);
epoll_ctl_type orig_epoll_ctl;

EXPORT int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
        if (!orig_epoll_ctl)
                orig_epoll_ctl =
                    (epoll_ctl_type)dlsym(RTLD_NEXT, "epoll_ctl");

        int ret = orig_epoll_ctl(epfd, op, fd, event);
        int err = errno;
        if (is_inet_socket(fd))
                sock_ev_epoll_ctl(fd, ret, err, op, event->events);

        errno = err;
        return ret;
}

typedef int (*epoll_wait_type)(int epfd, struct epoll_event *events,
                               int maxevents, int timeout);
epoll_wait_type orig_epoll_wait;

EXPORT int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                      int timeout) {
        if (!orig_epoll_wait)
                orig_epoll_wait =
                    (epoll_wait_type)dlsym(RTLD_NEXT, "epoll_wait");

        int ret = orig_epoll_wait(epfd, events, maxevents, timeout);
        int err = errno;
        for (int i = 0; i < ret; i++) {
                int fd = events[i].data.fd;
                if (is_inet_socket(fd))
                        sock_ev_epoll_wait(fd, ret, err, timeout,
                                           events[i].events);
        }

        errno = err;
        return ret;
}

typedef int (*epoll_pwait_type)(int epfd, struct epoll_event *events,
                                int maxevents, int timeout,
                                const sigset_t *sigmask);
epoll_pwait_type orig_epoll_pwait;

EXPORT int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
                       int timeout, const sigset_t *sigmask) {
        if (!orig_epoll_pwait)
                orig_epoll_pwait =
                    (epoll_pwait_type)dlsym(RTLD_NEXT, "epoll_pwait");

        int ret = orig_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
        int err = errno;
        for (int i = 0; i < ret; i++) {
                int fd = events[i].data.fd;
                if (is_inet_socket(fd))
                        sock_ev_epoll_pwait(fd, ret, err, timeout,
                                            events[i].events);
        }

        errno = err;
        return ret;
}

/* ── fdopen() / splice() ────────────────────────────────────────────────────── */

override(fdopen, FILE *, 2, const char *a);

typedef ssize_t (*splice_type)(int fd_in, loff_t *off_in, int fd_out,
                               loff_t *off_out, size_t len,
                               unsigned int flags);
static splice_type orig_splice;

EXPORT ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
                      size_t len, unsigned int flags) {
        if (!orig_splice)
                orig_splice = (splice_type)dlsym(RTLD_NEXT, "splice");

        ssize_t ret = orig_splice(fd_in, off_in, fd_out, off_out, len, flags);
        int err = errno;

        if (is_inet_socket(fd_in) || is_inet_socket(fd_out))
                sock_ev_splice(ret, err, fd_in, off_in, fd_out, off_out,
                               len, flags);

        errno = err;
        return ret;
}