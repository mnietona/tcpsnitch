#include "netlink_spy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "logger.h"

// Fonction pour ouvrir le socket Netlink
static int open_netlink_socket(void) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        LOG(ERROR, "Netlink: socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    // On s'abonne aux groupes multicast pour IPv4 et IPv6 (Adresses et Routes)
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE |
                     RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG(ERROR, "Netlink: bind() failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

// Thread qui écoute en boucle
static void* netlink_monitor_thread(void* arg) {
    (void)arg; // Unused
    LOG(INFO, "Netlink spy thread started (monitoring IP/Route changes).");

    int sock = open_netlink_socket();
    if (sock < 0) return NULL;

    char buffer[4096];
    struct iovec iov = { buffer, sizeof(buffer) };
    struct sockaddr_nl sa;
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

    while (1) {
        ssize_t len = recvmsg(sock, &msg, 0);
        if (len < 0) {
            LOG(ERROR, "Netlink: recvmsg failed: %s", strerror(errno));
            sleep(1);
            continue;
        }

        struct nlmsghdr *nh = (struct nlmsghdr *)buffer;

        for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) break;
            if (nh->nlmsg_type == NLMSG_ERROR) continue;

            if (nh->nlmsg_type == RTM_NEWADDR) {
                struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
                LOG(INFO, "NETLINK EVENT: New IP Address detected (if_index: %d)", ifa->ifa_index);
            }
            else if (nh->nlmsg_type == RTM_DELADDR) {
                struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
                LOG(INFO, "NETLINK EVENT: IP Address removed (if_index: %d)", ifa->ifa_index);
            }
            else if (nh->nlmsg_type == RTM_NEWROUTE) {
                LOG(INFO, "NETLINK EVENT: New Route added");
            }
            else if (nh->nlmsg_type == RTM_DELROUTE) {
                LOG(INFO, "NETLINK EVENT: Route removed");
            }
        }
    }
    close(sock);
    return NULL;
}

// Fonction publique appelée par init.c
void start_netlink_spy_thread(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, netlink_monitor_thread, NULL) != 0) {
        LOG(ERROR, "Failed to create Netlink spy thread");
    }
}