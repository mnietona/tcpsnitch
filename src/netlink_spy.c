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
#include "sock_events.h"
#include "logger.h"
#include <ifaddrs.h>
#include <net/if.h>

// Utile pour parser les attributs Netlink
void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len) {
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, len);
    }
}

static int open_netlink_socket(void) {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        LOG(ERROR, "Netlink: socket() failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
  
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE
                   | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG(ERROR, "Netlink: bind() failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

static void dump_initial_interfaces(int netlink_sock_fd) {
    struct ifaddrs *ifaddr, *ifa;
    char host[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1) {
        LOG(ERROR, "getifaddrs failed: %s", strerror(errno));
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        int family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) continue;

        int s = getnameinfo(
            ifa->ifa_addr,
            (family == AF_INET) ? sizeof(struct sockaddr_in)
                                : sizeof(struct sockaddr_in6),
            host, sizeof(host),
            NULL, 0,
            NI_NUMERICHOST);

        if (s != 0) continue;

        int if_index = if_nametoindex(ifa->ifa_name);

        sock_ev_netlink(netlink_sock_fd, RTM_NEWADDR, if_index, family, host);

        LOG(INFO, "Initial Interface: %s [%d] -> %s (msg_type=%d=RTM_NEWADDR)",
            ifa->ifa_name, if_index, host, RTM_NEWADDR);
    }

    freeifaddrs(ifaddr);
}


static void *netlink_monitor_thread(void *arg) {
    (void)arg;

    LOG(INFO, "Netlink spy thread started (monitoring IP/Route changes).");

    int sock = open_netlink_socket();
    if (sock < 0) {
        LOG(ERROR, "Failed to open Netlink socket");
        return NULL;
    }

    sock_ev_netlink_init(sock);
    dump_initial_interfaces(sock);

    char buffer[8192];
    struct iovec iov = { buffer, sizeof(buffer) };
    struct sockaddr_nl sa;
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

    while (1) {
        ssize_t len = recvmsg(sock, &msg, 0);
        if (len < 0) { sleep(1); continue; }

        struct nlmsghdr *nh = (struct nlmsghdr *)buffer;
        for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {

            if (nh->nlmsg_type == NLMSG_DONE)  break;
            if (nh->nlmsg_type == NLMSG_ERROR) continue;

            // Gestion des ADRESSES
            if (nh->nlmsg_type == RTM_NEWADDR || nh->nlmsg_type == RTM_DELADDR) {
                struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
                struct rtattr *tb[IFA_MAX + 1];
                parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(nh));

                char ip_str[INET6_ADDRSTRLEN] = {0};
                if (tb[IFA_ADDRESS]) {
                    inet_ntop(ifa->ifa_family,
                              RTA_DATA(tb[IFA_ADDRESS]),
                              ip_str, sizeof(ip_str));
                } else if (tb[IFA_LOCAL]) {
                    inet_ntop(ifa->ifa_family,
                              RTA_DATA(tb[IFA_LOCAL]),
                              ip_str, sizeof(ip_str));
                }

                const char *action = (nh->nlmsg_type == RTM_NEWADDR)
                                   ? "New Address" : "Address Removed";
                LOG(INFO, "NETLINK EVENT: %s (iface=%d ip=%s msg_type=%d)",
                    action, ifa->ifa_index, ip_str, nh->nlmsg_type);

                sock_ev_netlink(sock, nh->nlmsg_type,
                                ifa->ifa_index, ifa->ifa_family, ip_str);
            }

           // Gestion des ROUTES
            else if (nh->nlmsg_type == RTM_NEWROUTE ||
                     nh->nlmsg_type == RTM_DELROUTE) {

                struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
                struct rtattr *tb[RTA_MAX + 1];
                parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(nh));

                char dst_str[INET6_ADDRSTRLEN] = {0};

                if (tb[RTA_DST]) {
                    
                    inet_ntop(rtm->rtm_family,
                              RTA_DATA(tb[RTA_DST]),
                              dst_str, sizeof(dst_str));
                } else {
                   
                    if (rtm->rtm_family == AF_INET)
                        strncpy(dst_str, "0.0.0.0", sizeof(dst_str));
                    else
                        strncpy(dst_str, "::", sizeof(dst_str));
                }

                char gw_str[INET6_ADDRSTRLEN] = {0};
                if (tb[RTA_GATEWAY]) {
                    inet_ntop(rtm->rtm_family,
                              RTA_DATA(tb[RTA_GATEWAY]),
                              gw_str, sizeof(gw_str));
                }

                const char *action = (nh->nlmsg_type == RTM_NEWROUTE)
                                   ? "New Route" : "Route Removed";
                LOG(INFO,
                    "NETLINK EVENT: %s dst=%s/%d gw=%s family=%d msg_type=%d",
                    action, dst_str, rtm->rtm_dst_len,
                    gw_str[0] ? gw_str : "(direct)",
                    rtm->rtm_family, nh->nlmsg_type);

                sock_ev_netlink(sock, nh->nlmsg_type,
                                0,              
                                rtm->rtm_family,
                                dst_str);
            }
        }
    }

    close(sock);
    return NULL;
}

void start_netlink_spy_thread(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, netlink_monitor_thread, NULL) != 0) {
        LOG(ERROR, "Failed to create Netlink spy thread: %s", strerror(errno));
    }
}