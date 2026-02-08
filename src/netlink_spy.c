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


// TODO : check si on esy sur le bon PID quand on detecte

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
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG(ERROR, "Netlink: bind() failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

static void* netlink_monitor_thread(void* arg) {
    (void)arg;
    
    // Log de démarrage
    LOG(INFO, "Netlink spy thread started (monitoring IP/Route changes).");

    int sock = open_netlink_socket();
    if (sock < 0) {
        LOG(ERROR, "Failed to open Netlink socket");
        return NULL;
    }

    // On enregistre ce socket dans le système TCPSnitch
    sock_ev_netlink_init(sock);

    char buffer[8192];
    struct iovec iov = { buffer, sizeof(buffer) };
    struct sockaddr_nl sa;
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

    while (1) {
        ssize_t len = recvmsg(sock, &msg, 0);
        if (len < 0) { sleep(1); continue; }

        struct nlmsghdr *nh = (struct nlmsghdr *)buffer;
        for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) break;
            if (nh->nlmsg_type == NLMSG_ERROR) continue;

            // Gestion des ADRESSES (IP ajoutée/supprimée)
            if (nh->nlmsg_type == RTM_NEWADDR || nh->nlmsg_type == RTM_DELADDR) {
                struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
                struct rtattr *tb[IFA_MAX + 1];
                
                parse_rtattr(tb, IFA_MAX, IFA_RTA(ifa), IFA_PAYLOAD(nh));
                
                char ip_str[INET6_ADDRSTRLEN] = {0};
                if (tb[IFA_ADDRESS]) {
                    inet_ntop(ifa->ifa_family, RTA_DATA(tb[IFA_ADDRESS]), ip_str, sizeof(ip_str));
                } else if (tb[IFA_LOCAL]) {
                    inet_ntop(ifa->ifa_family, RTA_DATA(tb[IFA_LOCAL]), ip_str, sizeof(ip_str));
                }

                // Log textuel 
                const char *action = (nh->nlmsg_type == RTM_NEWADDR) ? "New Address" : "Address Removed";
                LOG(INFO, "NETLINK EVENT: %s detected (Interface: %d, IP: %s)", action, ifa->ifa_index, ip_str);

                // Envoi au JSON
                sock_ev_netlink(sock, nh->nlmsg_type, ifa->ifa_index, ifa->ifa_family, ip_str);
            }
            
            // Gestion des ROUTES (Route ajoutée/supprimée)
            else if (nh->nlmsg_type == RTM_NEWROUTE || nh->nlmsg_type == RTM_DELROUTE) {
                
                // Log textuel 
                const char *action = (nh->nlmsg_type == RTM_NEWROUTE) ? "New Route" : "Route Removed";
                LOG(INFO, "NETLINK EVENT: %s detected in routing table", action);

                // Envoi au JSON
                sock_ev_netlink(sock, nh->nlmsg_type, 0, 0, NULL);
            }
        }
    }
    close(sock);
    return NULL;
}

void start_netlink_spy_thread(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, netlink_monitor_thread, NULL) != 0) {
        LOG(ERROR, "Failed to create Netlink spy thread");
    }
}