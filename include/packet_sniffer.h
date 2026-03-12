#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <netinet/in.h>
#ifndef __ANDROID__
#include <pcap.h>
#endif
#include <pthread.h>
#include <stdbool.h>

#ifndef __ANDROID__
char *alloc_capture_filter(const struct sockaddr *addr1,
                           const struct sockaddr *addr2);

bool *start_capture(const char *filters, const char *path);
int stop_capture(bool *switch_flag, int delay_ms);
#endif /* __ANDROID__ */

#endif
