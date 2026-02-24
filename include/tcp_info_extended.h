#ifndef TCP_INFO_EXTENDED_H
#define TCP_INFO_EXTENDED_H

#include <jansson.h>
#include <linux/tcp.h>

void json_add_tcp_info_extended(json_t *json_details,
                                const struct tcp_info *info);

#endif /* TCP_INFO_EXTENDED_H */
