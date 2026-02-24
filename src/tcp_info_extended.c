#include "tcp_info_extended.h"

#include <jansson.h>
#include <linux/version.h>
#include <linux/tcp.h>


typedef int (*add_fn)(json_t *o, const char *k, json_t *v);
static add_fn _add = &json_object_set_new;

void json_add_tcp_info_extended(json_t *json_details,
                                const struct tcp_info *info)
{
        if (!json_details || !info) return;

        /* ---- kernel >= 3.12 ------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
        _add(json_details, "pacing_rate",
             json_integer((json_int_t)info->tcpi_pacing_rate));
        _add(json_details, "max_pacing_rate",
             json_integer((json_int_t)info->tcpi_max_pacing_rate));
#endif

        /* ---- kernel >= 4.0 -------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
        _add(json_details, "min_rtt",
             json_integer(info->tcpi_min_rtt));
#endif

        /* ---- kernel >= 4.2 -------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
        _add(json_details, "bytes_acked",
             json_integer((json_int_t)info->tcpi_bytes_acked));
        _add(json_details, "bytes_received",
             json_integer((json_int_t)info->tcpi_bytes_received));
        _add(json_details, "segs_out",
             json_integer(info->tcpi_segs_out));
        _add(json_details, "segs_in",
             json_integer(info->tcpi_segs_in));
#endif

        /* ---- kernel >= 4.4 -------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
        _add(json_details, "notsent_bytes",
             json_integer(info->tcpi_notsent_bytes));
#endif

        /* ---- kernel >= 4.13 ------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
        _add(json_details, "data_segs_in",
             json_integer(info->tcpi_data_segs_in));
        _add(json_details, "data_segs_out",
             json_integer(info->tcpi_data_segs_out));
#endif

        /* ---- kernel >= 4.16 ------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
        _add(json_details, "delivery_rate",
             json_integer((json_int_t)info->tcpi_delivery_rate));
        _add(json_details, "delivery_rate_app_limited",
             json_boolean(info->tcpi_delivery_rate_app_limited));
#endif

        /* ---- kernel >= 4.19 ------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
        _add(json_details, "busy_time",
             json_integer((json_int_t)info->tcpi_busy_time));
        _add(json_details, "rwnd_limited",
             json_integer((json_int_t)info->tcpi_rwnd_limited));
        _add(json_details, "sndbuf_limited",
             json_integer((json_int_t)info->tcpi_sndbuf_limited));
        _add(json_details, "delivered",
             json_integer(info->tcpi_delivered));
#endif

        /* ---- kernel >= 5.0 -------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
        _add(json_details, "delivered_ce",
             json_integer(info->tcpi_delivered_ce));
#endif

        /* ---- kernel >= 5.7 -------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
        _add(json_details, "bytes_sent",
             json_integer((json_int_t)info->tcpi_bytes_sent));
        _add(json_details, "bytes_retrans",
             json_integer((json_int_t)info->tcpi_bytes_retrans));
        _add(json_details, "dsack_dups",
             json_integer(info->tcpi_dsack_dups));
        _add(json_details, "reord_seen",
             json_integer(info->tcpi_reord_seen));
#endif

        /* ---- kernel >= 5.8 -------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
        _add(json_details, "rcv_ooopack",
             json_integer(info->tcpi_rcv_ooopack));
#endif

        /* ---- kernel >= 5.15 ------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        _add(json_details, "snd_wnd",
             json_integer(info->tcpi_snd_wnd));
        _add(json_details, "rcv_wnd",
             json_integer(info->tcpi_rcv_wnd));
        _add(json_details, "rehash",
             json_integer(info->tcpi_rehash));
#endif

        /* ---- kernel >= 6.4 -------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
        _add(json_details, "total_rto",
             json_integer(info->tcpi_total_rto));
        _add(json_details, "total_rto_time",
             json_integer(info->tcpi_total_rto_time));
#endif
}
