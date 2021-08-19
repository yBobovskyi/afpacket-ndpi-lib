#include "ndpi-afpacket-process.h"

#include <linux/if_ether.h>

ndpi_protocol process_afpacket(const struct tpacket3_hdr* pkt)
{
    /* Reaching an L3 pointer */
    const uint8_t* afpacket = (const uint8_t*)pkt + pkt->tp_net;

    /* IPv4 header */
    struct ndpi_iphdr* iph = (struct ndpi_iphdr*)afpacket;

    /* Initializing a detection module */
    struct ndpi_detection_module_struct* ndpi_detection_mod =
        ndpi_init_detection_module(ndpi_no_prefs);
    /* Enabling all protocols */
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_detection_mod, &all);
    ndpi_finalize_initialization(ndpi_detection_mod);

    /* Allocating a flow struct */
    struct ndpi_flow_struct* ndpi_flow =
        (struct ndpi_flow_struct*)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    memset(ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

    /* Allocating source and destination id structs */
    struct ndpi_id_struct* src_id =
        (struct ndpi_id_struct*)ndpi_malloc(SIZEOF_ID_STRUCT);
    memset(src_id, 0, SIZEOF_ID_STRUCT);
    struct ndpi_id_struct* dst_id =
        (struct ndpi_id_struct*)ndpi_malloc(SIZEOF_ID_STRUCT);
    memset(dst_id, 0, SIZEOF_ID_STRUCT);

    /* Getting 64bit timestamp in ms */
    uint64_t time_ms = (uint64_t)pkt->tp_sec * 1000 + pkt->tp_nsec / 1000000;

    /* Detecting AF_PACKET's protocol */
    ndpi_protocol result = ndpi_detection_process_packet(
        ndpi_detection_mod,
        ndpi_flow,
        afpacket,
        iph->tot_len,
        time_ms,
        src_id,
        dst_id
    );

    /* Destroying the detection module */
    ndpi_exit_detection_module(ndpi_detection_mod);

    return result;
}
