#include "lndpi_packet_flow.h"

struct lndpi_packet_flow* lndpi_packet_flow_init(
    struct in_addr* src_addr,
    struct in_addr* dst_addr,
    uint16_t src_port,
    uint16_t dst_port,
    uint8_t ip_protocol
) {
    struct lndpi_packet_flow* res = ndpi_malloc(sizeof(struct lndpi_packet_flow));
    memset(res, 0, sizeof(struct lndpi_packet_flow));

    res->ndpi_flow = (struct ndpi_flow_struct*)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    memset(res->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

    res->src_id_struct = (struct ndpi_id_struct*)ndpi_malloc(SIZEOF_ID_STRUCT);
    res->dst_id_struct = (struct ndpi_id_struct*)ndpi_malloc(SIZEOF_ID_STRUCT);
    memset(res->src_id_struct, 0, SIZEOF_ID_STRUCT);
    memset(res->dst_id_struct, 0, SIZEOF_ID_STRUCT);

    res->protocol.master_protocol = NDPI_PROTOCOL_UNKNOWN;
    res->protocol.app_protocol = NDPI_PROTOCOL_UNKNOWN;
    res->ip_protocol = ip_protocol;

    res->src_addr = *src_addr;
    res->dst_addr = *dst_addr;
    res->src_port = src_port;
    res->dst_port = dst_port;


    res->processed_packets_num = 0;

    res->protocol_was_guessed = 0;
}

int8_t lndpi_packet_flow_compare_with(
    struct lndpi_packet_flow* pkt_flow1,
    struct in_addr src_addr,
    struct in_addr dst_addr,
    uint16_t src_port,
    uint16_t dst_port
)
{
    if (pkt_flow1->src_addr.s_addr == src_addr.s_addr
        && pkt_flow1->dst_addr.s_addr == dst_addr.s_addr
        && pkt_flow1->src_port == src_port
        && pkt_flow1->dst_port == dst_port)
        return 1;
    else if (pkt_flow1->src_addr.s_addr == dst_addr.s_addr
        && pkt_flow1->dst_addr.s_addr == src_addr.s_addr
        && pkt_flow1->src_port == dst_port
        && pkt_flow1->dst_port == src_port)
        return -1;

    return 0;
}

void lndpi_packet_flow_destroy(struct lndpi_packet_flow* pkt_flow)
{
    ndpi_flow_free(pkt_flow->ndpi_flow);

    ndpi_free(pkt_flow->src_id_struct);
    ndpi_free(pkt_flow->dst_id_struct);

    ndpi_free(pkt_flow);
}
