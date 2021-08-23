#ifndef LNDPI_PACKET_FLOW_H
#define LNDPI_PACKET_FLOW_H

#include <stdlib.h>
#include <stdint.h>

#include <arpa/inet.h>

#include "ndpi_api.h"

struct lndpi_packet_flow
{
    struct ndpi_flow_struct* ndpi_flow;
    struct in_addr src_addr;
    struct in_addr dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    struct ndpi_id_struct* src_id_struct;
    struct ndpi_id_struct* dst_id_struct;
    ndpi_protocol protocol;
    uint8_t ip_protocol;
    uint8_t processed_packets_num;
    uint8_t protocol_was_guessed;
};

struct lndpi_packet_struct
{
    uint64_t time_ms;
    struct lndpi_packet_flow* ndpi_flow;
    uint16_t length;
    int8_t direction;
};


struct lndpi_packet_flow* lndpi_packet_flow_init(
    struct in_addr* src_addr,
    struct in_addr* dst_addr,
    uint16_t src_port,
    uint16_t dst_port,
    uint8_t ip_protocol
);

void lndpi_packet_flow_destroy(struct lndpi_packet_flow* pkt_flow);

int8_t lndpi_packet_flow_compare_with(
    struct lndpi_packet_flow* pkt_flow,
    struct in_addr src_addr,
    struct in_addr dst_addr,
    uint16_t src_port,
    uint16_t dst_port
);

#endif
