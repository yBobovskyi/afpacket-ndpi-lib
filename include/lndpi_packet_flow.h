#ifndef LNDPI_PACKET_FLOW_H
#define LNDPI_PACKET_FLOW_H

#include <stdlib.h>
#include <stdint.h>

#include <arpa/inet.h>

#include "ndpi_api.h"

/**
 *  Structure to describe packet flow
 *  Formal source is the source of the first arrivedc packet of the flow
 *  Formal destination is it's destination
 */
struct lndpi_packet_flow
{
    uint32_t id;                            /* ID */
    uint64_t last_packet_ms;                /* Timestamp for the last packet arrived */
    struct ndpi_flow_struct* ndpi_flow;     /* Pointer to nDPI flow state machine */
    struct in_addr src_addr;                /* Formal source IP address */
    struct in_addr dst_addr;                /* Formal destination IP address */
    uint16_t src_port;                      /* Formal source port */
    uint16_t dst_port;                      /* Formal destination port */
    struct ndpi_id_struct* src_id_struct;   /* Formal source state machine */
    struct ndpi_id_struct* dst_id_struct;   /* Formal destination state machine */
    ndpi_protocol protocol;                 /* Protocol detected by nDPI */
    uint32_t processed_packets_num;         /* Number of processed packets to detect protocol */
    uint32_t buffered_packets_num;          /* Number of packets that are currently in the packet buffer */
    uint8_t ip_protocol;                    /* Protocol ID from IP header */
    uint8_t protocol_was_guessed;           /* 1 if protocol was guessed after giving up; 0 otherwise */
};

/**
 *  Structure to describe packet
 */
struct lndpi_packet_struct
{
    uint64_t time_ms;                       /* Timestamp for arrival */
    struct lndpi_packet_flow* lndpi_flow;   /* Pointer to packet's flow */
    uint16_t length;                        /* Packet length */
    int8_t direction;                       /* Packet's direction regarding flow's formal parameters */
};

/**
 *  Allocate memory and initialize packet flow structure
 *  Allocate memory for state machines

 *  @param  src_addr        formal source IP address
 *  @param  dst_addr        formal destination IP address
 *  @param  src_port        formal source port
 *  @param  dst_port        formal destination port
 *  @param  ip_protocol     protocol ID from IP header
 *  @return pointer to a new allocated structure
 */
struct lndpi_packet_flow* lndpi_packet_flow_init(
    struct in_addr* src_addr,
    struct in_addr* dst_addr,
    uint16_t src_port,
    uint16_t dst_port,
    uint8_t ip_protocol
);

/**
 *  Free memory allocated for state machines
 *  Free memory allocated for packet flow structure
 *
 *  @param  pkt_flow        pointer to previously allocated packet flow structure
 */
void lndpi_packet_flow_destroy(struct lndpi_packet_flow* pkt_flow);

/**
 *  Check if packet flow is timed out
 *
 *  @param  flow        pointer to packet flow structure
 *  @param  timeout_ms  timeout duration in milliseconds
 *  @return 1 if timed out; 0 otherwise
 */
uint8_t lndpi_packet_flow_check_timeout(struct lndpi_packet_flow* flow, uint64_t timeout_ms);

/**
 *  Compare packet flow structure to a given addresses
 *
 *  @param  pkt_flow    pointer to packet flow structure
 *  @param  src_addr    source IP address
 *  @param  dst_addr    destination IP address
 *  @param  src_port    source port
 *  @param  dst_port    destination port
 *  @return 0 if addresses is not from given flow;
 *          1 if addresses match the flow's formal ones;
 *          -1 if addresses are indicated vice versa
 */
int8_t lndpi_packet_flow_compare_with(
    struct lndpi_packet_flow* pkt_flow,
    struct in_addr src_addr,
    struct in_addr dst_addr,
    uint16_t src_port,
    uint16_t dst_port
);

#endif
