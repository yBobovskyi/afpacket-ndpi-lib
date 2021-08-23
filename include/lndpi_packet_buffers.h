#ifndef LNDPI_PACKET_BUFFERS_H
#define LNDPI_PACKET_BUFFERS_H

#include "lndpi_packet_flow.h"

/* */

struct lndpi_flow_buffer_element
{
    struct lndpi_packet_flow* flow;
    uint8_t alive;
};

struct lndpi_flow_buffer
{
    struct lndpi_flow_buffer_element* begin;
    struct lndpi_flow_buffer_element* end;
    uint32_t max_flow_number;
};

struct lndpi_flow_buffer* lndpi_flow_buffer_init(uint32_t max_flow_number);

void lndpi_flow_buffer_destroy(struct lndpi_flow_buffer* flow_buffer);

struct lndpi_packet_flow* lndpi_flow_buffer_find(
    struct lndpi_flow_buffer* flow_buffer,
    struct in_addr src_addr,
    struct in_addr dst_addr,
    uint16_t src_port,
    uint16_t dst_port,
    int8_t* direction
);

void lndpi_flow_buffer_insert(struct lndpi_flow_buffer* buffer, struct lndpi_packet_flow* flow);

void lndpi_flow_buffer_cleanup(struct lndpi_flow_buffer* buffer);

/* */

struct lndpi_packet_buffer
{
    struct lndpi_packet_struct* begin;
    struct lndpi_packet_struct* head;
    struct lndpi_packet_struct* tail;
    uint32_t max_packet_number;
};

struct lndpi_packet_buffer* lndpi_packet_buffer_init(uint32_t max_packet_number);

void lndpi_packet_buffer_destroy(struct lndpi_packet_buffer* buffer);

struct lndpi_packet_struct* lndpi_packet_buffer_next(
    struct lndpi_packet_buffer* buffer,
    struct lndpi_packet_struct* elem
);

void lndpi_packet_buffer_put(
    struct lndpi_packet_buffer* buffer,
    struct lndpi_packet_struct* packet
);

const struct lndpi_packet_struct* lndpi_packet_buffer_get(struct lndpi_packet_buffer* buffer);

void lndpi_packet_buffer_advance(struct lndpi_packet_buffer* buffer);

#endif
