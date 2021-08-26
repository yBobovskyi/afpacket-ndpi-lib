#ifndef LNDPI_PACKET_BUFFERS_H
#define LNDPI_PACKET_BUFFERS_H

#include "lndpi_packet_flow.h"
#include "lndpi_errors.h"
/* */

struct lndpi_linked_list_element
{
    struct lndpi_linked_list_element* next;

    union
    {
        struct lndpi_packet_flow* flow;
        struct lndpi_packet_struct* packet;
    } data;
};

struct lndpi_linked_list
{
    struct lndpi_linked_list_element* head;
    struct lndpi_linked_list_element* tail;
    uint32_t elements_number;
    uint32_t max_elements_number;
};

void lndpi_flow_buffer_clear(struct lndpi_linked_list* flow_buffer);

struct lndpi_packet_flow* lndpi_flow_buffer_find(
    struct lndpi_linked_list* flow_buffer,
    struct in_addr src_addr,
    struct in_addr dst_addr,
    uint16_t src_port,
    uint16_t dst_port,
    int8_t* direction
);

enum lndpi_error lndpi_flow_buffer_put(
    struct lndpi_linked_list* buffer,
    struct lndpi_packet_flow* flow
);

void lndpi_flow_buffer_cleanup(struct lndpi_linked_list* flow_buffer, uint64_t timeout_ms);

/* */

void lndpi_packet_buffer_clear(struct lndpi_linked_list* buffer);

enum lndpi_error lndpi_packet_buffer_put(
    struct lndpi_linked_list* buffer,
    struct lndpi_packet_struct* packet
);

const struct lndpi_packet_struct* lndpi_packet_buffer_get(struct lndpi_linked_list* buffer);

void lndpi_packet_buffer_advance(struct lndpi_linked_list* buffer);

#endif
