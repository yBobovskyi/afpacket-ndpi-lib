#ifndef LNDPI_PACKET_BUFFERS_H
#define LNDPI_PACKET_BUFFERS_H

#include "lndpi_packet_flow.h"
#include "lndpi_errors.h"

/**
 *  Linked list element structure
 */
struct lndpi_linked_list_element
{
    struct lndpi_linked_list_element* next;     /* Pointer to the hext element */

    union                                       /* Union to store pointer to data */
    {
        struct lndpi_packet_flow* flow;
        struct lndpi_packet_struct* packet;
    } data;
};

/**
 *  Linked list structure
 */
struct lndpi_linked_list
{
    struct lndpi_linked_list_element* head;     /* Pointer to the first element */
    struct lndpi_linked_list_element* tail;     /* Pointer to the last element */
    uint32_t elements_number;                   /* Number of elements in the list */
    uint32_t max_elements_number;               /* Maximum allowed number of elements */
};

/**
 *  Free all memory allocated by flow structures
 *  Delete all elements
 *
 *  @par    flow_buffer     = pointer to flow buffer
 */
void lndpi_flow_buffer_clear(struct lndpi_linked_list* flow_buffer);

/**
 *  Find flow in a buffer with corresponding addresses
 *
 *  @par    flow_buffer     = pointer to flow buffer
 *  @par    src_addr        = source IP address
 *  @par    dst_addr        = destination IP address
 *  @par    src_port        = source port
 *  @par    dst_port        = destination port
 *  @par    direction       = buffer to store direction of given addresses
 *  @return pointer to the found flow or NULL
 */
struct lndpi_packet_flow* lndpi_flow_buffer_find(
    struct lndpi_linked_list* flow_buffer,
    struct in_addr src_addr,
    struct in_addr dst_addr,
    uint16_t src_port,
    uint16_t dst_port,
    int8_t* direction
);

/**
 *  Put a new flow in a buffer
 *
 *  @par    buffer      = pointer to a flow buffer
 *  @par    flow        = pointer to a new flow
 *  @return LNDPI_OK on a successful run and error code otherwise
 */
enum lndpi_error lndpi_flow_buffer_put(
    struct lndpi_linked_list* buffer,
    struct lndpi_packet_flow* flow
);

/**
 *  Remove and free all timed out flows from a buffer
 *
 *  @par    flow_buffer     = pointer to a flow buffer
 *  @par    timeout_ms      = timeout duration in milliseconds
 */
void lndpi_flow_buffer_cleanup(struct lndpi_linked_list* flow_buffer, uint64_t timeout_ms);

/**
 *  Remove and free all flows from a buffer
 *
 *  @par    flow_buffer     = pointer to a flow buffer
 */
void lndpi_packet_buffer_clear(struct lndpi_linked_list* buffer);

/**
 *  Put a new packet to a packet buffer
 *
 *  @par    buffer      = pointer to a packet buffer
 *  @par    packet      = pointer to a new packet
 *  @return LNDPI_OK on a successful run and error code otherwise
 */
enum lndpi_error lndpi_packet_buffer_put(
    struct lndpi_linked_list* buffer,
    struct lndpi_packet_struct* packet
);

/**
 *  Remove and free first packet from a packet buffer
 *
 *  @par    buffer      = pointer to a packet buffer
 */
void lndpi_packet_buffer_advance(struct lndpi_linked_list* buffer);

#endif
