#ifndef LNDPI_PACKET_H
#define LNDPI_PACKET_H

#include <stdint.h>

#include "lndpi_errors.h"
#include "lndpi_packet_buffers.h"

#include <linux/if_packet.h>

/**
 *  Packet callback function type
 *
 *  @par    ndpi_struct             = pointer to an nDPI detection module struct
 *  @par    packet_struct           = pointer to a packet struct
 *  @par    timeout_ms              = timeout in milliseconds for a flow
 *  @par    max_packets_to_process  = max number of packets to process without knowing protocol before give up
 *  @par    parameter               = parameter which can be passed to callback funcion
 *  @return LNDPI_OK on a successful run and error code otherwise
 */
typedef enum lndpi_error (*lndpi_packet_callback_t)(
    struct ndpi_detection_module_struct* ndpi_struct,
    struct lndpi_packet_struct* packet_struct,
    uint64_t timeout_ms,
    uint32_t max_packets_to_process,
    void* parameter
);

/**
 *  Buffers callback function type
 *
 *  @par    ndpi_struct             = pointer to an nDPI detection module struct
 *  @par    flow_buffer             = pointer to a flow buffer linked list
 *  @par    packet_buffer           = pointer to a packet buffer linked list
 *  @par    timeout_ms              = timeout in milliseconds for a flow
 *  @par    max_packets_to_process  = max number of packets to process without knowing protocol before give up
 *  @par    max_flow_number         = max number of flows which can be processed simultaneously
 *  @par    parameter               = parameter which can be passed to callback funcion
 *  @return LNDPI_OK on a successful run and error code otherwise
 */
typedef enum lndpi_error (*lndpi_buffers_callback_t)(
    struct ndpi_detection_module_struct* ndpi_struct,
    struct lndpi_linked_list* flow_buffer,
    struct lndpi_linked_list* packet_buffer,
    uint64_t timeout_ms,
    uint32_t max_packets_to_process,
    uint32_t max_flow_number,
    void* parameter
);

/**
 *  Buffers callback function type
 * 
 *  @par    ndpi_struct             = pointer to an nDPI detection module struct
 *  @par    flow_buffer             = pointer to a flow buffer linked list
 *  @par    packet_buffer           = pointer to a packet buffer linked list
 *  @par    timeout_ms              = timeout in milliseconds for a flow
 *  @par    max_packets_to_process  = max number of packets to process without knowing protocol before give up
 *  @par    max_flow_number         = max number of flows which can be processed simultaneously
 *  @par    parameter               = parameter which can be passed to callback funcion
 *  @return LNDPI_OK on a successful run and error code otherwise
 */
typedef enum lndpi_error (*lndpi_finalize_callback_t)(
    struct ndpi_detection_module_struct* ndpi_struct,
    struct lndpi_linked_list* flow_buffer,
    struct lndpi_linked_list* packet_buffer,
    uint64_t timeout_ms,
    uint32_t max_packets_to_process,
    uint32_t max_flow_number,
    void* parameter
);

/**
 * Set packet callback function
 *
 *  @par    packet_callback     = packet callback function
 *  @par    parameter           = parameter to pass to packet_callback
 */
void lndpi_set_packet_callback_function(
    lndpi_packet_callback_t packet_callback,
    void* parameter
);

/**
 * Set buffers callback function
 *
 *  @par    buffers_callback    = buffers callback function
 *  @par    parameter           = parameter to pass to buffers_callback
 */
void lndpi_set_buffers_callback_function(
    lndpi_buffers_callback_t buffers_callback,
    void* parameter
);

/**
 *  Set packet callback function
 *
 *  @par    buffers_callback    = buffers callback function
 *  @par    parameter           = parameter to pass to buffers_callback
 */
void lndpi_set_finalize_callback_function(
    lndpi_finalize_callback_t finalize_callback,
    void* parameter
);

/**
 *  Initialize library
 *
 *  @par    max_flow_number         = max number of flows to store in a buffer
 *  @par    max_packets_to_process  = number of packets to process before give up
 *  @par    packet_buffer_size      = max number of packet to store in a buffer
 *  @par    flow_timeout_ms         = timeout for flow in milliseconds
 *  @return LNDPI_OK on a successful run and error code otherwise
 */
enum lndpi_error lndpi_packet_lib_init(
    uint32_t max_flow_number,
    uint32_t max_packets_to_process,
    uint32_t packet_buffer_size,
    uint64_t flow_timeout_ms
);

/**
 *  Initialize a log file for the default packet callback function
 *  Do not call if you use a custom one
 *
 *  @par    log_file_path       = path to a log file
 *  @return LNDPI_OK on a successful run and error code otherwise
 */
enum lndpi_error lndpi_init_log_file_path(char* log_file_path);

/**
 *  Main processing function
 *  Process one packet and update information about the protocol of it's flow
 *
 *  @par    pkt     = pointer to a packet
 *  @return LNDPI_OK on a successful run and error code otherwise
 */
enum lndpi_error lndpi_process_packet(const struct tpacket3_hdr* pkt);

/**
 *  Library finalize function
 *  Logs all processed information
 *  Basically calls finalize_callback function
 *
 *  @return LNDPI_OK on a successful run and error code otherwise
 */
enum lndpi_error lndpi_packet_lib_finalize(void);

/**
 *  Frees all the resources allocated by the library
 */
void lndpi_packet_lib_exit(void);

#endif
