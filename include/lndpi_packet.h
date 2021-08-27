#ifndef LNDPI_PACKET_H
#define LNDPI_PACKET_H

#include <stdint.h>

#include "lndpi_errors.h"
#include "lndpi_packet_buffers.h"

#include <linux/if_packet.h>

/**
 *  Packet callback function type
 *
 *  @param  ndpi_struct             pointer to an nDPI detection module struct
 *  @param  packet_struct           pointer to a packet struct
 *  @param  timeout_ms              timeout in milliseconds for a flow
 *  @param  max_packets_to_process  max number of packets to process without knowing protocol before give up
 *  @param  parameter               parameter which can be passed to callback funcion
 *  @return LNDPI_OK on a successful run and an error code otherwise
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
 *  @param  ndpi_struct             pointer to an nDPI detection module struct
 *  @param  flow_buffer             pointer to a flow buffer linked list
 *  @param  packet_buffer           pointer to a packet buffer linked list
 *  @param  timeout_ms              timeout in milliseconds for a flow
 *  @param  max_packets_to_process  max number of packets to process without knowing protocol before give up
 *  @param  max_flow_number         max number of flows which can be processed simultaneously
 *  @param  parameter               parameter which can be passed to callback funcion
 *  @return LNDPI_OK on a successful run and an error code otherwise
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
 *  Finalize callback function type
 *
 *  @param  ndpi_struct             pointer to an nDPI detection module struct
 *  @param  flow_buffer             pointer to a flow buffer linked list
 *  @param  packet_buffer           pointer to a packet buffer linked list
 *  @param  timeout_ms              timeout in milliseconds for a flow
 *  @param  max_packets_to_process  max number of packets to process without knowing protocol before give up
 *  @param  max_flow_number         max number of flows which can be processed simultaneously
 *  @param  parameter               parameter which can be passed to callback funcion
 *  @return LNDPI_OK on a successful run and an error code otherwise
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
 *  @param  packet_callback     packet callback function
 *  @param  parameter           parameter to pass to packet_callback
 */
void lndpi_set_packet_callback_function(
    lndpi_packet_callback_t packet_callback,
    void* parameter
);

/**
 * Set buffers callback function
 *
 *  @param  buffers_callback    buffers callback function
 *  @param  parameter           parameter to pass to buffers_callback
 */
void lndpi_set_buffers_callback_function(
    lndpi_buffers_callback_t buffers_callback,
    void* parameter
);

/**
 *  Set finalize callback function
 *
 *  @param  buffers_callback    buffers callback function
 *  @param  parameter           parameter to pass to finalize_callback
 */
void lndpi_set_finalize_callback_function(
    lndpi_finalize_callback_t finalize_callback,
    void* parameter
);

/**
 *  Initialize library
 *
 *  @param  max_flow_number         max number of flows to store in a buffer
 *  @param  max_packets_to_process  number of packets to process before give up
 *  @param  packet_buffer_size      max number of packet to store in a buffer
 *  @param  flow_timeout_ms         timeout for flow in milliseconds
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
 *  @param  log_file_path       path to a log file
 *  @return LNDPI_OK on a successful run and an error code otherwise
 */
enum lndpi_error lndpi_init_log_file_path(char* log_file_path);

/**
 *  Main processing function
 *  Process one packet and update information about the protocol of it's flow
 *
 *  @param  pkt     = pointer to a packet
 *  @return LNDPI_OK on a successful run and an error code otherwise
 */
enum lndpi_error lndpi_process_packet(const struct tpacket3_hdr* pkt);

/**
 *  Library finalize function
 *  Log all processed information
 *  Basically call finalize_callback function
 *
 *  @return LNDPI_OK on a successful run and an error code otherwise
 */
enum lndpi_error lndpi_packet_lib_finalize(void);

/**
 *  Free all the resources allocated by the library
 */
void lndpi_packet_lib_exit(void);

#endif
