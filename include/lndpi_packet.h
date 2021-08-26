#ifndef LNDPI_PACKET_H
#define LNDPI_PACKET_H

#include <stdint.h>

#include "lndpi_errors.h"
#include "lndpi_packet_buffers.h"

#include <linux/if_packet.h>

void lndpi_set_packet_callback_function(
    enum lndpi_error (*packet_callback)(
        struct ndpi_detection_module_struct* ndpi_struct,
        struct lndpi_packet_struct* packet_struct,
        uint64_t timeout_ms,
        uint32_t max_packets_to_process,
        void* parameter
    ),
    void* parameter
);

void lndpi_set_buffers_callback_function(
    enum lndpi_error (*buffers_callback)(
        struct ndpi_detection_module_struct* ndpi_struct,
        struct lndpi_linked_list* flow_buffer,
        struct lndpi_linked_list* packet_buffer,
        uint64_t timeout_ms,
        uint32_t max_packets_to_process,
        uint32_t max_flow_number,
        void* parameter
    ),
    void* parameter
);

void lndpi_set_finalize_callback_function(
    enum lndpi_error (*finalize_callback)(
        struct ndpi_detection_module_struct* ndpi_struct,
        struct lndpi_linked_list*,
        struct lndpi_linked_list*,
        uint64_t timeout_ms,
        uint32_t max_packets_to_process,
        uint32_t max_flow_number,
        void* parameter
    ),
    void* parameter
);

enum lndpi_error lndpi_packet_lib_init(
    uint32_t max_flow_number,
    uint32_t max_packets_to_process,
    uint32_t packet_buffer_size,
    uint64_t flow_timeout_ms
);

enum lndpi_error lndpi_init_log_file_path(char* log_file_path);

enum lndpi_error lndpi_process_packet(const struct tpacket3_hdr* pkt);

enum lndpi_error lndpi_packet_lib_finalize(void);

void lndpi_packet_lib_exit(void);

#endif
