#ifndef LNDPI_PACKET_H
#define LNDPI_PACKET_H

#include <stdint.h>

#include "lndpi_errors.h"

#include <linux/if_packet.h>

enum lndpi_error lndpi_packet_lib_init(
    const char* log_file_path,
    uint32_t max_flow_number,
    uint32_t max_packets_to_process,
    uint32_t packet_buffer_size,
    uint64_t flow_timeout_ms
);

enum lndpi_error lndpi_process_packet(const struct tpacket3_hdr* pkt);

enum lndpi_error lndpi_packet_lib_finalize(void);

void lndpi_packet_lib_exit(void);

#endif
