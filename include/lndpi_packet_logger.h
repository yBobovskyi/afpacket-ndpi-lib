#ifndef LNDPI_PACKET_LOGGER_H
#define LNDPI_PACKET_LOGGER_H

#include "lndpi_packet_flow.h"
#include "lndpi_errors.h"

enum lndpi_error lndpi_logger_init(const char* log_file_path);

enum lndpi_error lndpi_log_packet(
    struct ndpi_detection_module_struct* ndpi_struct,
    struct lndpi_packet_struct* packet,
    uint64_t timeout_ms,
    uint32_t max_packets_to_process,
    void* parameter
);

void lndpi_logger_exit(void);

#endif
