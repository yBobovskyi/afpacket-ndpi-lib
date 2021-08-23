#ifndef LNDPI_PACKET_LOGGER_H
#define LNDPI_PACKET_LOGGER_H

#include "lndpi_packet_flow.h"

void lndpi_logger_init(const char* log_file_path);

void lndpi_log_packet(
    struct ndpi_detection_module_struct* ndpi_struct,
    struct lndpi_packet_struct* packet
);

void lndpi_logger_exit(void);

#endif
