#ifndef LNDPI_PACKET_LOGGER_H
#define LNDPI_PACKET_LOGGER_H

#include "lndpi_packet_flow.h"
#include "lndpi_errors.h"

/**
 *  Initialize log file descriptor
 *
 *  @param  log_file_path   path to log file
 *  @return LNDPI_OK on a successful run and an error code otherwise
 */
enum lndpi_error lndpi_logger_init(const char* log_file_path);

/**
 *  Default packet callback function
 *  Log packet information into log file
 *
 *  @param  ndpi_struct             pointer to an nDPI detection module struct
 *  @param  packet_struct           pointer to a packet struct
 *  @param  timeout_ms              timeout in milliseconds for a flow
 *  @param  max_packets_to_process  max number of packets to process without knowing protocol before give up
 *  @param  parameter               parameter which can be passed to callback funcion
 *  @return LNDPI_OK on a successful run and an error code otherwise
 */
enum lndpi_error lndpi_log_packet(
    struct ndpi_detection_module_struct* ndpi_struct,
    struct lndpi_packet_struct* packet,
    uint64_t timeout_ms,
    uint32_t max_packets_to_process,
    void* parameter
);

/**
 *  Close opened file descriptor
 */
void lndpi_logger_exit(void);

#endif
