#ifndef LNDPI_ERRORS_H
#define LNDPI_ERRORS_H

enum lndpi_error
{
    LNDPI_OK,
    LNDPI_OUT_OF_MEMORY,
    LNDPI_FLOW_BUFFER_OVERFLOW,
    LNDPI_PACKET_BUFFER_OVERFLOW,
    LNDPI_CANT_OPEN_LOG_FILE,
    LNDPI_CANT_WRITE_TO_LOG_FILE,
    LNDPI_NDPI_MODULE_INIT_ERROR,
    LNDPI_IPV6_NOT_SUPPORTED
};

char* lndpi_error_to_string(enum lndpi_error error, char* str_buffer);

#endif
