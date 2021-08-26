#include "lndpi_errors.h"

#include <string.h>

char* lndpi_error_to_string(enum lndpi_error error, char* str_buffer)
{
    switch (error) {
        case LNDPI_OK:
            strcpy(str_buffer, "OK");
            break;
        case LNDPI_OUT_OF_MEMORY:
            strcpy(str_buffer, "Out of memory");
            break;
        case LNDPI_FLOW_BUFFER_OVERFLOW:
            strcpy(str_buffer, "Flow buffer overflow");
            break;
        case LNDPI_PACKET_BUFFER_OVERFLOW:
            strcpy(str_buffer, "Packet buffer overflow");
            break;
        case LNDPI_CANT_OPEN_LOG_FILE:
            strcpy(str_buffer, "Can't open log file");
            break;
        case LNDPI_NDPI_MODULE_INIT_ERROR:
            strcpy(str_buffer, "ndpi_detection_module_struct can't be initialized");
            break;
        case LNDPI_IPV6_NOT_SUPPORTED:
            strcpy(str_buffer, "IPv6 is not supported yet");
            break;
        default:
            strcpy(str_buffer, "Unknown error");
    }

    return str_buffer;
}
