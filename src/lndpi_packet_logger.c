#include <stdio.h>
#include <string.h>

#include "lndpi_packet_logger.h"

static FILE* log_file;

void lndpi_logger_init(const char* log_file_path)
{
    log_file = fopen(log_file_path, "a");
}

void lndpi_log_packet(
    struct ndpi_detection_module_struct* ndpi_struct,
    struct lndpi_packet_struct* packet
) {
    char src_addr[16], dst_addr[16];
    uint16_t src_port, dst_port;

    if (packet->direction == 1)
    {
        strcpy(&src_addr[0], inet_ntoa(packet->lndpi_flow->src_addr));
        strcpy(&dst_addr[0], inet_ntoa(packet->lndpi_flow->dst_addr));
        src_port = packet->lndpi_flow->src_port;
        dst_port = packet->lndpi_flow->dst_port;
    } else
    {
        strcpy(&src_addr[0], inet_ntoa(packet->lndpi_flow->dst_addr));
        strcpy(&dst_addr[0], inet_ntoa(packet->lndpi_flow->src_addr));
        src_port = packet->lndpi_flow->dst_port;
        dst_port = packet->lndpi_flow->src_port;
    }

    char protocol_str[25], category_str[16];

    ndpi_protocol2name(ndpi_struct, packet->lndpi_flow->protocol, &protocol_str[0], 25);

    strcpy(&category_str[0], ndpi_category_get_name(ndpi_struct, packet->lndpi_flow->protocol.category));

    printf("| %10u | %20lu | %20s:%-7u | %20s:%-7u | %10u | %10u | %20s | %15s | %8s | %10u |\n",
        packet->lndpi_flow->id,
        packet->time_ms,
        &src_addr[0],
        src_port,
        &dst_addr[0],
        dst_port,
        packet->length,
        packet->lndpi_flow->ip_protocol,
        &protocol_str[0],
        &category_str[0],
        packet->lndpi_flow->protocol_was_guessed ? "Guessed" : "",
        packet->lndpi_flow->processed_packets_num
    );
}

void lndpi_logger_exit(void)
{
    fclose(log_file);
}
