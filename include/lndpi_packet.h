#ifndef LNDPI_PACKET_H
#define LNDPI_PACKET_H

#include <linux/if_packet.h>

void lndpi_packet_lib_init(const char* log_file_path);

void lndpi_process_packet(const struct tpacket3_hdr* pkt);

void lndpi_packet_lib_exit(void);

#endif
