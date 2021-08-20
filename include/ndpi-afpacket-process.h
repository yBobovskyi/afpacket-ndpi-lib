#include <stdlib.h>
#include <stdint.h>

#include <linux/if_packet.h>

void packet_process_init(const char* log_file_path);

void process_packet(const struct tpacket3_hdr* pkt);

void packet_process_exit(void);
