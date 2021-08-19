#include <stdlib.h>
#include <stdint.h>

#include <linux/if_packet.h>

#include "ndpi_api.h"

ndpi_protocol process_afpacket(const struct tpacket3_hdr* pkt);
