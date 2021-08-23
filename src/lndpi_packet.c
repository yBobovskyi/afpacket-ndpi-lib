#include "lndpi_packet.h"
#include "lndpi_packet_buffers.h"
#include "lndpi_packet_logger.h"

#define IPPROTO_ICMP    0x01
#define IPPROTO_IGMP    0x02


#define LNDPI_MAX_FLOWS 128
#define LNDPI_MAX_PACKETS_PER_FLOW 80

static struct ndpi_detection_module_struct* ndpi_struct;
static struct lndpi_flow_buffer* flow_buffer;
static struct lndpi_packet_buffer* packet_buffer;

/* */

static void lndpi_detection_module_init(void)
{
    /* Initializing a detection module */
    ndpi_struct = ndpi_init_detection_module(ndpi_no_prefs);
    /* Enabling all protocols */
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);
    ndpi_finalize_initialization(ndpi_struct);
}

/* */

void lndpi_packet_lib_init(const char* log_file_path)
{
    lndpi_detection_module_init();

    lndpi_logger_init(log_file_path);

    flow_buffer = lndpi_flow_buffer_init(LNDPI_MAX_FLOWS);

    packet_buffer = lndpi_packet_buffer_init(LNDPI_MAX_FLOWS * LNDPI_MAX_PACKETS_PER_FLOW);
}

void lndpi_packet_lib_exit(void)
{
    /* Destroying the detection module */
    ndpi_exit_detection_module(ndpi_struct);

    lndpi_logger_exit();

    lndpi_flow_buffer_destroy(flow_buffer);

    lndpi_packet_buffer_destroy(packet_buffer);
}

struct l4_header_addr
{
    uint16_t src_port;
    uint16_t dst_port;
};

static uint8_t lndpi_packet_has_l4header(struct ndpi_iphdr* iph)
{
    return (iph->protocol != IPPROTO_ICMP
        && iph->protocol != IPPROTO_IGMP);
}

static void lndpi_process_buffers(void)
{
    struct lndpi_packet_struct* packet_iter;

    for (packet_iter = packet_buffer->head; packet_iter != packet_buffer->tail;
        packet_iter = lndpi_packet_buffer_next(packet_buffer, packet_iter))
    {
        if (packet_iter->ndpi_flow->protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
        {
            lndpi_log_packet(ndpi_struct, packet_iter);

            lndpi_packet_buffer_advance(packet_buffer);
        } else
        {
            if (packet_iter->ndpi_flow->processed_packets_num == LNDPI_MAX_PACKETS_PER_FLOW)
            {
                ndpi_detection_giveup(
                    ndpi_struct,
                    packet_iter->ndpi_flow->ndpi_flow,
                    1,
                    &packet_iter->ndpi_flow->protocol_was_guessed
                );

                lndpi_log_packet(ndpi_struct, packet_iter);

                lndpi_packet_buffer_advance(packet_buffer);
            }
        }
    }

    lndpi_flow_buffer_cleanup(flow_buffer);
}

void lndpi_process_packet(const struct tpacket3_hdr* pkt)
{
    struct ndpi_iphdr* iph = (struct ndpi_iphdr*)((uint8_t*)pkt + pkt->tp_net);

    struct in_addr src_addr, dst_addr;
    uint16_t src_port, dst_port;

    src_addr.s_addr = iph->saddr;
    dst_addr.s_addr = iph->daddr;

    if (lndpi_packet_has_l4header(iph))
    {
        struct l4_header_addr* l4addr = (struct l4_header_addr*)((uint32_t*)iph + iph->ihl);

        src_port = l4addr->src_port;
        dst_port = l4addr->dst_port;
    } else
    {
        src_port = 0;
        dst_port = 0;
    }

    uint8_t direction;
    struct lndpi_packet_flow* pkt_flow = lndpi_flow_buffer_find(
        flow_buffer,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        &direction
    );

    if (pkt_flow == NULL)
    {
        pkt_flow = lndpi_packet_flow_init(
            &src_addr,
            &dst_addr,
            src_port,
            dst_port,
            iph->protocol
        );

        lndpi_flow_buffer_insert(flow_buffer, pkt_flow);

        direction = 1;
    }



    struct lndpi_packet_struct packet;
    packet.time_ms = (uint64_t)pkt->tp_sec * 1000 + pkt->tp_nsec / 1000000;
    packet.ndpi_flow = pkt_flow;
    packet.length = ntohs(iph->tot_len);
    packet.direction = direction;

    lndpi_packet_buffer_put(packet_buffer, &packet);

    ndpi_protocol proto;

    if (direction == 1)
        proto = ndpi_detection_process_packet(
            ndpi_struct,
            pkt_flow->ndpi_flow,
            (uint8_t*)iph,
            packet.length,
            packet.time_ms,
            pkt_flow->src_id_struct,
            pkt_flow->dst_id_struct
        );
    else
        proto = ndpi_detection_process_packet(
            ndpi_struct,
            pkt_flow->ndpi_flow,
            (uint8_t*)iph,
            packet.length,
            packet.time_ms,
            pkt_flow->dst_id_struct,
            pkt_flow->src_id_struct
        );

    pkt_flow->processed_packets_num++;

    printf("%u\t%u\n", proto.master_protocol, proto.app_protocol);

    lndpi_process_buffers();
}
