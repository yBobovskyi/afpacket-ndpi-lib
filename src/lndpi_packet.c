#include "lndpi_packet.h"
#include "lndpi_packet_buffers.h"
#include "lndpi_packet_logger.h"

#define IPPROTO_ICMP    0x01
#define IPPROTO_IGMP    0x02


#define LNDPI_MAX_FLOWS 0x1000
#define LNDPI_MAX_PACKETS_TO_PROCESS 80
#define LNDPI_PACKET_BUFFER_SIZE 0x100000
#define LNDPI_FLOW_TIMEOUT_MS 5000

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

    packet_buffer = lndpi_packet_buffer_init(LNDPI_PACKET_BUFFER_SIZE);
}

static void lndpi_packet_buffer_log(void)
{
    struct lndpi_packet_struct* iter;

    for (iter = packet_buffer->head; iter != packet_buffer->tail;
        iter = lndpi_packet_buffer_next(packet_buffer, iter))
    {
        if (iter->lndpi_flow->protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
        {
            iter->lndpi_flow->protocol = ndpi_detection_giveup(
                ndpi_struct,
                iter->lndpi_flow->ndpi_flow,
                1,
                &iter->lndpi_flow->protocol_was_guessed
            );
        }

        lndpi_log_packet(ndpi_struct, iter);
    }
}

void lndpi_packet_lib_exit(void)
{
    lndpi_packet_buffer_log();

    /* Destroying the detection module */
    ndpi_exit_detection_module(ndpi_struct);

    lndpi_flow_buffer_destroy(flow_buffer);

    lndpi_packet_buffer_destroy(packet_buffer);

    lndpi_logger_exit();
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
    struct lndpi_packet_struct* iter;

    for (iter = packet_buffer->head; iter != packet_buffer->tail;
        iter = lndpi_packet_buffer_next(packet_buffer, iter))
    {
        if (iter->lndpi_flow->protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
        {
            if (!lndpi_packet_flow_check_timeout(iter->lndpi_flow, LNDPI_FLOW_TIMEOUT_MS)
                && iter->lndpi_flow->processed_packets_num <= LNDPI_MAX_PACKETS_TO_PROCESS)
                break;

            iter->lndpi_flow->protocol = ndpi_detection_giveup(
                ndpi_struct,
                iter->lndpi_flow->ndpi_flow,
                1,
                &iter->lndpi_flow->protocol_was_guessed
            );
        } else
        {
            lndpi_log_packet(ndpi_struct, iter);
            lndpi_packet_buffer_advance(packet_buffer);
        }
    }

    lndpi_flow_buffer_cleanup(flow_buffer, LNDPI_FLOW_TIMEOUT_MS);
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

        src_port = ntohs(l4addr->src_port);
        dst_port = ntohs(l4addr->dst_port);
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
    packet.lndpi_flow = pkt_flow;
    packet.length = ntohs(iph->tot_len);
    packet.direction = direction;

    lndpi_packet_buffer_put(packet_buffer, &packet);

    if (pkt_flow->protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN
        || ndpi_extra_dissection_possible(ndpi_struct, pkt_flow->ndpi_flow))
    {
        struct ndpi_id_struct* src, * dst;

        if (direction == 1)
        {
            src = pkt_flow->src_id_struct;
            dst = pkt_flow->dst_id_struct;
        } else
        {
            src = pkt_flow->dst_id_struct;
            dst = pkt_flow->src_id_struct;
        }


        pkt_flow->protocol = ndpi_detection_process_packet(
            ndpi_struct,
            pkt_flow->ndpi_flow,
            (uint8_t*)iph,
            packet.length,
            packet.time_ms,
            src,
            dst
        );

        pkt_flow->processed_packets_num++;
    }

    pkt_flow->last_packet_ms = packet.time_ms;

    lndpi_process_buffers();
}
