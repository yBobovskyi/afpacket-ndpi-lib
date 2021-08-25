#include "lndpi_packet.h"
#include "lndpi_packet_buffers.h"
#include "lndpi_packet_logger.h"

static struct ndpi_detection_module_struct* s_ndpi_struct;
static struct lndpi_flow_buffer* s_flow_buffer;
static struct lndpi_packet_buffer* s_packet_buffer;
static uint32_t s_max_flow_number;
static uint32_t s_max_packets_to_process;
static uint32_t s_packet_buffer_size;
static uint64_t s_flow_timeout_ms;

/* */

static enum lndpi_error lndpi_detection_module_init(void)
{
    /* Initializing a detection module */
    if ((s_ndpi_struct = ndpi_init_detection_module(ndpi_no_prefs)) == NULL)
        return LNDPI_NDPI_MODULE_INIT_ERROR;
    /* Enabling all protocols */
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(s_ndpi_struct, &all);
    ndpi_finalize_initialization(s_ndpi_struct);

    return LNDPI_OK;
}

/* */

enum lndpi_error lndpi_packet_lib_init(
    const char* log_file_path,
    uint32_t max_flow_number,
    uint32_t max_packets_to_process,
    uint32_t packet_buffer_size,
    uint64_t flow_timeout_ms
) {
    s_max_flow_number = max_flow_number;
    s_max_packets_to_process = max_packets_to_process;
    s_packet_buffer_size = packet_buffer_size;
    s_flow_timeout_ms = flow_timeout_ms;

    enum lndpi_error error;

    if ((error = lndpi_detection_module_init()) != LNDPI_OK)
        return error;

    if ((error = lndpi_logger_init(log_file_path)) != LNDPI_OK)
        return error;

    if ((s_flow_buffer = lndpi_flow_buffer_init(s_max_flow_number)) == NULL)
        return LNDPI_OUT_OF_MEMORY;

    if ((s_packet_buffer = lndpi_packet_buffer_init(s_packet_buffer_size)) == NULL)
        return LNDPI_OUT_OF_MEMORY;

    return LNDPI_OK;
}

static enum lndpi_error lndpi_packet_buffer_log(void)
{
    struct lndpi_packet_struct* iter;

    for (iter = s_packet_buffer->head; iter != s_packet_buffer->tail;
        iter = lndpi_packet_buffer_next(s_packet_buffer, iter))
    {
        if (iter->lndpi_flow->protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
        {
            iter->lndpi_flow->protocol = ndpi_detection_giveup(
                s_ndpi_struct,
                iter->lndpi_flow->ndpi_flow,
                1,
                &iter->lndpi_flow->protocol_was_guessed
            );
        }

        enum lndpi_error error;
        if ((error = lndpi_log_packet(s_ndpi_struct, iter)) != LNDPI_OK)
            return error;
    }

    return LNDPI_OK;
}

enum lndpi_error lndpi_packet_lib_finalize(void)
{
    return lndpi_packet_buffer_log();
}

void lndpi_packet_lib_exit(void)
{
    /* Destroying the detection module */
    ndpi_exit_detection_module(s_ndpi_struct);

    lndpi_flow_buffer_destroy(s_flow_buffer);

    lndpi_packet_buffer_destroy(s_packet_buffer);

    lndpi_logger_exit();
}

struct l4_header_addr
{
    uint16_t src_port;
    uint16_t dst_port;
};

static uint8_t lndpi_packet_has_l4header(struct ndpi_iphdr* iph)
{
    return (iph->protocol == IPPROTO_TCP
        || iph->protocol == IPPROTO_UDP);
}

static enum lndpi_error lndpi_process_buffers(void)
{
    enum lndpi_error error;

    struct lndpi_packet_struct* iter;

    for (iter = s_packet_buffer->head; iter != s_packet_buffer->tail;
        iter = lndpi_packet_buffer_next(s_packet_buffer, iter))
    {
        if (iter->lndpi_flow->protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
        {
            if (!lndpi_packet_flow_check_timeout(iter->lndpi_flow, s_flow_timeout_ms)
                && iter->lndpi_flow->processed_packets_num <= s_max_packets_to_process)
                break;

            iter->lndpi_flow->protocol = ndpi_detection_giveup(
                s_ndpi_struct,
                iter->lndpi_flow->ndpi_flow,
                1,
                &iter->lndpi_flow->protocol_was_guessed
            );
        } else
        {
            if ((error = lndpi_log_packet(s_ndpi_struct, iter)) != LNDPI_OK)
                return error;
            lndpi_packet_buffer_advance(s_packet_buffer);
        }
    }

    lndpi_flow_buffer_cleanup(s_flow_buffer, s_flow_timeout_ms);

    return LNDPI_OK;
}

enum lndpi_error lndpi_process_packet(const struct tpacket3_hdr* pkt)
{
    enum lndpi_error error;

    struct ndpi_iphdr* iph = (struct ndpi_iphdr*)((uint8_t*)pkt + pkt->tp_net);

    if (iph->version == 6)
        return LNDPI_IPV6_NOT_SUPPORTED;

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
        s_flow_buffer,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        &direction
    );

    if (pkt_flow == NULL)
    {
        if ((pkt_flow = lndpi_packet_flow_init(
            &src_addr,
            &dst_addr,
            src_port,
            dst_port,
            iph->protocol
        )) == NULL)
            return LNDPI_OUT_OF_MEMORY;

        if ((error = lndpi_flow_buffer_insert(s_flow_buffer, pkt_flow)) != LNDPI_OK)
            return error;

        direction = 1;
    }

    struct lndpi_packet_struct packet;
    packet.time_ms = (uint64_t)pkt->tp_sec * 1000 + pkt->tp_nsec / 1000000;
    packet.lndpi_flow = pkt_flow;
    packet.length = ntohs(iph->tot_len);
    packet.direction = direction;

    if ((error = lndpi_packet_buffer_put(s_packet_buffer, &packet)) != LNDPI_OK)
        return error;

    if (pkt_flow->protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN
        || ndpi_extra_dissection_possible(s_ndpi_struct, pkt_flow->ndpi_flow))
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
            s_ndpi_struct,
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

    error = lndpi_process_buffers();

    return error;
}
