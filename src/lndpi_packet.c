#include "lndpi_packet.h"
#include "lndpi_packet_buffers.h"
#include "lndpi_packet_logger.h"

/* Global variables for all necessary resources */
static struct ndpi_detection_module_struct* s_ndpi_struct;
static struct lndpi_linked_list s_flow_buffer;
static struct lndpi_linked_list s_packet_buffer;
static uint32_t s_max_flow_number;
static uint32_t s_max_packets_to_process;
static uint32_t s_packet_buffer_size;
static uint64_t s_flow_timeout_ms;

static lndpi_packet_callback_t s_packet_callback;
static void* s_packet_callback_parameter;

static lndpi_buffers_callback_t s_buffers_callback;
static void* s_buffers_callback_parameter;

static lndpi_finalize_callback_t s_finalize_callback;
static void* s_finalize_callback_parameter;

/**
 *  Initialization of an nDPI detection module
 */
static enum lndpi_error lndpi_detection_module_init(void)
{
    if ((s_ndpi_struct = ndpi_init_detection_module(ndpi_no_prefs)) == NULL)
        return LNDPI_NDPI_MODULE_INIT_ERROR;

    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(s_ndpi_struct, &all);
    ndpi_finalize_initialization(s_ndpi_struct);

    return LNDPI_OK;
}

/**
 *  Helper function for initializing flow buffer
 */
static void lndpi_flow_buffer_init(uint32_t max_flow_number)
{
    s_flow_buffer.head = NULL;
    s_flow_buffer.tail = NULL;
    s_flow_buffer.elements_number = 0;
    s_flow_buffer.max_elements_number = max_flow_number;
}

/**
 *  Helper function for initializing packet buffer
 */
static void lndpi_packet_buffer_init(uint32_t packet_buffer_size)
{
    s_packet_buffer.head = NULL;
    s_packet_buffer.tail = NULL;
    s_packet_buffer.elements_number = 0;
    s_packet_buffer.max_elements_number = packet_buffer_size;
}

/**
 *  Set packet callback function definition
 */
void lndpi_set_packet_callback_function(
    lndpi_packet_callback_t packet_callback,
    void* parameter
) {
    s_packet_callback = packet_callback;

    s_packet_callback_parameter = parameter;
}

/**
 *  Set buffers callback function definition
 */
void lndpi_set_buffers_callback_function(
    lndpi_buffers_callback_t buffers_callback,
    void* parameter
) {
    s_buffers_callback = buffers_callback;

    s_buffers_callback_parameter = parameter;
}

/**
 *  Set finalize callback function definition
 */
void lndpi_set_finalize_callback_function(
    lndpi_finalize_callback_t finalize_callback,
    void* parameter
) {
    s_finalize_callback = finalize_callback;

    s_finalize_callback_parameter = parameter;
}

/**
 *  Default buffers callback function
 *  Send to packet callback function all packets from the begining of the packet buffer which:
 *      - have final protocol decision
 *      - have unknown protocol but:
 *          - have reached maximum number of processed packets
 *          - are in timed out flow
 *  Call flow buffer cleanup funtion
 */
static enum lndpi_error lndpi_process_buffers(
    struct ndpi_detection_module_struct* ndpi_struct,
    struct lndpi_linked_list* flow_buffer,
    struct lndpi_linked_list* packet_buffer,
    uint64_t timeout_ms,
    uint32_t max_packets_to_process,
    uint32_t max_flow_number,
    void* parameter
) {
    enum lndpi_error error;

    struct lndpi_linked_list_element* iter, * iter_next;

    for (iter = packet_buffer->head; iter != NULL; iter = iter_next)
    {
        iter_next = iter->next;

        if (iter->data.packet->lndpi_flow->protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
        {
            if (!lndpi_packet_flow_check_timeout(iter->data.packet->lndpi_flow, timeout_ms)
                && iter->data.packet->lndpi_flow->processed_packets_num <= max_packets_to_process)
                break;

            iter->data.packet->lndpi_flow->protocol = ndpi_detection_giveup(
                ndpi_struct,
                iter->data.packet->lndpi_flow->ndpi_flow,
                1,
                &iter->data.packet->lndpi_flow->protocol_was_guessed
            );
        } else
        {
            if ((error = s_packet_callback(
                ndpi_struct,
                iter->data.packet,
                timeout_ms,
                max_packets_to_process,
                s_packet_callback_parameter)
            ) != LNDPI_OK)
                return error;

            lndpi_packet_buffer_advance(packet_buffer);
        }
    }

    lndpi_flow_buffer_cleanup(flow_buffer, timeout_ms);

    return LNDPI_OK;
}

/**
 *  Default finalize callback function
 *  Send all packets from buffer to packet callback function
 */
static enum lndpi_error lndpi_packet_buffer_log(
    struct ndpi_detection_module_struct* ndpi_struct,
    struct lndpi_linked_list* flow_buffer,
    struct lndpi_linked_list* packet_buffer,
    uint64_t timeout_ms,
    uint32_t max_packets_to_process,
    uint32_t max_flow_number,
    void* parameter
)
{
    struct lndpi_linked_list_element* iter;

    for (iter = packet_buffer->head; iter != NULL; iter = iter->next)
    {
        if (iter->data.packet->lndpi_flow->protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
        {
            iter->data.packet->lndpi_flow->protocol = ndpi_detection_giveup(
                ndpi_struct,
                iter->data.packet->lndpi_flow->ndpi_flow,
                1,
                &iter->data.packet->lndpi_flow->protocol_was_guessed
            );
        }

        enum lndpi_error error;
        if ((error = s_packet_callback(
            ndpi_struct,
            iter->data.packet,
            timeout_ms,
            max_packets_to_process,
            s_packet_callback_parameter)
        ) != LNDPI_OK)
            return error;
    }

    return LNDPI_OK;
}

/**
 *  Library initialization function definition
 */
enum lndpi_error lndpi_packet_lib_init(
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

    lndpi_flow_buffer_init(s_max_flow_number);

    lndpi_packet_buffer_init(s_packet_buffer_size);

    s_buffers_callback = lndpi_process_buffers;
    s_buffers_callback_parameter = NULL;

    s_packet_callback = lndpi_log_packet;
    s_packet_callback_parameter = NULL;

    s_finalize_callback = lndpi_packet_buffer_log;
    s_finalize_callback_parameter = NULL;

    return LNDPI_OK;
}

/**
 *  Default log file function definition
 */
enum lndpi_error lndpi_init_log_file(char* log_file_path)
{
    enum lndpi_error error;

    if (s_packet_callback == lndpi_log_packet)
        if ((error = lndpi_logger_init(log_file_path)) != LNDPI_OK)
            return error;

    return LNDPI_OK;
}

/**
 *  Finalize function definition
 */
enum lndpi_error lndpi_packet_lib_finalize(void)
{
    return s_finalize_callback(
        s_ndpi_struct,
        &s_flow_buffer,
        &s_packet_buffer,
        s_flow_timeout_ms,
        s_max_packets_to_process,
        s_max_flow_number,
        s_finalize_callback_parameter
    );
}

/**
 *  Library exit funtion definition
 */
void lndpi_packet_lib_exit(void)
{
    lndpi_logger_exit();

    ndpi_exit_detection_module(s_ndpi_struct);

    lndpi_flow_buffer_clear(&s_flow_buffer);

    lndpi_packet_buffer_clear(&s_packet_buffer);
}

/**
 *  Structure to extract source and destination ports from L4 header
 */
struct l4_header_addr
{
    uint16_t src_port;
    uint16_t dst_port;
};

/**
 *  Check if packet has L4 header
 *  Currently only check if L4 protocol is TCP or UPD
 */
static uint8_t lndpi_packet_has_l4header(struct ndpi_iphdr* iph)
{
    return (iph->protocol == IPPROTO_TCP
        || iph->protocol == IPPROTO_UDP);
}

/**
 *  Main packet processing funtion definition
 */
enum lndpi_error lndpi_process_packet(const struct tpacket3_hdr* pkt)
{
    enum lndpi_error error;

    /* Get L3 header from tpacket3_hdr */
    struct ndpi_iphdr* iph = (struct ndpi_iphdr*)((uint8_t*)pkt + pkt->tp_net);

    /* IPv6 is not supported yet */
    if (iph->version == 6)
        return LNDPI_IPV6_NOT_SUPPORTED;

    /* Get address information from packet */
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

    /* Check for corresponding flow in the buffer */
    uint8_t direction;
    struct lndpi_packet_flow* pkt_flow = lndpi_flow_buffer_find(
        &s_flow_buffer,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        &direction
    );

    /* If no, create a new one */
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

        if ((error = lndpi_flow_buffer_put(&s_flow_buffer, pkt_flow)) != LNDPI_OK)
            return error;

        direction = 1;
    }

    /* Create a new packet structure */
    struct lndpi_packet_struct* packet;

    if ((packet = (struct lndpi_packet_struct*)ndpi_malloc(sizeof(struct lndpi_packet_struct))) == NULL)
        return LNDPI_OUT_OF_MEMORY;

    packet->time_ms = (uint64_t)pkt->tp_sec * 1000 + pkt->tp_nsec / 1000000;
    packet->lndpi_flow = pkt_flow;
    packet->length = ntohs(iph->tot_len);
    packet->direction = direction;

    /* Put it in a buffer */
    if ((error = lndpi_packet_buffer_put(&s_packet_buffer, packet)) != LNDPI_OK)
        return error;

    /* Invoke detection process if the protocol is unknown or some extra dissection possible */
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
            packet->length,
            packet->time_ms,
            src,
            dst
        );

        pkt_flow->processed_packets_num++;
    }

    pkt_flow->last_packet_ms = packet->time_ms;

    /* Call the buffers callback funtion */
    error = s_buffers_callback(
        s_ndpi_struct,
        &s_flow_buffer,
        &s_packet_buffer,
        s_flow_timeout_ms,
        s_max_packets_to_process,
        s_max_flow_number,
        s_buffers_callback_parameter
    );

    return error;
}
