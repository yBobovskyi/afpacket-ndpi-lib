#include "lndpi_packet_buffers.h"

/* */

struct lndpi_flow_buffer* lndpi_flow_buffer_init(uint32_t max_flow_number)
{
    struct lndpi_flow_buffer* res =
        (struct lndpi_flow_buffer*)ndpi_malloc(sizeof(struct lndpi_flow_buffer));

    res->begin = (struct lndpi_flow_buffer_element*)ndpi_malloc(
            sizeof(struct lndpi_flow_buffer_element) * max_flow_number);

    res->end = res->begin;
    res->current_flow_number = 0;
    res->max_flow_number = max_flow_number;

    return res;
}

void lndpi_flow_buffer_destroy(struct lndpi_flow_buffer* flow_buffer)
{
    struct lndpi_flow_buffer_element* iter;

    for (iter = flow_buffer->begin; iter != flow_buffer->end; ++iter)
        if (iter->alive)
            lndpi_packet_flow_destroy(iter->flow);

    ndpi_free(flow_buffer);
}

struct lndpi_packet_flow* lndpi_flow_buffer_find(
    struct lndpi_flow_buffer* flow_buffer,
    struct in_addr src_addr,
    struct in_addr dst_addr,
    uint16_t src_port,
    uint16_t dst_port,
    int8_t* direction
) {
    struct lndpi_flow_buffer_element* iter;

    for (iter = flow_buffer->begin; iter != flow_buffer->end; ++iter)
        if (iter->alive)
        {
            int8_t cmp_res = lndpi_packet_flow_compare_with(
                iter->flow,
                src_addr,
                dst_addr,
                src_port,
                dst_port
            );

            if (cmp_res)
            {
                *direction = cmp_res;
                return iter->flow;
            }
        }

    *direction = 0;
    return NULL;
}

static struct lndpi_flow_buffer_element* lndpi_flow_buffer_find_place(struct lndpi_flow_buffer* buffer)
{
    struct lndpi_flow_buffer_element* iter;

    for (iter = buffer->begin; iter != buffer->end; ++iter)
        if (!iter->alive)
            return iter;

    if (buffer->begin + buffer->max_flow_number > buffer->end)
        return buffer->end++;

    return NULL;
}

void lndpi_flow_buffer_insert(struct lndpi_flow_buffer* buffer, struct lndpi_packet_flow* flow)
{
    struct lndpi_flow_buffer_element* place = lndpi_flow_buffer_find_place(buffer);

    if (place != NULL)
    {
        place->flow = flow;
        place->alive = 1;
    }

    ++buffer->current_flow_number;
}

static void lndpi_flow_buffer_shrink(struct lndpi_flow_buffer* buffer)
{
    struct lndpi_flow_buffer_element* iter = buffer->end - 1;

    while (!iter->alive)
    {
        --iter;
        --buffer->end;
    }
}

void lndpi_flow_buffer_cleanup(struct lndpi_flow_buffer* buffer, uint64_t timeout_ms)
{
    struct lndpi_flow_buffer_element* iter;

    for (iter = buffer->begin; iter != buffer->end; ++iter)
    {
        if (iter->alive && iter->flow->protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN
            && iter->flow->buffered_packets_num == 0
            && lndpi_packet_flow_check_timeout(iter->flow, timeout_ms))
        {
            lndpi_packet_flow_destroy(iter->flow);
            iter->alive = 0;

            --buffer->current_flow_number;
        }
    }

    lndpi_flow_buffer_shrink(buffer);
}

/* */

struct lndpi_packet_buffer* lndpi_packet_buffer_init(uint32_t max_packet_number)
{
    struct lndpi_packet_buffer* res =
        (struct lndpi_packet_buffer*)ndpi_malloc(sizeof(struct lndpi_packet_buffer));

    res->begin = (struct lndpi_packet_struct*)ndpi_malloc(
        sizeof(struct lndpi_packet_struct) * max_packet_number);

    res->head = res->begin;
    res->tail = res->begin;

    res->max_packet_number = max_packet_number;

    return res;
}

void lndpi_packet_buffer_destroy(struct lndpi_packet_buffer* buffer)
{
    ndpi_free(buffer->begin);
    ndpi_free(buffer);
}

struct lndpi_packet_struct* lndpi_packet_buffer_next(
    struct lndpi_packet_buffer* buffer,
    struct lndpi_packet_struct* elem
) {
    struct lndpi_packet_struct* res = elem + 1;

    if (res != buffer->begin + buffer->max_packet_number)
        return res;

    return buffer->begin;
}

void lndpi_packet_buffer_put(
    struct lndpi_packet_buffer* buffer,
    struct lndpi_packet_struct* packet
)
{
    memcpy(buffer->tail, packet, sizeof(struct lndpi_packet_struct));

    buffer->tail = lndpi_packet_buffer_next(buffer, buffer->tail);

    ++packet->lndpi_flow->buffered_packets_num;
}

const struct lndpi_packet_struct* lndpi_packet_buffer_get(struct lndpi_packet_buffer* buffer)
{
    if (buffer->head != buffer->tail)
        return buffer->head;

    return NULL;
}

void lndpi_packet_buffer_advance(struct lndpi_packet_buffer* buffer)
{
    if (buffer->head != buffer->tail)
    {
        --buffer->head->lndpi_flow->buffered_packets_num;
        buffer->head = lndpi_packet_buffer_next(buffer, buffer->head);
    }
}
