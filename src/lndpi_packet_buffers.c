#include "lndpi_packet_buffers.h"

/* */

void lndpi_flow_buffer_clear(struct lndpi_linked_list* flow_buffer)
{
    struct lndpi_linked_list_element* iter, * iter_next = NULL;

    for (iter = flow_buffer->head; iter != NULL; iter = iter_next)
    {
        iter_next = iter->next;

        lndpi_packet_flow_destroy(iter->data.flow);

        ndpi_free(iter);
    }

    flow_buffer->head = flow_buffer->tail = NULL;
}

struct lndpi_packet_flow* lndpi_flow_buffer_find(
    struct lndpi_linked_list* flow_buffer,
    struct in_addr src_addr,
    struct in_addr dst_addr,
    uint16_t src_port,
    uint16_t dst_port,
    int8_t* direction
) {
    struct lndpi_linked_list_element* iter;

    for (iter = flow_buffer->head; iter != NULL; iter = iter->next)
    {
        *direction = lndpi_packet_flow_compare_with(
            iter->data.flow,
            src_addr,
            dst_addr,
            src_port,
            dst_port
        );

        if (*direction)
            return iter->data.flow;
    }

    return NULL;
}

static struct lndpi_linked_list_element* lndpi_linked_list_new_element(void)
{
    return (struct lndpi_linked_list_element*)ndpi_malloc(sizeof(struct lndpi_linked_list_element));
}

static uint8_t lndpi_linked_list_put_new_element(struct lndpi_linked_list* list) {
    if (list->elements_number == list->max_elements_number)
        return 1;

    if (list->tail == NULL)
    {
        if ((list->head = lndpi_linked_list_new_element()) == NULL)
            return 2;

        list->head->next = NULL;

        list->tail = list->head;
    } else
    {
        if ((list->tail->next = lndpi_linked_list_new_element()) == NULL)
            return 2;
        list->tail = list->tail->next;

        list->tail->next = NULL;
    }

    ++list->elements_number;

    return 0;
}

enum lndpi_error lndpi_flow_buffer_put(
    struct lndpi_linked_list* flow_buffer,
    struct lndpi_packet_flow* flow
) {
    switch (lndpi_linked_list_put_new_element(flow_buffer)) {
        case 1:
            return LNDPI_FLOW_BUFFER_OVERFLOW;
        case 2:
            return LNDPI_OUT_OF_MEMORY;
    }

    flow_buffer->tail->data.flow = flow;

    return LNDPI_OK;
}

static void lndpi_flow_buffer_erase(
    struct lndpi_linked_list* list,
    struct lndpi_linked_list_element* prev_element
) {
    if (prev_element == list->tail)
        return;

    struct lndpi_linked_list_element* erased;

    if (prev_element == NULL)
    {
        if (list->head == list->tail)
            list->tail = NULL;

        erased = list->head;

        list->head = list->head->next;
    } else
    {
        erased = prev_element->next;
        prev_element->next = prev_element->next->next;

        if (prev_element->next == list->tail)
            list->tail = prev_element;
    }

    --list->elements_number;

    lndpi_packet_flow_destroy(erased->data.flow);
    ndpi_free(erased);
}

void lndpi_flow_buffer_cleanup(struct lndpi_linked_list* flow_buffer, uint64_t timeout_ms)
{
    struct lndpi_linked_list_element* iter, * prev_iter = NULL;

    for (iter = flow_buffer->head; iter != NULL; iter = iter->next)
    {
        if (iter->data.flow->protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN
            && iter->data.flow->buffered_packets_num == 0
            && lndpi_packet_flow_check_timeout(iter->data.flow, timeout_ms))
        {
            lndpi_flow_buffer_erase(flow_buffer, prev_iter);
        }

        prev_iter = iter;
    }
}

/* */

void lndpi_packet_buffer_clear(struct lndpi_linked_list* buffer)
{
    struct lndpi_linked_list_element* iter, * iter_next = NULL;

    for (iter = buffer->head; iter != NULL; iter = iter_next)
    {
        iter_next = iter->next;

        ndpi_free(iter->data.packet);

        ndpi_free(iter);
    }

    buffer->head = buffer->tail = NULL;
}

enum lndpi_error lndpi_packet_buffer_put(
    struct lndpi_linked_list* buffer,
    struct lndpi_packet_struct* packet
) {
    if (lndpi_linked_list_put_new_element(buffer))
        return LNDPI_PACKET_BUFFER_OVERFLOW;

    buffer->tail->data.packet = packet;

    ++packet->lndpi_flow->buffered_packets_num;

    return LNDPI_OK;
}

void lndpi_packet_buffer_advance(struct lndpi_linked_list* buffer)
{
    if (buffer->head != NULL)
    {
        if (buffer->head == buffer->tail)
            buffer->tail = NULL;

        struct lndpi_linked_list_element* old_head = buffer->head;

        buffer->head = buffer->head->next;

        --buffer->elements_number;

        ++old_head->data.packet->lndpi_flow->buffered_packets_num;

        ndpi_free(old_head->data.packet);
        ndpi_free(old_head);
    }
}
