#include "ndpi-afpacket-process.h"

#include "ndpi_api.h"

#include <linux/if_ether.h>

#include <stdio.h>

static struct ndpi_detection_module_struct* ndpi_detection_mod;
static FILE* log_file;
static struct ndpi_flow_struct* ndpi_flow;
static struct ndpi_id_struct* src_id, * dst_id;

/*****************************************/

#define PROTOCOL_NAME_BUFFER_LENGTH 20

struct packet_info
{
    uint64_t timestamp;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    ndpi_protocol protocol;
    char protocol_name[PROTOCOL_NAME_BUFFER_LENGTH];
    const char* prot_category_name;
};


/*****************************************/

static void detection_module_init(void) {
    /* Initializing a detection module */
    ndpi_detection_mod = ndpi_init_detection_module(ndpi_no_prefs);
    /* Enabling all protocols */
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_detection_mod, &all);
    ndpi_finalize_initialization(ndpi_detection_mod);
}

/*****************************************/

static void static_machines_init(void)
{
    /* Allocating a flow struct */
    ndpi_flow = (struct ndpi_flow_struct*)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);

    /* Allocating source and destination id structs */
    src_id = (struct ndpi_id_struct*)ndpi_malloc(SIZEOF_ID_STRUCT);
    dst_id = (struct ndpi_id_struct*)ndpi_malloc(SIZEOF_ID_STRUCT);
}

/*****************************************/

void packet_process_init(const char* log_file_path)
{
    detection_module_init();

    static_machines_init();

    /* Opening a log file for appending */
    log_file = fopen(log_file_path, "a");
}

/*****************************************/

static ndpi_protocol detect_packet_protocol(const struct tpacket3_hdr* pkt)
{
    /* Reaching an L3 pointer */
    const uint8_t* packet = (const uint8_t*)pkt + pkt->tp_net;

    /* IPv4 header */
    struct ndpi_iphdr* iph = (struct ndpi_iphdr*)packet;

    /* Setting state machines to 0 */
    memset(ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
    memset(src_id, 0, SIZEOF_ID_STRUCT);
    memset(dst_id, 0, SIZEOF_ID_STRUCT);

    /* Getting 64bit timestamp in ms */
    uint64_t time_ms = (uint64_t)pkt->tp_sec * 1000 + pkt->tp_nsec / 1000000;

    /* Detecting AF_PACKET's protocol */
    return ndpi_detection_process_packet(
        ndpi_detection_mod,
        ndpi_flow,
        packet,
        iph->tot_len,
        time_ms,
        src_id,
        dst_id
    );
}

/*****************************************/

void log_packet(struct packet_info* pkt_info)
{
    fprintf(log_file, "%u, %u, %u\n", proto.master_protocol, proto.app_protocol);
}

/*****************************************/

void process_packet(const struct tpacket3_hdr* pkt)
{
    ndpi_protocol packet_proto = detect_packet_protocol(pkt);

    log_packet_protocol(packet_proto);
}

/*****************************************/

static void state_machines_destroy(void)
{
    ndpi_flow_free(ndpi_flow);

    ndpi_free(src_id);
    ndpi_free(dst_id);
}

/*****************************************/

void packet_process_exit(void)
{
    /* Destroying the detection module */
    ndpi_exit_detection_module(ndpi_detection_mod);

    state_machines_destroy();

    /* Closing the log file */
    fclose(log_file);
}
