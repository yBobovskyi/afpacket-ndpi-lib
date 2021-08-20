#include "ndpi_packet_process.h"

#include "ndpi_api.h"

#include <linux/if_ether.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>

/*****************************************/

static struct ndpi_detection_module_struct* ndpi_detection_mod;
static FILE* log_file;
static struct ndpi_flow_struct* ndpi_flow;
static struct ndpi_id_struct* src_id, * dst_id;

/*****************************************/

#define PROTOCOL_NAME_BUFFER_LENGTH 20

struct packet_info
{
    uint64_t timestamp;
    struct in_addr src_addr;
    struct in_addr dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint8_t ip_proto;
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

static ndpi_protocol detect_packet_protocol(const struct ndpi_iphdr* iph, uint64_t time_ms)
{
    /* Setting state machines to 0 */
    memset(ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
    memset(src_id, 0, SIZEOF_ID_STRUCT);
    memset(dst_id, 0, SIZEOF_ID_STRUCT);

    /* Detecting AF_PACKET's protocol */
    return ndpi_detection_process_packet(
        ndpi_detection_mod,
        ndpi_flow,
        (unsigned char*)iph,
        ntohs(iph->tot_len),
        time_ms,
        src_id,
        dst_id
    );
}

/*****************************************/

void log_packet(struct packet_info* pkt_info)
{
    char src_addr_buff[20], dst_addr_buff[20];

    strcpy(&src_addr_buff[0], inet_ntoa(pkt_info->src_addr));
    strcpy(&dst_addr_buff[0], inet_ntoa(pkt_info->dst_addr));

    fprintf(log_file, "%20lu, %20s, %20s, %10u, %10u, %10u, %10u, %25s, %25s\n",
        pkt_info->timestamp,
        &src_addr_buff[0],
        &dst_addr_buff[0],
        pkt_info->src_port,
        pkt_info->dst_port,
        pkt_info->length,
        pkt_info->ip_proto,
        pkt_info->protocol_name,
        pkt_info->prot_category_name
    );
}

/*****************************************/

void get_packet_l3_info(const struct ndpi_iphdr* iph, struct packet_info* pkt_info)
{
    pkt_info->src_addr.s_addr = iph->saddr;
    pkt_info->dst_addr.s_addr = iph->daddr;
    pkt_info->length = ntohs(iph->tot_len);
    pkt_info->ip_proto = iph->protocol;
}

/*****************************************/

struct l4_header
{
    uint16_t src;
    uint16_t dst;
};

void get_packet_l4_info(const struct l4_header* l4h, struct packet_info* pkt_info)
{
    pkt_info->src_port = ntohs(l4h->src);
    pkt_info->dst_port = ntohs(l4h->dst);
}

/*****************************************/

void parse_packet_protocol_info(const ndpi_protocol* pkt_proto, struct packet_info *pkt_info)
{
    ndpi_protocol2name(ndpi_detection_mod, *pkt_proto, &pkt_info->protocol_name[0],
        PROTOCOL_NAME_BUFFER_LENGTH);

    pkt_info->prot_category_name = ndpi_category_get_name(ndpi_detection_mod,
        pkt_proto->category);
}

/*****************************************/

void process_packet(const struct tpacket3_hdr* pkt)
{
    /* IPv4 header */
    struct ndpi_iphdr* iph = (struct ndpi_iphdr*)((const uint8_t*)pkt + pkt->tp_net);

    struct packet_info pkt_info;

    /* Getting 64bit ms timestamp from tpacket3_hdr */
    pkt_info.timestamp = (uint64_t)pkt->tp_sec * 1000 + pkt->tp_nsec / 1000000;

    /* Getting L3 info */
    get_packet_l3_info(iph, &pkt_info);

    /* L4 header */
    struct l4_header* l4h = (struct l4_header*)((uint32_t*)iph + iph->ihl);

    /* Getting L4 info */
    get_packet_l4_info(l4h, &pkt_info);

    /* Detecting packet protocol */
    ndpi_protocol pkt_proto = detect_packet_protocol(iph, pkt_info.timestamp);

    /* Parsing protocol info into packet_info struct */
    parse_packet_protocol_info(&pkt_proto, &pkt_info);

    /* Logging packet */
    log_packet(&pkt_info);
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
