/**@file arp.h
 *@brief this files contains all relevant data types and prototypes of the functions for an ARP module
 *@author Syed Amaar Ahmad
 *@date  September 27, 2010
 */

#include "finstypes.h"
#include <inttypes.h>

#define ARPREQUESTOP 1
#define ARPREPLYOP 2
#define NULLADDRESS 0
#define HWDTYPE 1
#define PROTOCOLTYPE 0x800
#define HDWADDRSLEN 6
#define PROTOCOLADDRSLEN 4
#define ARPMSGLENGTH 208

/**struct ARP_message is used for internal use for the module and stores all the traditional
 * fields. This struct has to be converted into an 'external' format once pushed outside the ARP module*/
struct ARP_message
{
	uint64_t sender_MAC_addrs;
	uint32_t sender_IP_addrs;
	uint64_t target_MAC_addrs;
	uint32_t target_IP_addrs;
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint16_t operation;
	uint8_t hardware_addrs_length;
	uint8_t protocol_addrs_length;
};

/**struct arp_hdr is used for use external to the module. It contains the regular
 * ARP message in addition to the hardware addresses of the sender/target as char pointers*/
struct arp_hdr
{
	struct ARP_message arp;
	unsigned char src_hwd_addrs[HDWADDRSLEN];
	unsigned char tgt_hwd_addrs[HDWADDRSLEN];
};

struct node{

	uint64_t MAC_addrs;
	uint32_t IP_addrs;

	struct node *next;
	struct node *co_intface;

};

void print_IP_addrs(uint32_t ip_addrs);

void print_MAC_addrs(uint64_t mac_addrs);

uint32_t gen_IP_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

uint64_t gen_MAC_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);

void gen_requestARP(uint32_t ip_target_addrs, struct ARP_message *request_ARP_ptr);

struct ARP_message gen_replyARP(struct ARP_message request);

int search_list(struct node *ptr_to_cache, uint64_t MAC_addrs);

void update_cache(struct ARP_message *pckt);

void print_msgARP(struct ARP_message *);

void print_neighbors(struct node *ptr_to_cache);

void print_cache();

uint64_t search_MAC_addrs(uint32_t IP_addrs, struct node *ptr);

void arp_to_fins(struct ARP_message *pckt_arp, struct finsFrame *pckt_fins);

void fins_to_arp(struct finsFrame *pckt_fins, struct ARP_message *pckt_arp);//, int size_of_finsFrame);

struct node* init_intface();

void term_intface();

void addrs_conversion(uint64_t MAC_int_addrs, unsigned char *MAC_addrs);

void net_fmt_conversion(struct ARP_message *pckt, struct arp_hdr *pckt_hdr);

void host_fmt_conversion(struct arp_hdr *pckt_hdr, struct ARP_message *pckt);

int check_valid_arp(struct ARP_message *pckt_arp);

void print_arp_hdr(struct arp_hdr *pckt);
