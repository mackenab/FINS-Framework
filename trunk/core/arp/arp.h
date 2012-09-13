/**@file arp.h
 *@brief this files contains all relevant data types and prototypes of the functions for an ARP module
 *@author Syed Amaar Ahmad
 *@date  September 27, 2010
 */

#ifndef ARP_H_
#define ARP_H_

#include <inttypes.h>

#include <finstypes.h>
#include <metadata.h>
#include <finsdebug.h>
#include <stdint.h>

//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
#include <sys/endian.h>
#endif

#include <finstypes.h>
#include <queueModule.h>

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define NULLADDRESS 0
#define HWDTYPE 1
#define PROTOCOLTYPE 0x800
#define HDWADDRSLEN 6
#define PROTOCOLADDRSLEN 4
#define ARPMSGLENGTH 32
#define REQUESTDATA 1
#define REPLYDATA 2
#define REPLYCONTROL 3

#define ARP_TYPE 0x0806
#define ARP_MAC_BROADCAST 0xFFFFFFFFFFFF
#define ARP_MAC_NULL 0x0

/**struct arp_hdr is used for use external to the ARP module. The zeroth element of both
 * the IP and MAC arrays (e.g. sender_MAC_addrs[0] or target_IP_addrs[0] etc.) is the
 * most significant byte while the last element is the least significant.*/
struct arp_hdr {
	uint16_t hardware_type;
	uint16_t protocol_type;
	unsigned char hardware_addrs_length;
	unsigned char protocol_addrs_length;
	uint16_t operation;
	unsigned char sender_MAC_addrs[HDWADDRSLEN];
	unsigned char sender_IP_addrs[PROTOCOLADDRSLEN];
	unsigned char target_MAC_addrs[HDWADDRSLEN];
	unsigned char target_IP_addrs[PROTOCOLADDRSLEN];

};

/**struct ARP_message is used for internal use for the module and stores all the traditional
 * fields in more convenient format (e.g. uint64_t instead of unsigned char array[6] etc.).
 * This struct has to be converted into an 'external' format once pushed outside the ARP module*/
struct arp_message {
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_addrs_length;
	uint8_t protocol_addrs_length;
	uint16_t operation;
	uint64_t sender_MAC_addrs;
	uint32_t sender_IP_addrs;
	uint64_t target_MAC_addrs;
	uint32_t target_IP_addrs;
};

/**This struct is used to store information about neighboring nodes of the host interface*/
struct arp_entry {
	struct arp_entry *next;
	uint64_t MAC_addrs;
	uint32_t IP_addrs;
	//TODO add time created - for timeout
};

struct arp_entry *interface_list;
struct arp_entry *cache_list; /**< points to the first element of the dynamic ARP cache*/

//request, call, element, node, inquiry, demand, store
struct arp_store {
	struct arp_store *next;
	struct finsFrame *ff;
	uint32_t dst_ip;
	uint32_t src_ip;
	//uint32_t retrans;
	//TODO add time created - for timeout
};

struct arp_store *store_list;

//####### //TODO deprecated, remove
uint64_t interface_MAC_addrs;/**<MAC address of interface*/
uint32_t interface_IP_addrs;/**<IP address of interface*/
unsigned char *fins_MAC_address; /**<void pointer of a fins control frame to pass MAC address*/
unsigned char *fins_IP_address;/**<void pointer of a fins control fram to pass IP address*/
struct arp_hdr *packet;/**<An arp header associated with the fins data frame's pdu*/
struct arp_message arp_msg; /**<This is the ARP message to store and pass replies/requests*/
uint32_t target_IP_addrs; /**<IP address of a target node*/
//#######

void gen_requestARP(uint32_t ip_target_addrs, struct arp_message *request_ARP_ptr);
void gen_requestARP_new(struct arp_message *request_ARP_ptr, uint64_t sender_mac, uint32_t sender_ip, uint64_t target_mac, uint32_t target_ip);

void gen_replyARP(struct arp_message *request, struct arp_message *reply);
void gen_replyARP_new(struct arp_message *reply_ARP, uint64_t sender_mac, uint32_t sender_ip, uint64_t target_mac, uint32_t target_ip);

int search_list(struct arp_entry *ptr_to_cache, uint32_t IP_addrs);
struct arp_entry *search_list_new(struct arp_entry *head, uint32_t IP_addrs);

void update_cache(struct arp_message *pckt);
void update_cache_new(struct arp_message *pckt);

uint64_t search_MAC_addrs(uint32_t IP_addrs, struct arp_entry *ptr);

void arp_to_fins(struct arp_hdr *pckt_arp, struct finsFrame *pckt_fins);

void fins_to_arp(struct finsFrame *pckt_fins, struct arp_hdr *pckt_arp); //, int size_of_finsFrame);

void init_arp_intface(uint64_t MAC_address, uint32_t IP_address);

int arp_register_interface(uint64_t MAC_address, uint32_t IP_address);

void term_arp_intface();

void MAC_addrs_conversion(uint64_t MAC_int_addrs, unsigned char *MAC_addrs);

void IP_addrs_conversion(uint32_t IP_int_addrs, unsigned char *IP_char_addrs);

void print_msgARP(struct arp_message *);

void print_neighbors(struct arp_entry *ptr_to_cache);

void print_IP_addrs(uint32_t ip_addrs);

void print_MAC_addrs(uint64_t mac_addrs);

uint32_t gen_IP_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

uint64_t gen_MAC_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);

void print_cache();

void host_to_net(struct arp_hdr *pckt_hdr);

int check_valid_arp(struct arp_message *msg);

void print_arp_hdr(struct arp_hdr *pckt);

void arp_msg_to_hdr(struct arp_message *ptr_msg, struct arp_hdr *ptr_hdr);

void arp_hdr_to_msg(struct arp_hdr *ptr_hdr, struct arp_message *ptr_msg);

void arp_in(struct finsFrame *sent_in);

void arp_out_reply(struct finsFrame *fins_arp_out);

void arp_out_request(struct finsFrame *ff, uint32_t sought_IP_addrs, uint32_t src_ip, uint64_t src_mac);

void arp_out_ctrl(uint32_t sought_IP_addrs, struct finsFrame *fins_arp_out);

void arp_out(int response_type);

struct finsFrame *arp_to_fdf(struct arp_message *tcp);
struct arp_message *fdf_to_arp(struct finsFrame *ff);

void arp_init(pthread_attr_t *fins_pthread_attr);
void arp_shutdown();
void arp_free();

void arp_get_ff();
int arp_to_switch(struct finsFrame *ff);

#define EXEC_ARP_GET_ADDR 0
//#define EXEC_ARP_GET_ADDR 0

void arp_out_fdf(struct finsFrame *ff);
void arp_in_fdf(struct finsFrame *ff);
void arp_fcf(struct finsFrame *ff);

void arp_exec(struct finsFrame *ff);
void arp_exec_get_addr(struct finsFrame *ff, uint32_t dst_ip, uint32_t src_ip);

#endif

