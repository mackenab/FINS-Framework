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

//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
#include <sys/endian.h>
#endif

#include <finstypes.h>
#include <queueModule.h>

extern sem_t ARP_to_Switch_Qsem;
extern finsQueue ARP_to_Switch_Queue;

extern sem_t Switch_to_ARP_Qsem;
extern finsQueue Switch_to_ARP_Queue;

#define ARPREQUESTOP 1
#define ARPREPLYOP 2
#define NULLADDRESS 0
#define HWDTYPE 1
#define PROTOCOLTYPE 0x800
#define HDWADDRSLEN 6
#define PROTOCOLADDRSLEN 4
#define ARPMSGLENGTH 32
#define REQUESTDATA 1
#define REPLYDATA 2
#define REPLYCONTROL 3

#define ARP_PROTOCOL 0x0806

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
struct ARP_message {
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
struct node {

	uint64_t MAC_addrs;
	uint32_t IP_addrs;
	struct node *next;
};

struct node *ptr_cacheHeader; /**< points to the first element of the dynamic ARP cache*/
uint64_t interface_MAC_addrs;/**<MAC address of interface*/
uint32_t interface_IP_addrs;/**<IP address of interface*/
unsigned char *fins_MAC_address; /**<void pointer of a fins control frame to pass MAC address*/
unsigned char *fins_IP_address;/**<void pointer of a fins control fram to pass IP address*/
struct arp_hdr *packet;/**<An arp header associated with the fins data frame's pdu*/
struct ARP_message arp_msg; /**<This is the ARP message to store and pass replies/requests*/
uint32_t target_IP_addrs; /**<IP address of a target node*/

void gen_requestARP(uint32_t ip_target_addrs, struct ARP_message *request_ARP_ptr);

void gen_replyARP(struct ARP_message *request, struct ARP_message *reply);

int search_list(struct node *ptr_to_cache, uint32_t IP_addrs);

void update_cache(struct ARP_message *pckt);

uint64_t search_MAC_addrs(uint32_t IP_addrs, struct node *ptr);

void arp_to_fins(struct arp_hdr *pckt_arp, struct finsFrame *pckt_fins);

void fins_to_arp(struct finsFrame *pckt_fins, struct arp_hdr *pckt_arp); //, int size_of_finsFrame);

void init_arp_intface(uint64_t MAC_address, uint32_t IP_address);

void term_arp_intface();

void MAC_addrs_conversion(uint64_t MAC_int_addrs, unsigned char *MAC_addrs);

void IP_addrs_conversion(uint32_t IP_int_addrs, unsigned char *IP_char_addrs);

void print_msgARP(struct ARP_message *);

void print_neighbors(struct node *ptr_to_cache);

void print_IP_addrs(uint32_t ip_addrs);

void print_MAC_addrs(uint64_t mac_addrs);

uint32_t gen_IP_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

uint64_t gen_MAC_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);

void print_cache();

void host_to_net(struct arp_hdr *pckt_hdr);

int check_valid_arp(struct ARP_message *pckt_arp);

void print_arp_hdr(struct arp_hdr *pckt);

void arp_msg_to_hdr(struct ARP_message *ptr_msg, struct arp_hdr *ptr_hdr);

void arp_hdr_to_msg(struct arp_hdr *ptr_hdr, struct ARP_message *ptr_msg);

void arp_in(struct finsFrame *sent_in);

void arp_out_reply(struct finsFrame *fins_arp_out);

void arp_out_request(uint32_t sought_IP_addrs, struct finsFrame *fins_arp_out);

void arp_out_ctrl(uint32_t sought_IP_addrs, struct finsFrame *fins_arp_out);

void arp_out(int response_type);

void output_arp_queue(struct finsFrame *fins_arp_out);
void arp_init();
void arp_shutdown();
void arp_free();

#endif
