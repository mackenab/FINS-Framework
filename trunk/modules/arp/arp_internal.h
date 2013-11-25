/**@file arp.h
 *@brief this files contains all relevant data types and prototypes of the functions for an ARP module
 *@author Jonathan Reed
 *@date  September 5, 2012
 */

#ifndef ARP_INTERNAL_H_
#define ARP_INTERNAL_H_

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <finstime.h>
#include <metadata.h>
#include <finsqueue.h>

//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
#include <sys/endian.h>
#endif

#include "arp.h"

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_HWD_TYPE 1
#define ARP_PROTOCOL_TYPE 0x800
#define ARP_HDW_ADDR_LEN 6
#define ARP_PROTOCOL_ADDR_LEN 4

#define ARP_TYPE 0x0806
#define ARP_MAC_BROADCAST 0xFFFFFFFFFFFFull
#define ARP_MAC_NULL 0x0
//#define ARP_IP_BROADCAST 0xFFFFFFFF
#define ARP_IP_NULL 0

/**struct arp_hdr is used for use external to the ARP module. The zeroth element of both
 * the IP and MAC arrays (e.g. sender_MAC_addrs[0] or target_IP_addrs[0] etc.) is the
 * most significant byte while the last element is the least significant.*/
struct arp_hdr {
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_addrs_length;
	uint8_t protocol_addrs_length;
	uint16_t operation;
	uint8_t sender_MAC_addrs[ARP_HDW_ADDR_LEN];
	uint8_t sender_IP_addrs[ARP_PROTOCOL_ADDR_LEN];
	uint8_t target_MAC_addrs[ARP_HDW_ADDR_LEN];
	uint8_t target_IP_addrs[ARP_PROTOCOL_ADDR_LEN];

};

uint64_t gen_MAC_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f);
uint32_t gen_IP_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
void MAC_addrs_conversion(uint64_t MAC_int_addrs, uint8_t *MAC_addrs);
void IP_addrs_conversion(uint32_t IP_int_addrs, uint8_t *IP_char_addrs);

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

void gen_requestARP(struct arp_message *request_ARP_ptr, uint64_t sender_mac, uint32_t sender_ip, uint64_t target_mac, uint32_t target_ip);
void gen_replyARP(struct arp_message *reply_ARP, uint64_t sender_mac, uint32_t sender_ip, uint64_t target_mac, uint32_t target_ip);
int check_valid_arp(struct arp_message *msg);

#define ARP_IF_LIST_MAX 256
#define ARP_REQUEST_LIST_MAX (2*65536) //TODO change back to 2^16?
//#define ARP_THREADS_MAX 50
#define ARP_RETRANS_TO_DEFAULT 1000
#define ARP_CACHE_TO_DEFAULT 50000 //#default should be 15sec, continued use extends up to 50sec, not implemented
#define ARP_CACHE_TO_MAX 50000 //unused atm
#define ARP_RETRIES 2
#define ARP_CACHE_LIST_MAX 8192

struct arp_request {
	struct finsFrame *ff;
	uint64_t src_mac;
	uint32_t src_ip;
};
struct arp_request *arp_request_create(struct finsFrame *ff, uint64_t src_mac, uint32_t src_ip);
int arp_request_ip_test(struct arp_request *request, uint32_t *src_ip);
void arp_request_free(struct arp_request *request);

/**This struct is used to store information about neighboring nodes of the host interface*/
struct arp_cache {
	uint64_t mac;
	uint32_t ip;

	struct linked_list *request_list; //linked list of arp_request structs, representing requests for this cache
	uint8_t seeking;
	struct timeval updated_stamp;

	struct intsem_to_timer_data *to_data;
	uint8_t to_flag;
	int retries;
};
struct arp_cache *arp_cache_create(uint32_t addr_ip, uint8_t *interrupt_flag, sem_t *event_sem);
int arp_cache_ip_test(struct arp_cache *cache, uint32_t *src_ip);
int arp_cache_non_seeking_test(struct arp_cache *cache);
void arp_cache_shutdown(struct arp_cache *cache);
void arp_cache_free(struct arp_cache *cache);

void print_msgARP(struct arp_message *msg);
void print_neighbors(struct linked_list *ptr_to_cache);
void print_IP_addrs(uint32_t addr_ip);
void print_MAC_addrs(uint64_t addr_mac);
void print_arp_hdr(struct arp_hdr *pckt);
void print_cache(struct fins_module *module);

struct finsFrame *arp_to_fdf(struct arp_message *msg);
struct arp_message *fdf_to_arp(struct finsFrame *ff);

#define ARP_LIB "arp"
#define ARP_MAX_FLOWS 		1
#define ARP_FLOW_INTERFACE	0

struct arp_data {
	struct linked_list *link_list; //linked list of link_record structs, representing links for this module
	uint32_t flows_num;
	struct fins_module_flow flows[ARP_MAX_FLOWS];

	pthread_t switch_to_arp_thread;
	struct linked_list *if_list; //linked list of if_record structs, representing all interfaces
	struct linked_list *cache_list; //linked list of cache_record structs, representing ARP cache

	uint8_t interrupt_flag;
	int thread_count;
};

int arp_init(struct fins_module *module, metadata_element *params, struct envi_record *envi);
int arp_run(struct fins_module *module, pthread_attr_t *attr);
int arp_pause(struct fins_module *module);
int arp_unpause(struct fins_module *module);
int arp_shutdown(struct fins_module *module);
int arp_release(struct fins_module *module);

void arp_get_ff(struct fins_module *module);
void arp_fcf(struct fins_module *module, struct finsFrame *ff);
void arp_set_param(struct fins_module *module, struct finsFrame *ff);
void arp_exec(struct fins_module *module, struct finsFrame *ff);
void arp_exec_get_addr(struct fins_module *module, struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip);
//void arp_exec_get_addr(struct finsFrame *ff, uint32_t addr_ip);

#define ARP_EXEC_GET_ADDR 0

void arp_in_fdf(struct fins_module *module, struct finsFrame *ff);
void arp_out_fdf(struct fins_module *module, struct finsFrame *ff);

void arp_interrupt(struct fins_module *module);
void arp_handle_to(struct fins_module *module, struct arp_cache *cache);

//don't use 0
#define ARP_READ_PARAM_FLOWS MOD_READ_PARAM_FLOWS
#define ARP_READ_PARAM_LINKS MOD_READ_PARAM_LINKS
#define ARP_READ_PARAM_DUAL MOD_READ_PARAM_DUAL

#define ARP_SET_PARAM_FLOWS MOD_SET_PARAM_FLOWS
#define ARP_SET_PARAM_LINKS MOD_SET_PARAM_LINKS
#define ARP_SET_PARAM_DUAL MOD_SET_PARAM_DUAL

#endif /* ARP_INTERNAL_H_ */
