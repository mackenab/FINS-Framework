/**@file arp.h
 *@brief this files contains all relevant data types and prototypes of the functions for an ARP module
 *@author Jonathan Reed
 *@date  September 5, 2012
 */

#ifndef ARP_H_
#define ARP_H_

#include <inttypes.h>
#include <finstypes.h>
#include <metadata.h>
#include <finsdebug.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <queueModule.h>

//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
#include <sys/endian.h>
#endif

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

struct arp_interface {
	struct arp_interface *next;

	uint64_t mac_addr;
	uint32_t ip_addr;
};

struct arp_interface *interface_create(uint64_t mac_addr, uint32_t ip_addr);
void interface_free(struct arp_interface *interface);

#define ARP_INTERFACE_LIST_MAX 256

int interface_list_insert(struct arp_interface *interface);
struct arp_interface *interface_list_find(uint32_t ip_addr);
void interface_list_remove(struct arp_interface *interface);
int interface_list_is_empty(void);
int interface_list_has_space(void);

struct arp_request {
	struct arp_request *next;
	struct finsFrame *ff;
	uint64_t src_mac;
	uint32_t src_ip;
};

struct arp_request *request_create(struct finsFrame *ff, uint64_t src_mac, uint32_t src_ip);
void request_free(struct arp_request *request);

struct arp_request_list {
	uint32_t max;
	uint32_t len;
	struct arp_request *front;
	struct arp_request *end;
};

#define ARP_REQUEST_LIST_MAX 65536

struct arp_request_list *request_list_create(uint32_t max);
void request_list_append(struct arp_request_list *request_list, struct arp_request *request);
struct arp_request *request_list_find(struct arp_request_list *request_list, uint32_t src_ip);
struct arp_request *request_list_remove_front(struct arp_request_list *request_list);
int request_list_is_empty(struct arp_request_list *request_list);
int request_list_has_space(struct arp_request_list *request_list);
void request_list_free(struct arp_request_list *request_list);

struct arp_to_thread_data {
	int id;
	int fd;
	uint8_t *running;
	uint8_t *flag;
	uint8_t *interrupt;
};

void arp_stop_timer(int fd);
void arp_start_timer(int fd, double millis);

/**This struct is used to store information about neighboring nodes of the host interface*/
struct arp_cache {
	struct arp_cache *next;
	uint8_t running_flag;

	uint64_t mac_addr;
	uint32_t ip_addr;

	struct arp_request_list *request_list;
	uint32_t request_num;
	uint8_t seeking;
	struct timeval updated_stamp;

	pthread_t to_thread;
	int to_fd;
	uint8_t to_flag;
	int retries;
};

//#define ARP_THREADS_MAX 50
#define ARP_RETRANS_TO_DEFAULT 1000
#define ARP_CACHE_TO_DEFAULT 15000
#define ARP_RETRIES 2
#define ARP_TO_MIN 0.00001

struct arp_cache *cache_create(uint32_t ip_addr);
void cache_shutdown(struct arp_cache *cache);
void cache_free(struct arp_cache *cache);

#define ARP_CACHE_LIST_MAX 8192
int cache_list_insert(struct arp_cache *cache);
struct arp_cache *cache_list_find(uint32_t ip_addr);
void cache_list_remove(struct arp_cache *cache);
struct arp_cache *cache_list_remove_first_non_seeking(void);
int cache_list_is_empty(void);
int cache_list_has_space(void);

void print_msgARP(struct arp_message *);
void print_neighbors(struct arp_cache *ptr_to_cache);
void print_IP_addrs(uint32_t ip_addrs);
void print_MAC_addrs(uint64_t mac_addrs);
void print_arp_hdr(struct arp_hdr *pckt);
void print_cache();

struct finsFrame *arp_to_fdf(struct arp_message *msg);
struct arp_message *fdf_to_arp(struct finsFrame *ff);

void arp_init(void);
void arp_run(pthread_attr_t *fins_pthread_attr);
void arp_shutdown(void);
void arp_release(void);

int arp_register_interface(uint64_t MAC_address, uint32_t IP_address);

void arp_get_ff(void);
int arp_to_switch(struct finsFrame *ff);

#define EXEC_ARP_GET_ADDR 0

void arp_fcf(struct finsFrame *ff);
void arp_exec(struct finsFrame *ff);
void arp_exec_get_addr(struct finsFrame *ff, uint32_t dst_ip, uint32_t src_ip);

void arp_in_fdf(struct finsFrame *ff);
void arp_out_fdf(struct finsFrame *ff);

void arp_interrupt(void);
void arp_handle_to(struct arp_cache *cache);

#endif

