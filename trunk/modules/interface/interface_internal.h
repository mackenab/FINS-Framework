/*
 * interface_internal.h
 *
 *  Created on: Apr 20, 2013
 *      Author: Jonathan Reed
 */

#ifndef INTERFACE_INTERNAL_H_
#define INTERFACE_INTERNAL_H_

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <finstime.h>
#include <metadata.h>
#include <finsqueue.h>

#include "interface.h"

/** Ethernet Stub Variables  */

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#ifdef BUILD_FOR_ANDROID
//#define FINS_TMP_ROOT "/data/data/fins"
#define FINS_TMP_ROOT "/data/data/com.BU_VT.FINS/files"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

#define CAPTURE_PATH FINS_TMP_ROOT "/fins_capture"
#define INJECT_PATH FINS_TMP_ROOT "/fins_inject"

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define ETH_TYPE_IP4  0x0800
#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_IP6  0x86dd

#define ETH_FRAME_LEN_MAX 1538

/* Ethernet header */
struct sniff_ethernet {
	uint8_t ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
	uint8_t ether_shost[ETHER_ADDR_LEN]; /* source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
	uint8_t data[1];
};

//vvvvvvvvvvvvvvvvvv ARP/interface stuff
#define INTERFACE_IF_LIST_MAX 256
#define INTERFACE_REQUEST_LIST_MAX (2*65536) //TODO change back to 2^16?
#define INTERFACE_CACHE_TO_DEFAULT 15000
#define INTERFACE_MAC_NULL 0x0
#define INTERFACE_CACHE_LIST_MAX 8192
#define INTERFACE_STORE_LIST_MAX (2*65536)

struct interface_request {
	struct sockaddr_storage src_ip;
	uint64_t src_mac;
	struct finsFrame *ff;
};
int interface_request_ipv4_test(struct interface_request *request, uint32_t *src_ip);
void interface_request_free(struct interface_request *request);

struct interface_cache {
	struct sockaddr_storage ip; //unique id
	uint64_t mac;

	struct linked_list *request_list;
	uint8_t seeking;
	struct timeval updated_stamp;
};
int interface_cache_ipv4_test(struct interface_cache *cache, uint32_t *ip);
int interface_cache_ipv6_test(struct interface_cache *cache, uint8_t *ip);
int interface_cache_non_seeking_test(struct interface_cache *cache);
void interface_cache_free(struct interface_cache *cache);

struct interface_store {
	uint32_t serial_num;
	uint32_t sent;
	struct interface_cache *cache;
	struct interface_request *request;
};
struct interface_store *interface_store_create(uint32_t serial_num, uint32_t sent, struct interface_cache *cache, struct interface_request *request);
int interface_store_serial_test(struct interface_store *store, uint32_t *serial_num);
int interface_store_request_test(struct interface_store *store, struct interface_request *request);
void interface_store_free(struct interface_store *store);
//^^^^^^^^^^^^^^^^^^ ARP/interface stuff

#define INTERFACE_LIB "interface"
#define INTERFACE_MAX_FLOWS 3
#define INTERFACE_FLOW_IPV4 0
#define INTERFACE_FLOW_ARP 	1
#define INTERFACE_FLOW_IPV6	2

struct interface_data {
	struct linked_list *link_list;
	uint32_t flows_num;
	uint32_t flows[INTERFACE_MAX_FLOWS];

	pthread_t switch_to_interface_thread;
	pthread_t capturer_to_interface_thread;

	int client_capture_fd;
	int client_inject_fd;

	struct linked_list *if_list;
	struct linked_list *cache_list; //The list of current cache we have
	struct linked_list *store_list; //Stored FDF waiting to send
};

int interface_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi);
int interface_run(struct fins_module *module, pthread_attr_t *attr);
int interface_pause(struct fins_module *module);
int interface_unpause(struct fins_module *module);
int interface_shutdown(struct fins_module *module);
int interface_release(struct fins_module *module);

void interface_get_ff(struct fins_module *module);
void interface_fcf(struct fins_module *module, struct finsFrame *ff);
void interface_read_param(struct fins_module *module, struct finsFrame *ff);
void interface_set_param(struct fins_module *module, struct finsFrame *ff);
void interface_exec(struct fins_module *module, struct finsFrame *ff);
void interface_exec_reply(struct fins_module *module, struct finsFrame *ff);
void interface_exec_reply_get_addr(struct fins_module *module, struct finsFrame *ff);

void interface_out_fdf(struct fins_module *module, struct finsFrame *ff);
void interface_out_ipv4(struct fins_module *module, struct finsFrame *ff);
void interface_out_arp(struct fins_module *module, struct finsFrame *ff);
void interface_out_ipv6(struct fins_module *module, struct finsFrame *ff);
int interface_inject_pdu(int fd, uint32_t pduLength, uint8_t *pdu, uint64_t dst_mac, uint64_t src_mac, uint32_t ether_type);
int interface_send_request(struct fins_module *module, uint32_t src_ip, uint32_t dst_ip, uint32_t serial_num);

#define EXEC_INTERFACE_GET_ADDR 0

//don't use 0
#define INTERFACE_GET_PARAM_FLOWS MOD_GET_PARAM_FLOWS
#define INTERFACE_GET_PARAM_LINKS MOD_GET_PARAM_LINKS
#define INTERFACE_GET_PARAM_DUAL MOD_GET_PARAM_DUAL

#endif /* INTERFACE_INTERNAL_H_ */
