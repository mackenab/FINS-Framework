/*
 * interface_internal.h
 *
 *  Created on: Apr 20, 2013
 *      Author: root
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

#define INTERFACE_LIB "interface"
#define INTERFACE_MAX_FLOWS 2

struct interface_data {
	struct linked_list *link_list;
	uint32_t flows_num;
	uint32_t flows[INTERFACE_MAX_FLOWS];

	pthread_t switch_to_interface_thread;
	pthread_t capturer_to_interface_thread;

	int client_capture_fd;
	int client_inject_fd;
};

#define INTERFACE_FLOW_UP 0
#define INTERFACE_FLOW_ARP 1 //for when ARP is called through interface using FCF

void interface_get_ff(struct fins_module *module);
void interface_fcf(struct fins_module *module, struct finsFrame *ff);
void interface_set_param(struct fins_module *module, struct finsFrame *ff);
void interface_out_fdf(struct fins_module *module, struct finsFrame *ff);

int interface_init(struct fins_module *module, uint32_t *flows, uint32_t flows_num, metadata_element *params, struct envi_record *envi);
int interface_run(struct fins_module *module, pthread_attr_t *attr);
int interface_pause(struct fins_module *module);
int interface_unpause(struct fins_module *module);
int interface_shutdown(struct fins_module *module);
int interface_release(struct fins_module *module);

#endif /* INTERFACE_INTERNAL_H_ */
