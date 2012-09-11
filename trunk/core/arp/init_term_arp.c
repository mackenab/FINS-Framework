/*
 * init_term_arp.c
 *
 *  Created on: Oct 18, 2010
 *      Author: Syed Amaar Ahmad
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <finstypes.h>
#include <finsdebug.h>
#include <metadata.h>
#include "arp.h"

/**
 * @brief this function initializes a cache for the host's interface. Note that an interface is the first element/header of
 * a linked list of neighbors' which are represented as nodes.  Each neighbor is linked to the next neighbor via the 'next' pointer
 * @param MAC_address is the MAC address of the interface
 * @param IP_address is its IP address
 */
void init_arp_intface(uint64_t MAC_address, uint32_t IP_address) {
	PRINT_DEBUG("\nInitializing ARP cache\n");

	struct arp_node *intface = (struct arp_node*) malloc(sizeof(struct arp_node));
	packet = (struct arp_hdr*) malloc(sizeof(struct arp_hdr));
	fins_MAC_address = (unsigned char*) malloc(sizeof(unsigned char) * HDWADDRSLEN);
	fins_IP_address = (unsigned char*) malloc(sizeof(unsigned char) * PROTOCOLADDRSLEN);
	interface_MAC_addrs = MAC_address;
	interface_IP_addrs = IP_address;
	intface->IP_addrs = interface_IP_addrs;
	intface->MAC_addrs = interface_MAC_addrs;
	intface->next = NULL;
	cache_list = intface;
}

int arp_register_interface(uint64_t MAC_address, uint32_t IP_address) {
	PRINT_DEBUG("Registering Interface: MAC=%llu, IP=%u", MAC_address, IP_address);

	struct arp_node *interface = (struct arp_node*) malloc(sizeof(struct arp_node));
	if (interface == NULL) {
		PRINT_DEBUG("todo error");
		return 0;
	}

	interface->MAC_addrs = MAC_address;
	interface->IP_addrs = IP_address;

	interface->next = interface_list;
	interface_list = interface;

	return 1;
}

/**
 * @brief this function liberates all memory allocated to store and frees the cache
 * of the ARP module */
void term_arp_intface() {
	struct arp_node *ptr_elementInList1, *ptr_elementInList2;
	ptr_elementInList1 = cache_list;
	ptr_elementInList2 = cache_list;

	PRINT_DEBUG("\nFreeing memory used for ARP module\n");
	free(fins_MAC_address);
	free(fins_IP_address);
	free(packet);

	while (ptr_elementInList1 != NULL) {
		ptr_elementInList2 = ptr_elementInList1->next;
		free(ptr_elementInList1);
		ptr_elementInList1 = ptr_elementInList2;
	}
}
