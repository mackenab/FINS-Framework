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
void init_arp_intface(uint64_t MAC_address, uint32_t IP_address)
{
	PRINT_DEBUG("\nInitializing ARP cache\n");

	struct node *intface = (struct node*) malloc(sizeof(struct node));
	packet = (struct arp_hdr*) malloc(sizeof(struct arp_hdr));
	fins_MAC_address = (unsigned char*) malloc(sizeof(unsigned char)*HDWADDRSLEN);
	fins_IP_address = (unsigned char*) malloc(sizeof(unsigned char)*PROTOCOLADDRSLEN);
	interface_MAC_addrs = MAC_address;
	interface_IP_addrs =IP_address;
	intface->IP_addrs = interface_IP_addrs;
	intface->MAC_addrs = interface_MAC_addrs;
	intface->next = NULL;
	ptr_cacheHeader = intface;
}

/**
 * @brief this function liberates all memory allocated to store and frees the cache
 * of the ARP module */
void term_arp_intface()
{
	struct node *ptr_elementInList1, *ptr_elementInList2;
	ptr_elementInList1 = ptr_cacheHeader;
	ptr_elementInList2 = ptr_cacheHeader;

	PRINT_DEBUG("\nFreeing memory used for ARP module\n");
	free(fins_MAC_address);
	free(fins_IP_address);
	free(packet);

	while (ptr_elementInList1!=NULL){
		ptr_elementInList2 = ptr_elementInList1->next;
		free(ptr_elementInList1);
		ptr_elementInList1 = ptr_elementInList2;
	}
}
