/**
 * @file IP4.c
 * @brief FINS module - Internet Protocol version 4
 *
 * Main function of the module.
 */

#include "ipv4.h"
#include <queueModule.h>

IP4addr my_ip_addr;
IP4addr loopback = IP4_ADR_P2H(127, 0, 0, 1);
IP4addr my_mask;

/*
 IP4addr my_ip_addr;
 IP4addr loopback_ip_addr;
 IP4addr any_ip_addr;
 */

struct ip4_routing_table* routing_table;
struct ip4_packet *construct_packet_buffer;
struct ip4_stats stats;

struct ip4_store *store_list;
uint32_t store_num;

void *switch_to_ipv4(void *local) {
	while (ipv4_running) {
		IP4_receive_fdf();
		PRINT_DEBUG("");
		//	free(ff);
	}

	PRINT_DEBUG("Exited");
	pthread_exit(NULL);
}

struct ip4_store *store_create(uint32_t serialNum, struct finsFrame *ff, u_char *pdu) {
	PRINT_DEBUG("Entered: ff=%p, serialNum=%u", ff, serialNum);

	struct ip4_store *store = (struct ip4_store *) malloc(sizeof(struct ip4_store));
	if (store == NULL) {
		PRINT_ERROR("store alloc fail");
		exit(-1);
	}

	store->next = NULL;
	store->serialNum = serialNum;
	store->ff = ff;
	store->pdu = pdu;

	return store;
}

void store_free(struct ip4_store *store) {
	PRINT_DEBUG("Entered: store=%p", store);

	//free pdu?
	//free ff?

	free(store);
}

int store_list_insert(struct ip4_store *store) {
	PRINT_DEBUG("Entered: store=%p", store);

	if (store_list == NULL) {
		store_list = store;
	} else {
		struct ip4_store *temp = store_list;

		while (temp->next != NULL) {
			temp = temp->next;
		}

		temp->next = store;
		store->next = NULL;
	}

	store_num++;
	return 1;
}

struct ip4_store *store_list_find(uint32_t serialNum) {
	PRINT_DEBUG("Entered: serialNum=%u", serialNum);

	struct ip4_store *temp = store_list;

	while (temp != NULL && temp->serialNum != serialNum) {
		temp = temp->next;
	}

	return temp;
}

void store_list_remove(struct ip4_store *store) {
	PRINT_DEBUG("Entered: store=%p", store);

	if (store_list == NULL) {
		return;
	}

	if (store_list == store) {
		store_list = store_list->next;
		store_num--;
		return;
	}

	struct ip4_store *temp = store_list;
	while (temp->next != NULL) {
		if (temp->next == store) {
			temp->next = store->next;
			store_num--;
			return;
		}
		temp = temp->next;
	}
}

int store_list_is_empty(void) {
	return store_num == 0;
}

int store_list_has_space(void) {
	return store_num < IP4_STORE_LIST_MAX;
}

void ipv4_init(void) {
	PRINT_DEBUG("Entered");
	ipv4_running = 1;

	store_list = NULL;
	store_num = 0;

	/* find a way to get the IP of the desired interface automatically from the system
	 * or from a configuration file
	 */

	//my_ip_addr = IP4_ADR_P2H(192, 168, 1, 20);
	//my_ip_addr = IP4_ADR_P2H(172,31,50,160);
	//my_ip_addr = IP4_ADR_P2H(127, 0, 0, 1);
	//my_ip_addr = IP4_ADR_P2H(172, 31, 63, 231);
	//my_ip_addr = IP4_ADR_P2H(172, 31, 53, 114);
	//PRINT_DEBUG("%lu", my_ip_addr);
	my_mask = IP4_ADR_P2H(255, 255, 255, 0); //TODO move to core/central place

	//ADDED mrd015 !!!!!
#ifndef BUILD_FOR_ANDROID
	IP4_init();
#endif
}

void set_interface(uint32_t IP_address, uint32_t mask) {
	my_ip_addr = IP_address;
	my_mask = mask;
}

void ipv4_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_DEBUG("Entered");

	pthread_create(&switch_to_ipv4_thread, fins_pthread_attr, switch_to_ipv4, fins_pthread_attr);
}

void ipv4_shutdown(void) {
	PRINT_DEBUG("Entered");
	ipv4_running = 0;

	//TODO expand this

	pthread_join(switch_to_ipv4_thread, NULL);
}

void ipv4_release(void) {
	PRINT_DEBUG("Entered");
	//TODO free all module related mem

	//term_queue(IPv4_to_Switch_Queue); //TODO uncomment
	//term_queue(Switch_to_IPv4_Queue);
}
