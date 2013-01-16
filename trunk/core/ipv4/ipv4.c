/**
 * @file IP4.c
 * @brief FINS module - Internet Protocol version 4
 *
 * Main function of the module.
 */

#include "ipv4.h"
#include <queueModule.h>

#include <switch.h>
struct fins_proto_module ipv4_proto = { .module_id = IPV4_ID, .name = "ipv4", .running_flag = 1, }; //TODO make static?

IP4addr my_ip_addr;
IP4addr my_mask;
IP4addr loopback;
IP4addr loopback_mask;

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

int ipv4_to_switch(struct finsFrame *ff) {
	return module_to_switch(&ipv4_proto, ff);
}

void *switch_to_ipv4(void *local) {
	PRINT_CRITICAL("Entered");

	while (ipv4_proto.running_flag) {
		IP4_receive_fdf();
		PRINT_DEBUG("");
	}

	PRINT_CRITICAL("Exited");
	pthread_exit(NULL);
}

struct ip4_store *store_create(uint32_t serial_num, struct finsFrame *ff, uint8_t *pdu) {
	PRINT_DEBUG("Entered: serial_num=%u, ff=%p, pdu=%p", serial_num, ff, pdu);

	struct ip4_store *store = (struct ip4_store *) fins_malloc(sizeof(struct ip4_store));
	store->next = NULL;

	store->serial_num = serial_num;
	store->ff = ff;
	store->pdu = pdu;

	PRINT_DEBUG("Exited: serial_num=%u, ff=%p, pdu=%p, store=%p", serial_num, ff, pdu, store);
	return store;
}

void store_free(struct ip4_store *store) {
	PRINT_DEBUG("Entered: store=%p", store);

	if (store->pdu) {
		PRINT_DEBUG("Freeing pdu=%p", store->pdu);
		free(store->pdu);
	}

	if (store->ff)
		freeFinsFrame(store->ff);

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
	PRINT_DEBUG("Exited: store=%p, store_num=%u", store, store_num);
	return 1;
}

struct ip4_store *store_list_find(uint32_t serial_num) {
	PRINT_DEBUG("Entered: serial_num=%u", serial_num);

	struct ip4_store *temp = store_list;

	while (temp != NULL && temp->serial_num != serial_num) {
		temp = temp->next;
	}

	PRINT_DEBUG("Exited: serial_num=%u, store=%p", serial_num, temp);
	return temp;
}

void store_list_remove(struct ip4_store *store) {
	PRINT_DEBUG("Entered: store=%p", store);

	if (store_list == NULL) {
		PRINT_DEBUG("Exited: store=%p, store_num=%u", store, store_num);
		return;
	}

	if (store_list == store) {
		store_list = store_list->next;
		store_num--;
		PRINT_DEBUG("Exited: store=%p, store_num=%u", store, store_num);
		return;
	}

	struct ip4_store *temp = store_list;
	while (temp->next != NULL) {
		if (temp->next == store) {
			temp->next = store->next;
			store_num--;
			PRINT_DEBUG("Exited: store=%p, store_num=%u", store, store_num);
			return;
		}
		temp = temp->next;
	}

	PRINT_DEBUG("Exited: store=%p, store_num=%u", store, store_num);
}

int store_list_is_empty(void) {
	return store_num == 0;
}

int store_list_has_space(void) {
	return store_num < IP4_STORE_LIST_MAX;
}

void ipv4_init(void) {
	PRINT_CRITICAL("Entered");
	ipv4_proto.running_flag = 1;

	module_create_ops(&ipv4_proto);
	module_register(&ipv4_proto);

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
	//my_mask = IP4_ADR_P2H(255, 255, 255, 0); //TODO move to core/central place
	//ADDED mrd015 !!!!!
#ifndef BUILD_FOR_ANDROID
	IP4_init();
#endif
}

void ipv4_set_interface(uint32_t IP_address, uint32_t mask) {
	my_ip_addr = IP_address;
	my_mask = mask;
}

void ipv4_set_loopback(uint32_t IP_address, uint32_t mask) {
	loopback = IP_address;
	loopback_mask = mask;
}

void ipv4_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_CRITICAL("Entered");

	pthread_create(&switch_to_ipv4_thread, fins_pthread_attr, switch_to_ipv4, fins_pthread_attr);
}

void ipv4_shutdown(void) {
	PRINT_CRITICAL("Entered");
	ipv4_proto.running_flag = 0;
	sem_post(ipv4_proto.event_sem);

	//TODO expand this

	PRINT_CRITICAL("Joining switch_to_ipv4_thread");
	pthread_join(switch_to_ipv4_thread, NULL);
}

void ipv4_release(void) {
	PRINT_CRITICAL("Entered");
	module_unregister(ipv4_proto.module_id);

	//TODO free all module related mem

	struct ip4_store *store;
	while (!store_list_is_empty()) {
		store = store_list;
		store_list_remove(store);
		store_free(store);
	}

	struct ip4_routing_table *table;
	while (routing_table) {
		table = routing_table;
		routing_table = routing_table->next_entry;

		free(table);
	}

	module_destroy_ops(&ipv4_proto);
}
