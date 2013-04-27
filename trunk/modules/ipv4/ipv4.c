/**
 * @file IP4.c
 * @brief FINS module - Internet Protocol version 4
 *
 * Main function of the module.
 */

#include "ipv4_internal.h"

void *switch_to_ipv4(void *local) {
	struct fins_module *module = (struct fins_module *) local;

	PRINT_IMPORTANT("Entered: module=%p", module);

	while (module->state == FMS_RUNNING) {
		ipv4_get_ff(module);
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Exited");
	//pthread_exit(NULL);
	return NULL;
}

//################ ARP/interface stuff //TODO move to common?
struct ipv4_interface *ipv4_interface_create(uint64_t addr_mac, uint32_t addr_ip) {
	PRINT_DEBUG("Entered: mac=0x%llx, ip=%u", addr_mac, addr_ip);

	struct ipv4_interface *interface = (struct ipv4_interface *) secure_malloc(sizeof(struct ipv4_interface));
	interface->addr_mac = addr_mac;
	interface->addr_ip = addr_ip;

	PRINT_DEBUG("Exited: mac=0x%llx, ip=%u, interface=%p", addr_mac, addr_ip, interface);
	return interface;
}

int ipv4_interface_ip_test(struct ipv4_interface *interface, uint32_t *addr_ip) {
	return interface->addr_ip == *addr_ip;
}

void ipv4_interface_free(struct ipv4_interface *interface) {
	PRINT_DEBUG("Entered: interface=%p", interface);

	free(interface);
}

int ipv4_register_interface(struct fins_module *module, uint64_t MAC_address, uint32_t IP_address) {
	PRINT_DEBUG("Registering Interface: MAC=0x%llx, IP=%u", MAC_address, IP_address);

	struct ipv4_data *data = (struct ipv4_data *) module->data;

	if (list_has_space(data->interface_list)) {
		struct ipv4_interface *interface = ipv4_interface_create(MAC_address, IP_address);
		list_append(data->interface_list, interface);

		return 1;
	} else {
		return 0;
	}
}

struct ipv4_request *ipv4_request_create(struct finsFrame *ff, uint64_t src_mac, uint32_t src_ip, uint8_t *pdu) {
	PRINT_DEBUG("Entered: ff=%p, mac=0x%llx, ip=%u", ff, src_mac, src_ip);

	struct ipv4_request *request = (struct ipv4_request *) secure_malloc(sizeof(struct ipv4_request));
	request->ff = ff;
	request->src_mac = src_mac;
	request->src_ip = src_ip;
	request->pdu = pdu;

	PRINT_DEBUG("Exited: ff=%p, src mac=0x%llx, src ip=%u, request=%p", ff, src_mac, src_ip, request);
	return request;
}

int ipv4_request_ip_test(struct ipv4_request *request, uint32_t *src_ip) {
	return request->src_ip == *src_ip;
}

void ipv4_request_free(struct ipv4_request *request) {
	PRINT_DEBUG("Entered: request=%p", request);

	if (request->ff) {
		freeFinsFrame(request->ff);
	}

	if (request->pdu) {
		PRINT_DEBUG("Freeing pdu=%p", request->pdu);
		free(request->pdu);
	}

	free(request);
}

struct ipv4_cache *ipv4_cache_create(uint32_t addr_ip) {
	PRINT_DEBUG("Entered: ip=%u", addr_ip);

	struct ipv4_cache *cache = (struct ipv4_cache *) secure_malloc(sizeof(struct ipv4_cache));
	cache->addr_mac = IPV4_MAC_NULL;
	cache->addr_ip = addr_ip;

	cache->request_list = list_create(IPV4_REQUEST_LIST_MAX);

	cache->seeking = 0;
	memset(&cache->updated_stamp, 0, sizeof(struct timeval));

	PRINT_DEBUG("Exited: ip=%u, cache=%p", addr_ip, cache);
	return cache;
}

int ipv4_cache_ip_test(struct ipv4_cache *cache, uint32_t *addr_ip) {
	return cache->addr_ip == *addr_ip;
}

int ipv4_cache_non_seeking_test(struct ipv4_cache *cache) {
	return !cache->seeking;
}

void ipv4_cache_free(struct ipv4_cache *cache) {
	PRINT_DEBUG("Entered: cache=%p", cache);

	if (cache->request_list) {
		list_free(cache->request_list, ipv4_request_free);
	}

	free(cache);
}

struct ipv4_store *ipv4_store_create(uint32_t serial_num, struct ipv4_cache *cache, struct ipv4_request *request) { //TODO remove request? not used
	PRINT_DEBUG("Entered: serial_num=%u, cache=%p, request=%p", serial_num, cache, request);

	struct ipv4_store *store = (struct ipv4_store *) secure_malloc(sizeof(struct ipv4_store));
	store->serial_num = serial_num;
	store->cache = cache;
	store->request = request;

	PRINT_DEBUG("Exited: serial_num=%u, cache=%p, request=%p, store=%p", serial_num, cache, request, store);
	return store;
}

int ipv4_store_serial_test(struct ipv4_store *store, uint32_t *serial_num) {
	return store->serial_num == *serial_num;
}

void ipv4_store_free(struct ipv4_store *store) {
	PRINT_DEBUG("Entered: store=%p", store);

	if (store->cache) {
		ipv4_cache_free(store->cache);
	}

	free(store);
}
//################

//####################################### autoconfig
void ipv4_init_params(struct fins_module *module) {
	metadata_element *root = config_root_setting(module->params);
	//int status;

	//-------------------------------------------------------------------------------------------
	metadata_element *exec_elem = config_setting_add(root, "exec", CONFIG_TYPE_GROUP);
	if (exec_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}

	//-------------------------------------------------------------------------------------------
	metadata_element *get_elem = config_setting_add(root, "get", CONFIG_TYPE_GROUP);
	if (get_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}
	//elem_add_param(get_elem, LOGGER_GET_INTERVAL__str, LOGGER_GET_INTERVAL__id, LOGGER_GET_INTERVAL__type);
	//elem_add_param(get_elem, LOGGER_GET_REPEATS__str, LOGGER_GET_REPEATS__id, LOGGER_GET_REPEATS__type);

	//-------------------------------------------------------------------------------------------
	metadata_element *set_elem = config_setting_add(root, "set", CONFIG_TYPE_GROUP);
	if (set_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}
	//elem_add_param(set_elem, LOGGER_SET_INTERVAL__str, LOGGER_SET_INTERVAL__id, LOGGER_SET_INTERVAL__type);
	//elem_add_param(set_elem, LOGGER_SET_REPEATS__str, LOGGER_SET_REPEATS__id, LOGGER_SET_REPEATS__type);
}

int ipv4_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi) {
	PRINT_IMPORTANT("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	ipv4_init_params(module);

	module->data = secure_malloc(sizeof(struct ipv4_data));
	struct ipv4_data *data = (struct ipv4_data *) module->data;

	if (module->flows_max < flows_num) {
		PRINT_ERROR("todo error");
		return 0;
	}
	data->flows_num = flows_num;

	int i;
	for (i = 0; i < flows_num; i++) {
		data->flows[i] = flows[i];
	}

	data->route_list = list_create(100); //TODO change num?
	routing_table = IP4_get_routing_table();
	PRINT_DEBUG("after ip4 sort route table");
	memset(&data->stats, 0, sizeof(struct ip4_stats));

	//ARP stuff that should be moved to interface
	data->store_list = list_create(IPV4_STORE_LIST_MAX);
	data->interface_list = list_create(IPV4_INTERFACE_LIST_MAX);
	data->cache_list = list_create(IPV4_CACHE_LIST_MAX);

	/* find a way to get the IP of the desired interface automatically from the system
	 * or from a configuration file
	 */
	//ADDED mrd015 !!!!!
	return 1;
}

int ipv4_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_IMPORTANT("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	struct ipv4_data *data = (struct ipv4_data *) module->data;
	secure_pthread_create(&data->switch_to_ipv4_thread, attr, switch_to_ipv4, module);
	return 1;
}

int ipv4_pause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_PAUSED;

	//TODO
	return 1;
}

int ipv4_unpause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_RUNNING;

	//TODO
	return 1;
}

int ipv4_shutdown(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN;
	sem_post(module->event_sem);

	struct ipv4_data *data = (struct ipv4_data *) module->data;

	//TODO expand this

	PRINT_IMPORTANT("Joining switch_to_ipv4_thread");
	pthread_join(data->switch_to_ipv4_thread, NULL);

	return 1;
}

int ipv4_release(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);

	struct ipv4_data *data = (struct ipv4_data *) module->data;
	//TODO free all module related mem
	PRINT_IMPORTANT("store_list->len=%u", data->store_list->len);
	list_free(data->store_list, ipv4_store_free);
	PRINT_IMPORTANT("interface_list->len=%u", data->interface_list->len);
	list_free(data->interface_list, ipv4_interface_free);
	PRINT_IMPORTANT("cache_list->len=%u", data->cache_list->len);
	list_free(data->cache_list, ipv4_cache_free);

	list_free(data->route_list, free);

	if (data->link_list) {
		list_free(data->link_list, free);
	}
	free(data);
	module_destroy_structs(module);
	free(module);
	return 1;
}

void ipv4_dummy(void) {

}

static struct fins_module_ops ipv4_ops = { .init = ipv4_init, .run = ipv4_run, .pause = ipv4_pause, .unpause = ipv4_unpause, .shutdown = ipv4_shutdown,
		.release = ipv4_release, };

struct fins_module *ipv4_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_IMPORTANT("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, IPV4_LIB);
	module->flows_max = IPV4_MAX_FLOWS;
	module->ops = &ipv4_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_IMPORTANT("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
