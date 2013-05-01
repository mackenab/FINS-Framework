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

	PRINT_IMPORTANT("Exited: module=%p", module);
	return NULL;
}

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

void ipv4_ifr_get_addr_func(struct if_record *ifr, struct linked_list *ret_list) {
	if (ifr->flags & IFF_RUNNING) { //ifr->status ?
		//struct linked_list *temp_list = list_find_all(ifr->addr_list, addr_is_v4);
		struct linked_list *temp_list = list_filter(ifr->addr_list, addr_is_v4, addr_copy);
		if (list_join(ret_list, temp_list)) {
			free(temp_list);
		} else {
			PRINT_ERROR("todo error");
			//list_free(temp_list, nop_func);
			list_free(temp_list, free);
		}
	}
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

	data->addr_list = list_create(IPV4_ADDRESS_LIST_MAX);
	list_for_each1(envi->if_list, ipv4_ifr_get_addr_func, data->addr_list);
	if (envi->if_loopback) {
		data->addr_loopback = (struct addr_record *) list_find(envi->if_loopback->addr_list, addr_is_v4);
	}
	if (envi->if_main) {
		data->addr_main = (struct addr_record *) list_find(envi->if_main->addr_list, addr_is_v4);
	}

	data->route_list = list_filter(envi->route_list, route_is_addr4, route_copy);
	if (data->route_list->len > IPV4_ROUTE_LIST_MAX) {
		PRINT_ERROR("todo");
		struct linked_list *leftover = list_split(data->route_list, IPV4_ROUTE_LIST_MAX - 1);
		list_free(leftover, free);
	}
	data->route_list->max = IPV4_ROUTE_LIST_MAX;

	//when recv pkt would need to check addresses
	//when send pkt would need to check routing table & addresses (for ip address)
	//both of these would need to be updated by switch etc

	//routing_table = IP4_get_routing_table();

	PRINT_DEBUG("after ip4 sort route table");
	memset(&data->stats, 0, sizeof(struct ip4_stats));

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
	list_free(data->addr_list, free);
	list_free(data->route_list, free);

	if (data->link_list != NULL) {
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
