/*
 * 		@file core.c
 * *  	@date Nov 26, 2010
 *      @author Abdallah Abdallah
 *      @brief This is the FINS CORE including (the Daemon name pipes based
 *      server)
 *      notice that A read call will normally block; that is, it will cause the process to
 *       wait until data becomes available. If the other end of the pipe has been closed,
 *       then no process has the pipe open for writing, and the read blocks. Because this isn’t
 *       very helpful, a read on a pipe that isn’t open for writing returns zero rather than
 *       blocking. This allows the reading process to detect the pipe equivalent of end of file
 *       and act appropriately. Notice that this isn’t the same as reading an invalid file
 *       descriptor, which read considers an error and indicates by returning –1.
 *       */
#include <signal.h>
//#include <libconfig.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <finstime.h>
#include <metadata.h>
#include <finsqueue.h>
#include <finsmodule.h>

#include "core.h"

#ifdef BUILD_FOR_ANDROID
#include <switch.h>
#include <interface.h>
#include <arp.h>
#include <ipv4.h>
#include <icmp.h>
#include <tcp.h>
#include <udp.h>
#include <daemon.h>
#include <logger.h>
#include <rtm.h>
#endif

extern sem_t control_serial_sem; //TODO remove & change gen process to RNG

struct fins_overall *overall;

int write_configurations() {

	config_t cfg;
	//config_setting_t *setting;
	//const char *str;

	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if (!config_write_file(&cfg, "fins.cfg")) {
		PRINT_ERROR("%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return EXIT_FAILURE;
	}

	config_destroy(&cfg);
	return EXIT_SUCCESS;
}

#ifdef BUILD_FOR_ANDROID
//TODO fix Android problems with dynamically loading shared libraries.
// Can find the upperlayer .so's when placed in FINS_TMP_ROOT/files and referenced at /data/data/com.BU_VT.FINS/files;
// However, the sub so's (common, data_structure) can't be found

void library_dummies(void) {
	switch_dummy();
	interface_dummy();
	arp_dummy();
	ipv4_dummy();
	icmp_dummy();
	tcp_dummy();
	udp_dummy();
	daemon_dummy();
	logger_dummy();
	rtm_dummy();
}

struct fins_library *library_fake_load(uint8_t *lib, uint8_t *base_path) {
	PRINT_IMPORTANT("Entered: lib='%s', base_path='%s'", lib, base_path);

	struct fins_library *library = (struct fins_library *) secure_malloc(sizeof(struct fins_library));
	strcpy((char *) library->name, (char *) lib);
	library->handle = NULL; //RTLD_LAZY | RTLD_GLOBAL?

	uint8_t lib_create[MOD_NAME_SIZE + 7];// +7 for "_create"
	sprintf((char *) lib_create, "%s_create", (char *) lib);

	if (strcmp((char *) lib_create, "switch_create") == 0) {
		library->create = (mod_create_type) switch_create;
	} else if (strcmp((char *) lib_create, "interface_create") == 0) {
		library->create = (mod_create_type) interface_create;
	} else if (strcmp((char *) lib_create, "arp_create") == 0) {
		library->create = (mod_create_type) arp_create;
	} else if (strcmp((char *) lib_create, "ipv4_create") == 0) {
		library->create = (mod_create_type) ipv4_create;
	} else if (strcmp((char *) lib_create, "icmp_create") == 0) {
		library->create = (mod_create_type) icmp_create;
	} else if (strcmp((char *) lib_create, "tcp_create") == 0) {
		library->create = (mod_create_type) tcp_create;
	} else if (strcmp((char *) lib_create, "udp_create") == 0) {
		library->create = (mod_create_type) udp_create;
	} else if (strcmp((char *) lib_create, "daemon_create") == 0) {
		library->create = (mod_create_type) daemon_create;
	} else if (strcmp((char *) lib_create, "logger_create") == 0) {
		library->create = (mod_create_type) logger_create;
	} else if (strcmp((char *) lib_create, "rtm_create") == 0) {
		library->create = (mod_create_type) rtm_create;
	} else {
		PRINT_ERROR("default: unknown library: lib='%s'", lib);
		exit(-1);
	}

	library->num_mods = 0;

	PRINT_IMPORTANT("Exited: lib='%s', base_path='%s', library=%p", lib, base_path, library);
	return library;
}
#endif

void core_dummy(void) {

}

void core_main(uint8_t *envi_name, uint8_t *stack_name) {
	PRINT_IMPORTANT("Core Initiation: Starting ************");

#ifdef BUILD_FOR_ANDROID
	library_dummies();
#endif

	register_to_signal(SIGRTMIN);

	sem_init(&control_serial_sem, 0, 1); //TODO remove after gen_control_serial_num() converted to RNG

	signal(SIGINT, core_termination_handler); //register termination handler

	int status;
	int i, j, k;
	metadata_element *list_elem;
	int list_num;
	metadata_element *elem;
	metadata_element *ip_elem;
	uint32_t ip_num;

	//######################################################################
	overall = (struct fins_overall *) secure_malloc(sizeof(struct fins_overall));
	sem_init(&overall->sem, 0, 1);

	//######################################################################
	overall->envi = (struct envi_record *) secure_malloc(sizeof(struct envi_record));

	PRINT_IMPORTANT("loading environment");
	metadata *meta_envi = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta_envi);

	status = config_read_file(meta_envi, (char *) envi_name);
	if (status == META_FALSE) {
		PRINT_ERROR("file='%s', %s:%d - %s\n", envi_name, config_error_file(meta_envi), config_error_line(meta_envi), config_error_text(meta_envi));
		metadata_destroy(meta_envi);
		PRINT_ERROR("todo error");
		exit(-1);
	}

	//############# if_list
	PRINT_IMPORTANT("interface list");
	overall->envi->if_list = list_create(MAX_INTERFACES);

	list_elem = config_lookup(meta_envi, "environment.interfaces");
	if (list_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}
	list_num = config_setting_length(list_elem);

	int32_t if_index;
	uint8_t *name;
	uint64_t mac;
	uint32_t mode;
	uint32_t mtu;
	uint32_t flags;

	struct if_record *ifr;

	for (i = 0; i < list_num; i++) {
		elem = config_setting_get_elem(list_elem, i);
		if (elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(elem, "index", (int *) &if_index);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_string(elem, "name", (const char **) &name);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int64(elem, "mac", (long long *) &mac);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(elem, "mode", (int *) &mode);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(elem, "mtu", (int *) &mtu);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(elem, "flags", (int *) &flags);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		//#############
		ifr = (struct if_record *) list_find1(overall->envi->if_list, ifr_index_test, &if_index);
		if (ifr == NULL) {
			ifr = (struct if_record *) secure_malloc(sizeof(struct if_record));
			ifr->index = if_index;
			strcpy((char *) ifr->name, (char *) name);
			ifr->mac = mac;

			ifr->mode = (uint8_t) mode;
			ifr->mtu = mtu;
			ifr->flags = flags;

			ifr->addr_list = list_create(MAX_FAMILIES);

			if (list_has_space(overall->envi->if_list)) {
				PRINT_IMPORTANT("Adding interface: ifr=%p, index=%u, name='%s', mac=0x%012llx", ifr, ifr->index, ifr->name, ifr->mac);
				list_append(overall->envi->if_list, ifr);
			} else {
				//TODO error
				PRINT_ERROR("todo error");
				exit(-1);
			}

			if (flags & IFF_LOOPBACK) {
				overall->envi->if_loopback = ifr;
			}
		} else {
			PRINT_ERROR("todo error");
			exit(-1);
		}
	}
	PRINT_IMPORTANT("if_list: list=%p, max=%u, len=%u", overall->envi->if_list, overall->envi->if_list->max, overall->envi->if_list->len);

	//############# if_loopback
	PRINT_IMPORTANT("loopback interface");
	if (overall->envi->if_loopback != NULL) {
		PRINT_IMPORTANT("loopback: name='%s', addr_list->len=%u", overall->envi->if_loopback->name, overall->envi->if_loopback->addr_list->len);
	} else {
		PRINT_WARN("todo error");
	}

	//############# if_main
	PRINT_IMPORTANT("main interface");
	uint32_t if_main;

	status = config_lookup_int(meta_envi, "environment.main_interface", (int *) &if_main);
	if (status == META_FALSE) {
		PRINT_ERROR("todo error");
		exit(-1);
	}

	overall->envi->if_main = (struct if_record *) list_find1(overall->envi->if_list, ifr_index_test, &if_main);
	if (overall->envi->if_main != NULL) {
		PRINT_IMPORTANT("main: name='%s', addr_list->len=%u", overall->envi->if_main->name, overall->envi->if_main->addr_list->len);
	} else {
		PRINT_WARN("todo error");
	}

	//############# addr_list
	PRINT_IMPORTANT("address list");
	//overall->envi->addr_list = list_create(MAX_INTERFACES * MAX_FAMILIES); //TODO use?

	list_elem = config_lookup(meta_envi, "environment.addresses");
	if (list_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}
	list_num = config_setting_length(list_elem);

	uint32_t family; //atm only AF_INET, but eventually also AF_INET6
	uint32_t ip[4]; //SIOCGIFADDR //ip
	uint32_t mask[4]; //SIOCGIFNETMASK //mask
	uint32_t gw[4]; //? //(ip & mask) | 1;
	uint32_t bdc[4]; //SIOCGIFBRDADDR //(ip & mask) | ~mask
	uint32_t dst[4]; //SIOCGIFDSTADDR //dst

	struct addr_record *addr;

	for (i = 0; i < list_num; i++) {
		elem = config_setting_get_elem(list_elem, i);
		if (elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(elem, "if_index", (int *) &if_index);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(elem, "family", (int *) &family);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		ip_elem = config_setting_get_member(elem, "ip");
		if (ip_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}
		ip_num = config_setting_length(ip_elem);

		for (j = 0; j < ip_num; j++) {
			ip[j] = (uint32_t) config_setting_get_int_elem(ip_elem, j);
		}

		ip_elem = config_setting_get_member(elem, "mask");
		if (ip_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}
		ip_num = config_setting_length(ip_elem);

		for (j = 0; j < ip_num; j++) {
			mask[j] = (uint32_t) config_setting_get_int_elem(ip_elem, j);
		}

		ip_elem = config_setting_get_member(elem, "gw");
		if (ip_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}
		ip_num = config_setting_length(ip_elem);

		for (j = 0; j < ip_num; j++) {
			gw[j] = (uint32_t) config_setting_get_int_elem(ip_elem, j);
		}

		ip_elem = config_setting_get_member(elem, "bdc");
		if (ip_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}
		ip_num = config_setting_length(ip_elem);

		for (j = 0; j < ip_num; j++) {
			bdc[j] = (uint32_t) config_setting_get_int_elem(ip_elem, j);
		}

		ip_elem = config_setting_get_member(elem, "dst");
		if (ip_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}
		ip_num = config_setting_length(ip_elem);

		for (j = 0; j < ip_num; j++) {
			dst[j] = (uint32_t) config_setting_get_int_elem(ip_elem, j);
		}

		//############
		ifr = (struct if_record *) list_find1(overall->envi->if_list, ifr_index_test, &if_index);
		if (ifr != NULL) {
			if (ifr->flags & IFF_RUNNING) {
				if (family == AF_INET) {
					addr = (struct addr_record *) list_find(ifr->addr_list, addr_is_v4);
				} else {
					addr = (struct addr_record *) list_find(ifr->addr_list, addr_is_v6);
				}

				if (addr == NULL) {
					addr = (struct addr_record *) secure_malloc(sizeof(struct addr_record));
					addr->if_index = if_index;
					addr->family = AF_INET;

					if (family == AF_INET) {
						addr4_set_ip(&addr->ip, IP4_ADR_P2H(ip[0], ip[1], ip[2],ip[3]));
						addr4_set_ip(&addr->mask, IP4_ADR_P2H(mask[0], mask[1], mask[2],mask[3]));
						addr4_set_ip(&addr->gw, IP4_ADR_P2H(gw[0], gw[1], gw[2], gw[3]));
						addr4_set_ip(&addr->bdc, IP4_ADR_P2H(bdc[0], bdc[1], bdc[2], bdc[3]));
						addr4_set_ip(&addr->dst, IP4_ADR_P2H(dst[0], dst[1], dst[2], dst[3]));
					} else if (family == AF_INET6) {
						//TODO
						//addr_set_addr6(&addr->ip, ip);
						PRINT_WARN("todo");
					} else {
						//TODO error?
						PRINT_ERROR("todo error");
						exit(-1);
					}

					if (list_has_space(ifr->addr_list)) {
						PRINT_IMPORTANT("Adding address: ifr=%p, if_index=%d, family=%u", ifr, addr->if_index, addr->family);
						list_append(ifr->addr_list, addr);
					} else {
						//TODO error
						PRINT_ERROR("todo error");
						exit(-1);
					}
				} else {
					//TODO error
					PRINT_ERROR("todo: replace or add new?");
				}
			} else {
				//TODO error
				PRINT_ERROR("todo: decide just drop or add?");
			}
		} else {
			//TODO error
			PRINT_ERROR("todo error");
			exit(-1);
		}
	}

	//############# route_list
	PRINT_IMPORTANT("route list");
	overall->envi->route_list = list_create(MAX_ROUTES);

	list_elem = config_lookup(meta_envi, "environment.routes");
	if (list_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}
	list_num = config_setting_length(list_elem);

	uint32_t metric; //SIOCGIFMETRIC
	uint32_t timeout;
	//struct timeval route_stamp;

	struct route_record *route;

	for (i = 0; i < list_num; i++) {
		elem = config_setting_get_elem(list_elem, i);
		if (elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(elem, "if_index", (int *) &if_index);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(elem, "family", (int *) &family);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		ip_elem = config_setting_get_member(elem, "dst");
		if (ip_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}
		ip_num = config_setting_length(ip_elem);

		for (j = 0; j < ip_num; j++) {
			dst[j] = (uint32_t) config_setting_get_int_elem(ip_elem, j);
		}

		ip_elem = config_setting_get_member(elem, "mask");
		if (ip_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}
		ip_num = config_setting_length(ip_elem);

		for (j = 0; j < ip_num; j++) {
			mask[j] = (uint32_t) config_setting_get_int_elem(ip_elem, j);
		}

		ip_elem = config_setting_get_member(elem, "gw");
		if (ip_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}
		ip_num = config_setting_length(ip_elem);

		for (j = 0; j < ip_num; j++) {
			gw[j] = (uint32_t) config_setting_get_int_elem(ip_elem, j);
		}

		status = config_setting_lookup_int(elem, "metric", (int *) &metric);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(elem, "timeout", (int *) &timeout);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		//############
		ifr = (struct if_record *) list_find1(overall->envi->if_list, ifr_index_test, &if_index);
		if (ifr != NULL) {
			if (ifr->flags & IFF_RUNNING) {
				route = (struct route_record *) secure_malloc(sizeof(struct route_record));
				route->if_index = if_index;
				route->family = family;

				if (family == AF_INET) {
					addr4_set_ip(&route->dst, IP4_ADR_P2H(dst[0], dst[1], dst[2], dst[3]));
					addr4_set_ip(&route->mask, IP4_ADR_P2H(mask[0], mask[1], mask[2],mask[3]));
					addr4_set_ip(&route->gw, IP4_ADR_P2H(gw[0], gw[1], gw[2], gw[3]));
					//addr4_set_addr(&route->ip, IP4_ADR_P2H(ip[0], ip[1], ip[2],ip[3]));
				} else if (family == AF_INET6) {
					//TODO
					//addr_set_addr6(&route->ip, ip);
				} else {
					//TODO error?
				}

				route->metric = metric;
				route->timeout = timeout;

				if (list_has_space(overall->envi->route_list)) {
					PRINT_IMPORTANT("Adding route: ifr=%p, if_index=%d, family=%u", ifr, route->if_index, route->family);
					list_append(overall->envi->route_list, route);
				} else {
					//TODO error
					PRINT_ERROR("todo error");
					exit(-1);
				}
			} else {
				//TODO error
				PRINT_ERROR("todo: decide just drop or add?");
			}
		}
	}
	PRINT_IMPORTANT("route_list: list=%p, max=%u, len=%u", overall->envi->route_list, overall->envi->route_list->max, overall->envi->route_list->len);
	metadata_destroy(meta_envi);

	//######################################################################
	PRINT_IMPORTANT("loading stack");
	metadata *meta_stack = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta_stack);

	status = config_read_file(meta_stack, (char *) stack_name);
	if (status == META_FALSE) {
		PRINT_ERROR("file='%s', %s:%d - %s\n", stack_name, config_error_file(meta_stack), config_error_line(meta_stack), config_error_text(meta_stack));
		metadata_destroy(meta_stack);
		PRINT_ERROR("todo error");
		exit(-1);
	}

	//############# module_list
	PRINT_IMPORTANT("module list");
	overall->lib_list = list_create(MAX_MODULES);
	memset(overall->modules, 0, MAX_MODULES * sizeof(struct fins_module *));
	overall->admin_list = list_create(MAX_MODULES);
	struct linked_list *mt_list = list_create(MAX_MODULES);

	uint8_t base_path[100];
	memset((char *) base_path, 0, 100);
#ifdef BUILD_FOR_ANDROID
	strcpy((char *) base_path, FINS_TMP_ROOT);
	//strcpy((char *) base_path, ".");
#else
	strcpy((char *) base_path, ".");
#endif

	metadata_element *mods_elem = config_lookup(meta_stack, "stack.modules");
	if (mods_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}
	int mods_num = config_setting_length(mods_elem);

	metadata_element *mod_elem;
	uint32_t mod_id;
	uint8_t *mod_lib;
	uint8_t *mod_name;
	metadata_element *flows_elem;
	uint32_t mod_flows[MAX_MOD_FLOWS];
	uint32_t mod_flows_num;
	metadata_element *mod_params;
	metadata_element *mod_admin;

	struct fins_library *library;
	struct fins_module *module;
	struct fins_module_table *mt;

	for (i = 0; i < mods_num; i++) {
		mod_elem = config_setting_get_elem(mods_elem, i);
		if (mod_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(mod_elem, "id", (int *) &mod_id);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_string(mod_elem, "lib", (const char **) &mod_lib);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_string(mod_elem, "name", (const char **) &mod_name);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		flows_elem = config_setting_get_member(mod_elem, "flows");
		if (flows_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}
		mod_flows_num = config_setting_length(flows_elem);

		for (j = 0; j < mod_flows_num; j++) {
			mod_flows[j] = (uint32_t) config_setting_get_int_elem(flows_elem, j);
		}

		mod_params = config_setting_get_member(mod_elem, "params");
		if (mod_params == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		mod_admin = config_setting_get_member(mod_elem, "admin");
		PRINT_DEBUG("admin=%u", mod_admin != NULL);

		//############
		library = (struct fins_library *) list_find1(overall->lib_list, library_name_test, mod_lib);
		if (library == NULL) {
#ifdef BUILD_FOR_ANDROID
			library = library_fake_load(mod_lib, base_path);
#else
			library = library_load(mod_lib, base_path);
#endif
			if (library == NULL) {
				PRINT_ERROR("Failed in loading library: lib='%s', base_path='%s'", mod_lib, base_path);
				exit(-1);
			}

			if (list_has_space(overall->lib_list)) {
				PRINT_IMPORTANT("Adding library: library=%p, name='%s'", library, library->name);
				list_append(overall->lib_list, library);
			} else {
				PRINT_ERROR("Failed in init sequence, too many libraries: lib_list->len=%u", overall->lib_list->len);
				exit(-1);
			}
		}

		module = library->create(i, mod_id, mod_name);
		if (module == NULL) {
			//TODO error
			PRINT_ERROR("Failed to create module: library=%p, index=%u, id=%u, name='%s'", library, i, mod_id, mod_name);
			exit(-1);
		}
		library->num_mods++;

		//TODO move flow to update? or links here?
		status = module->ops->init(module, mod_params, overall->envi); //TODO merge init into create?
		if (status != 0) {
			overall->modules[i] = module;

			if (module->flows_max < mod_flows_num) {
				PRINT_ERROR("todo error");
				exit(-1);
			}

			mt = (struct fins_module_table *) secure_malloc(sizeof(struct fins_module_table));
			mt->flows_num = mod_flows_num;
			memcpy(mt->flows, mod_flows, mod_flows_num * sizeof(uint32_t));
			list_append(mt_list, mt);

			if (mod_admin != NULL) {
				PRINT_IMPORTANT("Adding admin: module=%p, lib='%s', name='%s'", module, module->lib, module->name);
				list_append(overall->admin_list, module);
			}
		} else {
			PRINT_ERROR("Initialization of module failed: module=%p, lib='%s', name='%s', flows_num=%u, flows=%p, params=%p, envi=%p",
					module, module->lib, module->name, mod_flows_num, mod_flows, mod_params, overall->envi);
			exit(-1);
		}

		//free(mod_lib); //don't free, string from libconfig points to metadata memory
		//free(mod_name);
	}

	//############# admin_list //TODO change to admin_list?
	list_for_each1(overall->admin_list, assign_overall, overall);

	//############# linking_list
	PRINT_IMPORTANT("link list");
	overall->link_list = list_create(MAX_TABLE_LINKS);

	metadata_element *links_elem = config_lookup(meta_stack, "stack.links");
	if (links_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}
	int links_num = config_setting_length(links_elem);

	metadata_element *link_elem;
	uint32_t link_id;
	uint32_t link_src;
	metadata_element *dsts_elem;
	uint32_t link_dsts[MAX_MODULES];
	int link_dsts_num;

	struct link_record *link;

	for (i = 0; i < links_num; i++) {
		link_elem = config_setting_get_elem(links_elem, i);
		if (link_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(link_elem, "id", (int *) &link_id);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(link_elem, "src", (int *) &link_src);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		dsts_elem = config_setting_get_member(link_elem, "dsts");
		if (dsts_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}
		link_dsts_num = config_setting_length(dsts_elem);

		for (j = 0; j < link_dsts_num; j++) {
			link_dsts[j] = (uint32_t) config_setting_get_int_elem(dsts_elem, j);
		}

		//############
		link = (struct link_record *) secure_malloc(sizeof(struct link_record));
		link->id = link_id;

		//module = (struct fins_module *) list_find1(overall->envi->module_list, mod_id_test, &link_src);
		link->src_index = -1;
		for (j = 0; j < MAX_MODULES; j++) {
			if (overall->modules[j] != NULL && overall->modules[j]->id == link_src) {
				link->src_index = overall->modules[j]->index;
			}
		}
		if (link->src_index == -1) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		link->dsts_num = link_dsts_num;
		for (j = 0; j < link_dsts_num; j++) {
			//module = (struct fins_module *) list_find1(overall->envi->module_list, mod_id_test, &link_dsts[j]);
			link->dsts_index[j] = -1;
			for (k = 0; k < MAX_MODULES; k++) {
				if (overall->modules[k] != NULL && overall->modules[k]->id == link_dsts[j]) {
					link->dsts_index[j] = overall->modules[k]->index;
				}
			}
			if (link->dsts_index[j] == (uint32_t) -1) {
				PRINT_ERROR("todo error");
				exit(-1);
			}
		}

		if (list_has_space(overall->link_list)) {
			PRINT_IMPORTANT("Adding link: link=%p, id=%u, src_index=%u, dsts_num=%u", link, link->id, link->src_index, link->dsts_num);
			list_append(overall->link_list, link);
		} else {
			//TODO error
			PRINT_ERROR("todo error");
			exit(-1);
		}
	}
	metadata_destroy(meta_stack);

	//######################################################################
	PRINT_IMPORTANT("update modules");
	//send out subset of linking table to each module as update
	//TODO table subset update

	metadata *meta_update;
	struct finsFrame *ff_update;

	for (i = 0; i < MAX_MODULES; i++) {
		if (overall->modules[i] != NULL) {
			mt = (struct fins_module_table *) list_remove_front(mt_list);
			mt->link_list = list_filter1(overall->link_list, link_involved_test, &overall->modules[i]->index, link_clone); //TODO is mem leak
			PRINT_IMPORTANT("subset: i=%d, link_list=%p, len=%d", i, mt->link_list, mt->link_list->len);

			meta_update = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(meta_update);

			ff_update = (struct finsFrame*) secure_malloc(sizeof(struct finsFrame));
			ff_update->dataOrCtrl = FF_CONTROL;
			ff_update->destinationID = i;
			ff_update->metaData = meta_update;

			ff_update->ctrlFrame.sender_id = 0;
			ff_update->ctrlFrame.serial_num = gen_control_serial_num();
			ff_update->ctrlFrame.opcode = CTRL_SET_PARAM;
			ff_update->ctrlFrame.param_id = MOD_SET_PARAM_DUAL;

			ff_update->ctrlFrame.data_len = sizeof(struct fins_module_table);
			ff_update->ctrlFrame.data = (uint8_t *) mt;

			module_to_switch(overall->modules[0], ff_update);
		}
	}
	list_free(mt_list, free);

	//############ say by this point envi var completely init'd
	//assumed always connect/init to switch first

	pthread_attr_t attr;
	pthread_attr_init(&attr);

	PRINT_IMPORTANT("modules: run");

	for (i = 0; i < MAX_MODULES; i++) {
		if (overall->modules[i] != NULL) {
			overall->modules[i]->ops->run(overall->modules[i], &attr);
		}
	}

	PRINT_IMPORTANT("Core Initiation: Finished ************");
}

void core_termination_handler(int sig) {
	PRINT_IMPORTANT("**********Terminating *******");

	int i;

	//shutdown all module threads in backwards order of startup
	PRINT_IMPORTANT("modules: shutdown");
	for (i = MAX_MODULES - 1; i >= 0; i--) {
		if (overall->modules[i] != NULL) {
			overall->modules[i]->ops->shutdown(overall->modules[i]);
		}
	}

	//have each module free data & que/sem //TODO finish each of these
	PRINT_IMPORTANT("modules: release");
	for (i = MAX_MODULES - 1; i >= 0; i--) {
		if (overall->modules[i] != NULL) {
			overall->modules[i]->ops->release(overall->modules[i]);
		}
	}

	PRINT_IMPORTANT("admin: free");
	list_free(overall->admin_list, nop_func);

	PRINT_IMPORTANT("libraries: close");
	list_free(overall->lib_list, library_free);

	PRINT_IMPORTANT("Freeing links");
	list_free(overall->link_list, free);

	PRINT_IMPORTANT("Freeing environment");
	list_free(overall->envi->if_list, ifr_free);
	list_free(overall->envi->route_list, free);
	free(overall->envi);

	free(overall);
	sem_destroy(&control_serial_sem);

	PRINT_IMPORTANT("FIN");
	exit(-1);
}

void core_tests(void) {
	while (1) {
		PRINT_IMPORTANT("waiting...");
		//sleep(10);
		//char recv_data[4000];
		//gets(recv_data);
		fgetc(stdin); //wait until user enters
		PRINT_IMPORTANT("active");

		if (0) {
			metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(meta);

			uint32_t host_ip = IP4_ADR_P2H(192,168,1,8);
			uint32_t host_port = 55454;
			uint32_t dst_ip = IP4_ADR_P2H(192,168,1,3);
			uint32_t dst_port = 44444;
			uint32_t ttl = 64;
			uint32_t tos = 64;

			secure_metadata_writeToElement(meta, "send_src_ip", &host_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "send_src_port", &host_port, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "send_dst_ip", &dst_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "send_dst_port", &dst_port, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "send_ttl", &ttl, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "send_tos", &tos, META_TYPE_INT32);

			struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
			ff->dataOrCtrl = FF_DATA;
			ff->destinationID = 1;
			ff->metaData = meta;

			ff->dataFrame.directionFlag = DIR_UP;
			ff->dataFrame.pduLength = 10;
			ff->dataFrame.pdu = (uint8_t *) secure_malloc(10);

			PRINT_IMPORTANT("sending: ff=%p, meta=%p, src='%s' to dst='%s'", ff, meta, overall->modules[0]->name, overall->modules[1]->name);
			module_to_switch(overall->modules[0], ff);
		}

		if (0) {
			PRINT_DEBUG("Sending ARP req");

			metadata *meta_req = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(meta_req);

			uint32_t dst_ip = IP4_ADR_P2H(192, 168, 1, 1);
			//uint32_t dst_ip = IP4_ADR_P2H(172, 31, 54, 169);
			uint32_t src_ip = IP4_ADR_P2H(192, 168, 1, 20);
			//uint32_t src_ip = IP4_ADR_P2H(172, 31, 50, 160);

			secure_metadata_writeToElement(meta_req, "dst_ip", &dst_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(meta_req, "src_ip", &src_ip, META_TYPE_INT32);

			struct finsFrame *ff_req = (struct finsFrame*) secure_malloc(sizeof(struct finsFrame));
			ff_req->dataOrCtrl = FF_CONTROL;
			ff_req->destinationID = 1; //arp
			ff_req->metaData = meta_req;

			ff_req->ctrlFrame.sender_id = 4; //ipv4
			ff_req->ctrlFrame.serial_num = gen_control_serial_num();
			ff_req->ctrlFrame.opcode = CTRL_EXEC;
			ff_req->ctrlFrame.param_id = 0; //EXEC_ARP_GET_ADDR;

			ff_req->ctrlFrame.data_len = 0;
			ff_req->ctrlFrame.data = NULL;

			PRINT_IMPORTANT("sending: ff=%p, meta=%p, src='%s' to dst='%s'", ff_req, meta_req, overall->modules[0]->name, overall->modules[1]->name);
			module_to_switch(overall->modules[0], ff_req);
		}

		if (0) {
			PRINT_DEBUG("Sending data");

			metadata *meta_req = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(meta_req);

			uint32_t ether_type = 0x0800; //ipv4
			int32_t if_index = 3; //wlan0
			uint32_t src_ip = IP4_ADR_P2H(192, 168, 1, 5); //wlan0
			uint32_t dst_ip = IP4_ADR_P2H(192, 168, 1, 1); //gw

			secure_metadata_writeToElement(meta_req, "send_ether_type", &ether_type, META_TYPE_INT32);
			secure_metadata_writeToElement(meta_req, "send_if_index", &if_index, META_TYPE_INT32);
			secure_metadata_writeToElement(meta_req, "send_src_ipv4", &src_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(meta_req, "send_dst_ipv4", &dst_ip, META_TYPE_INT32);

			struct finsFrame *ff = (struct finsFrame*) secure_malloc(sizeof(struct finsFrame));
			ff->dataOrCtrl = FF_DATA;
			ff->destinationID = 1; //arp
			ff->metaData = meta_req;

			ff->dataFrame.directionFlag = DIR_DOWN;
			ff->dataFrame.pduLength = 100;
			ff->dataFrame.pdu = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
			memset(ff->dataFrame.pdu, 59, ff->dataFrame.pduLength);

			PRINT_IMPORTANT("sending: ff=%p, meta=%p, src='%s' to dst='%s'", ff, meta_req, overall->modules[0]->name, overall->modules[1]->name);
			module_to_switch(overall->modules[0], ff);
		}

		if (0) {
			PRINT_DEBUG("Sending data");

			metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(meta);

			uint32_t src_ip = IP4_ADR_P2H(192, 168, 1, 4); //wlan0
			uint32_t src_port = 6666;
			uint32_t dst_ip = IP4_ADR_P2H(192, 168, 1, 1); //gw
			uint32_t dst_port = 5555;

			secure_metadata_writeToElement(meta, "send_src_ipv4", &src_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "send_src_port", &src_port, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "send_dst_ipv4", &dst_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "send_dst_port", &dst_port, META_TYPE_INT32);

			uint32_t dst_index = 8;
			struct finsFrame *ff = (struct finsFrame*) secure_malloc(sizeof(struct finsFrame));
			ff->dataOrCtrl = FF_DATA;
			ff->destinationID = dst_index; //arp
			ff->metaData = meta;

			ff->dataFrame.directionFlag = DIR_DOWN;
			ff->dataFrame.pduLength = 10;
			ff->dataFrame.pdu = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
			memset(ff->dataFrame.pdu, 65, ff->dataFrame.pduLength);

			PRINT_IMPORTANT("sending: ff=%p, meta=%p, src='%s' to dst='%s'", ff, meta, overall->modules[0]->name, overall->modules[dst_index]->name);
			module_to_switch(overall->modules[0], ff);
		}

		if (0) {
			PRINT_DEBUG("Sending data");

			metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(meta);

			uint32_t family = AF_INET;
			uint32_t src_ip = IP4_ADR_P2H(192, 168, 1, 15); //wlan0
			uint32_t dst_ip = IP4_ADR_P2H(172, 168, 1, 1); //gw

			secure_metadata_writeToElement(meta, "send_family", &family, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "send_src_ipv4", &src_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "send_dst_ipv4", &dst_ip, META_TYPE_INT32);

			uint32_t dst_index = 4;
			struct finsFrame *ff = (struct finsFrame*) secure_malloc(sizeof(struct finsFrame));
			ff->dataOrCtrl = FF_DATA;
			ff->destinationID = dst_index;
			ff->metaData = meta;

			ff->dataFrame.directionFlag = DIR_DOWN;
			ff->dataFrame.pduLength = 10;
			ff->dataFrame.pdu = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
			memset(ff->dataFrame.pdu, 65, ff->dataFrame.pduLength);

			PRINT_IMPORTANT("sending: ff=%p, meta=%p, src='%s' to dst='%s'", ff, meta, overall->modules[0]->name, overall->modules[dst_index]->name);
			module_to_switch(overall->modules[0], ff);
		}
		break;
	}
}

//TODO replace this option system with getopt, can see in SuperSU code
//#include <getopt.h>
int main(int argc, char *argv[]) {
	PRINT_IMPORTANT("argc=%u", argc);

	int i;
#ifdef BUILD_FOR_ANDROID
	for (i = 0; i < 3; i++) {
		PRINT_IMPORTANT("argv[%d]='%s'", i, argv[i]);
	}

	core_main((uint8_t *)("envi.cfg"), (uint8_t *)("stack.cfg"));
#else
	for (i = 0; i < argc; i++) {
		PRINT_IMPORTANT("argv[%d]='%s'", i, argv[i]);
	}

	uint8_t envi_default = 1;
	uint8_t envi_name[FILE_NAME_SIZE];
	memset((char *) envi_name, 0, FILE_NAME_SIZE);

	uint8_t stack_default = 1;
	uint8_t stack_name[FILE_NAME_SIZE];
	memset((char *) stack_name, 0, FILE_NAME_SIZE);

	uint8_t capturer_default = 1;
	uint8_t capturer_name[FILE_NAME_SIZE];
	memset((char *) capturer_name, 0, FILE_NAME_SIZE);

	uint8_t core_default = 1;
	uint8_t core_name[FILE_NAME_SIZE];
	memset((char *) core_name, 0, FILE_NAME_SIZE);

	int j;
	uint32_t len;
	uint8_t ch;
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-' || argv[i][0] == '\\') {
			len = strlen(argv[i]);

			for (j = 1; j < len; j++) {
				ch = (uint8_t) argv[i][j];

				if (ch == 'e' || ch == 'E') {
					if (j + 1 == len) {
						if (i + 1 < argc) {
							strcpy((char *) envi_name, argv[i + 1]);
							printf("Using environment configuration: '%s'\n", envi_name);
							envi_default = 0;
							i += 1;
						} else {
							printf("Incorrect format. Usage: -e <file>\n");
							exit(-1);
						}
					} else {
						strcpy((char *) envi_name, &argv[i][j + 1]);
						printf("Using environment configuration: '%s'\n", envi_name);
						envi_default = 0;
						j = len;
					}
				} else if (ch == 's' || ch == 'S') {
					if (j + 1 == len) {
						if (i + 1 < argc) {
							strcpy((char *) stack_name, argv[i + 1]);
							printf("Using stack configuration: '%s'\n", stack_name);
							stack_default = 0;
							i += 1;
						} else {
							printf("Incorrect format. Usage: -s <file>\n");
							exit(-1);
						}
					} else {
						strcpy((char *) stack_name, &argv[i][j + 1]);
						printf("Using stack configuration: '%s'\n", stack_name);
						stack_default = 0;
						j = len;
					}
				} else if (ch == 'c' || ch == 'C') {
					if (j + 1 == len) {
						if (i + 1 < argc) {
							strcpy((char *) capturer_name, argv[i + 1]);
							printf("Capturer output to: '%s'\n", capturer_name);
							capturer_default = 0;
							i += 1;
						} else {
							printf("Incorrect format. Usage: -c <file>\n");
							exit(-1);
						}
					} else {
						strcpy((char *) capturer_name, &argv[i][j + 1]);
						printf("Capturer output to: '%s'\n", capturer_name);
						capturer_default = 0;
						j = len;
					}
				} else if (ch == 'o' || ch == 'O') {
					if (j + 1 == len) {
						if (i + 1 < argc) {
							strcpy((char *) core_name, argv[i + 1]);
							printf("Core output to: '%s'\n", core_name);
							core_default = 0;
							i += 1;
						} else {
							printf("Incorrect format. Usage: -o <file>\n");
							exit(-1);
						}
					} else {
						strcpy((char *) core_name, &argv[i][j + 1]);
						printf("Core output to: '%s'\n", core_name);
						core_default = 0;
						j = len;
					}
				} else if (ch == 'x' || ch == 'X') {
					printf("option x\n");
				} else {
					printf("Illegal option code = '%c'\n", ch);
					exit(-1);
				}
			}
		} else {
			printf("Illegal text: '%s'.\nUsage: core [-e <envi cfg>][-s <stack cfg>][-c <capturer output>][-o <core output>]\n", argv[i]);
			exit(-1);
		}
	}

	if (envi_default == 1) {
		strcpy((char *) envi_name, (char *) DEFAULT_ENVI_FILE);
		printf("Using default environment configuration: '%s'\n", envi_name);
	}
	if (stack_default == 1) {
		strcpy((char *) stack_name, (char *) DEFAULT_STACK_FILE);
		printf("Using default stack configuration: '%s'\n", stack_name);
	}
	if (capturer_default == 1) {
		strcpy((char *) capturer_name, (char *) DEFAULT_CAPTURER_FILE);
		//printf("Default: capturer output to: '%s'\n", capturer_name);
	}
	if (core_default == 1) {
		strcpy((char *) core_name, (char *) DEFAULT_CORE_FILE);
		//printf("Default: core output to: '%s'\n", core_name);
	}

	core_main(envi_name, stack_name);
#endif

	//core_tests(); //For random testing purposes

	PRINT_IMPORTANT("while (1) looping...");
	while (1) {
		sleep(1000000);
	}

	//############ terminating
	//core_termination_handler(0);

	return 0;
}
