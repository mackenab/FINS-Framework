/*
 * 		@file socketgeni.c
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
#include "core.h"

#include <signal.h>

#include <finsdebug.h>
//#include <finstypes.h>
#include <finstime.h>
//#include <metadata.h>
//#include <finsqueue.h>

#include <switch.h>
#include <dlfcn.h>
//#include <daemon.h>
//#include <interface.h>
//#include <ipv4.h>
//#include <arp.h>
//#include <udp.h>
//#include <tcp.h>
//#include <icmp.h>
//#include <rtm.h>
//#include <logger.h>

extern sem_t control_serial_sem; //TODO remove & change gen process to RNG

struct fins_module *switch_module; //TODO if move fins_modules entirely to switch, use this to get to them, remove otherwise

/**
 * @brief read the core parameters from the configuraions file called fins.cfg
 * @param
 * @return nothing
 */
int read_configurations() {
	//const char *str;

	//config_t cfg;
	//config_init(&cfg);

	metadata *meta = (metadata *) secure_malloc(sizeof(metadata)); //equivalent
	metadata_create(meta);

	/* Read the file. If there is an error, report it and exit. */
	if (!config_read_file(meta, "test.cfg")) {
		PRINT_ERROR("%s:%d - %s\n", config_error_file(meta), config_error_line(meta), config_error_text(meta));
		config_destroy(meta);
		return EXIT_FAILURE;
	}

	metadata_print(meta);

	//int config_setting_lookup_int64 (const config_setting_t * setting, const char * name, long long * value)
	//int config_lookup_int64 (const config_t * config, const char * path, long long * value)
	/*
	 int var1;
	 double var2;
	 const char *var3;

	 //config_lookup_int64
	 if (config.lookupValue("values.var1", var1) && config.lookupValue("values.var2", var2) && config.lookupValue("values.var3", var3)) {
	 // use var1, var2, var3
	 } else {
	 // error handling here
	 }

	 long width = config.lookup("application.window.size.w");

	 bool splashScreen = config.lookup("application.splash_screen");

	 std::string title = config.lookup("application.window.title");
	 title = (const char *)config.lookup("application.window.title");
	 */

	config_destroy(meta);
	return EXIT_SUCCESS;
}

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

void core_termination_handler(int sig) {
	PRINT_IMPORTANT("**********Terminating *******");

	//shutdown all module threads in backwards order of startup
	//logger_shutdown();
	//rtm_shutdown();

	//udp_shutdown();
	//tcp_shutdown();
	//icmp_shutdown();
	//ipv4_shutdown();
	//arp_shutdown();

	//interface_shutdown(); //TODO finish
	//daemon_shutdown(); //TODO finish
	//switch_shutdown(); //TODO finish

	//have each module free data & que/sem //TODO finish each of these
	//logger_release();
	//rtm_release();

	//udp_release();
	//tcp_release();
	//icmp_release();
	//ipv4_release();
	//arp_release();

	//interface_release();
	//daemon_release();
	//switch_release();

	sem_destroy(&control_serial_sem);

	PRINT_IMPORTANT("FIN");
	exit(-1);
}

void core_dummy(void) {

}

void set_addr4(struct sockaddr_storage *addr, uint32_t val) {
	struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
	memset(addr4, 0, sizeof(struct sockaddr_in));
	addr4->sin_family = AF_INET;
	addr4->sin_addr.s_addr = val;
}

int addr_is_addr4(struct addr_record *addr) {
	return addr->family == AF_INET;
}

void set_addr6(struct sockaddr_storage *addr, uint32_t val) {
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
	memset(addr6, 0, sizeof(struct sockaddr_in6));
	addr6->sin6_family = AF_INET6;
	//addr6->sin6_addr.s_addr = val;
}

int addr_is_addr6(struct addr_record *addr) {
	return addr->family == AF_INET6;
}

int ifr_index_test(struct if_record *ifr, uint32_t *if_index) {
	return ifr->index == *if_index;
}

int lib_name_test(struct fins_library *lib, uint8_t *if_name) {
	return strcmp((char *) lib->name, (char *) if_name) == 0;
}

int mod_id_test(struct fins_module *mod, uint32_t *mod_id) {
	return mod->id == *mod_id;
}

int link_involved_test(struct link_record *link, uint32_t *index) {
	if (link->src_index == *index) {
		return 1;
	} else {
		int i;
		for (i = 0; i < link->dsts_num; i++) {
			if (link->dsts_index[i] == *index) {
				return 1;
			}
		}
		return 0;
	}
}

int link_id_test(struct link_record *link, uint32_t *id) {
	return link->id == *id;
}

struct link_record *link_copy(struct link_record *link) {
	struct link_record *copy = (struct link_record *) secure_malloc(sizeof(struct link_record));
	memcpy(copy, link, sizeof(struct link_record)); //would need to change if linked_list
	return copy;
}

struct fins_library *library_load(uint8_t *lib, uint8_t *base_path) {
	PRINT_IMPORTANT("Entered: lib='%s', base_path='%s'", lib, base_path);

	struct fins_library *library = (struct fins_library *) secure_malloc(sizeof(struct fins_library));
	strcpy((char *) library->name, (char *) lib);

	uint8_t *error;
	uint8_t lib_path[MAX_BASE_PATH + MOD_NAME_SIZE + 7]; // +7 for "/lib<>.so"
	sprintf((char *) lib_path, "%s/lib%s.so", (char *) base_path, (char *) lib);
	library->handle = dlopen((char *) lib_path, RTLD_NOW); //RTLD_LAZY | RTLD_GLOBAL?
	if (library->handle == NULL) {
		fputs(dlerror(), stderr);
		PRINT_IMPORTANT("Entered: lib='%s', base_path='%s', library=%p", lib, base_path, NULL);
		return NULL;
	}

	uint8_t lib_create[MOD_NAME_SIZE + 7]; // +7 for "_create"
	sprintf((char *) lib_create, "%s_create", (char *) lib);
	library->create = (mod_create_type) dlsym(library->handle, (char *) lib_create);
	if ((error = (uint8_t *) dlerror()) != NULL) {
		fputs((char *) error, stderr);
		PRINT_IMPORTANT("Entered: lib='%s', base_path='%s', library=%p", lib, base_path, NULL);
		return NULL;
	}

	library->num_mods = 0;

	PRINT_IMPORTANT("Entered: lib='%s', base_path='%s', library=%p", lib, base_path, library);
	return library;
}
//################################ move above code to finsmodule.h or maybe finstypes.h

void core_main() {
	PRINT_IMPORTANT("Entered");

	register_to_signal(SIGRTMIN);

	sem_init(&control_serial_sem, 0, 1); //TODO remove after gen_control_serial_num() converted to RNG

	signal(SIGINT, core_termination_handler); //register termination handler

	//######################################################################
	int status;
	int i, j, k;

	//load envi.cfg file

	//#############
	//new module initialization prototype
	struct envi_record *envi = (struct envi_record *) secure_malloc(sizeof(struct envi_record));
	envi->any_ip_addr = IP4_ADR_P2H(0,0,0,0); //TODO change to addr_in?

	//############# if_list
	envi->if_list = list_create(MAX_INTERFACES);

	uint32_t if_index; //assigned by core?
	uint8_t if_name[IFNAMSIZ];
	uint64_t if_mac;
	uint16_t if_type;
	uint8_t if_status;
	uint32_t if_mtu;
	uint32_t if_flags;
	//#############
	struct if_record *ifr;

	if (1) { //TODO change to for loop from read data
		if_index = 1;
		strcpy((char *) if_name, "lo");
		if_mac = 0;
		if_type = 1;
		if_status = 1;
		if_mtu = 16436;
		if_flags = IFF_LOOPBACK | IFF_UP | IFF_RUNNING;
		//#############
		ifr = (struct if_record *) list_find1(envi->if_list, ifr_index_test, &if_index);
		if (ifr == NULL) {
			ifr = (struct if_record *) secure_malloc(sizeof(struct if_record));
			ifr->index = if_index;
			strcpy((char *) ifr->name, (char *) if_name);
			ifr->mac = if_mac;
			ifr->type = if_type;

			ifr->status = if_status;
			ifr->mtu = if_mtu;
			ifr->flags = if_flags;

			ifr->addr_list = list_create(MAX_FAMILIES);

			if (list_has_space(envi->if_list)) {
				list_append(envi->if_list, ifr);
			} else {
				//TODO error
			}

			if (if_flags & IFF_LOOPBACK) {
				envi->if_loopback = ifr;
			}
		} else {
			//TODO error
		}
	}

	if (1) {
		if_index = 2;
		strcpy((char *) if_name, "eth0");
		if_mac = 0;
		if_type = 1;
		if_status = 1;
		if_mtu = 1500;
		if_flags = IFF_BROADCAST | IFF_MULTICAST | IFF_UP; //IFF_RUNNING | //removed for wlan0
		//#############
		ifr = (struct if_record *) list_find1(envi->if_list, ifr_index_test, &if_index);
		if (ifr == NULL) {
			ifr = (struct if_record *) secure_malloc(sizeof(struct if_record));
			ifr->index = if_index;
			strcpy((char *) ifr->name, (char *) if_name);
			ifr->mac = if_mac;
			ifr->type = if_type;

			ifr->status = if_status;
			ifr->mtu = if_mtu;
			ifr->flags = if_flags;

			ifr->addr_list = list_create(MAX_FAMILIES);

			if (list_has_space(envi->if_list)) {
				list_append(envi->if_list, ifr);
			} else {
				//TODO error
			}

			if (if_flags & IFF_LOOPBACK) {
				envi->if_loopback = ifr;
			}
		} else {
			//TODO error
		}
	}

	if (1) {
		if_index = 3;
		strcpy((char *) if_name, "wlan0");
		if_mac = 0;
		if_type = 2;
		if_status = 1;
		if_mtu = 1500;
		if_flags = IFF_BROADCAST | IFF_MULTICAST | IFF_UP | IFF_RUNNING;
		//#############
		ifr = (struct if_record *) list_find1(envi->if_list, ifr_index_test, &if_index);
		if (ifr == NULL) {
			ifr = (struct if_record *) secure_malloc(sizeof(struct if_record));
			ifr->index = if_index;
			strcpy((char *) ifr->name, (char *) if_name);
			ifr->mac = if_mac;
			ifr->type = if_type;

			ifr->status = if_status;
			ifr->mtu = if_mtu;
			ifr->flags = if_flags;

			ifr->addr_list = list_create(MAX_FAMILIES);

			if (list_has_space(envi->if_list)) {
				list_append(envi->if_list, ifr);
			} else {
				//TODO error
			}

			if (if_flags & IFF_LOOPBACK) {
				envi->if_loopback = ifr;
			}
		} else {
			//TODO error
		}
	}

	//TODO change these to be dynamic, not static
	envi->if_main = (struct if_record *) list_look(envi->if_list, 2);

	//############# addr_list
	//envi->addr_list = list_create(MAX_INTERFACES * MAX_FAMILIES); //TODO use?

	uint32_t addr_if_index; //the index parameter of the interface in if_list, most likely its order index as well
	uint32_t addr_family; //atm only AF_INET, but eventually also AF_INET6
	uint32_t addr_ip; //SIOCGIFADDR //addr_ip
	uint32_t addr_mask; //SIOCGIFNETMASK //addr_mask
	uint32_t addr_gw; //? //(addr_ip & addr_mask)|1;
	uint32_t addr_bdc; //SIOCGIFBRDADDR //(addr_ip & addr_mask)|~addr_mask
	uint32_t addr_dst; //SIOCGIFDSTADDR //addr_dst
	//#############
	struct addr_record *addr;

	if (1) {
		addr_if_index = 1;
		addr_family = AF_INET;
		addr_ip = IP4_ADR_P2H(127,0,0,1);
		addr_mask = IP4_ADR_P2H(255,0,0,0);
		addr_gw = IP4_ADR_P2H(127,0,0,1); //?
		addr_bdc = IP4_ADR_P2H(127,255,255,255);
		addr_dst = IP4_ADR_P2H(127,0,0,1); //?
		//############
		ifr = (struct if_record *) list_find1(envi->if_list, ifr_index_test, &if_index);
		if (ifr) {
			if (ifr->flags & IFF_RUNNING) {
				if (addr_family == AF_INET) {
					addr = (struct addr_record *) list_find(ifr->addr_list, addr_is_addr4);
				} else {
					addr = (struct addr_record *) list_find(ifr->addr_list, addr_is_addr6);
				}

				if (addr == NULL) {
					addr = (struct addr_record *) secure_malloc(sizeof(struct addr_record));
					addr->if_index = addr_if_index;
					addr->family = AF_INET;

					if (addr_family == AF_INET) {
						set_addr4(&addr->ip, addr_ip);
						set_addr4(&addr->mask, addr_mask);
						set_addr4(&addr->gw, addr_gw);
						set_addr4(&addr->bdc, addr_bdc);
						set_addr4(&addr->dst, addr_dst);
					} else if (addr_family == AF_INET6) {
						//TODO
						set_addr6(&addr->ip, addr_ip);
					} else {
						//TODO error?
					}

					if (list_has_space(ifr->addr_list)) {
						list_append(ifr->addr_list, addr);
					} else {
						//TODO error
					}
				} else {
					//TODO error
				}
			} else {
				//TODO error
			}
		} else {
			//TODO error
		}
	}

	if (1) {
		addr_if_index = 2;
		addr_family = AF_INET;
		addr_ip = IP4_ADR_P2H(192,168,1,3);
		addr_mask = IP4_ADR_P2H(255,255,255,0);
		addr_gw = IP4_ADR_P2H(192,168,1,1); //???
		addr_bdc = IP4_ADR_P2H(192,168,1,255);
		addr_dst = envi->any_ip_addr; //???
		//############
		ifr = (struct if_record *) list_find1(envi->if_list, ifr_index_test, &if_index);
		if (ifr) {
			if (ifr->flags & IFF_RUNNING) {
				if (addr_family == AF_INET) {
					addr = (struct addr_record *) list_find(ifr->addr_list, addr_is_addr4);
				} else {
					addr = (struct addr_record *) list_find(ifr->addr_list, addr_is_addr6);
				}

				if (addr == NULL) {
					addr = (struct addr_record *) secure_malloc(sizeof(struct addr_record));
					addr->if_index = addr_if_index;
					addr->family = AF_INET;

					if (addr_family == AF_INET) {
						set_addr4(&addr->ip, addr_ip);
						set_addr4(&addr->mask, addr_mask);
						set_addr4(&addr->gw, addr_gw);
						set_addr4(&addr->bdc, addr_bdc);
						set_addr4(&addr->dst, addr_dst);
					} else if (addr_family == AF_INET6) {
						//TODO
						set_addr6(&addr->ip, addr_ip);
					} else {
						//TODO error?
					}

					if (list_has_space(ifr->addr_list)) {
						list_append(ifr->addr_list, addr);
					} else {
						//TODO error
					}
				} else {
					//TODO error
				}
			} else {
				//TODO error
			}
		} else {
			//TODO error
		}
	}

	if (1) {
		addr_if_index = 3;
		addr_family = AF_INET;
		addr_ip = IP4_ADR_P2H(192,168,1,5);
		addr_mask = IP4_ADR_P2H(255,255,255,0);
		addr_gw = IP4_ADR_P2H(192,168,1,1); //???
		addr_bdc = IP4_ADR_P2H(192,168,1,255);
		addr_dst = envi->any_ip_addr; //???
		//############
		ifr = (struct if_record *) list_find1(envi->if_list, ifr_index_test, &if_index);
		if (ifr) {
			if (ifr->flags & IFF_RUNNING) {
				if (addr_family == AF_INET) {
					addr = (struct addr_record *) list_find(ifr->addr_list, addr_is_addr4);
				} else {
					addr = (struct addr_record *) list_find(ifr->addr_list, addr_is_addr6);
				}

				if (addr == NULL) {
					addr = (struct addr_record *) secure_malloc(sizeof(struct addr_record));
					addr->if_index = addr_if_index;
					addr->family = AF_INET;

					if (addr_family == AF_INET) {
						set_addr4(&addr->ip, addr_ip);
						set_addr4(&addr->mask, addr_mask);
						set_addr4(&addr->gw, addr_gw);
						set_addr4(&addr->bdc, addr_bdc);
						set_addr4(&addr->dst, addr_dst);
					} else if (addr_family == AF_INET6) {
						//TODO
						set_addr6(&addr->ip, addr_ip);
					} else {
						//TODO error?
					}

					if (list_has_space(ifr->addr_list)) {
						list_append(ifr->addr_list, addr);
					} else {
						//TODO error
					}
				} else {
					//TODO error
				}
			} else {
				//TODO error
			}
		} else {
			//TODO error
		}
	}

	//############# route_list
	envi->route_list = list_create(MAX_ADDRESSES);

	uint32_t route_if_index;
	uint32_t route_family;
	uint32_t route_dst; //SIOCGIFDSTADDR //addr_dst
	uint32_t route_mask; //SIOCGIFNETMASK //addr_mask
	uint32_t route_gw; //? //(addr_ip & addr_mask)|1; //not sure about what gw is exactly
	//uint32_t route_ip; //SIOCGIFADDR //addr_ip //change to be dynamic from if_list?
	uint32_t route_metric; //SIOCGIFMETRIC
	uint32_t route_timeout;
	//struct timeval route_stamp;
	//#############
	struct route_record *route;

	if (1) {
		route_if_index = 3;
		route_family = AF_INET;
		route_dst = IP4_ADR_P2H(0,0,0,0);
		route_mask = IP4_ADR_P2H(0,0,0,0);
		route_gw = IP4_ADR_P2H(192,168,1,1); //???
		//route_ip = IP4_ADR_P2H(192,168,1,5);
		route_metric = 10;
		route_timeout = 0;
		//############
		ifr = (struct if_record *) list_find1(envi->if_list, ifr_index_test, &if_index);
		if (ifr) {
			if (ifr->flags & IFF_RUNNING) {
				//TODO remove copies?

				route = (struct route_record *) secure_malloc(sizeof(struct route_record));
				route->if_index = route_if_index;
				route->family = route_family;

				if (route_family == AF_INET) {
					set_addr4(&route->dst, route_dst);
					set_addr4(&route->mask, route_mask);
					set_addr4(&route->gw, route_gw);
					//set_addr4(&route->ip, route_ip);
				} else if (route_family == AF_INET6) {
					//TODO
					//set_addr6(&route->ip, route_ip);
				} else {
					//TODO error?
				}

				if (list_has_space(envi->route_list)) {
					list_append(envi->route_list, route);
				} else {
					//TODO error
				}
			} else {
				//TODO error
			}
		}
	}

	if (1) {
		route_if_index = 1;
		route_family = AF_INET;
		route_dst = IP4_ADR_P2H(127,0,0,0);
		route_mask = IP4_ADR_P2H(255,0,0,0);
		route_gw = IP4_ADR_P2H(127,0,0,1);
		//route_ip = IP4_ADR_P2H(127,0,0,1);
		route_metric = 1;
		route_timeout = 0;
		//############
		ifr = (struct if_record *) list_find1(envi->if_list, ifr_index_test, &if_index);
		if (ifr) {
			if (ifr->flags & IFF_RUNNING) {
				//TODO remove copies?

				route = (struct route_record *) secure_malloc(sizeof(struct route_record));
				route->if_index = route_if_index;
				route->family = route_family;

				if (route_family == AF_INET) {
					set_addr4(&route->dst, route_dst);
					set_addr4(&route->mask, route_mask);
					set_addr4(&route->gw, route_gw);
					//set_addr4(&route->ip, route_ip);
				} else if (route_family == AF_INET6) {
					//TODO
					//set_addr6(&route->ip, route_ip);
				} else {
					//TODO error?
				}

				if (list_has_space(envi->route_list)) {
					list_append(envi->route_list, route);
				} else {
					//TODO error
				}
			} else {
				//TODO error
			}
		}
	}

	if (0) { //would need for eth0
		route_if_index = 3;
		route_family = AF_INET;
		route_dst = IP4_ADR_P2H(192,168,1,0);
		route_mask = IP4_ADR_P2H(255,255,255,0);
		route_gw = envi->any_ip_addr; //gw==any, so send directly to dst
		//route_ip = IP4_ADR_P2H(192,168,1,5);
		route_metric = 1;
		route_timeout = 0;
		//############
		ifr = (struct if_record *) list_find1(envi->if_list, ifr_index_test, &if_index);
		if (ifr) {
			if (ifr->flags & IFF_RUNNING) {
				//TODO remove copies?

				route = (struct route_record *) secure_malloc(sizeof(struct route_record));
				route->if_index = route_if_index;
				route->family = route_family;

				if (route_family == AF_INET) {
					set_addr4(&route->dst, route_dst);
					set_addr4(&route->mask, route_mask);
					set_addr4(&route->gw, route_gw);
					//set_addr4(&route->ip, route_ip);
				} else if (route_family == AF_INET6) {
					//TODO
					//set_addr6(&route->ip, route_ip);
				} else {
					//TODO error?
				}

				if (list_has_space(envi->route_list)) {
					list_append(envi->route_list, route);
				} else {
					//TODO error
				}
			} else {
				//TODO error
			}
		}
	}

	if (1) {
		route_if_index = 1;
		route_family = AF_INET;
		route_dst = IP4_ADR_P2H(192,168,1,5);
		route_mask = IP4_ADR_P2H(255,255,255,255);
		route_gw = IP4_ADR_P2H(127,0,0,1);
		//route_ip = IP4_ADR_P2H(127,0,0,1);
		route_metric = 10;
		route_timeout = 0;
		//############
		ifr = (struct if_record *) list_find1(envi->if_list, ifr_index_test, &if_index);
		if (ifr) {
			if (ifr->flags & IFF_RUNNING) {
				//TODO remove copies?

				route = (struct route_record *) secure_malloc(sizeof(struct route_record));
				route->if_index = route_if_index;
				route->family = route_family;

				if (route_family == AF_INET) {
					set_addr4(&route->dst, route_dst);
					set_addr4(&route->mask, route_mask);
					set_addr4(&route->gw, route_gw);
					//set_addr4(&route->ip, route_ip);
				} else if (route_family == AF_INET6) {
					//TODO
					//set_addr6(&route->ip, route_ip);
				} else {
					//TODO error?
				}

				if (list_has_space(envi->route_list)) {
					list_append(envi->route_list, route);
				} else {
					//TODO error
				}
			} else {
				//TODO error
			}
		}
	}

	if (0) {
		route_if_index = 1;
		route_family = AF_INET;
		route_dst = IP4_ADR_P2H(192,168,1,255);
		route_mask = IP4_ADR_P2H(255,255,255,255);
		route_gw = envi->any_ip_addr; //gw==any, so send directly to dst
		//route_ip = IP4_ADR_P2H(192,168,1,5);
		route_metric = 10;
		route_timeout = 0;
		//############
		ifr = (struct if_record *) list_find1(envi->if_list, ifr_index_test, &if_index);
		if (ifr) {
			if (ifr->flags & IFF_RUNNING) {
				//TODO remove copies?

				route = (struct route_record *) secure_malloc(sizeof(struct route_record));
				route->if_index = route_if_index;
				route->family = route_family;

				if (route_family == AF_INET) {
					set_addr4(&route->dst, route_dst);
					set_addr4(&route->mask, route_mask);
					set_addr4(&route->gw, route_gw);
					//set_addr4(&route->ip, route_ip);
				} else if (route_family == AF_INET6) {
					//TODO
					//set_addr6(&route->ip, route_ip);
				} else {
					//TODO error?
				}

				if (list_has_space(envi->route_list)) {
					list_append(envi->route_list, route);
				} else {
					//TODO error
				}
			} else {
				//TODO error
			}
		}
	}

	//######################################################################
	PRINT_IMPORTANT("loading stack");
	metadata *meta_stack = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta_stack);

	status = config_read_file(meta_stack, "test2.cfg");
	if (status == META_FALSE) {
		PRINT_ERROR("%s:%d - %s\n", config_error_file(meta_stack), config_error_line(meta_stack), config_error_text(meta_stack));
		metadata_destroy(meta_stack);
		PRINT_ERROR("todo error");
		exit(-1);
	}

	//############# module_list
	PRINT_IMPORTANT("module list");
	struct linked_list *lib_list = list_create(MAX_MODULES);
	struct fins_module *fins_modules[MAX_MODULES];
	memset(fins_modules, 0, MAX_MODULES * sizeof(struct fins_module *));

	uint8_t base_path[100];
	memset((char *) base_path, 0, 100);
	strcpy((char *) base_path, ".");

	metadata_element *mods_elem = config_lookup(meta_stack, "stack.modules");
	if (mods_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}
	int mods_num = config_setting_length(mods_elem);
	PRINT_IMPORTANT("meta=%p, mods_elem=%p, mods_num=%d", meta_stack, mods_elem, mods_num);

	metadata_element *mod_elem;
	uint32_t mod_id;
	uint8_t *mod_lib;
	uint8_t *mod_name;
	metadata_element *flows_elem;
	uint32_t mod_flows[MAX_FLOWS];
	uint32_t mod_flows_num;
	metadata_element *mod_params;

	struct fins_library *library;
	struct fins_module *module;

	for (i = 0; i < mods_num; i++) {
		mod_elem = config_setting_get_elem(mods_elem, i);
		if (mod_elem == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}
		PRINT_IMPORTANT("meta=%p, mods_elem=%p, mod_elem=%p", meta_stack, mods_elem, mod_elem);

		status = config_setting_lookup_int(mod_elem, "id", (int *) &mod_id);
		PRINT_IMPORTANT("meta=%p, mods_elem=%p, mod_elem=%p, mod_id=%d, status=%d", meta_stack, mods_elem, mod_elem, mod_id, status);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_string(mod_elem, "lib", (const char **) &mod_lib);
		PRINT_IMPORTANT("meta=%p, mods_elem=%p, mod_elem=%p, mod_lib='%s', status=%d", meta_stack, mods_elem, mod_elem, mod_lib, status);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_string(mod_elem, "name", (const char **) &mod_name);
		PRINT_IMPORTANT("meta=%p, mods_elem=%p, mod_elem=%p, mod_name='%s', status=%d", meta_stack, mods_elem, mod_elem, mod_name, status);
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
		PRINT_IMPORTANT("meta=%p, mods_elem=%p, mod_elem=%p, flows_elem=%p, mod_flows_num=%d", meta_stack, mods_elem, mod_elem, flows_elem, mod_flows_num);

		for (j = 0; j < mod_flows_num; j++) {
			mod_flows[j] = (int32_t) config_setting_get_int_elem(flows_elem, j);
			PRINT_IMPORTANT("meta=%p, mods_elem=%p, mod_elem=%p, flows_elem=%p, mod_flows[%d]=%d",
					meta_stack, mods_elem, mod_elem, flows_elem, j, mod_flows[j]);
		}

		mod_params = config_setting_get_member(mod_elem, "params");
		if (mod_params == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}
		PRINT_IMPORTANT("meta=%p, mods_elem=%p, mod_elem=%p, mod_params=%p", meta_stack, mods_elem, mod_elem, mod_params);

		//############
		//library = library_get(lib_list, mod_lib, base_path);if (library == NULL) {PRINT_ERROR("todo error");exit(-1);}
		library = (struct fins_library *) list_find1(lib_list, lib_name_test, mod_lib);
		if (library == NULL) {
			library = library_load(mod_lib, base_path);
			if (library == NULL) {
				PRINT_ERROR("todo error");
				exit(-1);
			}
		}

		module = library->create(i, mod_id, mod_name);
		if (module == NULL) {
			//TODO error
			PRINT_ERROR("todo error");
			exit(-1);
		}
		library->num_mods++;

		//TODO move flow to update? or links here?
		status = module->ops->init(module, mod_flows, mod_flows_num, mod_params, envi); //TODO merge init into create?
		if (status) {
			if (i == SWITCH_INDEX) {
				switch_module = module; //TODO remove? unnecessary
			}
			fins_modules[i] = module;
			module_register(fins_modules[SWITCH_INDEX], module);
		} else {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		free(mod_lib);
		free(mod_name);
	}

	//############# linking_list
	PRINT_IMPORTANT("link list");
	struct linked_list *link_list = list_create(MAX_LINKS);

	metadata_element *links_elem = config_lookup(meta_stack, "stack.links");
	if (links_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}
	int links_num = config_setting_length(links_elem);
	PRINT_IMPORTANT("meta=%p, links_elem=%p, links_num=%d", meta_stack, links_elem, links_num);

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
		PRINT_IMPORTANT("meta=%p, links_elem=%p, elem=%p", meta_stack, links_elem, link_elem);

		status = config_setting_lookup_int(link_elem, "id", (int *) &link_id);
		PRINT_IMPORTANT("meta=%p, links_elem=%p, link_elem=%p, link_id=%d, status=%d", meta_stack, links_elem, link_elem, link_id, status);
		if (status == META_FALSE) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		status = config_setting_lookup_int(link_elem, "src", (int *) &link_src);
		PRINT_IMPORTANT("meta=%p, links_elem=%p, link_elem=%p, src=%d, status=%d", meta_stack, links_elem, link_elem, link_src, status);
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
		PRINT_IMPORTANT("meta=%p, links_elem=%p, link_elem=%p, dsts_elem=%p, dsts_num=%d", meta_stack, links_elem, link_elem, dsts_elem, link_dsts_num);

		for (j = 0; j < link_dsts_num; j++) {
			link_dsts[j] = (uint32_t) config_setting_get_int_elem(dsts_elem, j);
			PRINT_IMPORTANT("meta=%p, links_elem=%p, link_elem=%p, dsts_elem=%p, link_dsts[%d]=%d",
					meta_stack, links_elem, link_elem, dsts_elem, j, link_dsts[j]);
		}

		//############
		link = (struct link_record *) secure_malloc(sizeof(struct link_record));
		link->id = link_id;

		//module = (struct fins_module *) list_find1(envi->module_list, mod_id_test, &link_src);
		link->src_index = -1;
		for (j = 0; j < MAX_MODULES; j++) {
			if (fins_modules[j] != NULL && fins_modules[j]->id == link_src) {
				link->src_index = fins_modules[j]->index;
			}
		}
		if (link->src_index == -1) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		link->dsts_num = link_dsts_num;
		for (j = 0; j < link_dsts_num; j++) {
			//module = (struct fins_module *) list_find1(envi->module_list, mod_id_test, &link_dsts[j]);
			link->dsts_index[j] = -1;
			for (k = 0; k < MAX_MODULES; k++) {
				if (fins_modules[k] != NULL && fins_modules[k]->id == link_dsts[j]) {
					link->dsts_index[j] = fins_modules[k]->index;
				}
			}
			if (link->dsts_index[j] == (uint32_t) -1) {
				PRINT_ERROR("todo error");
				exit(-1);
			}
		}

		if (list_has_space(link_list)) {
			list_append(link_list, link);
		} else {
			//TODO error
			PRINT_ERROR("todo error");
			exit(-1);
		}
	}

	//############# update
	PRINT_IMPORTANT("update modules");
	//send out subset of linking table to each module as update
	//TODO table subset update

	struct linked_list *link_subset_list;
	metadata *meta_update;
	struct finsFrame *ff_update;

	for (i = 0; i < MAX_MODULES; i++) {
		if (fins_modules[i] != NULL) {
			link_subset_list = list_filter1(link_list, link_involved_test, &fins_modules[i]->index, link_copy);
			PRINT_IMPORTANT("i=%d, link_subset_list=%p, len=%d", i, link_subset_list, link_subset_list->len);

			meta_update = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(meta_update);

			//TODO decide on metadata params?
			//uint32_t host_ip = IP4_ADR_P2H(192,168,1,8);
			//secure_metadata_writeToElement(meta_update, "send_src_ip", &host_ip, META_TYPE_INT32);

			ff_update = (struct finsFrame*) secure_malloc(sizeof(struct finsFrame));
			ff_update->dataOrCtrl = CONTROL;
			ff_update->destinationID = i;
			ff_update->metaData = meta_update;

			ff_update->ctrlFrame.senderID = SWITCH_INDEX;
			ff_update->ctrlFrame.serial_num = gen_control_serial_num();
			ff_update->ctrlFrame.opcode = CTRL_SET_PARAM;
			ff_update->ctrlFrame.param_id = PARAM_LINKS;

			ff_update->ctrlFrame.data_len = sizeof(struct linked_list);
			ff_update->ctrlFrame.data = (uint8_t *) link_subset_list;

			if (module_to_switch(fins_modules[SWITCH_INDEX], ff_update)) {

			} else {
				PRINT_ERROR("todo error");
				freeFinsFrame(ff_update);
				list_free(link_subset_list, free);
				exit(-1);
			}
		}
	}

	//############ say by this point envi var completely init'd
	//assumed always connect/init to switch first

	pthread_attr_t attr;
	pthread_attr_init(&attr);

	PRINT_IMPORTANT("modules: run");

	for (i = 0; i < MAX_MODULES; i++) {
		if (fins_modules[i] != NULL) {
			fins_modules[i]->ops->run(fins_modules[i], &attr);
		}
	}

	//############ mini test
	//sleep(5);
	char recv_data[4000];

	//while (1) {
	PRINT_IMPORTANT("waiting...");
	gets(recv_data);

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
		ff->dataOrCtrl = DATA;
		ff->destinationID = 2;
		ff->metaData = meta;

		ff->dataFrame.directionFlag = DIR_UP;
		ff->dataFrame.pduLength = 10;
		ff->dataFrame.pdu = (uint8_t *) secure_malloc(10);

		PRINT_IMPORTANT("sending: ff=%p, meta=%p", ff, meta);
		if (module_to_switch(fins_modules[3], ff)) {
			//i++;
		} else {
			PRINT_ERROR("freeing: ff=%p", ff);
			freeFinsFrame(ff);
			return;
		}
	}

	if (1) {
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
		ff_req->dataOrCtrl = CONTROL;
		ff_req->destinationID = 3;
		ff_req->metaData = meta_req;

		ff_req->ctrlFrame.senderID = IPV4_ID;
		ff_req->ctrlFrame.serial_num = gen_control_serial_num();
		ff_req->ctrlFrame.opcode = CTRL_EXEC;
		ff_req->ctrlFrame.param_id = 0; //EXEC_ARP_GET_ADDR;

		ff_req->ctrlFrame.data_len = 0;
		ff_req->ctrlFrame.data = NULL;

		if (module_to_switch(fins_modules[3], ff_req)) {
			//i++;
		} else {
			PRINT_ERROR("freeing: ff=%p", ff_req);
			freeFinsFrame(ff_req);
			return;
		}
	}

	while (1)
		;

	sleep(5);
	PRINT_IMPORTANT("waiting...");
	char recv_data2[4000];
	gets(recv_data2);

	//############ terminating
	PRINT_IMPORTANT("modules: shutdown");
	for (i = MAX_MODULES - 1; i >= 0; i--) {
		if (fins_modules[i] != NULL) {
			fins_modules[i]->ops->shutdown(fins_modules[i]);
		}
	}

	PRINT_IMPORTANT("modules: release");
	for (i = MAX_MODULES - 1; i >= 0; i--) {
		if (fins_modules[i] != NULL) {
			fins_modules[i]->ops->release(fins_modules[i]);
		}
	}

	PRINT_IMPORTANT("libraries: close");
	while (1) {
		library = (struct fins_library *) list_remove_front(lib_list);
		if (library == NULL) {
			break;
		}
		PRINT_IMPORTANT("closing library: library=%p, name='%s'", library, library->name);
		dlclose(library->handle);
		free(library);
	}

	metadata_destroy(meta_stack);
	exit(1);
}

void core_main_old() {
//###################################################################### //TODO get this from config file eventually
//host interface
//strcpy((char *)my_host_if_name, "lo");
//strcpy((char *)my_host_if_name, "eth0");
//strcpy((char *)my_host_if_name, "eth1");
//strcpy((char *)my_host_if_name, "eth2");
	strcpy((char *) my_host_if_name, "wlan0");
//strcpy((char *)my_host_if_name, "wlan4");

//my_host_if_num = 1; //laptop lo //phone wlan0
//my_host_if_num = 2; //laptop eth0
//my_host_if_num = 3; //laptop wlan0
//my_host_if_num = 4; //laptop wlan4
//my_host_if_num = 10; //phone0 wlan0
	my_host_if_num = 17; //phone1 wlan0
//my_host_if_num = 6; //tablet1 wlan0

//my_host_mac_addr = 0x080027445566ull; //vbox eth2
//my_host_mac_addr = 0x001d09b35512ull; //laptop eth0
//my_host_mac_addr = 0x001cbf86d2daull; //laptop wlan0
//my_host_mac_addr = 0x00184d8f2a32ull; //laptop wlan4 card
//my_host_mac_addr = 0xa00bbae94bb0ull; //phone0 wlan0
	my_host_mac_addr = 0x10683f4f7467ull; //phone1 wlan0
//my_host_mac_addr = 0x50465d14e07full; //tablet1 wlan0

	my_host_ip_addr = IP4_ADR_P2H(192,168,1,8); //home testing
	my_host_mask = IP4_ADR_P2H(255,255,255,0); //home testing
//my_host_ip_addr = IP4_ADR_P2H(172,31,51,55); //lab testing
//my_host_mask = IP4_ADR_P2H(255,255,248,0); //lab testing

//loopback interface
	loopback_ip_addr = IP4_ADR_P2H(127,0,0,1);
	loopback_mask = IP4_ADR_P2H(255,0,0,0);

//any
	any_ip_addr = IP4_ADR_P2H(0,0,0,0);
//######################################################################

	switch_dummy();
//daemon_dummy();
//interface_dummy();

//arp_dummy();
//ipv4_dummy();
//icmp_dummy();
//tcp_dummy();
//udp_dummy();

//rtm_dummy();
//logger_dummy();

// Start the driving thread of each module
	PRINT_IMPORTANT("Initialize Modules");
//switch_init(); //should always be first
//daemon_init(); //TODO improve how sets mac/ip
//interface_init();

//arp_init();
//arp_register_interface(my_host_mac_addr, my_host_ip_addr);

//ipv4_init();
//ipv4_register_interface(my_host_mac_addr, my_host_ip_addr);

//icmp_init();
//tcp_init();
//udp_init();

//rtm_init(); //TODO when updated/fully implemented
//logger_init();

	pthread_attr_t fins_pthread_attr;
	pthread_attr_init(&fins_pthread_attr);

	PRINT_IMPORTANT("Run/start Modules");
//switch_run(&fins_pthread_attr);
//daemon_run(&fins_pthread_attr);
//interface_run(&fins_pthread_attr);

//arp_run(&fins_pthread_attr);
//ipv4_run(&fins_pthread_attr);
//icmp_run(&fins_pthread_attr);
//tcp_run(&fins_pthread_attr);
//udp_run(&fins_pthread_attr);

//rtm_run(&fins_pthread_attr);
//logger_run(&fins_pthread_attr);

//############################# //TODO custom test, remove later
	/*
	 if (1) {
	 //char recv_data[4000];

	 while (1) {
	 //gets(recv_data);

	 PRINT_DEBUG("Sending ARP req");

	 metadata *meta_req = (metadata *) secure_malloc(sizeof(metadata));
	 metadata_create(meta_req);

	 uint32_t dst_ip = IP4_ADR_P2H(192, 168, 1, 1);
	 //uint32_t dst_ip = IP4_ADR_P2H(172, 31, 54, 169);
	 uint32_t src_ip = my_host_ip_addr; //IP4_ADR_P2H(192, 168, 1, 20);
	 //uint32_t src_ip = IP4_ADR_P2H(172, 31, 50, 160);

	 secure_metadata_writeToElement(meta_req, "dst_ip", &dst_ip, META_TYPE_INT32);
	 secure_metadata_writeToElement(meta_req, "src_ip", &src_ip, META_TYPE_INT32);

	 struct finsFrame *ff_req = (struct finsFrame*) secure_malloc(sizeof(struct finsFrame));
	 ff_req->dataOrCtrl = CONTROL;
	 ff_req->destinationID.id = ARP_ID;
	 ff_req->destinationID.next = NULL;
	 ff_req->metaData = meta_req;

	 ff_req->ctrlFrame.senderID = IPV4_ID;
	 ff_req->ctrlFrame.serial_num = gen_control_serial_num();
	 ff_req->ctrlFrame.opcode = CTRL_EXEC;
	 ff_req->ctrlFrame.param_id = EXEC_ARP_GET_ADDR;

	 ff_req->ctrlFrame.data_len = 0;
	 ff_req->ctrlFrame.data = NULL;

	 arp_to_switch(ff_req); //doesn't matter which queue
	 }
	 }
	 if (0) {
	 //char recv_data[4000];
	 while (1) {
	 //gets(recv_data);
	 sleep(15);

	 PRINT_IMPORTANT("start timing");

	 struct timeval start, end;
	 gettimeofday(&start, 0);

	 int its = 2; //30000;
	 int len = 10; //1000;

	 int i = 0;
	 while (i < its) {
	 uint8_t *data = (uint8_t *) secure_malloc(len);
	 memset(data, 74, len);

	 metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	 metadata_create(meta);

	 //uint32_t host_ip = IP4_ADR_P2H(192,168,1,8);
	 uint32_t host_ip = my_host_ip_addr;
	 uint32_t host_port = 55454;
	 uint32_t dst_ip = IP4_ADR_P2H(192,168,1,3);
	 //uint32_t dst_ip = IP4_ADR_P2H(172, 31, 54, 169);
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
	 ff->dataOrCtrl = DATA;
	 ff->destinationID.id = UDP_ID;
	 ff->destinationID.next = NULL;
	 ff->metaData = meta;

	 ff->dataFrame.directionFlag = DIR_DOWN;
	 ff->dataFrame.pduLength = len;
	 ff->dataFrame.pdu = data;

	 PRINT_IMPORTANT("sending: ff=%p, meta=%p", ff, meta);
	 if (1) {
	 if (arp_to_switch(ff)) {
	 i++;
	 } else {
	 PRINT_ERROR("freeing: ff=%p", ff);
	 freeFinsFrame(ff);
	 return;
	 }
	 }
	 sleep(5);

	 if (0) {
	 if (daemon_fdf_to_switch(UDP_ID, data, len, meta)) {
	 i++;
	 } else {
	 PRINT_ERROR("error sending");
	 metadata_destroy(meta);
	 free(data);
	 break;
	 }
	 }
	 }

	 //struct timeval start, end;
	 //gettimeofday(&start, 0);
	 if (0) {
	 gettimeofday(&end, 0);
	 double diff = time_diff(&start, &end);
	 PRINT_IMPORTANT("diff=%f, len=%d, avg=%f ms, calls=%f, bits=%f", diff, len, diff/its, 1000/(diff/its), 8*1000/(diff/its)*len);
	 }
	 break;
	 }
	 }
	 if (0) {
	 //char recv_data[4000];
	 while (1) {
	 //gets(recv_data);
	 sleep(15);

	 PRINT_IMPORTANT("start timing");

	 struct timeval start, end;
	 gettimeofday(&start, 0);

	 int its = 1; //30000;
	 int len = 10; //1000;

	 int i = 0;
	 while (i < its) {
	 uint8_t *data = (uint8_t *) secure_malloc(len);
	 memset(data, 74, len);

	 metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	 metadata_create(meta);

	 uint32_t host_ip = IP4_ADR_P2H(192,168,1,7);
	 uint32_t host_port = 55454;
	 uint32_t dst_ip = IP4_ADR_P2H(192,168,1,8);
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
	 ff->dataOrCtrl = DATA;
	 ff->destinationID.id = UDP_ID;
	 ff->destinationID.next = NULL;
	 ff->metaData = meta;

	 ff->dataFrame.directionFlag = DIR_DOWN;
	 ff->dataFrame.pduLength = len;
	 ff->dataFrame.pdu = data;

	 PRINT_DEBUG("sending: ff=%p, meta=%p", ff, meta);
	 if (arp_to_switch(ff)) {
	 i++;
	 } else {
	 PRINT_ERROR("freeing: ff=%p", ff);
	 freeFinsFrame(ff);
	 return;
	 }

	 if (0) {
	 if (daemon_fdf_to_switch(UDP_ID, data, len, meta)) {
	 i++;
	 } else {
	 PRINT_ERROR("error sending");
	 metadata_destroy(meta);
	 free(data);
	 break;
	 }
	 }
	 }

	 //struct timeval start, end;
	 //gettimeofday(&start, 0);
	 gettimeofday(&end, 0);
	 double diff = time_diff(&start, &end);
	 PRINT_IMPORTANT("diff=%f, len=%d, avg=%f ms, calls=%f, bits=%f", diff, len, diff/its, 1000/(diff/its), 8*1000/(diff/its)*len);
	 break;
	 }
	 }
	 //*/
//#############################
	PRINT_IMPORTANT("Just waiting");
	while (1) {
		//sleep(1);
	}
}

#ifndef BUILD_FOR_ANDROID
int main() {
	core_main();
	return 0;
}
#endif
