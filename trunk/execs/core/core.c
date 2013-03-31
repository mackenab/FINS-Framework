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
//#include <finstime.h>
//#include <metadata.h>
//#include <finsqueue.h>

#include <switch.h>
#include <finstime.h>
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

//#define MAX_QUEUE_SIZE 100000

/**
 * @brief read the core parameters from the configuraions file called fins.cfg
 * @param
 * @return nothing
 */
int read_configurations() {

	config_t cfg;
	//config_setting_t *setting;
	//const char *str;

	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if (!config_read_file(&cfg, "fins.cfg")) {
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
	switch_shutdown(); //TODO finish

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
	switch_release();

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

struct if_record *if_list_find_index(struct linked_list *list, uint8_t if_index) {
	PRINT_DEBUG("Entered: list=%p, if_index=%u", list, if_index);

	struct if_record *ifr;

	struct list_node *comp = list->front;
	while (comp) {
		ifr = (struct if_record *) comp->data;
		if (ifr->index == if_index) {
			//list_check(list);
			PRINT_DEBUG("Entered: list=%p, if_index=%u, ifr=%p", list, if_index, ifr);
			return ifr;
		} else {
			comp = comp->next;
		}
	}

	//list_check(list);
	PRINT_DEBUG("Entered: list=%p, if_index=%u, data=%p", list, if_index, NULL);
	return NULL;
}

static struct fins_module *fins_modules_new[MAX_MODULES];

void core_main() {
	PRINT_IMPORTANT("Entered");

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
	//new module initialization prototype
	struct envi_record *envi = (struct envi_record *) secure_malloc(sizeof(struct envi_record));
	envi->any_ip_addr = IP4_ADR_P2H(0,0,0,0); //TODO change to addr_in?

	//############# if_list
	envi->if_list = list_create(MAX_INTERFACES);

	uint8_t if_index;
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
		ifr = if_list_find_index(envi->if_list, if_index);
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
				list_append(envi->if_list, (uint8_t *) ifr);
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
		ifr = if_list_find_index(envi->if_list, if_index);
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
				list_append(envi->if_list, (uint8_t *) ifr);
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
		ifr = if_list_find_index(envi->if_list, if_index);
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
				list_append(envi->if_list, (uint8_t *) ifr);
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

	uint8_t addr_if_index; //the index parameter of the interface in if_list, most likely its order index as well
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
		ifr = if_list_find_index(envi->if_list, addr_if_index);
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
						list_append(ifr->addr_list, (uint8_t *) addr);
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
		ifr = if_list_find_index(envi->if_list, addr_if_index);
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
						list_append(ifr->addr_list, (uint8_t *) addr);
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
		ifr = if_list_find_index(envi->if_list, addr_if_index);
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
						list_append(ifr->addr_list, (uint8_t *) addr);
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
	struct timeval route_stamp;
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
		ifr = if_list_find_index(envi->if_list, route_if_index);
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
					list_append(envi->route_list, (uint8_t *) route);
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
		ifr = if_list_find_index(envi->if_list, route_if_index);
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
					list_append(envi->route_list, (uint8_t *) route);
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
		ifr = if_list_find_index(envi->if_list, route_if_index);
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
					list_append(envi->route_list, (uint8_t *) route);
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
		ifr = if_list_find_index(envi->if_list, route_if_index);
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
					list_append(envi->route_list, (uint8_t *) route);
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
		ifr = if_list_find_index(envi->if_list, route_if_index);
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
					list_append(envi->route_list, (uint8_t *) route);
				} else {
					//TODO error
				}
			} else {
				//TODO error
			}
		}
	}

	//TODO linking table
	//read in & construct linking table

	//############# module_list
	envi->module_list = list_create(MAX_MODULES);

	uint32_t module_index; //determined by core
	uint32_t module_id; //read in
	char module_lib[MOD_NAME_SIZE]; //read in, determines so file
	char module_name[MOD_NAME_SIZE]; //read in
	//uint32_t module_ports;
	uint32_t num_params;
	//#############
	char base_path[100];
	char lib_path[100 + 2 * MOD_NAME_SIZE + 5];
	struct fins_module *module;
	metadata *meta;

	memset(base_path, 0, 100);
	strcpy((char *) base_path, "../../trunk/modules");

	if (1) {
		module_index = 0;
		module_id = 000;
		strcpy((char *) module_lib, "logger");
		strcpy((char *) module_name, "logger0");
		//module_ports = 1;
		num_params = 0;
		//############

		//TODO load library
		//strcpy(, "/lib/libm.so.6");
		sprintf(lib_path, "%s/%s/%s.so", base_path, module_lib, module_lib);
		//strcpy(lib_path, base_path module_lib "/" module_lib ".so");
		PRINT_IMPORTANT("lib_path='%s'", lib_path);

		//#################
		double (*cosine)(double);
		//struct fins_module *(*module_create)(uint32_t index, uint32_t id, char *name);
		char *error;

		void *lib_handle = dlopen(lib_path, RTLD_NOW); //RTLD_LAZY | RTLD_GLOBAL?
		if (!lib_handle) {
			fputs(dlerror(), stderr);
			exit(1);
		}
		cosine = dlsym(lib_handle, "cos");
		if ((error = dlerror()) != NULL) {
			fputs(error, stderr);
			exit(1);
		}
		void* initializer = dlsym(lib_handle, "cos");
		if ((error = dlerror()) != NULL) {
			fputs(error, stderr);
			exit(1);
		}
		typedef double (*cosine2)(double);
		cosine2 init_func = (cosine2) initializer;

		PRINT_IMPORTANT("cosine=%f\n", (*cosine)(2.0));
		PRINT_IMPORTANT("cosine2=%f\n", (*init_func)(2.0));
		dlclose(lib_handle);
		//#################
		exit(1);

		module = NULL; //logger_create_new(module_index, module_id, module_name);
		fins_modules_new[module_index] = module;

		meta = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(meta);

		if (0) {
			//no params to load
		}
		//secure_metadata_writeToElement(meta, "dst_ip", &dst_ip, META_TYPE_INT32);

		if (list_has_space(envi->module_list)) {
			list_append(envi->module_list, (uint8_t *) meta);
		} else {
			//TODO error
		}
	}

	//############# linking_list

	//############ say by this point envi var completely init'd
	//assumed always connect/init to switch first

	//for loop to init links, j=0
	//reads in module name (connected to so file), index,

	uint8_t mod_name[MOD_NAME_SIZE];

	if (1) {
		if_index = 0;
		strcpy((char *) mod_name, "logger");
		//############
		//open so/load library dynamically
		//call logger_init(virtual_id, module_id, envi);
	}

	//############ say by this point envi var completely init'd

	//######################################################################

	register_to_signal(SIGRTMIN);

	sem_init(&control_serial_sem, 0, 1); //TODO remove after gen_control_serial_num() converted to RNG

	signal(SIGINT, core_termination_handler); //register termination handler

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
	switch_init(); //should always be first
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
	switch_run(&fins_pthread_attr);
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
