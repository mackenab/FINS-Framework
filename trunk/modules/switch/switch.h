/*
 * @file switch.h
 *
 *  @date Mar 14, 2011
 *      @author Abdallah Abdallah
 */

#ifndef SWITCH_H_
#define SWITCH_H_

//#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <metadata.h>
#include <finsqueue.h>

#include <net/if.h>

#define MAX_INTERFACES 30
#define MAX_FAMILIES 64
#define MAX_ADDRESSES 8192
#define MAX_ROUTES 8192

#define MAX_MODULES 16
#define MOD_NAME_SIZE 64
#define MAX_QUEUE_SIZE 100000

struct addr_record { //for a particular address
	uint8_t if_index;
	uint32_t family;
	struct sockaddr_storage ip; //ip
	struct sockaddr_storage mask; //network mask
	struct sockaddr_storage gw; //gateway
	struct sockaddr_storage bdc; //broadcast
	struct sockaddr_storage dst; //end-to-end dst
//union {}; //bdc & dst can be unioned, not done for simplicity
};

struct if_record { //for an interface
	//inherent
	uint8_t index;
	uint8_t name[IFNAMSIZ]; //SIOCGIFNAME
	uint64_t mac; //SIOCGIFHWADDR
	uint16_t type; //eth/Wifi

	//changeable
	uint8_t status; //up/down
	uint32_t mtu; //SIOCGIFMTU
	uint32_t flags; //TODO use? //SIOCGIFFLAGS

	struct linked_list *addr_list;
};

struct route_record {
	uint8_t if_index;
	uint32_t family;
	struct sockaddr_storage dst; //end-to-end dst
	struct sockaddr_storage mask; //network mask
	struct sockaddr_storage gw; //gateway
	struct sockaddr_storage ip; //ip //TODO remove?

	uint32_t metric; //TODO remove?
	uint32_t timeout; //TODO remove?
	struct timeval *stamp;
};

struct cache_record {
	struct sockaddr_storage src;
	struct sockaddr_storage dst;
	struct sockaddr_storage gw;
	uint8_t if_index;

	uint32_t metric; //TODO remove?
	uint32_t timeout; //TODO remove?
	struct timeval *stamp;
};

struct envi_record {
	uint32_t any_ip_addr; //change to sockaddr_storage? or any_ip_addr & any_ip_addr6?
	//struct if_record if_list[MAX_INTERFACES];
	struct linked_list *if_list; //list of if_record, for a list of interfaces
	struct if_record *if_loopback;
	struct if_record *if_main;

	struct linked_list *addr_list;
	struct linked_list *route_list; //list of addr_record, for a routing table
	//struct linked_list *route_cache; //TODO add in routing cache?
	//struct linked_list *foward_list; //TODO add in forwarding table?
	struct linked_list *module_list;
	struct linked_list *link_list;
};

typedef enum {
	FMS_FREE = 0, FMS_INIT, FMS_RUNNING, FMS_PAUSED, FMS_SHUTDOWN
} fins_module_state;

struct fins_module {
	//inherent
	char lib[MOD_NAME_SIZE]; //name of module, shared library located at <FINS_ROOT>/trunk/modules/<lib>/<lib>.so?
	const struct fins_module_ops *ops;
	fins_module_state state;
	uint32_t num_ports;

	//assigned
	uint32_t index; //index of module in the module_list/fins_modules
	uint32_t id; //unique ID of module assigned in .ini files
	char name[MOD_NAME_SIZE]; //unique name of module (more for human recognition)

	//allocated
	finsQueue input_queue;
	sem_t *input_sem;
	finsQueue output_queue;
	sem_t *output_sem;
	sem_t *event_sem;

	uint8_t *data;
};

struct fins_module_ops {
	//struct fins_module *owner; //TODO remove?
	int (*init)(struct fins_module *module, metadata *meta, struct envi_record *envi);
	int (*run)(struct fins_module *module, pthread_attr_t *fins_pthread_attr);
	int (*pause)(struct fins_module *module);
	int (*unpause)(struct fins_module *module);
	int (*shutdown)(struct fins_module *module);
	int (*release)(struct fins_module *module);
};

//void switch_dummy(void);
//void init(void);
struct fins_module *switch_create(uint32_t index, uint32_t id, char *name);

struct fins_proto_module {
	int module_id;
	char name[MOD_NAME_SIZE];
	uint8_t running_flag; //TODO include?

	finsQueue input_queue;
	sem_t *input_sem;

	finsQueue output_queue;
	sem_t *output_sem;

	sem_t *event_sem;
};

void module_create_ops(struct fins_proto_module *module);
void module_destroy_ops(struct fins_proto_module *module);
int module_register(struct fins_proto_module *module);
void module_unregister(int module_id);
int module_to_switch(struct fins_proto_module *module, struct finsFrame *ff);

void switch_dummy(void);
void switch_init(void);
void switch_run(pthread_attr_t *fins_pthread_attr);
void switch_shutdown(void);
void switch_release(void);

#endif /* SWITCH_H_ */
