/*
 * finsmodule.h
 *
 *  Created on: Apr 18, 2013
 *      Author: Jonathan Reed
 */

#ifndef FINSMODULE_H_
#define FINSMODULE_H_

//#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <metadata.h>
#include "finsqueue.h"

#include <net/if.h>

#define MAX_MODULES 32
#define MAX_BASE_PATH 100
#define MOD_NAME_SIZE 64
#define MAX_QUEUE_SIZE 100000
#define MAX_FLOWS 256
#define MAX_LINKS 1024

//Needs to be 0 so that is loaded first
#define SWITCH_INDEX 0

typedef enum {
	FMS_FREE = 0, FMS_INIT, FMS_RUNNING, FMS_PAUSED, FMS_SHUTDOWN
} fins_module_state;

struct fins_module {
	//inherent
	uint8_t lib[MOD_NAME_SIZE]; //name of module, shared library located at <FINS_ROOT>/trunk/modules/<lib>/<lib>.so?
	uint32_t max_flows;
	const struct fins_module_ops *ops;
	fins_module_state state;

	//assigned
	uint32_t index; //index of module in the module_list/fins_modules
	uint32_t id; //unique ID of module assigned in .ini files
	uint8_t name[MOD_NAME_SIZE]; //unique name of instance of this module (more for human recognition)

	//allocated
	finsQueue input_queue;
	sem_t *input_sem;
	finsQueue output_queue;
	sem_t *output_sem;
	sem_t *event_sem;

	//private & dependent on the module
	uint8_t *data;
};

int mod_id_test(struct fins_module *mod, uint32_t *id);

struct fins_module_ops {
	//struct fins_module *owner; //TODO remove?
	int (*init)(struct fins_module *module, uint32_t *flows, uint32_t flows_num, metadata_element *params, struct envi_record *envi);
	int (*run)(struct fins_module *module, pthread_attr_t *fins_pthread_attr);
	int (*pause)(struct fins_module *module);
	int (*unpause)(struct fins_module *module);
	int (*shutdown)(struct fins_module *module);
	int (*release)(struct fins_module *module);
};

struct fins_module_switch_ops {
	int (*init)(struct fins_module *module, uint32_t *flows, uint32_t flows_num, metadata_element *params, struct envi_record *envi);
	int (*run)(struct fins_module *module, pthread_attr_t *fins_pthread_attr);
	int (*pause)(struct fins_module *module);
	int (*unpause)(struct fins_module *module);
	int (*shutdown)(struct fins_module *module);
	int (*release)(struct fins_module *module);
	int (*register_module)(struct fins_module *module, struct fins_module *new_mod);
	int (*unregister_module)(struct fins_module *module, int index);
};

struct link_record {
	uint32_t id;
	uint32_t src_index;
	uint32_t dsts_index[MAX_MODULES];
	uint32_t dsts_num;
//struct linked_list *dst_list;
};

int link_id_test(struct link_record *link, uint32_t *id);
int link_involved_test(struct link_record *link, uint32_t *index);
struct link_record *link_copy(struct link_record *link);

struct fins_module_table {
	//add max_flows? //as max number of flows
	struct linked_list *link_list;
	uint32_t flows_num;
	uint32_t flows[MAX_FLOWS];
};

void module_create_queues(struct fins_module *module);
void module_destroy_queues(struct fins_module *module);
int module_to_switch(struct fins_module *module, struct finsFrame *ff);
int module_send_flow(struct fins_module *module, struct fins_module_table *table, struct finsFrame *ff, uint32_t flow);

//not as sure since switch_event_sem

//SET_PARAM / GET_PARAM
#define PARAM_FLOWS 0
#define PARAM_LINKS 1
#define PARAM_DUAL 2

sem_t *switch_event_sem;

#endif /* FINSMODULE_H_ */
