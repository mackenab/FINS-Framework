/*
 * finsmodule.h
 *
 *  Created on: Apr 18, 2013
 *      Author: Jonathan Reed
 */

#ifndef FINSMODULE_H_
#define FINSMODULE_H_

//#include <arpa/inet.h>
#include <dlfcn.h>
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
#define MAX_MOD_FLOWS 256
#define MAX_TABLE_LINKS 1024

//Needs to be 0 so that is loaded first
#define NONE_INDEX 0
#define LINK_NULL 0
#define FLOW_NULL ((uint32_t) -1)

typedef enum {
	FMS_FREE = 0, FMS_INIT, FMS_RUNNING, FMS_PAUSED, FMS_SHUTDOWN
} fins_module_state;

struct fins_module {
	//inherent
	uint8_t lib[MOD_NAME_SIZE]; //name of module, shared library located at <FINS_ROOT>/trunk/modules/<lib>/<lib>.so?
	uint32_t flows_max;
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
	metadata *knobs; //TODO rename to knobs
	uint8_t *data;
};

int mod_id_test(struct fins_module *mod, uint32_t *id);

struct fins_module_ops {
	//struct fins_module *owner; //TODO remove?
	int (*init)(struct fins_module *module, metadata_element *params, struct envi_record *envi);
	int (*run)(struct fins_module *module, pthread_attr_t *fins_pthread_attr);
	int (*pause)(struct fins_module *module);
	int (*unpause)(struct fins_module *module);
	int (*shutdown)(struct fins_module *module);
	int (*release)(struct fins_module *module);
};

typedef struct fins_module *(*mod_create_type)(uint32_t index, uint32_t id, uint8_t *name);
struct fins_library {
	uint8_t name[MOD_NAME_SIZE];
	void *handle;
	mod_create_type create;
	uint32_t num_mods;
//struct linked_list *mod_list;
};
struct fins_library *library_load(uint8_t *lib, uint8_t *base_path);
int library_name_test(struct fins_library *lib, uint8_t *name);
void library_free(struct fins_library *lib);

struct fins_overall {
	sem_t sem;
	struct envi_record *envi;

	pthread_attr_t attr;
	struct linked_list *lib_list; //linked list of fins_library structs, representing all open libraries
	struct fins_module *modules[MAX_MODULES];
	struct linked_list *admin_list; //linked list of fins_module structs, representing all admin modules

	struct linked_list *link_list; //linked list of link_record structs, representing all links in linking table
};

struct fins_module_admin_ops {
	int (*init)(struct fins_module *module, metadata_element *params, struct envi_record *envi);
	int (*run)(struct fins_module *module, pthread_attr_t *fins_pthread_attr);
	int (*pause)(struct fins_module *module);
	int (*unpause)(struct fins_module *module);
	int (*shutdown)(struct fins_module *module);
	int (*release)(struct fins_module *module);
	int (*pass_overall)(struct fins_module *module, struct fins_overall *overall);
};
void assign_overall(struct fins_module *module, struct fins_overall *overall);

struct link_record {
	uint32_t id;
	uint32_t src_index;
	uint32_t dsts_num;
	uint32_t dsts_index[MAX_MODULES];
};

int link_id_test(struct link_record *link, uint32_t *id);
int link_src_test(struct link_record *link, uint32_t *index);
int link_involved_test(struct link_record *link, uint32_t *index);
struct link_record *link_clone(struct link_record *link);
void link_print(struct link_record *link);

struct fins_module_flow {
	uint32_t link_id;
	struct link_record *link;
};

struct fins_module_table {
	//add max_flows? //as max number of flows
	struct linked_list *link_list; //linked list of link_record structs, representing links for this module
	uint32_t flows_num;
	struct fins_module_flow flows[MAX_MOD_FLOWS];
};

void module_create_structs(struct fins_module *module);
void module_destroy_structs(struct fins_module *module);

#define module_to_switch(module, ff) module_to_switch_full(__FILE__, __FUNCTION__, __LINE__, module, ff)
void module_to_switch_full(const char *file, const char *func, int line, struct fins_module *module, struct finsFrame *ff);
void module_reply_fcf(struct fins_module *module, struct finsFrame *ff, uint32_t ret_val, uint32_t ret_msg);
int module_send_flow(struct fins_module *module, struct finsFrame *ff, uint32_t flow);

//operations - must match or be a subset of those in RTM
#define OP_HELP_STR "help"
#define OP_EXEC_STR "exec"
#define OP_GET_STR "get"
#define OP_SET_STR "set"
#define OP_PAUSE_STR "pause"
#define OP_UNPAUSE_STR "unpause"
#define OP_LINK_STR "link"
#define OP_UNLINK_STR "unlink"
#define OP_LOAD_STR "load"
#define OP_UNLOAD_STR "unload"
#define OP_REPLACE_STR "replace"
#define OP_SHUTDOWN_STR "shutdown"
#define OP_LISTEN_STR "listen"
//actually needed by module: exec, get, set, listen
//rest are handled in RTM/admin module

void module_set_param_flows(struct fins_module *module, struct finsFrame *ff);
void module_set_param_links(struct fins_module *module, struct finsFrame *ff);
void module_set_param_dual(struct fins_module *module, struct finsFrame *ff);

void module_read_param_flows(struct fins_module *module, struct finsFrame *ff);
void module_read_param_links(struct fins_module *module, struct finsFrame *ff);
void module_read_param_dual(struct fins_module *module, struct finsFrame *ff);

//SET_PARAM / GET_PARAM
#define MOD_READ_PARAM_FLOWS 0
#define MOD_READ_PARAM_LINKS 1
#define MOD_READ_PARAM_DUAL 2

#define MOD_SET_PARAM_FLOWS 0
#define MOD_SET_PARAM_LINKS 1
#define MOD_SET_PARAM_DUAL 2

#define MOD_ALERT_FLOWS 0
#define MOD_ALERT_LINKS 1
#define MOD_ALERT_DUAL 2

sem_t *global_switch_event_sem;

#endif /* FINSMODULE_H_ */
