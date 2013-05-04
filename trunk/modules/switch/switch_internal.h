/*
 * @file switch.h
 *
 *  @date Mar 14, 2011
 *      @author Abdallah Abdallah
 */

#ifndef SWITCH_INTERNAL_H_
#define SWITCH_INTERNAL_H_

#include "switch.h"

#define SWITCH_LIB "switch"
#define SWITCH_MAX_FLOWS 0

struct switch_data {
	struct linked_list *link_list;
	uint32_t flows_num;
	uint32_t flows[SWITCH_MAX_FLOWS];

	pthread_t switch_thread;

	struct fins_overall *overall;
};

int switch_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi);
int switch_run(struct fins_module *module, pthread_attr_t *fins_pthread_attr);
int switch_pause(struct fins_module *module);
int switch_unpause(struct fins_module *module);
int switch_shutdown(struct fins_module *module);
int switch_release(struct fins_module *module);
int switch_register_module(struct fins_module *module, struct fins_module *new_mod);
int switch_unregister_module(struct fins_module *module, int index);

void switch_process_ff(struct fins_module *module, struct finsFrame *ff);
void switch_fcf(struct fins_module *module, struct finsFrame *ff);
void switch_set_param(struct fins_module *module, struct finsFrame *ff);

//don't use 0
#define SWITCH_GET_PARAM_FLOWS MOD_GET_PARAM_FLOWS
#define SWITCH_GET_PARAM_LINKS MOD_GET_PARAM_LINKS
#define SWITCH_GET_PARAM_DUAL MOD_GET_PARAM_DUAL

#define SWITCH_SET_PARAM_FLOWS MOD_SET_PARAM_FLOWS
#define SWITCH_SET_PARAM_LINKS MOD_SET_PARAM_LINKS
#define SWITCH_SET_PARAM_DUAL MOD_SET_PARAM_DUAL

#endif /* SWITCH_INTERNAL_H_ */
