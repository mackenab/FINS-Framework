/*
 * @file switch.h
 *
 *  @date Mar 14, 2011
 *      @author Abdallah Abdallah
 */

#ifndef SWITCH_INTERNAL_H_
#define SWITCH_INTERNAL_H_

#include "switch.h"

#include <finsdebug.h>
#include <finstypes.h>
#include <metadata.h>
#include <finsqueue.h>

#define SWITCH_LIB "switch"
#define SWITCH_MAX_PORTS 0

struct switch_data {
	struct linked_list *link_list;
	uint32_t flows_num;
	uint32_t flows[SWITCH_MAX_PORTS];

	pthread_t switch_thread;
	struct fins_module *fins_modules[MAX_MODULES];
};

sem_t *switch_event_sem;

int switch_init(struct fins_module *module, uint32_t *flows, uint32_t flows_num, metadata_element *params, struct envi_record *envi);
int switch_run(struct fins_module *module, pthread_attr_t *fins_pthread_attr);
int switch_pause(struct fins_module *module);
int switch_unpause(struct fins_module *module);
int switch_shutdown(struct fins_module *module);
int switch_release(struct fins_module *module);

#endif /* SWITCH_INTERNAL_H_ */
