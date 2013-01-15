/**
 * @file switch.c
 *
 *  @date Mar 14, 2011
 *      @author Abdallah Abdallah
 */

#include <finstypes.h>
#include <metadata.h>
#include <queueModule.h>
#include <arpa/inet.h>

#include "switch.h"
static struct fins_proto_module switch_proto = { .module_id = SWITCH_ID, .name = "switch", .running_flag = 1, };

pthread_t switch_thread;

#define MAX_modules 16

static struct fins_proto_module *fins_modules[MAX_modules];

void module_create_ops(struct fins_proto_module *module) {
	PRINT_DEBUG("Entered: module=%p, module_id=%d, name='%s'", module, module->module_id, module->name);
	char buf[50];

	sprintf(buf, "switch_to_%s", module->name);
	module->input_queue = init_queue(buf, MAX_Queue_size);

	module->input_sem = (sem_t *) malloc(sizeof(sem_t));
	if (module->input_sem == NULL) {
		PRINT_ERROR("error alloc");
		exit(-1);
	}
	sem_init(module->input_sem, 0, 1);

	sprintf(buf, "%s_to_switch", module->name);
	module->output_queue = init_queue(buf, MAX_Queue_size);

	module->output_sem = (sem_t *) malloc(sizeof(sem_t));
	if (module->output_sem == NULL) {
		PRINT_ERROR("error alloc");
		exit(-1);
	}
	sem_init(module->output_sem, 0, 1);

	module->event_sem = (sem_t *) malloc(sizeof(sem_t));
	if (module->event_sem == NULL) {
		PRINT_ERROR("error alloc");
		exit(-1);
	}
	sem_init(module->event_sem, 0, 0);
}

void module_destroy_ops(struct fins_proto_module *module) {
	PRINT_DEBUG("Entered: module=%p, module_id=%d, name='%s'", module, module->module_id, module->name);

	term_queue(module->output_queue);
	term_queue(module->input_queue);

	sem_destroy(module->output_sem);
	free(module->output_sem);
	sem_destroy(module->input_sem);
	free(module->input_sem);
	sem_destroy(module->event_sem);
	free(module->event_sem);
}

int module_register(struct fins_proto_module *module) {
	PRINT_DEBUG("Entered: module=%p, module_id=%d, name='%s'", module, module->module_id, module->name);

	if (module->module_id >= MAX_modules) {
		PRINT_ERROR("todo error");
		return -1;
	}

	//TODO add sem's
	if (fins_modules[module->module_id] != NULL) {
		PRINT_CRITICAL("Replacing: module=%p, module_id=%d, name='%s'", fins_modules[module->module_id], fins_modules[module->module_id]->module_id, fins_modules[module->module_id]->name);
	}
	PRINT_CRITICAL("Registered: module=%p, module_id=%d, name='%s'", module, module->module_id, module->name);
	fins_modules[module->module_id] = module;

	PRINT_DEBUG("Exited: module=%p, module_id=%d, name='%s'", module, module->module_id, module->name);
	return 0;
}

void module_unregister(int module_id) {
	PRINT_DEBUG("Entered: module_id=%d", module_id);

	if (module_id < 0 || module_id > MAX_modules) {
		PRINT_ERROR("todo error");
		return;
	}

	//TODO add sem's
	if (fins_modules[module_id] != NULL) {
		PRINT_CRITICAL("Unregistering: module=%p, module_id=%d, name='%s'", fins_modules[module_id], fins_modules[module_id]->module_id, fins_modules[module_id]->name);
		fins_modules[module_id] = NULL;
	} else {
		PRINT_CRITICAL("No module to unregister: module_id=%d", module_id);
	}
}

int module_to_switch(struct fins_proto_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, module_id=%d, name='%s', ff=%p, meta=%p", module, module->module_id, module->name, ff, ff->metaData);
	if (sem_wait(module->output_sem)) {
		PRINT_ERROR("output_sem wait prob: module=%p, module_id=%d, name='%s', ff=%p, meta=%p", module, module->module_id, module->name, ff, ff->metaData);
		exit(-1);
	}
	if (write_queue(ff, module->output_queue)) {
		PRINT_DEBUG("Exited: module=%p, module_id=%d, name='%s', 1", module, module->module_id, module->name);
		sem_post(switch_proto.event_sem);
		sem_post(module->output_sem);
		return 1;
	} else {
		PRINT_DEBUG("Exited: module=%p, module_id=%d, name='%s', 0", module, module->module_id, module->name);
		sem_post(module->output_sem);
		return 0;
	}
}

void *switch_loop(void *local) {
	PRINT_DEBUG("Entered");

	int i;
	struct finsFrame *ff;
	uint8_t id;

	int counter = 0;

	while (switch_proto.running_flag) {
		if (sem_wait(switch_proto.event_sem)) {
			PRINT_ERROR("sem wait prob");
			exit(-1);
		}

		for (i = 0; i < MAX_modules; i++) {
			if (fins_modules[i] != NULL) {
				if (sem_wait(fins_modules[i]->output_sem)) {
					PRINT_ERROR("sem wait prob: src module_id=%d", i);
					exit(-1);
				}
				ff = read_queue(fins_modules[i]->output_queue);
				sem_post(fins_modules[i]->output_sem);

				if (ff != NULL) {
					counter++;

					id = ff->destinationID.id;
					if (id < 0 || id > MAX_modules) { //TODO check/change should be MAX_ID?
						PRINT_ERROR("dropping ff: illegal destination: src module_id=%d, dst module_id=%u, ff=%p, meta=%p", i, id, ff, ff->metaData);
						freeFinsFrame(ff);
					} else { //if (i != id) //TODO add this?
						if (fins_modules[id] != NULL) {
							PRINT_DEBUG("Counter=%d, from='%s', to='%s', ff=%p, meta=%p", counter, fins_modules[i]->name, fins_modules[id]->name, ff, ff->metaData);
							if (sem_wait(fins_modules[id]->input_sem)) {
								PRINT_ERROR("sem wait prob: dst module_id=%u, ff=%p, meta=%p", id, ff, ff->metaData);
								exit(-1);
							}
							if (write_queue(ff, fins_modules[id]->input_queue)) {
								sem_post(fins_modules[id]->event_sem);
								sem_post(fins_modules[id]->input_sem);
							} else {
								sem_post(fins_modules[id]->input_sem);
								PRINT_ERROR("Write queue error: dst module_id=%u, ff=%p, meta=%p", id, ff, ff->metaData);
								freeFinsFrame(ff);
							}
						} else {
							PRINT_ERROR("dropping ff: destination not registered: dst module_id=%u, ff=%p, meta=%p", id, ff, ff->metaData);
							freeFinsFrame(ff);
						}
					}
				}
			}
		}
	}

	PRINT_DEBUG("Exited");
	pthread_exit(NULL);
} // end of switch_init Function

void switch_init(void) {
	PRINT_CRITICAL("Entered");
	switch_proto.running_flag = 1;

	switch_proto.event_sem = (sem_t *) malloc(sizeof(sem_t));
	if (switch_proto.event_sem == NULL) {
		PRINT_ERROR("error alloc");
		exit(-1);
	}
	sem_init(switch_proto.event_sem, 0, 0);

	//module_create_ops(&switch_proto);
	//module_register(&switch_proto);

	//Queues_init(); //TODO split & move to each module
	//TODO not much, init queues here?

	int i;
	for (i = 0; i < MAX_modules; i++) {
		fins_modules[i] = NULL;
	}
}

void switch_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_CRITICAL("Entered");

	pthread_create(&switch_thread, fins_pthread_attr, switch_loop, fins_pthread_attr);
}

void switch_shutdown(void) {
	PRINT_CRITICAL("Entered");
	switch_proto.running_flag = 0;
	sem_post(switch_proto.event_sem);

	//TODO expand this

	PRINT_CRITICAL("Joining switch_thread");
	pthread_join(switch_thread, NULL);
}

void switch_release(void) {
	PRINT_CRITICAL("Entered");
	//TODO free all module related mem

	//module_unregister(switch_proto.module_id);
	//module_destroy_ops(&switch_proto);
	sem_destroy(switch_proto.event_sem);
	free(switch_proto.event_sem);
}
