/**
 * @file switch.c
 *
 *  @date Mar 14, 2011
 *      @author Abdallah Abdallah
 */
#include "switch.h"

#include <finsdebug.h>
#include <finstypes.h>
#include <metadata.h>
#include <finsqueue.h>

static struct fins_proto_module switch_proto = { .module_id = SWITCH_ID, .name = "switch", .running_flag = 1, };

pthread_t switch_thread;

static struct fins_proto_module *fins_modules[MAX_MODULES];
static struct fins_module *fins_modules_new[MAX_MODULES];

void module_create_ops(struct fins_proto_module *module) {
	PRINT_DEBUG("Entered: module=%p, module_id=%d, name='%s'", module, module->module_id, module->name);
	char buf[MOD_NAME_SIZE+10];

	sprintf(buf, "switch_to_%s", module->name);
	module->input_queue = init_queue(buf, MAX_QUEUE_SIZE);
	module->input_sem = (sem_t *) secure_malloc(sizeof(sem_t));
	sem_init(module->input_sem, 0, 1);

	sprintf(buf, "%s_to_switch", module->name);
	module->output_queue = init_queue(buf, MAX_QUEUE_SIZE);
	module->output_sem = (sem_t *) secure_malloc(sizeof(sem_t));
	sem_init(module->output_sem, 0, 1);

	module->event_sem = (sem_t *) secure_malloc(sizeof(sem_t));
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

	if (module->module_id >= MAX_MODULES) {
		PRINT_ERROR("todo error");
		return -1;
	}

	secure_sem_wait(switch_proto.input_sem);
	if (fins_modules[module->module_id] != NULL) {
		PRINT_IMPORTANT("Replacing: module=%p, module_id=%d, name='%s'", fins_modules[module->module_id], fins_modules[module->module_id]->module_id, fins_modules[module->module_id]->name);
	}
	PRINT_IMPORTANT("Registered: module=%p, module_id=%d, name='%s'", module, module->module_id, module->name);
	fins_modules[module->module_id] = module;
	sem_post(switch_proto.input_sem);

	PRINT_DEBUG("Exited: module=%p, module_id=%d, name='%s'", module, module->module_id, module->name);
	return 0;
}

void module_unregister(int module_id) {
	PRINT_DEBUG("Entered: module_id=%d", module_id);

	if (module_id < 0 || module_id > MAX_MODULES) {
		PRINT_ERROR("todo error");
		return;
	}

	secure_sem_wait(switch_proto.input_sem);
	if (fins_modules[module_id] != NULL) {
		PRINT_IMPORTANT("Unregistering: module=%p, module_id=%d, name='%s'", fins_modules[module_id], fins_modules[module_id]->module_id, fins_modules[module_id]->name);
		fins_modules[module_id] = NULL;
	} else {
		PRINT_IMPORTANT("No module to unregister: module_id=%d", module_id);
	}
	sem_post(switch_proto.input_sem);
}

int module_to_switch(struct fins_proto_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, module_id=%d, name='%s', ff=%p, meta=%p", module, module->module_id, module->name, ff, ff->metaData);
	int ret;

	while ((ret = sem_wait(module->output_sem)) && errno == EINTR);
	if (ret) {
		PRINT_ERROR("output_sem wait prob: module=%p, module_id=%d, name='%s', ff=%p, meta=%p, ret=%d", module, module->module_id, module->name, ff, ff->metaData, ret);
		exit(-1);
	}
	if (write_queue(ff, module->output_queue)) {
		PRINT_DEBUG("Exited: module=%p, module_id=%d, name='%s', 1", module, module->module_id, module->name);
		sem_post(switch_proto.event_sem);
		sem_post(module->output_sem);
		return 1;
	} else {
		PRINT_ERROR("Exited: module=%p, module_id=%d, name='%s', ff=%p, 0", module, module->module_id, module->name, ff);
		sem_post(module->output_sem);
		return 0;
	}
}

void *switch_loop(void *local) {
	PRINT_IMPORTANT("Entered");

	int i;
	int ret;
	struct finsFrame *ff;
	uint8_t id;

	int counter = 0;

	while (switch_proto.running_flag) {
		secure_sem_wait(switch_proto.event_sem);
		secure_sem_wait(switch_proto.input_sem);
		for (i = 0; i < MAX_MODULES; i++) {
			if (fins_modules[i] != NULL) {
				if (!IsEmpty(fins_modules[i]->output_queue)) { //added as optimization
					while ((ret = sem_wait(fins_modules[i]->output_sem)) && errno == EINTR);
					if (ret) {
						PRINT_ERROR("sem wait prob: src module_id=%d, ret=%d", i, ret);
						exit(-1);
					}
					ff = read_queue(fins_modules[i]->output_queue);
					sem_post(fins_modules[i]->output_sem);

					//if (ff != NULL) { //shouldn't occur
					counter++;

					id = ff->destinationID.id;
					if (id < 0 || id > MAX_MODULES) { //TODO check/change should be MAX_ID?
						PRINT_ERROR("dropping ff: illegal destination: src module_id=%d, dst module_id=%u, ff=%p, meta=%p", i, id, ff, ff->metaData);
						//TODO if FCF set ret_val=0 & return? or free or just exit(-1)?
						freeFinsFrame(ff);
					} else { //if (i != id) //TODO add this?
						//id = LOGGER_ID; //TODO comment
						if (fins_modules[id] != NULL) {
							PRINT_DEBUG("Counter=%d, from='%s', to='%s', ff=%p, meta=%p", counter, fins_modules[i]->name, fins_modules[id]->name, ff, ff->metaData);
							while ((ret = sem_wait(fins_modules[id]->input_sem)) && errno == EINTR);
							if (ret) {
								PRINT_ERROR("sem wait prob: dst module_id=%u, ff=%p, meta=%p, ret=%d", id, ff, ff->metaData, ret);
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
							PRINT_ERROR("dropping ff: destination not registered: src module_id=%u, dst module_id=%u, ff=%p, meta=%p", i, id, ff, ff->metaData);
							print_finsFrame(ff);
							//TODO if FCF set ret_val=0 & return? or free or just exit(-1)?
							freeFinsFrame(ff);
						}
					}
					//}
				}
			}
		}
		sem_post(switch_proto.input_sem);
	}

	PRINT_IMPORTANT("Exited");
	//pthread_exit(NULL);
	return NULL;
} // end of switch_init Function

void switch_dummy(void) {

}

void switch_init(void) {
	PRINT_IMPORTANT("Entered");
	switch_proto.running_flag = 1;

	switch_proto.event_sem = (sem_t *) secure_malloc(sizeof(sem_t)); //triggered when activity on module output queues
	sem_init(switch_proto.event_sem, 0, 0);

	switch_proto.input_sem = (sem_t *) secure_malloc(sizeof(sem_t)); //protecting module list
	sem_init(switch_proto.input_sem, 0, 1);

	//module_create_ops(&switch_proto);
	//module_register(&switch_proto);

	int i;
	for (i = 0; i < MAX_MODULES; i++) {
		fins_modules[i] = NULL;
	}
}

void switch_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_IMPORTANT("Entered");

	secure_pthread_create(&switch_thread, fins_pthread_attr, switch_loop, fins_pthread_attr);
}

void switch_shutdown(void) {
	PRINT_IMPORTANT("Entered");
	switch_proto.running_flag = 0;
	sem_post(switch_proto.event_sem);

	//TODO expand this

	PRINT_IMPORTANT("Joining switch_thread");
	pthread_join(switch_thread, NULL);
}

void switch_release(void) {
	PRINT_IMPORTANT("Entered");
	//TODO free all module related mem

	//module_unregister(switch_proto.module_id);
	//module_destroy_ops(&switch_proto);
	sem_destroy(switch_proto.input_sem);
	free(switch_proto.input_sem);

	sem_destroy(switch_proto.event_sem);
	free(switch_proto.event_sem);
}
