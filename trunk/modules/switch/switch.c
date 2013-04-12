/**
 * @file switch.c
 *
 *  @date Mar 14, 2011
 *      @author Abdallah Abdallah
 */

#include "switch_internal.h"

void module_create_queues(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p, id=%d, name='%s'", module, module->id, module->name);
	char buf[MOD_NAME_SIZE + 10];

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

void module_destroy_queues(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p, id=%d, name='%s'", module, module->id, module->name);

	term_queue(module->output_queue);
	term_queue(module->input_queue);

	sem_destroy(module->output_sem);
	free(module->output_sem);
	sem_destroy(module->input_sem);
	free(module->input_sem);
	sem_destroy(module->event_sem);
	free(module->event_sem);
}

int module_to_switch(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, id=%d, name='%s', ff=%p, meta=%p", module, module->id, module->name, ff, ff->metaData);
	int ret;

	while ((ret = sem_wait(module->output_sem)) && errno == EINTR)
		;
	if (ret) {
		PRINT_ERROR("output_sem wait prob: module=%p, id=%d, name='%s', ff=%p, meta=%p, ret=%d", module, module->id, module->name, ff, ff->metaData, ret);
		exit(-1);
	}
	if (write_queue(ff, module->output_queue)) {
		PRINT_DEBUG("Exited: module=%p, id=%d, name='%s', 1", module, module->id, module->name);
		sem_post(switch_module->event_sem);
		sem_post(module->output_sem);
		return 1;
	} else {
		PRINT_ERROR("Exited: module=%p, id=%d, name='%s', ff=%p, 0", module, module->id, module->name, ff);
		sem_post(module->output_sem);
		return 0;
	}
}

//TODO redo this for new fins_module's, check functionality
int module_register(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p, id=%d, name='%s'", module, module->id, module->name);

	if (module->index >= MAX_MODULES) {
		PRINT_ERROR("todo error");
		return -1;
	}

	struct switch_data *data = (struct switch_data *) switch_module->data;

	secure_sem_wait(switch_module->input_sem);
	if (data->fins_modules[module->id] != NULL) {
		PRINT_IMPORTANT("Replacing: module=%p, module_id=%d, name='%s'",
				data->fins_modules[module->id], data->fins_modules[module->id]->id, data->fins_modules[module->id]->name);
	}
	PRINT_IMPORTANT("Registered: module=%p, module_id=%d, name='%s'", module, module->id, module->name);
	data->fins_modules[module->id] = module;
	sem_post(switch_module->input_sem);

	PRINT_DEBUG("Exited: module=%p, module_id=%d, name='%s'", module, module->id, module->name);
	return 0;
}

//TODO redo this for new fins_module's, check functionality
void module_unregister(int module_id) {
	PRINT_DEBUG("Entered: module_id=%d", module_id);

	if (module_id < 0 || module_id > MAX_MODULES) {
		PRINT_ERROR("todo error");
		return;
	}

	struct switch_data *data = (struct switch_data *) switch_module->data;

	secure_sem_wait(switch_module->input_sem);
	if (data->fins_modules[module_id] != NULL) {
		PRINT_IMPORTANT("Unregistering: module=%p, module_id=%d, name='%s'",
				data->fins_modules[module_id], data->fins_modules[module_id]->id, data->fins_modules[module_id]->name);
		data->fins_modules[module_id] = NULL;
	} else {
		PRINT_IMPORTANT("No module to unregister: module_id=%d", module_id);
	}
	sem_post(switch_module->input_sem);
}

void *switch_loop(void *local) {
	struct fins_module *module = (struct fins_module *) local;

	PRINT_IMPORTANT("Entered: module=%p", module);

	struct switch_data *data = (struct switch_data *) module->data;

	int i;
	int ret;
	struct finsFrame *ff;
	uint8_t id;

	int counter = 0;

	while (module->state == FMS_RUNNING) {
		secure_sem_wait(module->event_sem);
		secure_sem_wait(module->input_sem);
		for (i = 0; i < MAX_MODULES; i++) {
			if (data->fins_modules[i] != NULL) {
				if (!IsEmpty(data->fins_modules[i]->output_queue)) { //added as optimization
					while ((ret = sem_wait(data->fins_modules[i]->output_sem)) && errno == EINTR)
						;
					if (ret) {
						PRINT_ERROR("sem wait prob: src module_id=%d, ret=%d", i, ret);
						exit(-1);
					}
					ff = read_queue(data->fins_modules[i]->output_queue);
					sem_post(data->fins_modules[i]->output_sem);

					//if (ff != NULL) { //shouldn't occur
					counter++;

					id = ff->destinationID;
					if (id < 0 || id > MAX_MODULES) { //TODO check/change should be MAX_ID?
						PRINT_ERROR("dropping ff: illegal destination: src module_id=%d, dst module_id=%u, ff=%p, meta=%p", i, id, ff, ff->metaData);
						//TODO if FCF set ret_val=0 & return? or free or just exit(-1)?
						freeFinsFrame(ff);
					} else { //if (i != id) //TODO add this?
						//id = LOGGER_ID; //TODO comment
						if (data->fins_modules[id] != NULL) {
							PRINT_DEBUG("Counter=%d, from='%s', to='%s', ff=%p, meta=%p",
									counter, data->fins_modules[i]->name, data->fins_modules[id]->name, ff, ff->metaData);
							while ((ret = sem_wait(data->fins_modules[id]->input_sem)) && errno == EINTR)
								;
							if (ret) {
								PRINT_ERROR("sem wait prob: dst module_id=%u, ff=%p, meta=%p, ret=%d", id, ff, ff->metaData, ret);
								exit(-1);
							}
							if (write_queue(ff, data->fins_modules[id]->input_queue)) {
								sem_post(data->fins_modules[id]->event_sem);
								sem_post(data->fins_modules[id]->input_sem);
							} else {
								sem_post(data->fins_modules[id]->input_sem);
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
		sem_post(module->input_sem);
	}

	PRINT_IMPORTANT("Exited");
	//pthread_exit(NULL);
	return NULL;
} // end of switch_init Function

int switch_init(struct fins_module *module, metadata *meta, struct envi_record *envi) {
	PRINT_IMPORTANT("Entered: module=%p, meta=%p, envi=%p", module, meta, envi);
	module->state = FMS_INIT;

	//module_create_queues(module);
	module->event_sem = (sem_t *) secure_malloc(sizeof(sem_t)); //triggered when activity on module output queues
	sem_init(module->event_sem, 0, 0);

	module->input_sem = (sem_t *) secure_malloc(sizeof(sem_t)); //protecting module list
	sem_init(module->input_sem, 0, 1);

	module->data = secure_malloc(sizeof(struct switch_data));
	struct switch_data *data = (struct switch_data *) module->data;

	int i;
	for (i = 0; i < MAX_MODULES; i++) {
		data->fins_modules[i] = NULL;
	}

	return 1;
}

int switch_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_IMPORTANT("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	struct switch_data *data = (struct switch_data *) module->data;
	secure_pthread_create(&data->switch_thread, attr, switch_loop, module);

	return 1;
}

int switch_pause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_PAUSED;

	//TODO
	return 1;
}

int switch_unpause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_RUNNING;

	//TODO
	return 1;
}

int switch_shutdown(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN;
	sem_post(module->event_sem);

	struct switch_data *data = (struct switch_data *) module->data;

	//TODO expand this

	PRINT_IMPORTANT("Joining switch_thread");
	pthread_join(data->switch_thread, NULL);

	return 1;
}

int switch_release(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);

	struct switch_data *data = (struct switch_data *) module->data;
	//TODO free all module related mem

	free(data);

	//module_destroy_queues(module);
	sem_destroy(module->input_sem);
	free(module->input_sem);

	sem_destroy(module->event_sem);
	free(module->event_sem);

	free(module);
	return 1;
}

void switch_dummy(void) {

}

static struct fins_module_ops switch_ops = { .init = switch_init, .run = switch_run, .pause = switch_pause, .unpause = switch_unpause, .shutdown =
		switch_shutdown, .release = switch_release, };

struct fins_module *switch_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_IMPORTANT("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, "logger");
	module->ops = &switch_ops;
	module->state = FMS_FREE;
	module->num_ports = 0; //TODO change?

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	switch_module = module;

	PRINT_IMPORTANT("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
