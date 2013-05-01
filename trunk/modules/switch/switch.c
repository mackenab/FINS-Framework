/**
 * @file switch.c
 *
 *  @date Mar 14, 2011
 *      @author Abdallah Abdallah
 */

#include "switch_internal.h"

void *switch_loop(void *local) {
	struct fins_module *module = (struct fins_module *) local;

	PRINT_IMPORTANT("Entered: module=%p", module);

	struct switch_data *data = (struct switch_data *) module->data;

	uint32_t i;
	int ret;
	struct finsFrame *ff;
	uint8_t index;

	int counter = 0;

	while (module->state == FMS_RUNNING) {
		secure_sem_wait(module->event_sem);
		//secure_sem_wait(module->input_sem);
		secure_sem_wait(&data->overall->sem);
		for (i = 0; i < MAX_MODULES; i++) {
			if (data->overall->modules[i] != NULL) {
				if (!IsEmpty(data->overall->modules[i]->output_queue)) { //added as optimization
					while ((ret = sem_wait(data->overall->modules[i]->output_sem)) && errno == EINTR)
						;
					if (ret != 0) {
						PRINT_ERROR("sem wait prob: src module_index=%u, ret=%d", i, ret);
						exit(-1);
					}
					ff = read_queue(data->overall->modules[i]->output_queue);
					sem_post(data->overall->modules[i]->output_sem);

					//if (ff != NULL) { //shouldn't occur
					counter++;

					index = ff->destinationID;
					if (index < 0 || index > MAX_MODULES) { //TODO check/change should be MAX_ID?
						PRINT_ERROR("dropping ff: illegal destination: src module_index=%u, dst module_index=%u, ff=%p, meta=%p", i, index, ff, ff->metaData);
						//TODO if FCF set ret_val=0 & return? or free or just exit(-1)?
						freeFinsFrame(ff);
					} else { //if (i != id) //TODO add this?
						//id = LOGGER_ID; //TODO comment
						if (data->overall->modules[index] != NULL) {
							PRINT_DEBUG("Counter=%d, from='%s', to='%s', ff=%p, meta=%p",
									counter, data->overall->modules[i]->name, data->overall->modules[index]->name, ff, ff->metaData);
							//TODO decide if should drop all traffic to switch input queues, or use that as linking table requests
							if (index == module->index) {
								switch_process_ff(module, ff);
							} else {
								while ((ret = sem_wait(data->overall->modules[index]->input_sem)) && errno == EINTR)
									;
								if (ret != 0) {
									PRINT_ERROR("sem wait prob: dst index=%u, ff=%p, meta=%p, ret=%d", index, ff, ff->metaData, ret);
									exit(-1);
								}
								if (write_queue(ff, data->overall->modules[index]->input_queue)) {
									sem_post(data->overall->modules[index]->event_sem);
									sem_post(data->overall->modules[index]->input_sem);
								} else {
									sem_post(data->overall->modules[index]->input_sem);
									PRINT_ERROR("Write queue error: dst index=%u, ff=%p, meta=%p", index, ff, ff->metaData);
									freeFinsFrame(ff);
								}
							}
						} else {
							PRINT_ERROR("dropping ff: destination not registered: src index=%u, dst index=%u, ff=%p, meta=%p", i, index, ff, ff->metaData);
							print_finsFrame(ff);
							//TODO if FCF set ret_val=0 & return? or free or just exit(-1)?
							freeFinsFrame(ff);
						}
					}
					//}
				}
			}
		}
		//sem_post(module->input_sem);
		sem_post(&data->overall->sem);
	}

	PRINT_IMPORTANT("Exited: module=%p", module);
	return NULL;
}

void switch_process_ff(struct fins_module *module, struct finsFrame *ff) {
	PRINT_IMPORTANT("Entered: module=%p, ff=%p", module, ff);

	if (ff->metaData == NULL) {
		PRINT_ERROR("Error fcf.metadata==NULL");
		exit(-1);
	}

	PRINT_ERROR("TODO: switch process received frames: ff=%p, meta=%p", ff, ff->metaData);
	print_finsFrame(ff);

	if (ff->dataOrCtrl == FF_CONTROL) {
		switch_fcf(module, ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == FF_DATA) {
		if (ff->dataFrame.directionFlag == DIR_UP) {
			//switch_in_fdf(module, ff);
			PRINT_DEBUG("todo");
			freeFinsFrame(ff);
		} else if (ff->dataFrame.directionFlag == DIR_DOWN) {
			//switch_out_fdf(ff);
			PRINT_ERROR("todo");
			freeFinsFrame(ff);
		} else {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
		}
	} else {
		PRINT_ERROR("todo error: dataOrCtrl=%u", ff->dataOrCtrl);
		exit(-1);
	}
}

void switch_fcf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		switch_set_param(module, ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	}
}

void switch_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	struct switch_data *data = (struct switch_data *) module->data;
	int i;

	switch (ff->ctrlFrame.param_id) {
	case MOD_SET_PARAM_FLOWS:
		PRINT_DEBUG("PARAM_FLOWS");
		uint32_t flows_num = ff->ctrlFrame.data_len / sizeof(uint32_t);
		uint32_t *flows = (uint32_t *) ff->ctrlFrame.data;

		if (module->flows_max < flows_num) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}
		data->flows_num = flows_num;

		for (i = 0; i < flows_num; i++) {
			data->flows[i] = flows[i];
		}

		//freeFF frees flows
		break;
	case MOD_SET_PARAM_LINKS:
		PRINT_DEBUG("PARAM_LINKS");
		if (ff->ctrlFrame.data_len != sizeof(struct linked_list)) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}

		if (data->link_list != NULL) {
			list_free(data->link_list, free);
		}
		data->link_list = (struct linked_list *) ff->ctrlFrame.data;

		ff->ctrlFrame.data = NULL;
		break;
	case MOD_SET_PARAM_DUAL:
		PRINT_DEBUG("PARAM_DUAL");

		if (ff->ctrlFrame.data_len != sizeof(struct fins_module_table)) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}
		struct fins_module_table *table = (struct fins_module_table *) ff->ctrlFrame.data;

		if (module->flows_max < table->flows_num) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}
		data->flows_num = table->flows_num;

		for (i = 0; i < table->flows_num; i++) {
			data->flows[i] = table->flows[i];
		}

		if (data->link_list != NULL) {
			list_free(data->link_list, free);
		}
		data->link_list = table->link_list;

		//freeFF frees table
		break;
	default:
		PRINT_DEBUG("param_id=default (%d)", ff->ctrlFrame.param_id);
		PRINT_ERROR("todo");
		break;
	}

	freeFinsFrame(ff);
}

void switch_init_params(struct fins_module *module) {
	metadata_element *root = config_root_setting(module->params);
	metadata_element *sub = config_setting_add(root, "test", CONFIG_TYPE_GROUP);
	if (sub == NULL) {
		PRINT_DEBUG("todo error");
	}

	metadata_element *elem = config_setting_add(sub, "key", CONFIG_TYPE_INT);
	if (elem == NULL) {
		PRINT_DEBUG("todo error");
	}

	uint32_t value = 10;
	int status = config_setting_set_int(elem, *(int *) &value);
	if (status == CONFIG_FALSE) {
		PRINT_DEBUG("todo error");
	}
}

int switch_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi) {
	PRINT_IMPORTANT("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	switch_event_sem = module->event_sem;

	switch_init_params(module);

	module->data = secure_malloc(sizeof(struct switch_data));
	struct switch_data *data = (struct switch_data *) module->data;

	if (module->flows_max < flows_num) {
		PRINT_ERROR("todo error");
		return 0;
	}
	data->flows_num = flows_num;

	int i;
	for (i = 0; i < flows_num; i++) {
		data->flows[i] = flows[i];
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

	if (data->link_list != NULL) {
		list_free(data->link_list, free);
	}
	free(data);
	module_destroy_structs(module);
	free(module);
	return 1;
}

//TODO remove? deprecated
int switch_register_module(struct fins_module *module, struct fins_module *new_mod) {
	PRINT_DEBUG("Entered: module=%p, new_mod=%p, id=%d, name='%s'", module, new_mod, new_mod->id, new_mod->name);

	if (new_mod->index >= MAX_MODULES) {
		PRINT_ERROR("todo error");
		return -1;
	}

	struct switch_data *data = (struct switch_data *) module->data;

	secure_sem_wait(module->input_sem);
	if (data->overall->modules[new_mod->index] != NULL) {
		PRINT_IMPORTANT("Replacing: mod=%p, id=%d, name='%s'",
				data->overall->modules[new_mod->index], data->overall->modules[new_mod->index]->id, data->overall->modules[new_mod->index]->name);
	}
	PRINT_IMPORTANT("Registered: new_mod=%p, id=%d, name='%s'", new_mod, new_mod->id, new_mod->name);
	data->overall->modules[new_mod->index] = new_mod;
	sem_post(module->input_sem);

	PRINT_DEBUG("Exited: module=%p, new_mod=%p, id=%d, name='%s'", module, new_mod, new_mod->id, new_mod->name);
	return 0;
}

//TODO remove? deprecated
int switch_unregister_module(struct fins_module *module, int index) {
	PRINT_DEBUG("Entered: module=%p, index=%d", module, index);

	if (index < 0 || index > MAX_MODULES) {
		PRINT_ERROR("todo error");
		return 0;
	}

	struct switch_data *data = (struct switch_data *) module->data;

	secure_sem_wait(module->input_sem);
	if (data->overall->modules[index] != NULL) {
		PRINT_IMPORTANT("Unregistering: mod=%p, id=%d, name='%s'",
				data->overall->modules[index], data->overall->modules[index]->id, data->overall->modules[index]->name);
		data->overall->modules[index] = NULL;
	} else {
		PRINT_IMPORTANT("No module to unregister: index=%d", index);
	}
	sem_post(module->input_sem);

	return 1;
}

int switch_pass_overall(struct fins_module *module, struct fins_overall *overall) {
	PRINT_DEBUG("Entered: module=%p, overall=%p", module, overall);

	struct switch_data *data = (struct switch_data *) module->data;
	data->overall = overall;

	return 1;
}

void switch_dummy(void) {

}

static struct fins_module_admin_ops switch_ops = { .init = switch_init, .run = switch_run, .pause = switch_pause, .unpause = switch_unpause, .shutdown =
		switch_shutdown, .release = switch_release, .pass_overall = switch_pass_overall };

struct fins_module *switch_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_IMPORTANT("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, SWITCH_LIB);
	module->flows_max = SWITCH_MAX_FLOWS;
	module->ops = (struct fins_module_ops *) &switch_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_IMPORTANT("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
