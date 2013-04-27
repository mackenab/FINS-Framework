/*
 * logger.c
 *
 *  Created on: Feb 3, 2013
 *      Author: alex
 */
#include "logger_internal.h"

void *switch_to_logger(void *local) {
	struct fins_module *module = (struct fins_module *) local;

	PRINT_IMPORTANT("Entered: module=%p", module);

	while (module->state == FMS_RUNNING) {
		logger_get_ff(module);
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Exited: module=%p", module);
	return NULL;
}

void logger_get_ff(struct fins_module *module) {
	struct logger_data *data = (struct logger_data *) module->data;

	struct finsFrame *ff;
	do {
		secure_sem_wait(module->event_sem);
		secure_sem_wait(module->input_sem);
		ff = read_queue(module->input_queue);
		sem_post(module->input_sem);
	} while (module->state == FMS_RUNNING && ff == NULL && !data->interrupt_flag); //TODO change logic here, combine with switch_to_logger?

	if (module->state != FMS_RUNNING) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff != NULL) {
		if (ff->metaData == NULL) {
			PRINT_ERROR("Error fcf.metadata==NULL");
			exit(-1);
		}

		if (ff->dataOrCtrl == CONTROL) {
			logger_fcf(module, ff);
			PRINT_DEBUG("");
		} else if (ff->dataOrCtrl == DATA) {
			if (data->logger_started) {
				gettimeofday(&data->logger_end, 0);
				data->logger_packets++;
				data->logger_bytes += ff->dataFrame.pduLength;
				//logger_bytes += ff->dataFrame.pduLength-28; //for end-end throughput of exp 2, to remove IP/UDP hdrs
			} else {
				data->logger_started = 1;
				gettimeofday(&data->logger_start, 0);
				data->logger_packets = 1;
				data->logger_bytes = ff->dataFrame.pduLength;
				//logger_bytes = ff->dataFrame.pduLength-28; //for end-end throughput of exp 2, to remove IP/UDP hdrs

				data->logger_saved_packets = 0;
				data->logger_saved_bytes = 0;
				data->logger_saved_curr = 0;

				timer_once_start(data->logger_to_data->tid, data->logger_interval);
				PRINT_IMPORTANT("Logger starting");
			}
			freeFinsFrame(ff);
		} else {
			PRINT_ERROR("todo error");
			exit(-1);
		}
	} else if (data->interrupt_flag) {
		data->interrupt_flag = 0;

		logger_interrupt(module);
	} else {
		PRINT_ERROR("todo error");
	}
}

void logger_fcf(struct fins_module *module, struct finsFrame *ff) {
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
		logger_set_param(module, ff);
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

void logger_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	struct logger_data *data = (struct logger_data *) module->data;
	int i;

	switch (ff->ctrlFrame.param_id) {
	case LOGGER_SET_PARAM_FLOWS:
		PRINT_DEBUG("LOGGER_SET_PARAM_FLOWS");
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
	case LOGGER_SET_PARAM_LINKS:
		PRINT_DEBUG("LOGGER_SET_PARAM_LINKS");
		if (ff->ctrlFrame.data_len != sizeof(struct linked_list)) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}

		if (data->link_list != NULL) {
			list_free(data->link_list, free);
		}
		struct linked_list *link_list = (struct linked_list *) ff->ctrlFrame.data;
		data->link_list = link_list;

		ff->ctrlFrame.data = NULL;
		break;
	case LOGGER_SET_PARAM_DUAL:
		PRINT_DEBUG("LOGGER_SET_PARAM_DUAL");

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
	case LOGGER_SET_INTERVAL__id:
		PRINT_DEBUG("LOGGER_SET_INTERVAL");
		ff->destinationID = ff->ctrlFrame.sender_id;

		//TODO change to actual

		ff->ctrlFrame.sender_id = module->index;
		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		ff->ctrlFrame.ret_val = 0;

		module_to_switch(module, ff);
		break;
	case LOGGER_SET_REPEATS__id:
		PRINT_DEBUG("LOGGER_SET_REPEATS");
		ff->destinationID = ff->ctrlFrame.sender_id;

		//TODO change to actual

		ff->ctrlFrame.sender_id = module->index;
		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		ff->ctrlFrame.ret_val = 0;

		module_to_switch(module, ff);
		break;
	default:
		PRINT_DEBUG("param_id=default (%d)", ff->ctrlFrame.param_id);
		PRINT_ERROR("todo");
		break;
	}

	freeFinsFrame(ff);
}

void logger_interrupt(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);

	struct logger_data *data = (struct logger_data *) module->data;

	if (data->logger_started) {
		struct timeval current;
		gettimeofday(&current, 0);

		double diff_curr = time_diff(&data->logger_start, &current) / 1000.0;
		double diff_period = diff_curr - data->logger_saved_curr;
		int diff_packets = data->logger_packets - data->logger_saved_packets;
		int diff_bytes = data->logger_bytes - data->logger_saved_bytes;
		double diff_through = 8.0 * diff_bytes / diff_period;
		PRINT_IMPORTANT("period=%f-%f,\t packets=%d,\t bytes=%d,\t through=%f", data->logger_saved_curr, diff_curr, diff_packets, diff_bytes, diff_through);

		data->logger_saved_packets = data->logger_packets;
		data->logger_saved_bytes = data->logger_bytes;
		data->logger_saved_curr = diff_curr;

		//if (diff_curr > 2 * logger_repeats * logger_interval / 1000.0) {
		if (diff_curr >= 1 * data->logger_repeats * data->logger_interval / 1000.0) {
			data->logger_started = 0;

			double test = time_diff(&data->logger_start, &data->logger_end) / 1000.0;
			//double through = 8.0 * (logger_bytes - 10 * 1470) / test;
			double through = 8.0 * data->logger_bytes / test;
			PRINT_IMPORTANT("Logger stopping: total=%f,\t packets=%d,\t bytes=%d,\t through=%f", test, data->logger_packets, data->logger_bytes, through);
		} else {
			timer_once_start(data->logger_to_data->tid, data->logger_interval);
		}
	} else {
		PRINT_ERROR("run over?");
	}
}

void logger_init_params(struct fins_module *module) {
	metadata_element *root = config_root_setting(module->params);
	//int status;

	//-------------------------------------------------------------------------------------------
	metadata_element *exec_elem = config_setting_add(root, "exec", CONFIG_TYPE_GROUP);
	if (exec_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}

	//-------------------------------------------------------------------------------------------
	metadata_element *get_elem = config_setting_add(root, "get", CONFIG_TYPE_GROUP);
	if (get_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}
	elem_add_param(get_elem, LOGGER_GET_INTERVAL__str, LOGGER_GET_INTERVAL__id, LOGGER_GET_INTERVAL__type);
	elem_add_param(get_elem, LOGGER_GET_REPEATS__str, LOGGER_GET_REPEATS__id, LOGGER_GET_REPEATS__type);

	//-------------------------------------------------------------------------------------------
	metadata_element *set_elem = config_setting_add(root, "set", CONFIG_TYPE_GROUP);
	if (set_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}
	elem_add_param(set_elem, LOGGER_SET_INTERVAL__str, LOGGER_SET_INTERVAL__id, LOGGER_SET_INTERVAL__type);
	elem_add_param(set_elem, LOGGER_SET_REPEATS__str, LOGGER_SET_REPEATS__id, LOGGER_SET_REPEATS__type);
}

int logger_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi) {
	PRINT_IMPORTANT("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	logger_init_params(module);

	module->data = secure_malloc(sizeof(struct logger_data));
	struct logger_data *data = (struct logger_data *) module->data;

	if (module->flows_max < flows_num) {
		PRINT_ERROR("todo error");
		return 0;
	}
	data->flows_num = flows_num;

	int i;
	for (i = 0; i < flows_num; i++) {
		data->flows[i] = flows[i];
	}

	//TODO extract this from meta?
	data->logger_started = 0;
	data->logger_interval = 1000;
	data->logger_repeats = 10;

	data->logger_to_data = secure_malloc(sizeof(struct intsem_to_timer_data));
	data->logger_to_data->handler = intsem_to_handler;
	data->logger_to_data->flag = &data->logger_flag;
	data->logger_to_data->interrupt = &data->interrupt_flag;
	data->logger_to_data->sem = module->event_sem;
	timer_create_to((struct to_timer_data *) data->logger_to_data);

	return 1;
}

int logger_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_IMPORTANT("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	struct logger_data *data = (struct logger_data *) module->data;
	secure_pthread_create(&data->switch_to_logger_thread, attr, switch_to_logger, module);

	return 1;
}

int logger_pause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_PAUSED;

	//TODO
	return 1;
}

int logger_unpause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_RUNNING;

	//TODO
	return 1;
}

int logger_shutdown(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN;
	sem_post(module->event_sem);

	struct logger_data *data = (struct logger_data *) module->data;
	timer_stop(data->logger_to_data->tid);

	//TODO expand this

	PRINT_IMPORTANT("Joining switch_to_logger_thread");
	pthread_join(data->switch_to_logger_thread, NULL);

	return 1;
}

int logger_release(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);

	struct logger_data *data = (struct logger_data *) module->data;
	//TODO free all module related mem

	//delete threads
	timer_delete(data->logger_to_data->tid);
	free(data->logger_to_data);

	if (data->link_list != NULL) {
		list_free(data->link_list, free);
	}
	free(data);
	module_destroy_structs(module);
	free(module);
	return 1;
}

void logger_dummy(void) {

}

static struct fins_module_ops logger_ops = { .init = logger_init, .run = logger_run, .pause = logger_pause, .unpause = logger_unpause, .shutdown =
		logger_shutdown, .release = logger_release, };

struct fins_module *logger_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_IMPORTANT("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, LOGGER_LIB);
	module->flows_max = LOGGER_MAX_FLOWS;
	module->ops = &logger_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_IMPORTANT("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
