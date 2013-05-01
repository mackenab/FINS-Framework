/*
 * IP4_fdf_in.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "ipv4_internal.h"
#include <finsqueue.h>

void ipv4_get_ff(struct fins_module *module) {
	struct finsFrame *ff;
	do {
		secure_sem_wait(module->event_sem);
		secure_sem_wait(module->input_sem);
		ff = read_queue(module->input_queue);
		sem_post(module->input_sem);
	} while (module->state == FMS_RUNNING && ff == NULL); //TODO change logic here, combine with switch_to_logger?

	if (module->state != FMS_RUNNING) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff->metaData == NULL) {
		PRINT_ERROR("Error fcf.metadata==NULL");
		exit(-1);
	}

	if (ff->dataOrCtrl == FF_CONTROL) {
		ipv4_fcf(module, ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == FF_DATA) {
		if (ff->dataFrame.directionFlag == DIR_UP) {
			ipv4_in_fdf(module, ff);
			PRINT_DEBUG("");
		} else if (ff->dataFrame.directionFlag == DIR_DOWN) {
			ipv4_out_fdf(module, ff);
			PRINT_DEBUG("");
		} else {
			PRINT_ERROR("Error: Wrong value of fdf.directionFlag");
			freeFinsFrame(ff);
		}
	} else {
		PRINT_ERROR("Error: Wrong ff->dataOrCtrl value");
		exit(-1);
	}

}

void ipv4_fcf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	//TODO make sure is meant for IP, filter out FCF sent through flows w/multi dest

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
		ipv4_read_param(module, ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		ipv4_set_param(module, ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		ipv4_exec(module, ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		ipv4_exec_reply(module, ff);
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

void ipv4_read_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_ERROR("todo");
	freeFinsFrame(ff);
}

void ipv4_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	struct ipv4_data *data = (struct ipv4_data *) module->data;
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

void ipv4_exec(struct fins_module *module, struct finsFrame *ff) {
	PRINT_ERROR("todo");
	freeFinsFrame(ff);
}

void ipv4_exec_reply(struct fins_module *module, struct finsFrame *ff) {
	PRINT_ERROR("todo");
	freeFinsFrame(ff);
}
