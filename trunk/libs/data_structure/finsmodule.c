/*
 * finsmodule.c
 *
 *  Created on: Apr 18, 2013
 *      Author: Jonathan Reed
 */

#include "finsmodule.h"

int mod_id_test(struct fins_module *mod, uint32_t *id) {
	return mod->id == *id;
}

int link_id_test(struct link_record *link, uint32_t *id) {
	return link->id == *id;
}

int link_involved_test(struct link_record *link, uint32_t *index) {
	if (link->src_index == *index) {
		return 1;
	} else {
		int i;
		for (i = 0; i < link->dsts_num; i++) {
			if (link->dsts_index[i] == *index) {
				return 1;
			}
		}
		return 0;
	}
}

struct link_record *link_clone(struct link_record *link) {
	PRINT_DEBUG("Entered: link=%p", link);

	struct link_record *link_clone = (struct link_record *) secure_malloc(sizeof(struct link_record));
	memcpy(link_clone, link, sizeof(struct link_record)); //would need to change if linked_list

	PRINT_DEBUG("Exited: link=%p, ret=%p", link, link_clone);
	return link_clone;
}

void module_create_structs(struct fins_module *module) {
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

	module->params = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(module->params);
}

void module_destroy_structs(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p, id=%d, name='%s'", module, module->id, module->name);

	term_queue(module->output_queue);
	term_queue(module->input_queue);

	sem_destroy(module->output_sem);
	free(module->output_sem);
	sem_destroy(module->input_sem);
	free(module->input_sem);
	sem_destroy(module->event_sem);
	free(module->event_sem);

	metadata_destroy(module->params);
}

void module_to_switch_full(const char *file, const char *func, int line, struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, id=%d, name='%s', ff=%p, meta=%p", module, module->id, module->name, ff, ff->metaData);
	int ret;

	while ((ret = sem_wait(module->output_sem)) && errno == EINTR)
		;
	if (ret != 0) {
#ifdef ERROR
		printf("ERROR(%s, %s, %d):output_sem wait prob: module=%p, id=%d, name='%s', ff=%p, meta=%p, ret=%d\n", file, func, line, module, module->id,
				module->name, ff, ff->metaData, ret);
		fflush(stdout);
#endif
		exit(-1);
	}
	if (write_queue(ff, module->output_queue)) {
		PRINT_DEBUG("Exited: module=%p, id=%d, name='%s', 1", module, module->id, module->name);
		sem_post(switch_event_sem);
		sem_post(module->output_sem);
	} else {
		sem_post(module->output_sem);
#ifdef ERROR
		printf("ERROR(%s, %s, %d):write_queue fail: module=%p, id=%d, name='%s', ff=%p, 0\n", file, func, line, module, module->id, module->name, ff);
		fflush(stdout);
#endif
		exit(-1);
	}
}

void module_reply_fcf(struct fins_module *module, struct finsFrame *ff, uint32_t ret_val, uint32_t ret_msg) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, ret_val=%u, ret_msg=%u", module, ff, ret_val, ret_msg);

	secure_metadata_writeToElement(ff->metaData, "ret_msg", &ret_msg, META_TYPE_INT32);

	ff->destinationID = ff->ctrlFrame.sender_id;

	ff->ctrlFrame.sender_id = module->index;
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		ff->ctrlFrame.opcode = CTRL_ALERT_REPLY;
		break;
	case CTRL_READ_PARAM:
		ff->ctrlFrame.opcode = CTRL_READ_PARAM_REPLY;
		break;
	case CTRL_SET_PARAM:
		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		break;
	case CTRL_EXEC:
		ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
		break;
	default:
		PRINT_ERROR("Unhandled msg case: opcode=%u", ff->ctrlFrame.opcode);
		exit(-1);
		return;
	}
	ff->ctrlFrame.ret_val = ret_val;

	module_to_switch(module, ff);
}

//exits - problem sending
//0 - flow outside range, no link
//dst_num - sent all ff
int module_send_flow(struct fins_module *module, struct finsFrame *ff, uint32_t flow) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, flow=%u", module, ff, flow);
	struct fins_module_table *table = (struct fins_module_table *) module->data;

	PRINT_DEBUG("table: flows_num=%u", table->flows_num);
	if (flow >= table->flows_num) {
		PRINT_DEBUG("Exited: module=%p, ff=%p, flow=%u, ret=%d", module, ff, flow, 0);
		return 0;
	}

	PRINT_DEBUG("table->flows[%u]=%u", flow, table->flows[flow]);
	if (table->flows[flow] == LINK_NULL) {
		PRINT_DEBUG("Exited: module=%p, ff=%p, flow=%u, ret=%d", module, ff, flow, 0);
		return 0;
	}

	struct link_record *link = (struct link_record *) list_find1(table->link_list, link_id_test, &table->flows[flow]);
	if (link == NULL) {
		PRINT_DEBUG("Exited: module=%p, ff=%p, flow=%u, ret=%d", module, ff, flow, 0);
		return 0;
	}
	PRINT_DEBUG("link=%p, id=%u, src=%u, dst_num=%u", link, link->id, link->src_index, link->dsts_num);

	if (link->dsts_num == 0) {
		PRINT_DEBUG("Exited: module=%p, ff=%p, flow=%u, ret=%d", module, ff, flow, 0);
		return 0;
	} else {
		struct finsFrame *ff_clone;

		int i;
		for (i = 1; i < link->dsts_num; i++) {
			ff_clone = cloneFinsFrame(ff);
			ff_clone->destinationID = link->dsts_index[i];
			module_to_switch(module, ff_clone);
		}

		ff->destinationID = link->dsts_index[0];
		module_to_switch(module, ff);

		PRINT_DEBUG("Exited: module=%p, ff=%p, flow=%u, ret=%d", module, ff, flow, link->dsts_num);
		return link->dsts_num;
	}
}

void module_set_param_flows(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct fins_module_table *mt = (struct fins_module_table *) module->data;

	uint32_t flows_num = ff->ctrlFrame.data_len / sizeof(uint32_t);
	uint32_t *flows = (uint32_t *) ff->ctrlFrame.data;

	if (module->flows_max < flows_num) {
		PRINT_ERROR("todo error");
		freeFinsFrame(ff);
		return;
	}
	mt->flows_num = flows_num;

	int i;
	for (i = 0; i < flows_num; i++) {
		mt->flows[i] = flows[i];
	}

	//freeFF frees flows
	freeFinsFrame(ff);
}

void module_set_param_links(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct fins_module_table *mt = (struct fins_module_table *) module->data;

	if (ff->ctrlFrame.data_len != sizeof(struct linked_list)) {
		PRINT_ERROR("todo error");
		freeFinsFrame(ff);
		return;
	}

	if (mt->link_list != NULL) {
		list_free(mt->link_list, free);
	}
	mt->link_list = (struct linked_list *) ff->ctrlFrame.data;

	ff->ctrlFrame.data = NULL;
	freeFinsFrame(ff);
}

void module_set_param_dual(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct fins_module_table *mt = (struct fins_module_table *) module->data;

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
	mt->flows_num = table->flows_num;

	int i;
	for (i = 0; i < table->flows_num; i++) {
		mt->flows[i] = table->flows[i];
	}

	if (mt->link_list != NULL) {
		list_free(mt->link_list, free);
	}
	mt->link_list = table->link_list;

	//freeFF frees table
	freeFinsFrame(ff);
}
