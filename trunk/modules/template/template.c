/*
 * template.c
 *
 *  Created on: Dec 19, 2013
 *      Author: Jonathan Reed
 */

#include "template_internal.h"

void *switch_to_template(void *local) {
	struct fins_module *module = (struct fins_module *) local;
	PRINT_DEBUG("Entered: module=%p", module);
	PRINT_IMPORTANT("Thread started: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);

	while (module->state == FMS_RUNNING) {
		template_get_ff(module); //get & process FF, event, or interrupt
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Thread exited: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);
	PRINT_DEBUG("Exited: module=%p", module);
	return NULL;
}

void template_get_ff(struct fins_module *module) {
	struct template_data *md = (struct template_data *) module->data;

	struct finsFrame *ff;
	do {
		secure_sem_wait(module->event_sem);
		//Wait until something occurs, constrains looping
		secure_sem_wait(module->input_sem);
		//Protects input queue
		ff = read_queue(module->input_queue); //Try to pull a FF from the queue
		sem_post(module->input_sem);
	} while (module->state == FMS_RUNNING && ff == NULL && !md->interrupt_flag); //break if state changes, gets FF, or interrupt

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

		if (ff->dataOrCtrl == FF_CONTROL) {
			template_fcf(module, ff); //handle the FCF
			PRINT_DEBUG("");
		} else if (ff->dataOrCtrl == FF_DATA) {
			if (ff->dataFrame.directionFlag == DIR_UP) {
				template_in_fdf(module, ff); //handle the FDF going up the stack (to app)
				PRINT_DEBUG("");
			} else if (ff->dataFrame.directionFlag == DIR_DOWN) {
				template_out_fdf(module, ff); //handle the FDF going down the stack (to netw)
				PRINT_DEBUG("");
			} else {
				PRINT_ERROR("todo error");
				exit(-1);
			}
		} else {
			PRINT_ERROR("todo error: dataOrCtrl=%u", ff->dataOrCtrl);
			exit(-1);
		}
	} else if (md->interrupt_flag) {
		md->interrupt_flag = 0;

		template_interrupt(module); //handle interrupt, distinguish multiple timers through flags
	} else {
		PRINT_WARN("todo error");
	}
}

void template_fcf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		PRINT_WARN("todo");
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		template_read_param(module, ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		template_set_param(module, ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		PRINT_WARN("todo");
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	default:
		PRINT_ERROR("opcode=default (%d)", ff->ctrlFrame.opcode);
		exit(-1);
		break;
	}
}

void template_read_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	//int32_t val_int32;
	//int64_t val_int64;
	//float val_float;

	switch (ff->ctrlFrame.param_id) {
	case TEMPLATE_READ_PARAM_FLOWS:
		PRINT_DEBUG("param_id=TEMPLATE_READ_PARAM_FLOWS (%d)", ff->ctrlFrame.param_id);
		module_read_param_flows(module, ff);
		break;
	case TEMPLATE_READ_PARAM_LINKS:
		PRINT_DEBUG("param_id=TEMPLATE_READ_PARAM_LINKS (%d)", ff->ctrlFrame.param_id);
		module_read_param_links(module, ff);
		break;
	case TEMPLATE_READ_PARAM_DUAL:
		PRINT_DEBUG("param_id=TEMPLATE_READ_PARAM_DUAL (%d)", ff->ctrlFrame.param_id);
		module_read_param_dual(module, ff);
		break;
	default:
		PRINT_DEBUG("param_id=default (%d)", ff->ctrlFrame.param_id);
		PRINT_WARN("todo");
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void template_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct template_data *md = (struct template_data *) module->data;

	//int32_t val_int32;
	//int64_t val_int64;
	float val_float;

	switch (ff->ctrlFrame.param_id) {
	case TEMPLATE_SET_PARAM_FLOWS:
		PRINT_DEBUG("param_id=TEMPLATE_SET_PARAM_FLOWS (%d)", ff->ctrlFrame.param_id);
		module_set_param_flows(module, ff);
		break;
	case TEMPLATE_SET_PARAM_LINKS:
		PRINT_DEBUG("param_id=TEMPLATE_SET_PARAM_LINKS (%d)", ff->ctrlFrame.param_id);
		module_set_param_links(module, ff);
		break;
	case TEMPLATE_SET_PARAM_DUAL:
		PRINT_DEBUG("param_id=TEMPLATE_SET_PARAM_DUAL (%d)", ff->ctrlFrame.param_id);
		module_set_param_dual(module, ff);
		break;
	case TEMPLATE_SET_TIMEOUT__id:
		PRINT_DEBUG("param_id=TEMPLATE_SET_TIMEOUT (%d)", ff->ctrlFrame.param_id);

		secure_metadata_readFromElement(ff->metaData, "value", &val_float);
		md->timeout = (double) val_float;
		timer_repeat_start(md->to_data->tid, md->timeout);

		module_reply_fcf(module, ff, FCF_TRUE, 0);
		break;
	default:
		PRINT_DEBUG("param_id=default (%d)", ff->ctrlFrame.param_id);
		PRINT_WARN("todo");
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void template_in_fdf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	freeFinsFrame(ff);
}

void template_out_fdf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	freeFinsFrame(ff);
}

void template_interrupt(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);

	struct template_data *md = (struct template_data *) module->data;

	if (md->flag) {
		md->flag = 0;

		//handle TO

		//as an example send a control frame to the logger
		metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(meta);

		uint32_t info = 10;
		secure_metadata_writeToElement(meta, "info", &info, META_TYPE_INT32);

		struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
		ff->dataOrCtrl = FF_CONTROL;
		ff->metaData = meta;

		ff->ctrlFrame.sender_id = module->index;
		ff->ctrlFrame.serial_num = gen_control_serial_num();
		ff->ctrlFrame.opcode = CTRL_ALERT;
		ff->ctrlFrame.param_id = TEMPLATE_ALERT_TO;

		PRINT_DEBUG("ff=%p, meta=%p", ff, meta);
		int sent = module_send_flow(module, ff, TEMPLATE_FLOW_LOGGER);
		if (sent == 0) {
			freeFinsFrame(ff);
		}
	}
}

void template_init_knobs(struct fins_module *module) {
	metadata_element *root = config_root_setting(module->knobs);

	//metadata_element *exec_elem = secure_config_setting_add(root, OP_EXEC_STR, META_TYPE_GROUP);

	//metadata_element *get_elem = secure_config_setting_add(root, OP_GET_STR, META_TYPE_GROUP);

	metadata_element *set_elem = secure_config_setting_add(root, OP_SET_STR, META_TYPE_GROUP);
	elem_add_param(set_elem, TEMPLATE_SET_TIMEOUT__str, TEMPLATE_SET_TIMEOUT__id, TEMPLATE_SET_TIMEOUT__type);

	//metadata_element *alert_elem = secure_config_setting_add(root, OP_LISTEN_STR, META_TYPE_GROUP);
}

int template_init(struct fins_module *module, metadata_element *params, struct envi_record *envi) {
	PRINT_DEBUG("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT; //fins module state: initial
	module_create_structs(module); //create in/out queues & basic structs common to all modules

	template_init_knobs(module); //Establish interactions provided for RTM

	//malloc struct to store all module data
	module->data = secure_malloc(sizeof(struct template_data));
	struct template_data *md = (struct template_data *) module->data;

	//Clone the list containing if_record structures to keep for this module.
	md->if_list = list_clone(envi->if_list, ifr_clone);

	//create a list of max size TEMPLATE_LIST_SIZE
	md->list = list_create(TEMPLATE_LIST_SIZE);

	//setup timer so that on timeout it throws a timer-specific flag (flag), an interrupt (interrupt_flag), & triggers the module thread (event_sem)
	//module thread should wake from sem_wait, notice the interrupt, & use the flag to know what timer TO'd
	md->to_data = secure_malloc(sizeof(struct intsem_to_timer_data)); //malloc, if fail exit(-1).
	md->to_data->handler = intsem_to_handler; //function to handle TO
	md->to_data->flag = &md->flag; //throw when TO occurs (flag=1), should be timer specific
	md->to_data->interrupt = &md->interrupt_flag; //interrupt flag of module, throw when TO
	md->to_data->sem = module->event_sem; //trigger module thread to handle interrupt
	timer_create_to((struct to_timer_data *) md->to_data); //Create system alert-based timer

	md->timeout = TEMPLATE_TIMEOUT_DEFAULT;

	return 1;
}

int template_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_DEBUG("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING; //fins module state: running

	template_get_ff(module); //get/process first FF, which must be a FCF that updates the flows/links

	struct template_data *md = (struct template_data *) module->data;
	secure_pthread_create(&md->switch_to_template_thread, attr, switch_to_template, module);

	timer_repeat_start(md->to_data->tid, md->timeout);
	//timer_once_start(md->to_data->tid, md->timeout);

	return 1;
}

int template_pause(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_PAUSED; //fins module state: paused

	//TODO instruct threads to pause processing FF & timers
	return 1;
}

int template_unpause(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_RUNNING; //fins module state: running

	//TODO unpause processing of FF & restart timers
	return 1;
}

int template_shutdown(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN; //fins module state: shutdown
	sem_post(module->event_sem); //trigger module thread, so it notices new state & exits

	struct template_data *md = (struct template_data *) module->data;
	timer_stop(md->to_data->tid); //stop timer

	PRINT_IMPORTANT("Joining switch_to_template_thread");
	pthread_join(md->switch_to_template_thread, NULL);

	return 1;
}

int template_release(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);

	struct template_data *md = (struct template_data *) module->data;
	//TODO free all module related mem
	list_free(md->if_list, ifr_free);
	list_free(md->list, free);

	//delete timer
	timer_delete(md->to_data->tid);
	free(md->to_data);

	//free common module data (queues, etc)
	if (md->link_list != NULL) {
		list_free(md->link_list, free);
	}
	free(md);
	module_destroy_structs(module);
	free(module);
	return 1;
}

void template_dummy(void) {
}

static struct fins_module_ops template_ops = { .init = template_init, .run = template_run, .pause = template_pause, .unpause = template_unpause, .shutdown =
		template_shutdown, .release = template_release, };

struct fins_module *template_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_DEBUG("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, TEMPLATE_LIB);
	module->flows_max = TEMPLATE_MAX_FLOWS;
	module->ops = &template_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_DEBUG("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
