/*
 * rtm.c
 *
 *  Created on: Jul 10, 2012
 *      Author: bamj001, atm011
 */

#include "rtm_internal.h"

//Struct for args passed to rtm_send_ff
//struct args {
//int socket;
//struct finsFrame *ff;
//};

void* recvr(void* socket) {
	int rtm_in_fd, rtm_in_fd1;

	//initializes all necessary variables
	int numBytes;
	int temp_serial_cntr = 0;
	unsigned char * serialized_FCF;
	int length_serialized_FCF;

	PRINT_DEBUG("recvr running");
	//create a fins frame to be sent over the queue
	struct finsFrame *fins_frame = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	fins_frame->dataOrCtrl = CONTROL;
	for (;;) {
		//checks for errors
		if (rtm_in_fd1 == -1) {
			perror("accept");
		} else {
			temp_serial_cntr++; //used as a temporary serialNumber generator

			//RECEIVE FROM RTM_IN
			numBytes = 0;
			numBytes += recv(rtm_in_fd1, &length_serialized_FCF, sizeof(int), 0); //length of incoming serialized FCF
			perror("receiving buffer length: ");
			printf("length_serialized_FCF: %d\n", length_serialized_FCF);
			PRINT_DEBUG("number of bytes of buffer length received by RTM: %d", numBytes);
			serialized_FCF = malloc(length_serialized_FCF);
			numBytes += recv(rtm_in_fd1, serialized_FCF, length_serialized_FCF, 0); //incoming serialized FCF
			int i = 0;
			for (i = 0; i < 27; i++) {
				printf("char: %d %u\n", i, (unsigned int) serialized_FCF[i]/*,(int) *(serialized_FCF + i)*/);
			}
			perror("receiving serialized FCF: ");
			PRINT_DEBUG("length of buffer: %d", length_serialized_FCF);
			PRINT_DEBUG("TOTAL number of bytes received by RTM: %d", numBytes);
			PRINT_DEBUG("Printing buffer...");

			//PRINT_DEBUG("finsframe raw: %s", serialized_FCF);
			fins_frame = unserializeCtrlFrame(serialized_FCF, length_serialized_FCF);

			PRINT_DEBUG("RTM: received data");
			numBytes = 0;

			//ERROR Message
			fflush(stdout);
			if (numBytes >= 0) {
				PRINT_DEBUG("RTM: numBytes written %d", numBytes);
			}

			//CHANGE SenderID and SerialNum
			fins_frame->ctrlFrame.sender_id = RTM_ID;
			fins_frame->ctrlFrame.serial_num = temp_serial_cntr;

			//SEND TO QUEUE
			//sem_wait(&RTM_to_Switch_Qsem);
			//write_queue(fins_frame, RTM_to_Switch_Queue);
			//sem_post(&RTM_to_Switch_Qsem);
			PRINT_DEBUG("RTM: sent data ");
			break;
		}

	}
	//pthread_exit(NULL);
	//close(rtm_in_fd1);
	return ((void *) 0);

}

void *cmdline_to_rtm(void *local) {
	struct fins_module *module = (struct fins_module *) local;

	struct rtm_data *data = (struct rtm_data *) module->data;
	PRINT_IMPORTANT("Entered: module=%p", module);

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	int32_t size = sizeof(addr);

	int server_cmd_fd;

	while (module->state == FMS_RUNNING) {
		server_cmd_fd = accept(data->server_fd, (struct sockaddr *) &addr, (socklen_t *) &size);
		if (server_cmd_fd < 0) {
			PRINT_ERROR("accept error: cmd_fd=%d, errno=%u, str='%s'", server_cmd_fd, errno, strerror(errno));
			continue;
		}
		PRINT_DEBUG("accepted at: cmd_fd=%d, addr='%s'", server_cmd_fd, addr.sun_path);

		//close(data->server_fd);
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Exited: module=%p", module);
	return NULL;
}

void rtm_get_ff(struct fins_module *module) {
	struct rtm_data *data = (struct rtm_data *) module->data;
	struct finsFrame *ff;

	do {
		secure_sem_wait(module->event_sem);
		secure_sem_wait(module->input_sem);
		ff = read_queue(module->input_queue);
		sem_post(module->input_sem);
	} while (module->state == FMS_RUNNING && ff == NULL && !data->interrupt_flag); //TODO change logic here, combine with switch_to_rtm?

	if (module->state != FMS_RUNNING) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff) {
		if (ff->metaData == NULL) {
			PRINT_ERROR("Error fcf.metadata==NULL");
			exit(-1);
		}

		if (ff->dataOrCtrl == CONTROL) {
			rtm_fcf(module, ff);
			PRINT_DEBUG("");
		} else if (ff->dataOrCtrl == DATA) {
			if (ff->dataFrame.directionFlag == DIR_UP) {
				//rtm_in_fdf(module, ff);
				PRINT_DEBUG("");
			} else { //directionFlag==DIR_DOWN
				//rtm_out_fdf(ff); //TODO remove?
				PRINT_ERROR("todo error");
			}
		} else {
			PRINT_ERROR("todo error");
			exit(-1);
		}
	} else if (data->interrupt_flag) {
		data->interrupt_flag = 0;

		rtm_interrupt(module);
	} else {
		PRINT_ERROR("todo error");
		exit(-1);
	}
}

void rtm_fcf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

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
		rtm_set_param(module, ff);
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

void rtm_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	struct rtm_data *data = (struct rtm_data *) module->data;
	int i;

	switch (ff->ctrlFrame.param_id) {
	case PARAM_FLOWS:
		PRINT_DEBUG("PARAM_FLOWS");
		uint32_t flows_num = ff->ctrlFrame.data_len / sizeof(uint32_t);
		uint32_t *flows = (uint32_t *) ff->ctrlFrame.data;

		if (module->max_flows < flows_num) {
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
	case PARAM_LINKS:
		PRINT_DEBUG("PARAM_LINKS");
		if (ff->ctrlFrame.data_len != sizeof(struct linked_list)) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}

		if (data->link_list) {
			list_free(data->link_list, free);
		}
		struct linked_list *link_list = (struct linked_list *) ff->ctrlFrame.data;
		data->link_list = link_list;

		ff->ctrlFrame.data = NULL;
		break;
	case PARAM_DUAL:
		PRINT_DEBUG("PARAM_DUAL");

		if (ff->ctrlFrame.data_len != sizeof(struct fins_module_table)) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}
		struct fins_module_table *table = (struct fins_module_table *) ff->ctrlFrame.data;

		if (module->max_flows < table->flows_num) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}
		data->flows_num = table->flows_num;

		for (i = 0; i < table->flows_num; i++) {
			data->flows[i] = table->flows[i];
		}

		if (data->link_list) {
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

void rtm_interrupt(struct fins_module *module) {
	struct rtm_data *data = (struct rtm_data *) module->data;

	//list_for_each1(data->cache_list, arp_to_func, module);
}

void *switch_to_rtm(void *local) {
	struct fins_module *module = (struct fins_module *) local;

	PRINT_IMPORTANT("Entered: module=%p", module);

	while (module->state == FMS_RUNNING) {
		rtm_get_ff(module);
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Exited: module=%p", module);
	return NULL;
}

int rtm_init(struct fins_module *module, uint32_t *flows, uint32_t flows_num, metadata_element *params, struct envi_record *envi) {
	PRINT_IMPORTANT("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_queues(module);

	module->data = secure_malloc(sizeof(struct rtm_data));
	struct rtm_data *data = (struct rtm_data *) module->data;

	if (module->max_flows < flows_num) {
		PRINT_ERROR("todo error");
		return 0;
	}
	data->flows_num = flows_num;

	int i;
	for (i = 0; i < flows_num; i++) {
		data->flows[i] = flows[i];
	}

	//TODO extract this from meta?
	//data->rtm_started = 0;

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	int32_t size = sizeof(addr);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, RTM_PATH);
	unlink(addr.sun_path);

	data->server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (data->server_fd < 0) {
		PRINT_ERROR("socket error: server_fd=%d, errno=%u, str='%s'", data->server_fd, errno, strerror(errno));
		return 0;
	}

	PRINT_DEBUG("binding to: addr='%s'", RTM_PATH);
	if (bind(data->server_fd, (struct sockaddr *) &addr, size) < 0) {
		PRINT_ERROR("bind error: server_fd=%d, errno=%u, str='%s'", data->server_fd, errno, strerror(errno));
		return 0;
	}
	if (listen(data->server_fd, 10) < 0) {
		PRINT_ERROR("listen error: server_fd=%d, errno=%u, str='%s'", data->server_fd, errno, strerror(errno));
		return 0;
	}

	return 1;
}

int rtm_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_IMPORTANT("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	struct rtm_data *data = (struct rtm_data *) module->data;
	secure_pthread_create(&data->switch_to_rtm_thread, attr, switch_to_rtm, module);
	//secure_pthread_create(&data->cmdline_to_rtm_thread, attr, to_rtm, module);
	secure_pthread_create(&data->cmdline_to_rtm_thread, attr, cmdline_to_rtm, module);

	return 1;
}

int rtm_pause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_PAUSED;

	//TODO
	return 1;
}

int rtm_unpause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_RUNNING;

	//TODO
	return 1;
}

int rtm_shutdown(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN;
	sem_post(module->event_sem);

	struct rtm_data *data = (struct rtm_data *) module->data;
	//timer_stop(data->rtm_to_data->tid);

	//TODO expand this

	PRINT_IMPORTANT("Joining switch_to_rtm_thread");
	pthread_join(data->switch_to_rtm_thread, NULL);

	return 1;
}

int rtm_release(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);

	struct rtm_data *data = (struct rtm_data *) module->data;
	//TODO free all module related mem
	//delete threads

	if (data->link_list) {
		list_free(data->link_list, free);
	}
	free(data);
	module_destroy_queues(module);
	free(module);
	return 1;
}

void rtm_dummy(void) {

}

static struct fins_module_ops rtm_ops = { .init = rtm_init, .run = rtm_run, .pause = rtm_pause, .unpause = rtm_unpause, .shutdown = rtm_shutdown, .release =
		rtm_release, };

struct fins_module *rtm_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_IMPORTANT("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, RTM_LIB);
	module->max_flows = RTM_MAX_FLOWS;
	module->ops = &rtm_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_IMPORTANT("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
