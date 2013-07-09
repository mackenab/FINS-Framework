/*
 * @file daemon.c
 *
 * @date Mar 6, 2011
 *      @author Abdallah Abdallah
 *      @brief  The DeMux which redirects every request to its appropriate
 *      protocol alternative socket interface. This initial basic
 *      version includes UDP handlers and TCP handlers). It also has the functions
 *      which manage and maintain our socket database
 */
#include "daemon_internal.h"

void daemon_store_free(struct daemon_store *store) {
	PRINT_DEBUG("Entered: store=%p", store);

	if (store->ff != NULL) {
		freeFinsFrame(store->ff);
	}

	if (store->addr != NULL) {
		free(store->addr);
	}

	free(store);
}

struct daemon_call *daemon_call_create(uint32_t call_id, int call_index, int call_pid, uint32_t call_type, uint64_t sock_id, int sock_index) {
	PRINT_DEBUG("Entered: call_id=%u, call_index=%d, call_pid=%d, call_type=%u, sock_id=%llu, sock_index=%d",
			call_id, call_index, call_pid, call_type, sock_id, sock_index);

	struct daemon_call *call = (struct daemon_call *) secure_malloc(sizeof(struct daemon_call));
	call->alloc = 1;

	call->id = call_id;
	call->index = call_index;

	call->pid = call_pid;
	call->type = call_type;

	call->sock_id = sock_id;
	call->sock_index = sock_index;

	PRINT_DEBUG("Exited: call_id=%u, call_index=%d, call_pid=%d, call_type=%u, sock_id=%llu, sock_index=%d, call=%p",
			call_id, call_index, call_pid, call_type, sock_id, sock_index, call);
	return call;
}

struct daemon_call *daemon_call_clone(struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);

	struct daemon_call *call_clone = (struct daemon_call *) secure_malloc(sizeof(struct daemon_call));
	memcpy(call_clone, call, sizeof(struct daemon_call));
	call_clone->alloc = 1;

	PRINT_DEBUG("Exited: call=%p, ret=%p", call, call_clone);
	return call_clone;
}

//struct daemon_call *call_list_find_pid(struct daemon_call_list *call_list, int call_pid, uint32_t call_type, uint64_t sock_id) { //TODO remove sock_id? since call_list divided by sock
int daemon_call_pid_test(struct daemon_call *call, int *call_pid, uint32_t *call_type) {
	return call->pid == *call_pid && call->type == *call_type;
}

int daemon_call_serial_test(struct daemon_call *call, uint32_t *serial_num) {
	return call->serial_num == *serial_num;
}

int daemon_call_recvmsg_test(struct daemon_call *call, uint32_t *flag) {
	return call->type == RECVMSG_CALL && (*flag ? call->flags & MSG_ERRQUEUE : !(call->flags & MSG_ERRQUEUE));
}

void daemon_call_free(struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);

	if (call->alloc) {
		free(call);
	} else {
		if (call->id != -1) {
			call->id = -1;

			timer_stop(call->to_data->tid);
			call->to_flag = 0;
		} else {
			PRINT_WARN("todo error");
		}
	}
}

int daemon_calls_insert(struct fins_module *module, uint32_t call_id, int call_index, int call_pid, uint32_t call_type, uint64_t sock_id, int sock_index) {
	PRINT_DEBUG("Entered: call_id=%u, call_index=%d, call_pid=%d, call_type=%u, sock_id=%llu, sock_index=%d",
			call_id, call_index, call_pid, call_type, sock_id, sock_index);
	struct daemon_data *md = (struct daemon_data *) module->data;

	if (md->calls[call_index].id != -1) { //TODO may actually remove, add check such that FCF pointing
		PRINT_WARN("Error, call_index in use: daemon_calls[%d].call_id=%u", call_index, md->calls[call_index].id);
		PRINT_WARN("Overwriting with: daemon_calls[%d].call_id=%u", call_index, call_id);

		if (md->sockets[md->calls[call_index].sock_index].sock_id == md->calls[call_index].sock_id
				&& (md->calls[call_index].type == POLL_CALL || md->calls[call_index].type == RECVMSG_CALL)) {
			list_remove(md->sockets[md->calls[call_index].sock_index].call_list, &md->calls[call_index]);
		}

		//this should only occur on a ^C which breaks the wedge sem_wait(), thus exiting the call before hearing back from the daemon and then re-using the index
		//since the wedge side call already returned and the program is exiting, replying to the wedge for the old call is unnecessary as it would be dropped
		//also the associated daemon_in function from a returning FCF for the old call does not need to be executed as the socket will soon be removed
		//TODO exception might be overwriting as the daemon_in function occurring
	}

	md->calls[call_index].id = call_id;
	md->calls[call_index].index = call_index;
	md->calls[call_index].pid = call_pid;
	md->calls[call_index].type = call_type;

	md->calls[call_index].sock_id = sock_id;
	md->calls[call_index].sock_index = sock_index;

	md->calls[call_index].serial_num = 0;
	md->calls[call_index].buf = 0;
	md->calls[call_index].flags = 0;
	md->calls[call_index].ret = 0;
	md->calls[call_index].sent = 0;

	md->calls[call_index].sock_id_new = 0;
	md->calls[call_index].sock_index_new = 0;

	return 1;
}

int daemon_calls_find(struct fins_module *module, uint32_t serial_num) {
	PRINT_DEBUG("Entered: serial_num=%u", serial_num);
	struct daemon_data *md = (struct daemon_data *) module->data;

	int i;
	for (i = 0; i < DAEMON_MAX_CALLS; i++) {
		if (md->calls[i].id != -1 && md->calls[i].serial_num == serial_num) {
			PRINT_DEBUG("Exited: serial_num=%u, call_index=%u", serial_num, i);
			return i;
		}
	}

	PRINT_DEBUG("Exited: serial_num=%u, call_index=%d", serial_num, -1);
	return -1;
}

void daemon_calls_remove(struct fins_module *module, int call_index) {
	PRINT_DEBUG("Entered: call_index=%d", call_index);
	struct daemon_data *md = (struct daemon_data *) module->data;

	md->calls[call_index].id = -1;

	timer_stop(md->calls[call_index].to_data->tid);
	md->calls[call_index].to_flag = 0;
}

void daemon_calls_shutdown(struct fins_module *module, int call_index) {
	PRINT_DEBUG("Entered: module=%p, call_index=%d", module, call_index);
	struct daemon_data *md = (struct daemon_data *) module->data;

	//stop threads
	timer_delete(md->calls[call_index].to_data->tid);
	free(md->calls[call_index].to_data);

	//clear all threads using this conn_stub

	PRINT_DEBUG("");
	//post to read/write/connect/etc threads
	//pthread_join(daemon_calls[call_index].to_thread, NULL);
}

/**
 * @brief insert new daemon socket in the first empty location
 * in the daemon sockets array
 * @param
 * @return value of 1 on success , -1 on failure
 */
int daemon_sockets_insert(struct fins_module *module, uint64_t sock_id, int sock_index, int type, int protocol, struct daemon_socket_out_ops *out_ops,
		struct daemon_socket_in_ops *in_ops, struct daemon_socket_other_ops *other_ops) {
	PRINT_DEBUG("Entered: sock_id=%llu, sock_index=%d, type=%d, protocol=%d", sock_id, sock_index, type, protocol);
	struct daemon_data *md = (struct daemon_data *) module->data;

	if (md->sockets[sock_index].sock_id == -1) {
		md->sockets[sock_index].sock_id = sock_id;
		md->sockets[sock_index].state = SS_UNCONNECTED;
		md->sockets[sock_index].status = DAEMON_STATUS_RDWR;

		/**
		 * bind the socket by default to the default IP which is assigned
		 * to the Interface which was already started by the Capturing and Injecting process
		 * The IP default value it supposed to be acquired from the configuration file
		 * The allowable ports range is supposed also to be aquired the same way
		 */

		md->sockets[sock_index].type = type; //Transport protocol SUBTYPE SOCK_DGRAM , SOCK_RAW, SOCK_STREAM it has nothing to do with layer 4 protocols like TCP, UDP , etc
		md->sockets[sock_index].protocol = protocol;
		md->sockets[sock_index].out_ops = out_ops;
		md->sockets[sock_index].in_ops = in_ops;
		md->sockets[sock_index].other_ops = other_ops;

		md->sockets[sock_index].family = AF_UNSPEC;
		memset(&md->sockets[sock_index].host_addr, 0, sizeof(struct sockaddr_storage));
		memset(&md->sockets[sock_index].rem_addr, 0, sizeof(struct sockaddr_storage));

		md->sockets[sock_index].listening = 0;
		md->sockets[sock_index].backlog = DEFAULT_BACKLOG;

		md->sockets[sock_index].sock_id_new = -1;
		md->sockets[sock_index].sock_index_new = -1;

		md->sockets[sock_index].call_list = list_create(DAEMON_CALL_LIST_MAX); //really only for POLL_CALL & RECVMSG_CALL, split for efficiency?
		memset(&md->sockets[sock_index].stamp, 0, sizeof(struct timeval));

		md->sockets[sock_index].data_list = list_create(MAX_QUEUE_SIZE);
		md->sockets[sock_index].data_buf = 0;

		md->sockets[sock_index].error_list = list_create(MAX_QUEUE_SIZE); //only used when RECVERR enabled for ICMP/UDP
		md->sockets[sock_index].error_buf = 0;

		md->sockets[sock_index].error_call = 0;
		md->sockets[sock_index].error_msg = 0;

		md->sockets[sock_index].sockopts.FIP_TTL = 64;
		md->sockets[sock_index].sockopts.FIP_TOS = 64;
		md->sockets[sock_index].sockopts.FSO_REUSEADDR = 0;

		md->sockets[sock_index].count = 0;

		//data->daemon_sockets[sock_index].sockopts.FSO_RCVTIMEO = IPTOS_LOWDELAY;
		//data->daemon_sockets[sock_index].sockopts.FSO_SNDTIMEO = IPTOS_LOWDELAY;

		return 1;
	} else {
		PRINT_DEBUG("index in use: index=%d", sock_index);
		return 0;
	}
}

/**
 * @brief find a daemon socket among the daemon sockets array
 * @param
 * @return the location index on success , -1 on failure
 */
int daemon_sockets_find(struct fins_module *module, uint64_t sock_id) {
	PRINT_DEBUG("Entered: sock_id=%llu", sock_id);
	struct daemon_data *md = (struct daemon_data *) module->data;

	int i = 0;
	for (i = 0; i < DAEMON_MAX_SOCKETS; i++) {
		if (md->sockets[i].sock_id == sock_id) {
			PRINT_DEBUG("Exited: sock_id=%llu, sock_index=%d", sock_id, i);
			return i;
		}
	}

	PRINT_DEBUG("Exited: sock_id=%llu, sock_index=%d", sock_id, -1);
	return (-1);
}

/**
 * @brief remove a daemon socket from
 * the daemon sockets array
 * @param
 * @return value of 1 on success , -1 on failure
 */
int daemon_sockets_remove(struct fins_module *module, int sock_index) {
	struct daemon_data *md = (struct daemon_data *) module->data;
	PRINT_DEBUG("Entered: module=%p, sock_id=%llu, sock_index=%d", module, md->sockets[sock_index].sock_id, sock_index);

	md->sockets[sock_index].sock_id = -1;
	md->sockets[sock_index].state = SS_FREE;

	//TODO stop all threads related to

	//TODO send NACK for each call in call_list

	struct linked_list *call_list = md->sockets[sock_index].call_list;

	struct daemon_call *call;
	while (!list_is_empty(call_list)) {
		call = (struct daemon_call *) list_remove_front(call_list);
		if (call != NULL) {
			if (call->alloc) {
				nack_send(module, call->id, call->index, call->type, 1);

				daemon_call_free(call);
			} else {
				if (call->id != -1) {
					nack_send(module, call->id, call->index, call->type, 1);

					daemon_calls_remove(module, call->index);
				} else {
					PRINT_ERROR("todo error: call_id=%u, call_index=%d, call_type=%u", call->id, call->index, call->type);
				}
			}
		} else {
			PRINT_WARN("todo error");
			break;
		}
	}
	free(call_list);

	list_free(md->sockets[sock_index].error_list, daemon_store_free);
	list_free(md->sockets[sock_index].data_list, daemon_store_free);

	return 1;
}

/**
 * @brief generate a random integer between min and max
 * @param minimum value of the range, maximum value of the range
 * @return the random integer value
 *
 */

int daemon_randoming(int min, int max) {
	return (min + (int) (max - min + 1) * (rand() / (RAND_MAX + 1.0)));
}

uint32_t daemon_fcf_to_switch(struct fins_module *module, uint32_t flow, metadata *meta, uint32_t serial_num, uint16_t opcode, uint32_t param_id) {
	PRINT_DEBUG("Entered: module_id=%d, meta=%p, serial_num=%u, opcode=%u, param_id=%u", flow, meta, serial_num, opcode, param_id);

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = FF_CONTROL;
	ff->metaData = meta;

	ff->ctrlFrame.sender_id = module->index;
	ff->ctrlFrame.serial_num = serial_num;
	ff->ctrlFrame.opcode = opcode;
	ff->ctrlFrame.param_id = param_id;

	PRINT_DEBUG("ff=%p, meta=%p", ff, meta);
	int sent = module_send_flow(module, ff, flow);
	if (sent == 0) {
		freeFinsFrame(ff);
	}
	return sent;
}

uint32_t daemon_fdf_to_switch(struct fins_module *module, uint32_t flow, uint32_t data_len, uint8_t *data, metadata *meta) {
	PRINT_DEBUG("Entered: flow=%u, data=%p, data_len=%u, meta=%p", flow, data, data_len, meta);

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = FF_DATA;
	ff->metaData = meta;

	ff->dataFrame.directionFlag = DIR_DOWN;
	ff->dataFrame.pduLength = data_len;
	ff->dataFrame.pdu = data;

	PRINT_DEBUG("sending: ff=%p, meta=%p", ff, meta);
	uint32_t sent = module_send_flow(module, ff, flow);
	if (sent == 0) {
		freeFinsFrame(ff);
	}
	return sent;
}

int daemon_setNonblocking(int fd) {
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	return ioctl(fd, FIOBIO, &flags);
#endif
}

int daemon_setBlocking(int fd) {
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 0; //TODO verify is right?
	return ioctl(fd, FIOBIO, &flags);
#endif
}

void daemon_exec_reply_new(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	switch (ff->ctrlFrame.param_id) {

	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		//TODO implement?
		freeFinsFrame(ff);
		break;
	}
}

void *switch_to_daemon(void *local) {
	struct fins_module *module = (struct fins_module *) local;
	PRINT_IMPORTANT("Entered: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);

	while (module->state == FMS_RUNNING) {
		daemon_get_ff(module);
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Exited: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);
	return NULL;
}

void daemon_get_ff(struct fins_module *module) {
	struct daemon_data *md = (struct daemon_data *) module->data;

	struct finsFrame *ff;
	do {
		secure_sem_wait(module->event_sem);
		secure_sem_wait(module->input_sem);
		ff = read_queue(module->input_queue);
		sem_post(module->input_sem);
	} while (module->state == FMS_RUNNING && ff == NULL && !md->interrupt_flag); //TODO change logic here, combine with switch_to_daemon?

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

		if (ff->dataOrCtrl == FF_CONTROL) {
			daemon_fcf(module, ff);
			PRINT_DEBUG("");
		} else if (ff->dataOrCtrl == FF_DATA) {
			if (ff->dataFrame.directionFlag == DIR_UP) {
				daemon_in_fdf(module, ff);
				PRINT_DEBUG("");
			} else if (ff->dataFrame.directionFlag == DIR_DOWN) { //directionFlag==DIR_DOWN
				PRINT_WARN("todo error");
				freeFinsFrame(ff);
			} else {
				PRINT_ERROR("todo error");
				exit(-1);
			}
		} else {
			PRINT_ERROR("todo error");
			exit(-1);
		}
	} else if (md->interrupt_flag) {
		md->interrupt_flag = 0;

		daemon_interrupt(module);
	} else {
		PRINT_WARN("todo error");
	}
}

void daemon_fcf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		daemon_alert(module, ff);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		PRINT_WARN("todo");
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		daemon_read_param_reply(module, ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		daemon_set_param(module, ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		daemon_set_param_reply(module, ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		PRINT_WARN("todo");
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		daemon_exec_reply(module, ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		daemon_error(module, ff);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		exit(-1);
		break;
	}
}

void daemon_alert(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t protocol;
	uint32_t ret_msg;

	switch (ff->ctrlFrame.param_id) {
	case DAEMON_ALERT_POLL:
		PRINT_DEBUG("param_id=DAEMON_ALERT_POLL (%d)", ff->ctrlFrame.param_id);

		secure_metadata_readFromElement(ff->metaData, "protocol", &protocol);
		secure_metadata_readFromElement(ff->metaData, "ret_msg", &ret_msg);

		PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		secure_sem_wait(&md->sockets_sem);

		switch (protocol) {
		case IPPROTO_ICMP:
			//daemon_in_poll_icmp(module, ff, ret_msg);
			PRINT_WARN("todo");
			break;
		case IPPROTO_TCP:
			daemon_in_poll_tcp(module, ff, ret_msg);
			break;
		case IPPROTO_UDP:
			//daemon_in_poll_udp(module, ff, ret_msg);
			PRINT_WARN("todo");
			break;
		default:
			PRINT_ERROR("Unknown protocol, protocol=%u", protocol);
			module_reply_fcf(module, ff, FCF_FALSE, 0);
			//freeFinsFrame(ff);
			break;
		}

		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->sockets_sem);
		break;
	case DAEMON_ALERT_SHUTDOWN:
		PRINT_DEBUG("param_id=DAEMON_ALERT_SHUTDOWN (%d)", ff->ctrlFrame.param_id);

		secure_metadata_readFromElement(ff->metaData, "protocol", &protocol);
		secure_metadata_readFromElement(ff->metaData, "ret_msg", &ret_msg);

		PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		secure_sem_wait(&md->sockets_sem);

		switch (protocol) {
		case IPPROTO_ICMP:
			//daemon_in_shutdown_icmp(module, ff, ret_msg);
			PRINT_WARN("todo");
			break;
		case IPPROTO_TCP:
			daemon_in_shutdown_tcp(module, ff, ret_msg);
			break;
		case IPPROTO_UDP:
			//daemon_in_shutdown_udp(module, ff, ret_msg);
			PRINT_WARN("todo");
			break;
		default:
			PRINT_ERROR("Unknown protocol, protocol=%u", protocol);
			module_reply_fcf(module, ff, FCF_FALSE, 0);
			break;
		}

		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->sockets_sem);
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void daemon_read_param_reply(struct fins_module *module, struct finsFrame *ff) { //TODO update to new version once Daemon EXEC_CALL's are standardized, that and split //atm suited only for wedge pass through (TCP)
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct daemon_data *md = (struct daemon_data *) module->data;

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->sockets_sem);
	int call_index = daemon_calls_find(module, ff->ctrlFrame.serial_num); //assumes all EXEC_REPLY FCF, are in daemon_calls,
	if (call_index == -1) {
		PRINT_ERROR("Exited, no corresponding call: ff=%p", ff);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->sockets_sem);

		freeFinsFrame(ff);
		return;
	}

	struct daemon_call *call = daemon_call_clone(&md->calls[call_index]);
	if (--md->calls[call_index].sent == 0) {
		daemon_calls_remove(module, call_index);
	}

	if (md->sockets[call->sock_index].sock_id != call->sock_id) { //TODO shouldn't happen, check release
		PRINT_ERROR("Exited, socket closed: ff=%p", ff);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->sockets_sem);

		nack_send(module, call->id, call->index, call->type, 1);
		daemon_call_free(call);
		freeFinsFrame(ff);
		return;
	}
	if (call->type == POLL_CALL || call->type == RECVMSG_CALL) {
		list_remove(md->sockets[call->sock_index].call_list, &md->calls[call_index]);
	}

	switch (call->type) {
	case GETSOCKOPT_CALL:
		if (md->sockets[call->sock_index].in_ops->getsockopt_in != NULL) {
			(md->sockets[call->sock_index].in_ops->getsockopt_in)(module, ff, call); //CTRL_READ_PARAM_REPLY
		} else {
			PRINT_WARN("todo error");
			nack_send(module, call->id, call->index, call->type, 1);
			daemon_call_free(call);
			freeFinsFrame(ff);
		}
		break;
	default:
		PRINT_ERROR("Not supported dropping: call_type=%d", call->type);
		exit(-1);
		break;
	}
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->sockets_sem);
}

void daemon_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	switch (ff->ctrlFrame.param_id) {
	case DAEMON_SET_PARAM_FLOWS:
		PRINT_DEBUG("DAEMON_SET_PARAM_FLOWS");
		module_set_param_flows(module, ff);
		break;
	case DAEMON_SET_PARAM_LINKS:
		PRINT_DEBUG("DAEMON_SET_PARAM_LINKS");
		module_set_param_links(module, ff);
		break;
	case DAEMON_SET_PARAM_DUAL:
		PRINT_DEBUG("DAEMON_SET_PARAM_DUAL");
		module_set_param_dual(module, ff);
		break;
	default:
		PRINT_ERROR("param_id=default (%d)", ff->ctrlFrame.param_id);
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void daemon_set_param_reply(struct fins_module *module, struct finsFrame *ff) { //TODO update to new version once Daemon EXEC_CALL's are standardized, that and split //atm suited only for wedge pass through (TCP)
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct daemon_data *md = (struct daemon_data *) module->data;

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->sockets_sem);
	int call_index = daemon_calls_find(module, ff->ctrlFrame.serial_num); //assumes all EXEC_REPLY FCF, are in daemon_calls,
	if (call_index == -1) {
		PRINT_ERROR("Exited, no corresponding call: ff=%p", ff);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->sockets_sem);

		freeFinsFrame(ff);
		return;
	}

	struct daemon_call *call = daemon_call_clone(&md->calls[call_index]);
	if (--md->calls[call_index].sent == 0) {
		daemon_calls_remove(module, call_index);
	}

	if (md->sockets[call->sock_index].sock_id != call->sock_id) { //TODO shouldn't happen, check release
		PRINT_ERROR("Exited, socket closed: ff=%p", ff);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->sockets_sem);

		nack_send(module, call->id, call->index, call->type, 1);
		daemon_call_free(call);
		freeFinsFrame(ff);
		return;
	}
	if (call->type == POLL_CALL || call->type == RECVMSG_CALL) {
		list_remove(md->sockets[call->sock_index].call_list, &md->calls[call_index]);
	}

	switch (call->type) {
	case SETSOCKOPT_CALL:
		if (md->sockets[call->sock_index].in_ops->setsockopt_in != NULL) {
			(md->sockets[call->sock_index].in_ops->setsockopt_in)(module, ff, call); //CTRL_SET_PARAM_REPLY
		} else {
			PRINT_WARN("todo error");
			nack_send(module, call->id, call->index, call->type, 1);
			daemon_call_free(call);
			freeFinsFrame(ff);
		}
		break;
	default:
		PRINT_ERROR("Not supported dropping: call_type=%d", call->type);
		exit(-1);
		break;
	}
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->sockets_sem);
}

void daemon_exec_reply(struct fins_module *module, struct finsFrame *ff) { //TODO update to new version once Daemon EXEC_CALL's are standardized, that and split //atm suited only for wedge pass through (TCP)
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct daemon_data *md = (struct daemon_data *) module->data;

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->sockets_sem);
	struct daemon_call *call = (struct daemon_call *) list_find1(md->expired_call_list, daemon_call_serial_test, &ff->ctrlFrame.serial_num);
	if (call != NULL) {
		list_remove(md->expired_call_list, call);

		if (md->sockets[call->sock_index].sock_id != call->sock_id) { //TODO shouldn't happen, check release
			PRINT_ERROR("Exited, socket closed: ff=%p", ff);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&md->sockets_sem);

			freeFinsFrame(ff);
			return;
		}

		switch (call->type) {
		case CONNECT_CALL:
			if (md->sockets[call->sock_index].other_ops->connect_expired != NULL) {
				(md->sockets[call->sock_index].other_ops->connect_expired)(module, ff, call, 0); //TODO include data? or don't post until after?
			} else {
				PRINT_WARN("todo error");
				nack_send(module, call->id, call->index, call->type, 1);
				daemon_call_free(call);
				freeFinsFrame(ff);
			}
			break;
		case ACCEPT_CALL:
			if (md->sockets[call->sock_index].other_ops->accept_expired != NULL) {
				(md->sockets[call->sock_index].other_ops->accept_expired)(module, ff, call, 0); //TODO include data? or don't post until after?
			} else {
				PRINT_WARN("todo error");
				nack_send(module, call->id, call->index, call->type, 1);
				daemon_call_free(call);
				freeFinsFrame(ff);
			}
			break;
		default:
			PRINT_ERROR("Not supported dropping: call_type=%d", call->type);
			exit(1);
			break;
		}
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->sockets_sem);
	} else {
		int call_index = daemon_calls_find(module, ff->ctrlFrame.serial_num); //assumes all EXEC_REPLY FCF, are in daemon_calls,
		if (call_index == -1) {
			PRINT_ERROR("Exited, no corresponding call: ff=%p", ff);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&md->sockets_sem);

			freeFinsFrame(ff);
			return;
		}

		call = daemon_call_clone(&md->calls[call_index]);
		if (--md->calls[call_index].sent == 0) {
			daemon_calls_remove(module, call_index);
		}

		if (md->sockets[call->sock_index].sock_id != call->sock_id) { //TODO shouldn't happen, check release
			PRINT_ERROR("Exited, socket closed: ff=%p", ff);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&md->sockets_sem);

			nack_send(module, call->id, call->index, call->type, 1);
			daemon_call_free(call);
			freeFinsFrame(ff);
			return;
		}
		if (call->type == POLL_CALL || call->type == RECVMSG_CALL) {
			list_remove(md->sockets[call->sock_index].call_list, &md->calls[call_index]);
		}

		switch (call->type) {
		case CONNECT_CALL:
			if (md->sockets[call->sock_index].in_ops->connect_in != NULL) {
				(md->sockets[call->sock_index].in_ops->connect_in)(module, ff, call); //TODO include data? or don't post until after?
			} else {
				PRINT_WARN("todo error");
				nack_send(module, call->id, call->index, call->type, 1);
				daemon_call_free(call);
				freeFinsFrame(ff);
			}
			break;
		case ACCEPT_CALL:
			if (md->sockets[call->sock_index].in_ops->accept_in != NULL) {
				(md->sockets[call->sock_index].in_ops->accept_in)(module, ff, call);
			} else {
				PRINT_WARN("todo error");
				nack_send(module, call->id, call->index, call->type, 1);
				daemon_call_free(call);
				freeFinsFrame(ff);
			}
			break;
		case SENDMSG_CALL:
			if (md->sockets[call->sock_index].in_ops->sendmsg_in != NULL) {
				(md->sockets[call->sock_index].in_ops->sendmsg_in)(module, ff, call); //FDF, so get EXEC? //atm CTRL_EXEC_REPLY
			} else {
				PRINT_WARN("todo error");
				nack_send(module, call->id, call->index, call->type, 1);
				daemon_call_free(call);
				freeFinsFrame(ff);
			}
			break;
		case RELEASE_CALL:
			if (md->sockets[call->sock_index].in_ops->release_in != NULL) {
				(md->sockets[call->sock_index].in_ops->release_in)(module, ff, call);
			} else {
				PRINT_WARN("todo error");
				nack_send(module, call->id, call->index, call->type, 1);
				daemon_call_free(call);
				freeFinsFrame(ff);
			}
			break;
		case POLL_CALL:
			if (md->sockets[call->sock_index].in_ops->poll_in != NULL) {
				(md->sockets[call->sock_index].in_ops->poll_in)(module, ff, call); //CTRL_EXEC_REPLY
			} else {
				PRINT_WARN("todo error");
				nack_send(module, call->id, call->index, call->type, 1);
				daemon_call_free(call);
				freeFinsFrame(ff);
			}
			break;
		default:
			PRINT_ERROR("Not supported dropping: call_type=%d", call->type);
			exit(-1);
			break;
		}
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->sockets_sem);
	}
}

void daemon_error(struct fins_module *module, struct finsFrame *ff) { //TODO expand for different error types, atm only for TTL expired/dest unreach
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t protocol;
	secure_metadata_readFromElement(ff->metaData, "send_protocol", &protocol);
	uint32_t family;
	secure_metadata_readFromElement(ff->metaData, "send_family", &family);

	struct sockaddr_storage src_addr = { .ss_family = family };
	struct sockaddr_storage dst_addr = { .ss_family = family };
	if (family == AF_INET) {
		uint32_t src_ip;
		secure_metadata_readFromElement(ff->metaData, "send_src_ipv4", &src_ip);
		addr4_set_ip(&src_addr, src_ip);

		uint32_t dst_ip;
		secure_metadata_readFromElement(ff->metaData, "send_dst_ipv4", &dst_ip);
		addr4_set_ip(&dst_addr, dst_ip);
	} else if (family == AF_INET6) {
		PRINT_WARN("todo");
	} else {
		PRINT_ERROR("todo error");
		exit(-1);
	}

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->sockets_sem);
	switch (protocol) {
	case IPPROTO_ICMP:
		daemon_in_error_icmp(module, ff, family, &src_addr, &dst_addr);
		break;
	case IPPROTO_TCP:
		daemon_in_error_tcp(module, ff, family, &src_addr, &dst_addr);
		break;
	case IPPROTO_UDP:
		daemon_in_error_udp(module, ff, family, &src_addr, &dst_addr);
		break;
	default:
		PRINT_ERROR("Unknown protocol, protocol=%u", protocol);
		exit(-1);
		break;
	}
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->sockets_sem);
}

void daemon_in_fdf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p, len=%d", module, ff, ff->metaData, ff->dataFrame.pduLength);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t protocol;
	secure_metadata_readFromElement(ff->metaData, "recv_protocol", &protocol);
	uint32_t family;
	secure_metadata_readFromElement(ff->metaData, "recv_family", &family);

	struct sockaddr_storage src_addr = { .ss_family = family };
	struct sockaddr_storage dst_addr = { .ss_family = family };
	if (family == AF_INET) {
		uint32_t src_ip;
		secure_metadata_readFromElement(ff->metaData, "recv_src_ipv4", &src_ip);
		addr4_set_ip(&src_addr, src_ip);

		uint32_t dst_ip;
		secure_metadata_readFromElement(ff->metaData, "recv_dst_ipv4", &dst_ip);
		addr4_set_ip(&dst_addr, dst_ip);

		//##############################################
#ifdef DEBUG
		struct in_addr *temp = (struct in_addr *) secure_malloc(sizeof(struct in_addr));
		if (src_ip) {
			temp->s_addr = htonl(src_ip);
		} else {
			temp->s_addr = 0;
		}
		struct in_addr *temp2 = (struct in_addr *) secure_malloc(sizeof(struct in_addr));
		if (dst_ip) {
			temp2->s_addr = htonl(dst_ip);
		} else {
			temp2->s_addr = 0;
		}
		PRINT_DEBUG("ff=%p, prot=%u", ff, protocol);
		PRINT_DEBUG("src=%s (%u)", inet_ntoa(*temp), src_ip);
		PRINT_DEBUG("dst=%s (%u)", inet_ntoa(*temp2), dst_ip);

		free(temp);
		free(temp2);

		char *buf = (char *) secure_malloc(ff->dataFrame.pduLength + 1);
		memcpy(buf, ff->dataFrame.pdu, ff->dataFrame.pduLength);
		buf[ff->dataFrame.pduLength] = '\0';
		PRINT_DEBUG("pdulen=%u, pdu='%s'", ff->dataFrame.pduLength, buf);
		free(buf);
#endif
		//##############################################
	} else if (family == AF_INET6) {
		PRINT_WARN("todo");
	} else {
		PRINT_ERROR("todo error: family=%u", family);
		exit(-1);
	}

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->sockets_sem);
	switch (protocol) {
	case IPPROTO_ICMP:
		daemon_in_fdf_icmp(module, ff, family, &src_addr, &dst_addr);
		break;
	case IPPROTO_TCP:
		daemon_in_fdf_tcp(module, ff, family, &src_addr, &dst_addr);
		break;
	case IPPROTO_UDP:
		daemon_in_fdf_udp(module, ff, family, &src_addr, &dst_addr);
		break;
	default:
		PRINT_ERROR("Unknown protocol, protocol=%u", protocol);
		exit(-1);
		break;
	}
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->sockets_sem);
}

void daemon_interrupt(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	struct daemon_data *md = (struct daemon_data *) module->data;

	int i;

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->sockets_sem);
	for (i = 0; i < DAEMON_MAX_CALLS; i++) {
		if (md->calls[i].sock_id != -1 && md->calls[i].to_flag) {
			md->calls[i].to_flag = 0;

			daemon_handle_to(module, &md->calls[i]);
		}
	}
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->sockets_sem);
}

void daemon_handle_to(struct fins_module *module, struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p, call_index=%d", call, call->index);
	struct daemon_data *md = (struct daemon_data *) module->data;

	if (md->sockets[call->sock_index].sock_id != call->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, call->sock_id=%llu", call->sock_index, md->sockets[call->sock_index].sock_id, call->sock_id);

		nack_send(module, call->id, call->index, call->type, 1);
		daemon_calls_remove(module, call->index);
		return;
	}

	switch (call->type) {
	case CONNECT_CALL:
		if (md->sockets[call->sock_index].other_ops->connect_timeout != NULL) {
			(md->sockets[call->sock_index].other_ops->connect_timeout)(module, call);
		} else {
			PRINT_WARN("todo error");
			nack_send(module, call->id, call->index, call->type, 1);
			daemon_calls_remove(module, call->index);
		}
		break;
	case ACCEPT_CALL:
		if (md->sockets[call->sock_index].other_ops->accept_timeout != NULL) {
			(md->sockets[call->sock_index].other_ops->accept_timeout)(module, call);
		} else {
			PRINT_WARN("todo error");
			nack_send(module, call->id, call->index, call->type, 1);
			daemon_calls_remove(module, call->index);
		}
		break;
	case RECVMSG_CALL:
		if (md->sockets[call->sock_index].other_ops->recvmsg_timeout != NULL) {
			(md->sockets[call->sock_index].other_ops->recvmsg_timeout)(module, call);
		} else {
			PRINT_WARN("todo error");
			nack_send(module, call->id, call->index, call->type, 1);
			daemon_calls_remove(module, call->index);
		}
		break;
		//Close or poll? sendmsg TO in TCP
	default:
		PRINT_ERROR("Not supported dropping: call_type=%d", call->type);
		exit(-1);
		break;
	}
}

void *wedge_to_daemon(void *local) {
	struct fins_module *module = (struct fins_module *) local;
	PRINT_IMPORTANT("Entered: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);
	struct daemon_data *md = (struct daemon_data *) module->data;

	// Begin receive message section
	// Allocate a buffer to hold contents of recvfrom call
	int nfds = 1;
	struct pollfd fds[nfds];
	fds[0].fd = md->nl_sockfd;
	fds[0].events = POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND; //| POLLERR;
	//fds[0].events = POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;
	PRINT_DEBUG("fd: sock=%d, events=%x", md->nl_sockfd, fds[0].events);
	int time = 1000;

	uint8_t *recv_buf = (uint8_t *) secure_malloc(RECV_BUFFER_SIZE + 16); //16 = NLMSGHDR size

	struct sockaddr sockaddr_sender; // Needed for recvfrom
	socklen_t sockaddr_senderlen = sizeof(sockaddr_sender); // Needed for recvfrom
	memset(&sockaddr_sender, 0, sockaddr_senderlen);

	struct nlmsghdr *nlh;
	void *nl_buf; // Pointer to your actual data payload
	struct nl_wedge_to_daemon_hdr *msg_hdr;
	int nl_len; //, part_len; // Size of your actual data payload
	uint8_t *part_pt;

	uint8_t *msg_buf = NULL;
	int msg_len = -1;
	uint8_t *msg_pt = NULL;

	struct wedge_to_daemon_hdr *hdr;
	int okFlag, doneFlag = 0;

	PRINT_DEBUG("Waiting for message from kernel");

	int ret;
	int counter = 0;
	while (module->state == FMS_RUNNING) {
		++counter;
		PRINT_DEBUG("NL counter = %d", counter);

		if (1) { //works, appears to be minor overhead, select/poll have fd cap if increase num of nl sockets
			do {
				ret = poll(fds, nfds, time);
			} while (module->state == FMS_RUNNING && ret <= 0);

			if (module->state != FMS_RUNNING) {
				break;
			}

			if (fds[0].revents & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
				ret = recvfrom(md->nl_sockfd, recv_buf, RECV_BUFFER_SIZE + 16, 0, &sockaddr_sender, &sockaddr_senderlen);
			} else {
				PRINT_ERROR("nl poll error");
				perror("nl poll");
				break;
			}
		}

		//PRINT_DEBUG("%d", sockaddr_sender);

		nlh = (struct nlmsghdr *) recv_buf;

		if ((okFlag = NLMSG_OK(nlh, ret))) {
			switch (nlh->nlmsg_type) {
			case NLMSG_NOOP:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_NOOP");
				break;
			case NLMSG_ERROR:
				PRINT_ERROR("nlh->nlmsg_type=NLMSG_ERROR");
				okFlag = 0;
				break;
			case NLMSG_OVERRUN:
				PRINT_ERROR("nlh->nlmsg_type=NLMSG_OVERRUN");
				okFlag = 0;
				break;
			case NLMSG_DONE:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_DONE");
				doneFlag = 1;
			default:
				PRINT_DEBUG("nlh->nlmsg_type=default");
				nl_buf = NLMSG_DATA(nlh);
				nl_len = NLMSG_PAYLOAD(nlh, 0);

				PRINT_DEBUG("nl_len=%d", nl_len);
				if (nl_len < sizeof(struct nl_wedge_to_daemon_hdr)) {
					PRINT_WARN("todo error");
				}

				msg_hdr = (struct nl_wedge_to_daemon_hdr *) nl_buf;
				//part_pt = nl_buf;
				//test_msg_len = *(int *) part_pt;
				//part_pt += sizeof(int);

				//PRINT_DEBUG("test_msg_len=%d, msg_len=%d", test_msg_len, msg_len);

				if (msg_len == -1) {
					msg_len = msg_hdr->msg_len;
				} else if (msg_len != msg_hdr->msg_len) {
					okFlag = 0;
					PRINT_ERROR("diff lengs: msg_len=%d, msg_hdr->msg_len=%d", msg_len, msg_hdr->msg_len);
					//could just malloc msg_buff again
					break;//might comment out or make so start new
				}

				//part_len = *(int *) part_pt;
				//part_pt += sizeof(int);
				if (msg_hdr->part_len > RECV_BUFFER_SIZE) {
					PRINT_ERROR("part len too big: part_len=%d, RECV_BUFFER_SIZE=%d", msg_hdr->part_len, RECV_BUFFER_SIZE);
				}

				//PRINT_DEBUG("part_len=%d", part_len);

				//pos = *(int *) part_pt;
				//part_pt += sizeof(int);
				if (msg_hdr->pos > msg_len || msg_hdr->pos != msg_pt - msg_buf) {
					if (msg_hdr->pos > msg_len) {
						PRINT_ERROR("pos > msg_len");
					} else {
						PRINT_ERROR("pos != msg_pt - msg_buf");
					}
				}

				//PRINT_DEBUG("pos=%d", pos);

				PRINT_DEBUG("msg_len=%d, part_len=%d, pos=%d, seq=%d", msg_len, msg_hdr->part_len, msg_hdr->pos, nlh->nlmsg_seq);

				if (nlh->nlmsg_seq == 0) {
					if (msg_buf != NULL) {
						PRINT_ERROR("error: msg_buf != NULL at new sequence, freeing");
						free(msg_buf);
					}
					msg_buf = (uint8_t *) secure_malloc(msg_len);
					msg_pt = msg_buf;
				}

				if (msg_pt != NULL) {
					part_pt = nl_buf + sizeof(struct nl_wedge_to_daemon_hdr);
					msg_pt = msg_buf + msg_hdr->pos; //atm redundant, is for if out of sync msgs
					memcpy(msg_pt, part_pt, msg_hdr->part_len);
					msg_pt += msg_hdr->part_len;
				} else {
					PRINT_ERROR("error: msg_pt is NULL");
				}

				if ((nlh->nlmsg_flags & NLM_F_MULTI) == 0) {
					//doneFlag = 1; //not multi-part msg //removed multi
				}
				break;
			}
		}

		if (okFlag != 1) {
			doneFlag = 0;
			PRINT_ERROR("okFlag != 1");
			//send kernel a resend request
			//with pos of part being passed can store msg_buf, then recopy new part when received
		}

		if (doneFlag) {
			if (msg_len < sizeof(struct wedge_to_daemon_hdr)) {
				//TODOD error
				PRINT_WARN("todo error");
			}

			hdr = (struct wedge_to_daemon_hdr *) msg_buf;
			msg_pt = msg_buf + sizeof(struct wedge_to_daemon_hdr);
			msg_len -= sizeof(struct wedge_to_daemon_hdr);

			daemon_out(module, hdr, msg_pt, msg_len);

			free(msg_buf);
			doneFlag = 0;
			msg_buf = NULL;
			msg_pt = NULL;
			msg_len = -1;
		}
	}

	PRINT_IMPORTANT("Total NL msgs: counter=%d", counter);

	free(recv_buf);
	close(md->nl_sockfd);

	PRINT_IMPORTANT("Exited: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);
	return NULL;
}

void daemon_init_knobs(struct fins_module *module) {
	metadata_element *root = config_root_setting(module->knobs);
	//int status;

	//-------------------------------------------------------------------------------------------
	metadata_element *exec_elem = config_setting_add(root, OP_EXEC_STR, META_TYPE_GROUP);
	if (exec_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}

	//-------------------------------------------------------------------------------------------
	metadata_element *get_elem = config_setting_add(root, OP_GET_STR, META_TYPE_GROUP);
	if (get_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}
	//elem_add_param(get_elem, LOGGER_GET_INTERVAL__str, LOGGER_GET_INTERVAL__id, LOGGER_GET_INTERVAL__type);
	//elem_add_param(get_elem, LOGGER_GET_REPEATS__str, LOGGER_GET_REPEATS__id, LOGGER_GET_REPEATS__type);

	//-------------------------------------------------------------------------------------------
	metadata_element *set_elem = config_setting_add(root, OP_SET_STR, META_TYPE_GROUP);
	if (set_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}
	//elem_add_param(set_elem, LOGGER_SET_INTERVAL__str, LOGGER_SET_INTERVAL__id, LOGGER_SET_INTERVAL__type);
	//elem_add_param(set_elem, LOGGER_SET_REPEATS__str, LOGGER_SET_REPEATS__id, LOGGER_SET_REPEATS__type);
}

int daemon_init(struct fins_module *module, metadata_element *params, struct envi_record *envi) {
	PRINT_DEBUG("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	daemon_init_knobs(module);

	module->data = secure_malloc(sizeof(struct daemon_data));
	struct daemon_data *md = (struct daemon_data *) module->data;

	sem_init(&md->sockets_sem, 0, 1);
	int i;
	for (i = 0; i < DAEMON_MAX_SOCKETS; i++) {
		md->sockets[i].sock_id = -1;
		md->sockets[i].state = SS_FREE;
	}

	for (i = 0; i < DAEMON_MAX_CALLS; i++) {
		md->calls[i].id = -1;

		md->calls[i].to_data = secure_malloc(sizeof(struct intsem_to_timer_data));
		md->calls[i].to_data->handler = intsem_to_handler;
		md->calls[i].to_data->flag = &md->calls[i].to_flag;
		md->calls[i].to_data->interrupt = &md->interrupt_flag;
		md->calls[i].to_data->sem = module->event_sem;
		timer_create_to((struct to_timer_data *) md->calls[i].to_data);
	}

	md->expired_call_list = list_create(DAEMON_MAX_CALLS);

	md->if_list = list_clone(envi->if_list, ifr_clone);
	if (md->if_list->len > DAEMON_IF_LIST_MAX) {
		PRINT_WARN("todo");
		struct linked_list *leftover = list_split(md->if_list, DAEMON_IF_LIST_MAX - 1);
		list_free(leftover, free);
	}
	md->if_list->max = DAEMON_IF_LIST_MAX;
	PRINT_DEBUG("if_list: list=%p, max=%u, len=%u", md->if_list, md->if_list->max, md->if_list->len);

	if (envi->if_loopback != NULL) {
		md->if_loopback = (struct if_record *) list_find1(md->if_list,ifr_index_test,&envi->if_loopback->index);
		PRINT_DEBUG("loopback: name='%s', addr_list->len=%u", md->if_loopback->name, md->if_loopback->addr_list->len);
	} else {
		md->if_loopback = NULL;
	}

	if (envi->if_main != NULL) {
		md->if_main = (struct if_record *) list_find1(md->if_list,ifr_index_test,&envi->if_main->index);
		PRINT_DEBUG("main: name='%s', addr_list->len=%u", md->if_main->name, md->if_main->addr_list->len);
	} else {
		md->if_main = NULL;
	}

	//init the netlink socket connection to daemon
	int ret = init_fins_nl(module);
	if (ret == 0) {
		PRINT_ERROR("netlink setup failed");
		exit(-1);
	}
	return 1;
}

int daemon_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_DEBUG("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	daemon_get_ff(module);

	struct daemon_data *md = (struct daemon_data *) module->data;
	secure_pthread_create(&md->switch_to_daemon_thread, attr, switch_to_daemon, module);
	secure_pthread_create(&md->wedge_to_daemon_thread, attr, wedge_to_daemon, module);

	return 1;
}

int daemon_pause(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_PAUSED;

	//TODO
	return 1;
}

int daemon_unpause(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_RUNNING;

	//TODO
	return 1;
}

int daemon_shutdown(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN;
	sem_post(module->event_sem);

	struct daemon_data *md = (struct daemon_data *) module->data;
	//inform the kernel daemon is shutting down
	int daemoncode = DAEMON_STOP_CALL;
	int ret = send_wedge(module, (uint8_t *) &daemoncode, sizeof(int), 0);
	if (ret) {
		PRINT_ERROR("send_wedge failure");
		//perror("sendfins() caused an error");
		exit(-1);
	}
	PRINT_IMPORTANT("Disconnecting from wedge at fd=%d", md->nl_sockfd);

	PRINT_IMPORTANT("Joining switch_to_daemon_thread");
	pthread_join(md->switch_to_daemon_thread, NULL);
	PRINT_IMPORTANT("Joining wedge_to_daemon_thread");
	pthread_join(md->wedge_to_daemon_thread, NULL);

	return 1;
}

int daemon_release(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);

	struct daemon_data *md = (struct daemon_data *) module->data;
	PRINT_IMPORTANT("expired_call_list->len=%u", md->expired_call_list->len);
	list_free(md->expired_call_list, daemon_call_free);
	PRINT_IMPORTANT("if_list->len=%u", md->if_list->len);
	list_free(md->if_list, ifr_free);

	int i = 0;
	for (i = 0; i < DAEMON_MAX_SOCKETS; i++) {
		if (md->sockets[i].sock_id != -1) {
			daemon_sockets_remove(module, i); //TODO replace inner with this?
		}
	}

	for (i = 0; i < DAEMON_MAX_CALLS; i++) {
		daemon_calls_shutdown(module, i);
	}

	sem_destroy(&md->nl_sem);
	sem_destroy(&md->sockets_sem);

	if (md->link_list != NULL) {
		list_free(md->link_list, free);
	}
	free(md);
	module_destroy_structs(module);
	free(module);
	return 1;
}

void daemon_dummy(void) {

}

static struct fins_module_ops daemon_ops = { .init = daemon_init, .run = daemon_run, .pause = daemon_pause, .unpause = daemon_unpause, .shutdown =
		daemon_shutdown, .release = daemon_release, };

struct fins_module *daemon_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_DEBUG("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, DAEMON_LIB);
	module->flows_max = DAEMON_MAX_FLOWS;
	module->ops = &daemon_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_DEBUG("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
