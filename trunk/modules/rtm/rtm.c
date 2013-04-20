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
	int rtm_in_fd1 = 0;
	//int rtm_in_fd;

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

int rtm_setNonblocking(int fd) { //TODO move to common file?
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

int rtm_setBlocking(int fd) {
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

void console_free(struct rtm_console *console) {
	PRINT_DEBUG("Entered: console=%p", console);

	if (console->addr) {
		PRINT_DEBUG("Freeing addr=%p", console->addr);
		free(console->addr);
	}

	free(console);
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
				PRINT_ERROR("todo error");
			} else { //directionFlag==DIR_DOWN
				//rtm_out_fdf(module, ff);
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

	//TODO when recv FCF, pull params from meta to figure out connection, send through socket

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

	if (data) {

	}
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

int console_fd_test(struct rtm_console *console, int *fd) {
	return console->fd == *fd;
}

void *console_to_rtm(void *local) {
	struct fins_module *module = (struct fins_module *) local;
	struct rtm_data *data = (struct rtm_data *) module->data;

	PRINT_IMPORTANT("Entered: module=%p", module);

	int poll_num;
	struct pollfd poll_fds[MAX_CONSOLES];
	int time = 1;
	int ret;
	struct rtm_console *console;

	int i;
	for (i = 0; i < MAX_CONSOLES; i++) {
		poll_fds[i].events = POLLIN | POLLPRI | POLLRDNORM;
		//poll_fds[1].events = POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;
	}
	PRINT_DEBUG("events=0x%x", poll_fds[0].events);

	int numBytes;
	uint32_t cmd_len;
	uint8_t cmd_buf[MAX_CMD_LEN + 1];

	secure_sem_wait(&data->console_sem);
	while (module->state == FMS_RUNNING) {
		poll_num = data->console_list->len;
		if (poll_num) {
			for (i = 0; i < MAX_CONSOLES; i++) {
				if (data->console_fds[i] == 0) {
					poll_fds[i].fd = -1;
				} else {
					poll_fds[i].fd = data->console_fds[i];
				}
			}
			sem_post(&data->console_sem);

			ret = poll(poll_fds, poll_num, time);
			if (ret < 0) {
				PRINT_ERROR("ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
				break;
			} else if (ret) {
				PRINT_DEBUG("poll: ret=%d", ret);

				secure_sem_wait(&data->console_sem);
				for (i = 0; i < MAX_CONSOLES; i++) {
					if (poll_fds[i].fd > 0 && poll_fds[i].revents > 0) {
						if (1) {
							PRINT_DEBUG(
									"POLLIN=%d POLLPRI=%d POLLOUT=%d POLLERR=%d POLLHUP=%d POLLNVAL=%d POLLRDNORM=%d POLLRDBAND=%d POLLWRNORM=%d POLLWRBAND=%d",
									(poll_fds[i].revents & POLLIN) > 0, (poll_fds[i].revents & POLLPRI) > 0, (poll_fds[i].revents & POLLOUT) > 0, (poll_fds[i].revents & POLLERR) > 0, (poll_fds[i].revents & POLLHUP) > 0, (poll_fds[i].revents & POLLNVAL) > 0, (poll_fds[i].revents & POLLRDNORM) > 0, (poll_fds[i].revents & POLLRDBAND) > 0, (poll_fds[i].revents & POLLWRNORM) > 0, (poll_fds[i].revents & POLLWRBAND) > 0);
						}
						if (poll_fds[i].revents & (POLLERR | POLLNVAL)) {
							//TODO ??
							PRINT_DEBUG("todo");
						} else if (poll_fds[i].revents & (POLLHUP)) {
							//TODO console closed etc, remove, from list
							data->console_fds[i] = 0;
							console = (struct rtm_console *) list_find1(data->console_list, console_fd_test, &poll_fds[i].fd);
							list_remove(data->console_list, console);
							console_free(console);
						} else if (poll_fds[i].revents & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
							numBytes = read(poll_fds[i].fd, &cmd_len, sizeof(uint32_t));
							if (numBytes <= 0) {
								PRINT_ERROR("error reading size: numBytes=%d", numBytes);
								PRINT_ERROR("todo error");
								exit(-1);
							}

							numBytes = read(poll_fds[i].fd, cmd_buf, cmd_len);
							if (numBytes <= 0) {
								PRINT_ERROR("error reading frame: numBytes=%d", numBytes);
								PRINT_ERROR("todo error");
								exit(-1);
							}

							if (numBytes != cmd_len) {
								PRINT_ERROR("lengths not equal: cmd_len=%d, numBytes=%d", cmd_len, numBytes);
								PRINT_ERROR("todo error");
								exit(-1);
							}
							cmd_buf[cmd_len] = '\0';

							rtm_process_cmd(module, poll_fds[i].fd, cmd_len, cmd_buf);
						}
					}
				}
			}
		} else {
			sem_post(&data->console_sem);
			sleep(time);
			secure_sem_wait(&data->console_sem);
		}
	}

	PRINT_IMPORTANT("Exited: module=%p", module);
	return NULL;
}

void rtm_process_cmd(struct fins_module *module, int fd, uint32_t cmd_len, uint8_t *cmd_buf) {
	PRINT_DEBUG("Entered: module=%p, fd=%d, cmd_len=%u, cmd_buf='%s'", module, fd, cmd_len, cmd_buf);

	uint8_t *word, *cmd_pt;
	for (word = (uint8_t *) strtok_r((char *) cmd_buf, " ", (char **) &cmd_pt); word; word = (uint8_t *) strtok_r(NULL, " ", (char **) &cmd_pt)) {
		PRINT_DEBUG("word='%s'", word);
		PRINT_DEBUG("*cmd_pt=0x%x cmd_pt='%s'", *cmd_pt, cmd_pt);
	}

	PRINT_DEBUG("Exited: cmd_len=%u, cmd_buf='%s'", strlen((char *)cmd_buf), cmd_buf);
}

void *accept_console(void *local) {
	struct fins_module *module = (struct fins_module *) local;
	struct rtm_data *data = (struct rtm_data *) module->data;

	PRINT_IMPORTANT("Entered: module=%p", module);

	int32_t addr_size = sizeof(struct sockaddr_un);
	struct sockaddr_un *addr;
	int console_fd;
	struct rtm_console *console;
	int i;

	secure_sem_wait(&data->console_sem);
	while (module->state == FMS_RUNNING) {
		if (list_has_space(data->console_list)) {
			sem_post(&data->console_sem);

			addr = (struct sockaddr_un *) secure_malloc(addr_size);
			while (module->state == FMS_RUNNING) {
				sleep(1);
				console_fd = accept(data->server_fd, (struct sockaddr *) addr, (socklen_t *) &addr_size);
				if (console_fd > 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
					break;
				}
			}
			if (module->state != FMS_RUNNING) {
				free(addr);

				secure_sem_wait(&data->console_sem);
				break;
			}

			if (console_fd < 0) {
				PRINT_ERROR("accept error: server_fd=%d, console_fd=%d, errno=%u, str='%s'", data->server_fd, console_fd, errno, strerror(errno));
				free(addr);

				secure_sem_wait(&data->console_sem);
				continue;
			}

			secure_sem_wait(&data->console_sem);
			console = (struct rtm_console *) secure_malloc(sizeof(struct rtm_console));
			console->id = data->console_counter++;
			console->fd = console_fd;
			console->addr = addr;

			PRINT_IMPORTANT("Console created: id=%u, fd=%d, addr='%s'", console->id, console->fd, console->addr->sun_path);
			list_append(data->console_list, console);

			for (i = 0; i < MAX_CONSOLES; i++) {
				if (data->console_fds[i] == 0) {
					data->console_fds[i] = console_fd;
					break;
				}
			}
		} else {
			sem_post(&data->console_sem);
			sleep(5);
			secure_sem_wait(&data->console_sem);
		}
	}
	sem_post(&data->console_sem);

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

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	int32_t size = sizeof(addr);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, RTM_PATH);
	unlink(addr.sun_path);

	data->server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
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

	sem_init(&data->console_sem, 0, 1);
	data->console_list = list_create(MAX_CONSOLES);
	data->console_counter = 0;

	for (i = 0; i < MAX_CONSOLES; i++) {
		data->console_fds[i] = 0;
	}

	return 1;
}

int rtm_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_IMPORTANT("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	struct rtm_data *data = (struct rtm_data *) module->data;
	secure_pthread_create(&data->switch_to_rtm_thread, attr, switch_to_rtm, module);
	secure_pthread_create(&data->console_to_rtm_thread, attr, console_to_rtm, module);
	secure_pthread_create(&data->accept_console_thread, attr, accept_console, module);
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
	close(data->server_fd);
	list_free(data->console_list, console_free);

	PRINT_IMPORTANT("Joining switch_to_rtm_thread");
	pthread_join(data->switch_to_rtm_thread, NULL);
	pthread_join(data->console_to_rtm_thread, NULL);
	pthread_join(data->accept_console_thread, NULL);

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
