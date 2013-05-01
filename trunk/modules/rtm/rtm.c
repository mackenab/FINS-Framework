/*
 * rtm.c
 *
 *  Created on: Jul 10, 2012
 *      Author: bamj001, atm011
 */

#include "rtm_internal.h"

int rtm_cmd_serial_test(struct rtm_command *cmd, uint32_t *serial_num) {
	return cmd->serial_num == *serial_num;
}

int rtm_console_id_test(struct rtm_console *console, uint32_t *id) {
	return console->id == *id;
}

int rtm_console_fd_test(struct rtm_console *console, int *fd) {
	return console->fd == *fd;
}

void console_free(struct rtm_console *console) {
	PRINT_DEBUG("Entered: console=%p", console);

	if (console->addr != NULL) {
		PRINT_DEBUG("Freeing: addr=%p", console->addr);
		free(console->addr);
	}

	free(console);
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

	secure_sem_wait(&data->shared_sem);
	while (module->state == FMS_RUNNING) {
		if (list_has_space(data->console_list)) {
			sem_post(&data->shared_sem);

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

				secure_sem_wait(&data->shared_sem);
				break;
			}

			if (console_fd < 0) {
				PRINT_ERROR("accept error: server_fd=%d, console_fd=%d, errno=%u, str='%s'", data->server_fd, console_fd, errno, strerror(errno));
				free(addr);

				secure_sem_wait(&data->shared_sem);
				continue;
			}

			secure_sem_wait(&data->shared_sem);
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
			sem_post(&data->shared_sem);
			sleep(5);
			secure_sem_wait(&data->shared_sem);
		}
	}
	sem_post(&data->shared_sem);

	PRINT_IMPORTANT("Exited: module=%p", module);
	return NULL;
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

	uint32_t cmd_len;
	uint8_t cmd_buf[MAX_CMD_LEN + 1];

	secure_sem_wait(&data->shared_sem);
	while (module->state == FMS_RUNNING) {
		poll_num = data->console_list->len;
		if (poll_num > 0) {
			for (i = 0; i < MAX_CONSOLES; i++) {
				if (data->console_fds[i] == 0) {
					poll_fds[i].fd = -1;
				} else {
					poll_fds[i].fd = data->console_fds[i];
				}
			}
			sem_post(&data->shared_sem);
			ret = poll(poll_fds, poll_num, time);
			secure_sem_wait(&data->shared_sem);
			if (ret < 0) {
				PRINT_ERROR("ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
				break;
			} else if (ret > 0) {
				PRINT_DEBUG("poll: ret=%d", ret);

				for (i = 0; i < MAX_CONSOLES; i++) {
					if (poll_fds[i].fd > 0 && poll_fds[i].revents > 0) {
						if (1) {
							PRINT_DEBUG(
									"POLLIN=%d POLLPRI=%d POLLOUT=%d POLLERR=%d POLLHUP=%d POLLNVAL=%d POLLRDNORM=%d POLLRDBAND=%d POLLWRNORM=%d POLLWRBAND=%d",
									(poll_fds[i].revents & POLLIN) > 0, (poll_fds[i].revents & POLLPRI) > 0, (poll_fds[i].revents & POLLOUT) > 0, (poll_fds[i].revents & POLLERR) > 0, (poll_fds[i].revents & POLLHUP) > 0, (poll_fds[i].revents & POLLNVAL) > 0, (poll_fds[i].revents & POLLRDNORM) > 0, (poll_fds[i].revents & POLLRDBAND) > 0, (poll_fds[i].revents & POLLWRNORM) > 0, (poll_fds[i].revents & POLLWRBAND) > 0);
						}

						console = (struct rtm_console *) list_find1(data->console_list, rtm_console_fd_test, &poll_fds[i].fd);
						if (console != NULL) {
							if (poll_fds[i].revents & (POLLERR | POLLNVAL)) {
								//TODO ??
								PRINT_DEBUG("todo: kinda error case that needs to be handled");
							} else if (poll_fds[i].revents & (POLLHUP)) {
								PRINT_IMPORTANT("Console closed: console=%p, id=%u", console, console->id);
								list_remove(data->console_list, console);
								console_free(console);

								data->console_fds[i] = 0;
							} else if (poll_fds[i].revents & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
								cmd_len = (uint32_t) rtm_recv_fd(console->fd, MAX_CMD_LEN, cmd_buf);
								if (cmd_len != (uint32_t) -1) {
									cmd_buf[cmd_len] = '\0';
									rtm_process_cmd(module, console, cmd_len, cmd_buf);
								} else {
									PRINT_ERROR("todo error");
								}
							}
						} else {
							PRINT_ERROR("todo error");
							//console removed after poll started, before it returned, remove?
						}
					}
				}
			}
		} else {
			sem_post(&data->shared_sem);
			sleep(time);
			secure_sem_wait(&data->shared_sem);
		}
	}
	sem_post(&data->shared_sem);

	PRINT_IMPORTANT("Exited: module=%p", module);
	return NULL;
}

int rtm_recv_fd(int fd, uint32_t buf_len, uint8_t *buf) {
	PRINT_DEBUG("Entered: fd=%d, buf_len=%u, buf='%s'", fd, buf_len, buf);

	uint32_t msg_len;
	int numBytes = read(fd, &msg_len, sizeof(uint32_t));
	if (numBytes <= 0) {
		PRINT_DEBUG("Exited: fd=%d, buf_len=%u, buf='%s', %d", fd, buf_len, buf, numBytes);
		return numBytes;
	}

	if (numBytes != sizeof(uint32_t) || msg_len > buf_len) {
		PRINT_ERROR("todo error");
		PRINT_DEBUG("Exited: fd=%d, buf_len=%u, buf='%s', %d", fd, buf_len, buf, -1);
		return -1;
	}

	numBytes = read(fd, buf, msg_len);
	if (numBytes <= 0) {
		PRINT_DEBUG("Exited: fd=%d, buf_len=%u, buf='%s', %d", fd, buf_len, buf, numBytes);
		return numBytes;
	}

	if (msg_len != (uint32_t) numBytes) {
		PRINT_ERROR("todo error");
		PRINT_DEBUG("Exited: fd=%d, buf_len=%u, buf='%s', %d", fd, buf_len, buf, -1);
		return -1;
	}

	PRINT_DEBUG("Exited: fd=%d, buf_len=%u, buf='%s', %d", fd, buf_len, buf, numBytes);
	return numBytes;
}

int rtm_send_fd(int fd, uint32_t buf_len, uint8_t *buf) {
	PRINT_DEBUG("Entered: fd=%d, buf_len=%u, buf='%s'", fd, buf_len, buf);

	int numBytes = write(fd, &buf_len, sizeof(uint32_t));
	if (numBytes <= 0) {
		PRINT_DEBUG("Exited: fd=%d, buf_len=%u, buf='%s', %d", fd, buf_len, buf, numBytes);
		return numBytes;
	}

	if (numBytes != sizeof(uint32_t)) {
		PRINT_ERROR("todo error");
		PRINT_DEBUG("Exited: fd=%d, buf_len=%u, buf='%s', %d", fd, buf_len, buf, -1);
		return -1;
	}

	numBytes = write(fd, buf, buf_len);
	if (numBytes <= 0) {
		PRINT_DEBUG("Exited: fd=%d, buf_len=%u, buf='%s', %d", fd, buf_len, buf, numBytes);
		return numBytes;
	}

	if (buf_len != (uint32_t) numBytes) {
		PRINT_ERROR("todo error");
		PRINT_DEBUG("Exited: fd=%d, buf_len=%u, buf='%s', %d", fd, buf_len, buf, -1);
		return -1;
	}

	PRINT_DEBUG("Exited: fd=%d, buf_len=%u, buf='%s', %d", fd, buf_len, buf, numBytes);
	return numBytes;
}

int rtm_send_nack(int fd, uint32_t cmd_len, uint8_t *cmd_buf) {
	uint8_t msg[1000];
	memset(msg, 0, 1000);

	sprintf((char *) msg, "Unsupported:'%s'", cmd_buf);
	msg[cmd_len + 14] = '\0';
	PRINT_DEBUG("msg='%s'", msg);
	//TODO remove

	return rtm_send_fd(fd, cmd_len + 14, msg);
}

int rtm_send_error(int fd, const char *text, uint32_t buf_len, uint8_t *buf) {
	uint8_t msg[2000];
	memset(msg, 0, 2000);

	uint32_t text_len = strlen(text);

	sprintf((char *) msg, "%s:'%s'", text, buf);
	msg[text_len + buf_len + 3] = '\0';
	PRINT_DEBUG("msg='%s'", msg);
	//TODO remove

	return rtm_send_fd(fd, text_len + buf_len + 3, msg);
}

int rtm_send_text(int fd, const char *text) {
	uint32_t text_len = strlen(text);
	return rtm_send_fd(fd, text_len, (uint8_t *) text);
}

void rtm_process_cmd(struct fins_module *module, struct rtm_console *console, uint32_t cmd_len, uint8_t *cmd_buf) {
	struct rtm_data *data = (struct rtm_data *) module->data;
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd_len=%u, cmd_buf='%s'", module, console, cmd_len, cmd_buf);

	struct rtm_command *cmd = (struct rtm_command *) secure_malloc(sizeof(struct rtm_command));
	cmd->id = data->cmd_counter++;
	cmd->console_id = console->id;
	cmd->cmd_len = cmd_len;
	memcpy(cmd->cmd_buf, cmd_buf, cmd_len);
	memcpy(cmd->words_buf, cmd_buf, cmd_len);

	uint8_t *pt;
	uint8_t *word = (uint8_t *) strtok_r((char *) cmd->words_buf, CMD_DELIMS, (char **) &pt);
	while (word) {
		PRINT_DEBUG("word='%s'", word);
		cmd->words[cmd->words_num++] = word;

		if (cmd->words_num == MAX_WORDS) {
			break;
		}
		word = (uint8_t *) strtok_r(NULL, CMD_DELIMS, (char **) &pt);
	}
	PRINT_DEBUG("words_num=%u", cmd->words_num);

	int i;
	for (i = 0; i < OP_MAX; i++) {
		if (strcmp((char *) cmd->words[INDEX_OP], op_strs[i]) == 0) {
			(op_funcs[i])(module, console, cmd);
			return;
		}
	}

	PRINT_IMPORTANT("Operation unsupported: console=%p, id=%u, op='%s'", console, console->id, cmd->words[INDEX_OP]);
	rtm_send_error(console->fd, "See 'help', unsupported operation", (uint32_t) strlen((char *) cmd->words[INDEX_OP]), cmd->words[INDEX_OP]);

	PRINT_DEBUG("Freeing: cmd=%p", cmd);
	free(cmd);
}

int match_module(struct fins_module **modules, uint8_t *word) {
	if (strcmp((char *) word, MOD_ALL) == 0) {
		return MAX_MODULES;
	}

	int i;
	for (i = 0; i < MAX_MODULES; i++) {
		if (modules[i] != NULL) {
			if (strcmp((char *) word, (char *) modules[i]->name) == 0) {
				return i;
			}
		}
	}

	return -1;
}

metadata_element *match_params(metadata *params, uint8_t **words, int path_end) {
	metadata_element *elem = config_lookup(params, (char *) words[INDEX_OP]);
	if (elem == NULL) {
		return NULL; //TODO shouldn't happen
	}

	int i;
	for (i = INDEX_PARAM; i < path_end; i++) {
		if (strcmp(PARAM_ID, (char *) words[i]) != 0 && strcmp(PARAM_TYPE, (char *) words[i]) != 0) {
			if (strchr((char *) words[i], '=') == NULL) {
				elem = config_setting_get_member(elem, (char *) words[i]);
				if (elem == NULL) {
					PRINT_DEBUG("missing: words[%d]='%s'", i, words[i]);
					return NULL;
				}
			} else {
				return NULL;
				//return elem; //?
			}
		} else {
			return NULL;
		}
	}

	return elem;
}

void rtm_send_fcf(struct fins_module *module, struct rtm_command *cmd, metadata *meta) {
	PRINT_DEBUG("Entered: module=%p, cmd=%p, meta=%p", module, cmd, meta);

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = FF_CONTROL;
	ff->destinationID = cmd->mod;
	ff->metaData = meta;

	ff->ctrlFrame.sender_id = module->index;
	ff->ctrlFrame.serial_num = cmd->serial_num;
	ff->ctrlFrame.opcode = cmd->op;
	ff->ctrlFrame.param_id = cmd->param_id;

	ff->ctrlFrame.data_len = 0;
	ff->ctrlFrame.data = NULL;

	PRINT_DEBUG("Sending ff=%p", ff);
	module_to_switch(module, ff);
}

void rtm_process_help(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);

	uint8_t msg[2000];
	memset(msg, 0, 2000);
	uint8_t *pt = msg;

//TODO build better help, such as topics etc

	int i;
	if (cmd->words_num == 1) {
		sprintf((char *) msg, OP_HELP_MSG);
		pt += strlen(OP_HELP_MSG);

		for (i = 0; i < OP_MAX; i++) {
			if (i == 0) {
				sprintf((char *) pt, " %s", op_strs[i]);
				pt += strlen(op_strs[i]) + 1;
			} else {
				sprintf((char *) pt, ", %s", op_strs[i]);
				pt += strlen(op_strs[i]) + 2;
			}
		}

		PRINT_IMPORTANT("msg='%s'", msg);
		rtm_send_text(console->fd, (char *) msg);

		PRINT_DEBUG("Freeing: cmd=%p", cmd);
		free(cmd);
		return;
	}

	if (cmd->words_num == 2) {
		for (i = 0; i < OP_MAX; i++) {
			PRINT_DEBUG("checking: '%s'", op_strs[i]);
			if (strcmp((char *) cmd->words[INDEX_MOD], op_strs[i]) == 0) {
				sprintf((char *) msg, "%s\nUsage:%s", op_info[i], op_usages[i]);

				PRINT_IMPORTANT("msg='%s'", msg);
				rtm_send_text(console->fd, (char *) msg);

				PRINT_DEBUG("Freeing: cmd=%p", cmd);
				free(cmd);
				return;
			}
		}
	}

	PRINT_IMPORTANT("Operation unsupported: console=%p, id=%u, op='%s'", console, console->id, cmd->words[INDEX_MOD]);
	rtm_send_error(console->fd, "See 'help', unsupported operation", (uint32_t) strlen((char *) cmd->words[INDEX_MOD]), cmd->words[INDEX_MOD]);

	PRINT_DEBUG("Freeing cmd=%p", cmd);
	free(cmd);
}

void rtm_process_exec(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);

	struct rtm_data *data = (struct rtm_data *) module->data;

	if (cmd->words_num < 3) {
		PRINT_IMPORTANT("Incorrect usage: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Incorrect usage:" OP_EXEC_USAGE);

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

//TODO identify module
	struct fins_module **modules = data->overall->modules;

	secure_sem_wait(&data->overall->sem);
	int mod = match_module(modules, cmd->words[INDEX_MOD]);
	if (mod == -1) {
		sem_post(&data->overall->sem);
		PRINT_IMPORTANT("Module unsupported: console=%p, id=%u, mod='%s'", console, console->id, cmd->words[INDEX_MOD]);
		rtm_send_error(console->fd, "Unknown module", (uint32_t) strlen((char *) cmd->words[INDEX_MOD]), cmd->words[INDEX_MOD]);

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}
	PRINT_IMPORTANT("op=%u, mod=%u", cmd->op, cmd->mod);

//TODO poll to get params or look at directly?

//TODO change so that it's only the first procedure name and then afterwards anything that's <key>=<value> is used as meta params
	uint32_t path_end = INDEX_PARAM + 1;

	metadata_element *param = match_params(modules[mod]->params, cmd->words, path_end);
	if (param == NULL) {
		sem_post(&data->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

	int param_id;
	int status = config_setting_lookup_int(param, PARAM_ID, (int *) &param_id);
	if (status == META_FALSE) {
		sem_post(&data->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}
	sem_post(&data->overall->sem);

	cmd->mod = mod;
	cmd->serial_num = gen_control_serial_num();
	cmd->op = CTRL_EXEC;
	cmd->param_id = param_id;
	PRINT_DEBUG("mod=%u, serial_num=%u, op=%u, param_id=%u", cmd->mod, cmd->serial_num, cmd->op, cmd->param_id);

	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta);

//TODO process key=value pairs passed after procedure, store in metadata
//uint32_t src_ip = 0;
//secure_metadata_writeToElement(meta, "src_ip", &src_ip, META_TYPE_INT32);

	rtm_send_fcf(module, cmd, meta);

	if (list_has_space(data->cmd_list)) {
		list_append(data->cmd_list, cmd);
	} else {
		PRINT_ERROR("todo error");
	}

//rtm_send_error(console->fd, "Correct so far", cmd_len, cmd_buf);
//PRINT_DEBUG("Exited: module=%p, console=%p, cmd_len=%u, cmd_buf='%s'", module, console, cmd_len, cmd_buf);
}

void rtm_process_get(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);

	struct rtm_data *data = (struct rtm_data *) module->data;

	if (cmd->words_num < 3) {
		PRINT_IMPORTANT("Incorrect usage: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Incorrect usage:" OP_GET_USAGE);

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

//TODO identify module
	struct fins_module **modules = data->overall->modules;

	secure_sem_wait(&data->overall->sem);
	int mod = match_module(modules, cmd->words[INDEX_MOD]);
	if (mod == -1) {
		sem_post(&data->overall->sem);
		PRINT_IMPORTANT("Module unsupported: console=%p, id=%u, mod='%s'", console, console->id, cmd->words[INDEX_MOD]);
		rtm_send_error(console->fd, "Unknown module", (uint32_t) strlen((char *) cmd->words[INDEX_MOD]), cmd->words[INDEX_MOD]);

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}
	PRINT_IMPORTANT("op=%u, mod=%u", cmd->op, cmd->mod);

//TODO poll to get params or look at directly?

//TODO change so that it's only the first procedure name and then afterwards anything that's <key>=<value> is used as meta params
	uint32_t path_end = cmd->words_num;

	metadata_element *param = match_params(modules[mod]->params, cmd->words, path_end);
	if (param == NULL) {
		sem_post(&data->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

	int param_id;
	int status = config_setting_lookup_int(param, PARAM_ID, (int *) &param_id);
	if (status == META_FALSE) {
		sem_post(&data->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}
	sem_post(&data->overall->sem);

	cmd->mod = mod;
	cmd->serial_num = gen_control_serial_num();
	cmd->op = CTRL_READ_PARAM;
	cmd->param_id = param_id;
	PRINT_DEBUG("mod=%u, serial_num=%u, op=%u, param_id=%u", cmd->mod, cmd->serial_num, cmd->op, cmd->param_id);

	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta);

//uint32_t src_ip = 0;
//secure_metadata_writeToElement(meta, "src_ip", &src_ip, META_TYPE_INT32);

	rtm_send_fcf(module, cmd, meta);

	if (list_has_space(data->cmd_list)) {
		list_append(data->cmd_list, cmd);
	} else {
		PRINT_ERROR("todo error");
	}

//rtm_send_error(console->fd, "Correct so far", cmd_len, cmd_buf);
//PRINT_DEBUG("Exited: module=%p, console=%p, cmd_len=%u, cmd_buf='%s'", module, console, cmd_len, cmd_buf);
}

void rtm_process_set(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);

	struct rtm_data *data = (struct rtm_data *) module->data;

	if (cmd->words_num < 4) {
		PRINT_IMPORTANT("Incorrect usage: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Incorrect usage:" OP_SET_USAGE);

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

//TODO identify module
	struct fins_module **modules = data->overall->modules;

	secure_sem_wait(&data->overall->sem);
	int mod = match_module(modules, cmd->words[INDEX_MOD]);
	if (mod == -1) {
		sem_post(&data->overall->sem);
		PRINT_IMPORTANT("Module unsupported: console=%p, id=%u, mod='%s'", console, console->id, cmd->words[INDEX_MOD]);
		rtm_send_error(console->fd, "Unknown module", (uint32_t) strlen((char *) cmd->words[INDEX_MOD]), cmd->words[INDEX_MOD]);

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}
	PRINT_IMPORTANT("op=%u, mod=%u", cmd->op, cmd->mod);

//TODO poll to get params or look at directly?

//TODO change so that it's only the first procedure name and then afterwards anything that's <key>=<value> is used as meta params
	uint32_t path_end = cmd->words_num - 1;

	metadata_element *param = match_params(modules[mod]->params, cmd->words, path_end);
	if (param == NULL) {
		sem_post(&data->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

	int param_id;
	int status = config_setting_lookup_int(param, PARAM_ID, (int *) &param_id);
	if (status == META_FALSE) {
		sem_post(&data->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

	int param_type;
	status = config_setting_lookup_int(param, PARAM_TYPE, (int *) &param_type);
	if (status == META_FALSE) {
		sem_post(&data->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}
	sem_post(&data->overall->sem);

	cmd->mod = mod;
	cmd->serial_num = gen_control_serial_num();
	cmd->op = CTRL_SET_PARAM;
	cmd->param_id = param_id;
	PRINT_DEBUG("mod=%u, serial_num=%u, op=%u, param_id=%u", cmd->mod, cmd->serial_num, cmd->op, cmd->param_id);

	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta);

	int32_t val_int32;
	int64_t val_int64;
	float val_float;

	switch (param_type) {
	case CONFIG_TYPE_INT:
		status = sscanf((char *) cmd->words[cmd->words_num - 1], "%d", &val_int32);
		if (status <= 0) {
			PRINT_IMPORTANT("Incorrect value format: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
			rtm_send_text(console->fd, "Incorrect value format, expected int32_t");

			metadata_destroy(meta);
			PRINT_DEBUG("Freeing cmd=%p", cmd);
			free(cmd);
			return;
		}
		PRINT_DEBUG("value=%d", val_int32);
		secure_metadata_writeToElement(meta, "value", &val_int32, CONFIG_TYPE_INT);
		break;
	case CONFIG_TYPE_INT64:
		status = sscanf((char *) cmd->words[cmd->words_num - 1], "%lld", &val_int64);
		if (status <= 0) {
			PRINT_IMPORTANT("Incorrect value format: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
			rtm_send_text(console->fd, "Incorrect value format, expected int64_t");

			metadata_destroy(meta);
			PRINT_DEBUG("Freeing cmd=%p", cmd);
			free(cmd);
			return;
		}
		PRINT_DEBUG("value=%lld", val_int64);
		secure_metadata_writeToElement(meta, "value", &val_int64, CONFIG_TYPE_INT64);
		break;
	case CONFIG_TYPE_FLOAT:
		status = sscanf((char *) cmd->words[cmd->words_num - 1], "%f", &val_float);
		if (status <= 0) {
			PRINT_IMPORTANT("Incorrect value format: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
			rtm_send_text(console->fd, "Incorrect value format, expected float");

			metadata_destroy(meta);
			PRINT_DEBUG("Freeing cmd=%p", cmd);
			free(cmd);
			return;
		}
		PRINT_DEBUG("value=%f", val_float);
		secure_metadata_writeToElement(meta, "value", &val_float, CONFIG_TYPE_FLOAT);
		break;
	case CONFIG_TYPE_STRING:
		PRINT_DEBUG("value='%s'", cmd->words[cmd->words_num - 1]);
		secure_metadata_writeToElement(meta, "value", &cmd->words[cmd->words_num - 1], CONFIG_TYPE_STRING);
		break;
	default:
		PRINT_ERROR("todo error");
		break;
	}

	rtm_send_fcf(module, cmd, meta);

	if (list_has_space(data->cmd_list)) {
		list_append(data->cmd_list, cmd);
	} else {
		PRINT_ERROR("todo error");
	}

//rtm_send_error(console->fd, "Correct so far", cmd_len, cmd_buf);
//PRINT_DEBUG("Exited: module=%p, console=%p, cmd_len=%u, cmd_buf='%s'", module, console, cmd_len, cmd_buf);
}

void rtm_process_pause(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);
	rtm_send_text(console->fd, "todo");
	PRINT_DEBUG("Freeing cmd=%p", cmd);
	free(cmd);
}

void rtm_process_unpause(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);
	rtm_send_text(console->fd, "todo");
	PRINT_DEBUG("Freeing cmd=%p", cmd);
	free(cmd);
}

void rtm_process_link(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);
	rtm_send_text(console->fd, "todo");
	PRINT_DEBUG("Freeing cmd=%p", cmd);
	free(cmd);
}

void rtm_process_unlink(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);
	rtm_send_text(console->fd, "todo");
	PRINT_DEBUG("Freeing cmd=%p", cmd);
	free(cmd);
}

void rtm_process_load(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);
	rtm_send_text(console->fd, "todo");
	PRINT_DEBUG("Freeing cmd=%p", cmd);
	free(cmd);
}

void rtm_process_unload(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);
	rtm_send_text(console->fd, "todo");
	PRINT_DEBUG("Freeing cmd=%p", cmd);
	free(cmd);
}

void rtm_process_replace(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);
	rtm_send_text(console->fd, "todo");
	PRINT_DEBUG("Freeing cmd=%p", cmd);
	free(cmd);
}

void rtm_process_shutdown(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);
	rtm_send_text(console->fd, "todo");
	PRINT_DEBUG("Freeing cmd=%p", cmd);
	free(cmd);
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

	if (ff != NULL) {
		if (ff->metaData == NULL) {
			PRINT_ERROR("Error fcf.metadata==NULL");
			exit(-1);
		}

		if (ff->dataOrCtrl == FF_CONTROL) {
			rtm_fcf(module, ff);
			PRINT_DEBUG("");
		} else if (ff->dataOrCtrl == FF_DATA) {
			if (ff->dataFrame.directionFlag == DIR_UP) {
				//rtm_in_fdf(module, ff);
				PRINT_ERROR("todo error");
				freeFinsFrame(ff);
			} else if (ff->dataFrame.directionFlag == DIR_DOWN) {
				//rtm_out_fdf(module, ff);
				PRINT_ERROR("todo error");
				freeFinsFrame(ff);
			} else {
				PRINT_ERROR("todo error");
				freeFinsFrame(ff);
			}
		} else {
			PRINT_ERROR("todo error");
			exit(-1);
		}
	} else if (data->interrupt_flag) {
		data->interrupt_flag = 0;

		rtm_interrupt(module); //TODO unused, implement or remove
	} else {
		PRINT_ERROR("todo error: dataOrCtrl=%u", ff->dataOrCtrl);
		exit(-1);
	}
}

void rtm_fcf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

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
		rtm_read_param_reply(module, ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		rtm_set_param(module, ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		rtm_set_param_reply(module, ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		rtm_exec_reply(module, ff);
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

void rtm_read_param_reply(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

}

void rtm_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	struct rtm_data *data = (struct rtm_data *) module->data;
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

void rtm_set_param_reply(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	struct rtm_data *data = (struct rtm_data *) module->data;

	secure_sem_wait(&data->shared_sem);
	struct rtm_command *cmd = (struct rtm_command *) list_find1(data->cmd_list, rtm_cmd_serial_test, &ff->ctrlFrame.serial_num);
	if (cmd != NULL) {
		list_remove(data->cmd_list, cmd);

		struct rtm_console *console = (struct rtm_console *) list_find1(data->console_list, rtm_console_id_test, &cmd->console_id);
		if (console != NULL) {
			//TODO extract answer
			if (ff->ctrlFrame.ret_val) {
				//send '' ?
				rtm_send_text(console->fd, "successful");
			} else {
				//send error
				rtm_send_text(console->fd, "unsuccessful");
			}
		} else {
			PRINT_ERROR("todo error");
		}
		sem_post(&data->shared_sem);

		free(cmd);
	} else {
		sem_post(&data->shared_sem);
		PRINT_ERROR("todo error");
		//TODO error, drop
		freeFinsFrame(ff);
	}
}

void rtm_exec_reply(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
}

void rtm_interrupt(struct fins_module *module) {
	struct rtm_data *data = (struct rtm_data *) module->data;

	if (data != NULL) {
		//TODO for any timers/TOs that we eventually implement
	}
}

void rtm_init_params(struct fins_module *module) {
	metadata_element *root = config_root_setting(module->params);
	metadata_element *exec_elem = config_setting_add(root, "exec", CONFIG_TYPE_GROUP);
	if (exec_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}

	metadata_element *get_elem = config_setting_add(root, "get", CONFIG_TYPE_GROUP);
	if (get_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}

	metadata_element *set_elem = config_setting_add(root, "set", CONFIG_TYPE_GROUP);
	if (set_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}

	metadata_element *sub = config_setting_add(exec_elem, "test", CONFIG_TYPE_GROUP);
	if (sub == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}

	metadata_element *elem = config_setting_add(sub, "key", CONFIG_TYPE_INT);
	if (elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}

	uint32_t value = 10;
	int status = config_setting_set_int(elem, *(int *) &value);
	if (status == CONFIG_FALSE) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}
}

int rtm_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi) {
	PRINT_IMPORTANT("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	rtm_init_params(module);

	module->data = secure_malloc(sizeof(struct rtm_data));
	struct rtm_data *data = (struct rtm_data *) module->data;

	if (module->flows_max < flows_num) {
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

	sem_init(&data->shared_sem, 0, 1);
	for (i = 0; i < MAX_CONSOLES; i++) {
		data->console_fds[i] = 0;
	}

	data->console_list = list_create(MAX_CONSOLES);
	data->console_counter = 0;

	data->cmd_list = list_create(MAX_COMMANDS);
	data->cmd_counter = 0;

	return 1;
}

int rtm_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_IMPORTANT("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	struct rtm_data *data = (struct rtm_data *) module->data;
	secure_pthread_create(&data->accept_console_thread, attr, accept_console, module);
	secure_pthread_create(&data->console_to_rtm_thread, attr, console_to_rtm, module);
	secure_pthread_create(&data->switch_to_rtm_thread, attr, switch_to_rtm, module);
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

	PRINT_IMPORTANT("Joining accept_console_thread");
	pthread_join(data->accept_console_thread, NULL);
	PRINT_IMPORTANT("Joining console_to_rtm_thread");
	pthread_join(data->console_to_rtm_thread, NULL);
	PRINT_IMPORTANT("Joining switch_to_rtm_thread");
	pthread_join(data->switch_to_rtm_thread, NULL);

	return 1;
}

int rtm_release(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);

	struct rtm_data *data = (struct rtm_data *) module->data;
//TODO free all module related mem
	list_free(data->cmd_list, free);

	if (data->link_list != NULL) {
		list_free(data->link_list, free);
	}
	free(data);
	module_destroy_structs(module);
	free(module);
	return 1;
}

int rtm_register_module(struct fins_module *module, struct fins_module *new_mod) {
	PRINT_DEBUG("Entered: module=%p, new_mod=%p, id=%d, name='%s'", module, new_mod, new_mod->id, new_mod->name);

	if (new_mod->index >= MAX_MODULES) {
		PRINT_ERROR("todo error");
		return -1;
	}

	struct rtm_data *data = (struct rtm_data *) module->data;

	if (data->overall->modules[new_mod->index] != NULL) {
		PRINT_IMPORTANT("Replacing: mod=%p, id=%d, name='%s'",
				data->overall->modules[new_mod->index], data->overall->modules[new_mod->index]->id, data->overall->modules[new_mod->index]->name);
	}
	PRINT_IMPORTANT("Registered: new_mod=%p, id=%d, name='%s'", new_mod, new_mod->id, new_mod->name);
	data->overall->modules[new_mod->index] = new_mod;

	PRINT_DEBUG("Exited: module=%p, new_mod=%p, id=%d, name='%s'", module, new_mod, new_mod->id, new_mod->name);
	return 0;
}

int rtm_unregister_module(struct fins_module *module, int index) {
	PRINT_DEBUG("Entered: module=%p, index=%d", module, index);

	if (index < 0 || index > MAX_MODULES) {
		PRINT_ERROR("todo error");
		return 0;
	}

	struct rtm_data *data = (struct rtm_data *) module->data;

	if (data->overall->modules[index] != NULL) {
		PRINT_IMPORTANT("Unregistering: mod=%p, id=%d, name='%s'",
				data->overall->modules[index], data->overall->modules[index]->id, data->overall->modules[index]->name);
		data->overall->modules[index] = NULL;
	} else {
		PRINT_IMPORTANT("No module to unregister: index=%d", index);
	}

	return 1;
}

int rtm_pass_overall(struct fins_module *module, struct fins_overall *overall) {
	PRINT_DEBUG("Entered: module=%p, overall=%p", module, overall);

	struct rtm_data *data = (struct rtm_data *) module->data;
	data->overall = overall;

	return 1;
}

void rtm_dummy(void) {

}

static struct fins_module_admin_ops rtm_ops = { .init = rtm_init, .run = rtm_run, .pause = rtm_pause, .unpause = rtm_unpause, .shutdown = rtm_shutdown,
		.release = rtm_release, .pass_overall = rtm_pass_overall };

struct fins_module *rtm_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_IMPORTANT("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, RTM_LIB);
	module->flows_max = RTM_MAX_FLOWS;
	module->ops = (struct fins_module_ops *) &rtm_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_IMPORTANT("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
