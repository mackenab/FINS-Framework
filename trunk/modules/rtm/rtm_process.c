/*
 * rtm_process.c
 *
 *  Created on: May 3, 2013
 *      Author: Jonathan Reed
 */
#include "rtm_internal.h"

static char *op_strs[] = { OP_HELP_STR, OP_EXEC_STR, OP_GET_STR, OP_SET_STR, OP_PAUSE_STR, OP_UNPAUSE_STR, OP_LINK_STR, OP_UNLINK_STR, OP_LOAD_STR,
		OP_UNLOAD_STR, OP_REPLACE_STR, OP_SHUTDOWN_STR };
static char *op_info[] = { OP_HELP_INFO, OP_EXEC_INFO, OP_GET_INFO, OP_SET_INFO, OP_PAUSE_INFO, OP_UNPAUSE_INFO, OP_LINK_INFO, OP_UNLINK_INFO, OP_LOAD_INFO,
		OP_UNLOAD_INFO, OP_REPLACE_INFO, OP_SHUTDOWN_INFO };
static char *op_usages[] = { OP_HELP_USAGE, OP_EXEC_USAGE, OP_GET_USAGE, OP_SET_USAGE, OP_PAUSE_USAGE, OP_UNPAUSE_USAGE, OP_LINK_USAGE, OP_UNLINK_USAGE,
		OP_LOAD_USAGE, OP_UNLOAD_USAGE, OP_REPLACE_USAGE, OP_SHUTDOWN_USAGE };
static process_op_type op_funcs[] = { rtm_process_help, rtm_process_exec, rtm_process_get, rtm_process_set, rtm_process_pause, rtm_process_unpause,
		rtm_process_link, rtm_process_unlink, rtm_process_load, rtm_process_unload, rtm_process_replace, rtm_process_shutdown };

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

void rtm_process_cmd(struct fins_module *module, struct rtm_console *console, uint32_t cmd_len, uint8_t *cmd_buf) {
	struct rtm_data *md = (struct rtm_data *) module->data;
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd_len=%u, cmd_buf='%s'", module, console, cmd_len, cmd_buf);

	struct rtm_command *cmd = (struct rtm_command *) secure_malloc(sizeof(struct rtm_command));
	cmd->id = md->cmd_counter++;
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
	struct rtm_data *md = (struct rtm_data *) module->data;

	if (cmd->words_num < 3) {
		PRINT_IMPORTANT("Incorrect usage: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Incorrect usage:" OP_EXEC_USAGE);

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

//TODO identify module
	struct fins_module **modules = md->overall->modules;

	secure_sem_wait(&md->overall->sem);
	int mod = match_module(modules, cmd->words[INDEX_MOD]);
	if (mod == -1) {
		sem_post(&md->overall->sem);
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
		sem_post(&md->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

	int param_id;
	int status = config_setting_lookup_int(param, PARAM_ID, (int *) &param_id);
	if (status == META_FALSE) {
		sem_post(&md->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}
	sem_post(&md->overall->sem);

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

	if (list_has_space(md->cmd_list)) {
		list_append(md->cmd_list, cmd);
	} else {
		PRINT_ERROR("todo error");
	}

//rtm_send_error(console->fd, "Correct so far", cmd_len, cmd_buf);
//PRINT_DEBUG("Exited: module=%p, console=%p, cmd_len=%u, cmd_buf='%s'", module, console, cmd_len, cmd_buf);
}

void rtm_process_get(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);
	struct rtm_data *md = (struct rtm_data *) module->data;

	if (cmd->words_num < 3) {
		PRINT_IMPORTANT("Incorrect usage: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Incorrect usage:" OP_GET_USAGE);

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

//TODO identify module
	struct fins_module **modules = md->overall->modules;

	secure_sem_wait(&md->overall->sem);
	int mod = match_module(modules, cmd->words[INDEX_MOD]);
	if (mod == -1) {
		sem_post(&md->overall->sem);
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
		sem_post(&md->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

	int param_id;
	int status = config_setting_lookup_int(param, PARAM_ID, (int *) &param_id);
	if (status == META_FALSE) {
		sem_post(&md->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}
	sem_post(&md->overall->sem);

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

	if (list_has_space(md->cmd_list)) {
		list_append(md->cmd_list, cmd);
	} else {
		PRINT_ERROR("todo error");
	}

//rtm_send_error(console->fd, "Correct so far", cmd_len, cmd_buf);
//PRINT_DEBUG("Exited: module=%p, console=%p, cmd_len=%u, cmd_buf='%s'", module, console, cmd_len, cmd_buf);
}

void rtm_process_set(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd) {
	PRINT_DEBUG("Entered: module=%p, console=%p, cmd=%p", module, console, cmd);
	struct rtm_data *md = (struct rtm_data *) module->data;

	if (cmd->words_num < 4) {
		PRINT_IMPORTANT("Incorrect usage: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Incorrect usage:" OP_SET_USAGE);

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

//TODO identify module
	struct fins_module **modules = md->overall->modules;

	secure_sem_wait(&md->overall->sem);
	int mod = match_module(modules, cmd->words[INDEX_MOD]);
	if (mod == -1) {
		sem_post(&md->overall->sem);
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
		sem_post(&md->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

	int param_id;
	int status = config_setting_lookup_int(param, PARAM_ID, (int *) &param_id);
	if (status == META_FALSE) {
		sem_post(&md->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}

	int param_type;
	status = config_setting_lookup_int(param, PARAM_TYPE, (int *) &param_type);
	if (status == META_FALSE) {
		sem_post(&md->overall->sem);
		PRINT_IMPORTANT("Unknown parameter: console=%p, id=%u, cmd='%s'", console, console->id, cmd->cmd_buf);
		rtm_send_text(console->fd, "Unknown parameter");

		PRINT_DEBUG("Freeing cmd=%p", cmd);
		free(cmd);
		return;
	}
	sem_post(&md->overall->sem);

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

	if (list_has_space(md->cmd_list)) {
		list_append(md->cmd_list, cmd);
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
