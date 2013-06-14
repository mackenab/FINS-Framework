/*
 * rtm_internal.h
 *
 *  Created on: Apr 18, 2013
 *      Author: Jonathan Reed
 */

#ifndef RTM_INTERNAL_H_
#define RTM_INTERNAL_H_

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <finstime.h>
#include <metadata.h>
#include <finsqueue.h>

#include "rtm.h"

//--------------------------------------------------- //temp stuff to cross compile, remove/implement better eventual?
#ifndef POLLRDNORM
#define POLLRDNORM POLLIN
#endif

#ifndef POLLRDBAND
#define POLLRDBAND POLLIN
#endif

#ifndef POLLWRNORM
#define POLLWRNORM POLLOUT
#endif

#ifndef POLLWRBAND
#define POLLWRBAND POLLOUT
#endif

#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#ifndef ALLPERMS
#define ALLPERMS (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO)/* 07777 */
#endif

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

//TODO change this macro to an extern in core? expect all exec apps to define FINS_TMP_ROOT
#ifdef BUILD_FOR_ANDROID
#define FINS_TMP_ROOT "/data/local/fins"
//#define FINS_TMP_ROOT "/data/data/com.BU_VT.FINS/files"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

#define RTM_PATH FINS_TMP_ROOT "/fins_rtm"

#define MAX_CONSOLES 20
#define MAX_COMMANDS 40
#define MAX_CMD_LEN 500
#define MAX_WORDS 500
#define CMD_DELIMS " "

//$: <command> <module_name> <param_name> <value>
//TODO instead of 4 fixed, change to have value as LAST word, everything after module as augments
#define INDEX_OP 0
#define INDEX_MOD 1
#define INDEX_PARAM 2
#define INDEX_VAL 3

//operations
#define OP_HELP_STR "help"
#define OP_EXEC_STR "exec"
#define OP_GET_STR "get"
#define OP_SET_STR "set"
#define OP_PAUSE_STR "pause"
#define OP_UNPAUSE_STR "unpause"
#define OP_LINK_STR "link"
#define OP_UNLINK_STR "unlink"
#define OP_LOAD_STR "load"
#define OP_UNLOAD_STR "unload"
#define OP_REPLACE_STR "replace"
#define OP_SHUTDOWN_STR "shutdown"
//display params?
//help options, operations --help
//tab complete?
//list of modules / current state

#define OP_HELP_MSG "Available operations:"

//TODO finish
#define OP_HELP_INFO "Documentation on available operations and their usage."
#define OP_EXEC_INFO "Execute a procedure for one or all of the modules."
#define OP_GET_INFO "Get the value of a parameter or sub-parameter for a module."
#define OP_SET_INFO "Set the value of a parameter or sub-parameter for a module."
#define OP_PAUSE_INFO "Pause one or all the modules." //TODO finish
#define OP_UNPAUSE_INFO "Un-pause one or all the modules." //TODO finish
#define OP_LINK_INFO "todo"
#define OP_UNLINK_INFO "todo"
#define OP_LOAD_INFO "todo"
#define OP_UNLOAD_INFO "todo"
#define OP_REPLACE_INFO "todo"
#define OP_SHUTDOWN_INFO "todo"

//TODO finish
#define OP_HELP_USAGE "help <operation>"
#define OP_EXEC_USAGE "exec <module> <procedure> [<param1>=<value1>]"
#define OP_GET_USAGE "get <module> <param> [<subparam> [<subsubparam>]]"
#define OP_SET_USAGE "set <module> <param> [<subparam> [<subsubparam>]] <value>"
#define OP_PAUSE_USAGE "pause [all|<module>]"
#define OP_UNPAUSE_USAGE "unpause [all|<module>]"
#define OP_LINK_USAGE "link" //link [add|remove|edit]
#define OP_UNLINK_USAGE "unlink" //unlink [all|<module>]
#define OP_LOAD_USAGE "load <library>"
#define OP_UNLOAD_USAGE "unload <module>"
#define OP_REPLACE_USAGE "replace <module>"
#define OP_SHUTDOWN_USAGE "shutdown"

typedef enum {
	OP_HELP = 0, OP_EXEC, OP_GET, OP_SET, OP_PAUSE, OP_UNPAUSE, OP_LINK, OP_UNLINK, OP_LOAD, OP_UNLOAD, OP_REPLACE, OP_SHUTDOWN, OP_MAX
} operations;

//modules
#define MOD_ALL "all"
//TODO remove?
#define MOD_NONE "none"

struct rtm_command {
	uint32_t id;
	uint32_t console_id;
	uint32_t cmd_len;
	uint8_t cmd_buf[MAX_CMD_LEN];

	uint32_t words_num;
	uint8_t words_buf[MAX_CMD_LEN];
	uint8_t *words[MAX_WORDS];

	//FCF values
	uint32_t mod;
	uint32_t serial_num;
	uint32_t op;

	//param values
	uint32_t param_id;
	uint8_t param_str[MAX_CMD_LEN];
	uint32_t param_type;
};
int rtm_cmd_serial_test(struct rtm_command *cmd, uint32_t *serial_num);

struct rtm_console {
	uint32_t id;
	int fd;
	struct sockaddr_un *addr;
};
int rtm_console_id_test(struct rtm_console *console, uint32_t *id);
int rtm_console_fd_test(struct rtm_console *console, int *fd);
void console_free(struct rtm_console *console);

int rtm_recv_fd(int fd, uint32_t buf_len, uint8_t *buf);
int rtm_send_fd(int fd, uint32_t buf_len, uint8_t *buf);
int rtm_send_ack(int fd, uint32_t cmd_len, uint8_t *cmd_buf); //TODO remove? probably not as necessary
int rtm_send_nack(int fd, uint32_t cmd_len, uint8_t *cmd_buf);
int rtm_send_error(int fd, const char *text, uint32_t buf_len, uint8_t *buf);
int rtm_send_text(int fd, const char *text);

void rtm_send_fcf(struct fins_module *module, struct rtm_command *cmd, metadata *meta);

int match_module(struct fins_module **modules, uint8_t *word);
metadata_element *match_params(metadata *params, uint8_t **words, int path_end);

void rtm_process_cmd(struct fins_module *module, struct rtm_console *console, uint32_t cmd_len, uint8_t *cmd_buf);
typedef void (*process_op_type)(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);

void rtm_process_help(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);
void rtm_process_exec(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);
void rtm_process_get(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);
void rtm_process_set(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);
void rtm_process_pause(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);
void rtm_process_unpause(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);
void rtm_process_link(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);
void rtm_process_unlink(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);
void rtm_process_load(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);
void rtm_process_unload(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);
void rtm_process_replace(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);
void rtm_process_shutdown(struct fins_module *module, struct rtm_console *console, struct rtm_command *cmd);

#define RTM_LIB "rtm"
#define RTM_MAX_FLOWS 0

struct rtm_data {
	struct linked_list *link_list;
	uint32_t flows_num;
	uint32_t flows[RTM_MAX_FLOWS];

	pthread_t switch_to_rtm_thread;
	pthread_t console_to_rtm_thread;
	pthread_t accept_console_thread;
	uint8_t interrupt_flag;

	struct fins_overall *overall;
	int server_fd;

	sem_t shared_sem;
	int console_fds[MAX_CONSOLES];

	struct linked_list *console_list;
	uint32_t console_counter;

	struct linked_list *cmd_list;
	uint32_t cmd_counter;
};

int rtm_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi);
int rtm_run(struct fins_module *module, pthread_attr_t *attr);
int rtm_pause(struct fins_module *module);
int rtm_unpause(struct fins_module *module);
int rtm_shutdown(struct fins_module *module);
int rtm_release(struct fins_module *module);
int rtm_register_module(struct fins_module *module, struct fins_module *new_mod);
int rtm_unregister_module(struct fins_module *module, int index);
int rtm_pass_overall(struct fins_module *module, struct fins_overall *overall);

void rtm_get_ff(struct fins_module *module);
void rtm_fcf(struct fins_module *module, struct finsFrame *ff);
void rtm_read_param_reply(struct fins_module *module, struct finsFrame *ff);
void rtm_set_param(struct fins_module *module, struct finsFrame *ff);
void rtm_set_param_reply(struct fins_module *module, struct finsFrame *ff);
//void rtm_exec(struct fins_module *module, struct finsFrame *ff);
void rtm_exec_reply(struct fins_module *module, struct finsFrame *ff);
//void rtm_error(struct fins_module *module, struct finsFrame *ff);

//void rtm_in_fdf(struct fins_module *module, struct finsFrame *ff);
//void rtm_out_fdf(struct fins_module *module, struct finsFrame *ff);

void rtm_interrupt(struct fins_module *module);

//don't use 0
#define RTM_GET_PARAM_FLOWS MOD_GET_PARAM_FLOWS
#define RTM_GET_PARAM_LINKS MOD_GET_PARAM_LINKS
#define RTM_GET_PARAM_DUAL MOD_GET_PARAM_DUAL

#define RTM_SET_PARAM_FLOWS MOD_SET_PARAM_FLOWS
#define RTM_SET_PARAM_LINKS MOD_SET_PARAM_LINKS
#define RTM_SET_PARAM_DUAL MOD_SET_PARAM_DUAL

#endif /* RTM_INTERNAL_H_ */
