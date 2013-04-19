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
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <finstime.h>
#include <metadata.h>
#include <finsqueue.h>

#include "rtm.h"

#define RTM_LIB "rtm"
#define RTM_MAX_FLOWS 1

struct rtm_data {
	struct linked_list *link_list;
	uint32_t flows_num;
	uint32_t flows[RTM_MAX_FLOWS];

	pthread_t switch_to_rtm_thread;
	pthread_t cmdline_to_rtm_thread;
	uint8_t interrupt_flag;

	int server_fd;
};

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

//TODO change this macro to an extern in core? expect all exec apps to define FINS_TMP_ROOT
#ifdef BUILD_FOR_ANDROID
#define FINS_TMP_ROOT "/data/data/com.BU_VT.FINS/files"
//#define FINS_TMP_ROOT "/data/data/com.BU_VT.FINS"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

#define RTM_PATH FINS_TMP_ROOT "/fins_rtm"

void rtm_out(struct finsFrame *ff);
void rtm_in(struct finsFrame *ff);
void rtm_send_FF(int socket, struct finsFrame *ff);
void* rtm_get_FF(void* socket);
//void rtm_init();

void rtm_get_ff(struct fins_module *module);
void rtm_fcf(struct fins_module *module, struct finsFrame *ff);
void rtm_set_param(struct fins_module *module, struct finsFrame *ff);
//void rtm_exec(struct fins_module *module, struct finsFrame *ff);
//void rtm_exec_clear_sent(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
//void rtm_error(struct fins_module *module, struct finsFrame *ff);

//void rtm_in_fdf(struct fins_module *module, struct finsFrame *ff);
//void rtm_out_fdf(struct fins_module *module, struct finsFrame *ff);

void rtm_interrupt(struct fins_module *module);

int rtm_init(struct fins_module *module, uint32_t *flows, uint32_t flows_num, metadata_element *params, struct envi_record *envi);
int rtm_run(struct fins_module *module, pthread_attr_t *attr);
int rtm_pause(struct fins_module *module);
int rtm_unpause(struct fins_module *module);
int rtm_shutdown(struct fins_module *module);
int rtm_release(struct fins_module *module);

#endif /* RTM_INTERNAL_H_ */
