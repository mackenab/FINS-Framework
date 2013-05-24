/*
 * logger_internal.h
 *
 *  Created on: Feb 3, 2013
 *      Author: Jonathan Reed
 */

#ifndef LOGGER_INTERNAL_H_
#define LOGGER_INTERNAL_H_

#include <arpa/inet.h>
#include <pthread.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#ifdef BUILD_FOR_ANDROID
#include <sys/endian.h>
#endif

#include <finsdebug.h>
#include <finstypes.h>
#include <finstime.h>
#include <metadata.h>
#include <finsqueue.h>

#include "logger.h"

#define LOGGER_LIB "logger"
#define LOGGER_MAX_FLOWS 0

struct logger_data {
	struct linked_list *link_list;
	uint32_t flows_num;
	uint32_t flows[LOGGER_MAX_FLOWS];

	pthread_t switch_to_logger_thread;
	uint8_t interrupt_flag;

	double logger_interval;
	int logger_repeats;

	int logger_started;
	int logger_packets;
	int logger_bytes;
	int logger_saved_packets;
	int logger_saved_bytes;

	struct timeval logger_start;
	double logger_saved_curr;
	struct timeval logger_end;

	struct intsem_to_timer_data *logger_to_data;
	uint8_t logger_flag;
};

int logger_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi);
int logger_run(struct fins_module *module, pthread_attr_t *attr);
int logger_pause(struct fins_module *module);
int logger_unpause(struct fins_module *module);
int logger_shutdown(struct fins_module *module);
int logger_release(struct fins_module *module);

int logger_to_switch(struct fins_module *module, struct finsFrame *ff);
void logger_get_ff(struct fins_module *module);
void logger_fcf(struct fins_module *module, struct finsFrame *ff);
void logger_set_param(struct fins_module *module, struct finsFrame *ff);
//void logger_exec(struct fins_module *module, struct finsFrame *ff);
//void logger_error(struct fins_module *module, struct finsFrame *ff);

//void logger_in_fdf(struct fins_module *module, struct finsFrame *ff);
//void logger_out_fdf(struct fins_module *module, struct finsFrame *ff);

void logger_interrupt(struct fins_module *module);

//don't use 0
#define RTM_EXEC_START 1
#define RTM_EXEC_PAUSE 2
#define RTM_EXEC_UNPAUSE 3
#define RTM_EXEC_STOP 4

//don't use 0
#define LOGGER_GET_PARAM_FLOWS MOD_GET_PARAM_FLOWS
#define LOGGER_GET_PARAM_LINKS MOD_GET_PARAM_LINKS
#define LOGGER_GET_PARAM_DUAL MOD_GET_PARAM_DUAL
#define LOGGER_GET_INTERVAL__id 3
#define LOGGER_GET_INTERVAL__str "interval"
#define LOGGER_GET_INTERVAL__type CONFIG_TYPE_FLOAT
#define LOGGER_GET_REPEATS__id 4
#define LOGGER_GET_REPEATS__str "repeats"
#define LOGGER_GET_REPEATS__type CONFIG_TYPE_INT

#define LOGGER_SET_PARAM_FLOWS MOD_SET_PARAM_FLOWS
#define LOGGER_SET_PARAM_LINKS MOD_SET_PARAM_LINKS
#define LOGGER_SET_PARAM_DUAL MOD_SET_PARAM_DUAL
#define LOGGER_SET_INTERVAL__id 3
#define LOGGER_SET_INTERVAL__str "interval"
#define LOGGER_SET_INTERVAL__type CONFIG_TYPE_FLOAT
#define LOGGER_SET_REPEATS__id 4
#define LOGGER_SET_REPEATS__str "repeats"
#define LOGGER_SET_REPEATS__type CONFIG_TYPE_INT

#endif /* LOGGER_INTERNAL_H_ */
