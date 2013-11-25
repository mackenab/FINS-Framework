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

#define LOGGER_INTERVAL_DEFAULT 1000
#define LOGGER_REPEATS_DEFAULT 	30


#define LOGGER_LIB "logger"
#define LOGGER_MAX_FLOWS 0
//#define LOGGER_FLOW_RTM  0 //TODO remove

struct logger_data {
	struct linked_list *link_list; //linked list of link_record structs, representing links for this module
	uint32_t flows_num;
	struct fins_module_flow flows[LOGGER_MAX_FLOWS];

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

int logger_init(struct fins_module *module, metadata_element *params, struct envi_record *envi);
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
#define LOGGER_READ_PARAM_FLOWS MOD_READ_PARAM_FLOWS
#define LOGGER_READ_PARAM_LINKS MOD_READ_PARAM_LINKS
#define LOGGER_READ_PARAM_DUAL MOD_READ_PARAM_DUAL
#define LOGGER_GET_INTERVAL__id 3
#define LOGGER_GET_INTERVAL__str "interval"
#define LOGGER_GET_INTERVAL__type META_TYPE_FLOAT
#define LOGGER_GET_REPEATS__id 4
#define LOGGER_GET_REPEATS__str "repeats"
#define LOGGER_GET_REPEATS__type META_TYPE_INT32

#define LOGGER_SET_PARAM_FLOWS MOD_SET_PARAM_FLOWS
#define LOGGER_SET_PARAM_LINKS MOD_SET_PARAM_LINKS
#define LOGGER_SET_PARAM_DUAL MOD_SET_PARAM_DUAL
#define LOGGER_SET_INTERVAL__id 3
#define LOGGER_SET_INTERVAL__str "interval"
#define LOGGER_SET_INTERVAL__type META_TYPE_FLOAT
#define LOGGER_SET_REPEATS__id 4
#define LOGGER_SET_REPEATS__str "repeats"
#define LOGGER_SET_REPEATS__type META_TYPE_INT32

#define LOGGER_ALERT_FLOWS MOD_ALERT_FLOWS
#define LOGGER_ALERT_LINKS MOD_ALERT_LINKS
#define LOGGER_ALERT_DUAL MOD_ALERT_DUAL
#define LOGGER_ALERT_UPDATE__id 3
#define LOGGER_ALERT_UPDATE__str "update"
#define LOGGER_ALERT_UPDATE__type META_TYPE_STRING

#endif /* LOGGER_INTERNAL_H_ */
