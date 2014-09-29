/*
 * logger_iperf_internal.h
 *
*  Created on: Aug 20, 2014
 *      Author: Jonathan Reed
 */

#ifndef LOGGER_IPERF_INTERNAL_H_
#define LOGGER_IPERF_INTERNAL_H_

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

#include "logger_iperf.h"

#define LOGGER_IPERF_INTERVAL_DEFAULT 80000 //1000
#define LOGGER_IPERF_REPEATS_DEFAULT 	1 //30


#define LOGGER_IPERF_LIB "logger_iperf"
#define LOGGER_IPERF_MAX_FLOWS 0
//#define LOGGER_IPERF_FLOW_RTM  0 //TODO remove

struct logger_iperf_data {
	struct linked_list *link_list; //linked list of link_record structs, representing links for this module
	uint32_t flows_num;
	struct fins_module_flow flows[LOGGER_IPERF_MAX_FLOWS];

	pthread_t switch_to_logger_iperf_thread;
	uint8_t interrupt_flag;

	double interval;
	int repeats;

	int started;
	int packets;
	int bytes;
	int saved_packets;
	int saved_bytes;

	int count;

	struct timeval start;
	double saved_curr;
	struct timeval end;

	struct intsem_to_timer_data *to_data;
	uint8_t flag;
};

int logger_iperf_init(struct fins_module *module, metadata_element *params, struct envi_record *envi);
int logger_iperf_run(struct fins_module *module, pthread_attr_t *attr);
int logger_iperf_pause(struct fins_module *module);
int logger_iperf_unpause(struct fins_module *module);
int logger_iperf_shutdown(struct fins_module *module);
int logger_iperf_release(struct fins_module *module);

int logger_iperf_to_switch(struct fins_module *module, struct finsFrame *ff);
void logger_iperf_get_ff(struct fins_module *module);
void logger_iperf_fcf(struct fins_module *module, struct finsFrame *ff);
void logger_iperf_set_param(struct fins_module *module, struct finsFrame *ff);
//void logger_iperf_exec(struct fins_module *module, struct finsFrame *ff);
//void logger_iperf_error(struct fins_module *module, struct finsFrame *ff);

//void logger_iperf_in_fdf(struct fins_module *module, struct finsFrame *ff);
//void logger_iperf_out_fdf(struct fins_module *module, struct finsFrame *ff);

void logger_iperf_interrupt(struct fins_module *module);

//don't use 0
#define RTM_EXEC_START 1
#define RTM_EXEC_PAUSE 2
#define RTM_EXEC_UNPAUSE 3
#define RTM_EXEC_STOP 4

//don't use 0
#define LOGGER_IPERF_READ_PARAM_FLOWS MOD_READ_PARAM_FLOWS
#define LOGGER_IPERF_READ_PARAM_LINKS MOD_READ_PARAM_LINKS
#define LOGGER_IPERF_READ_PARAM_DUAL MOD_READ_PARAM_DUAL
#define LOGGER_IPERF_GET_INTERVAL__id 3
#define LOGGER_IPERF_GET_INTERVAL__str "interval"
#define LOGGER_IPERF_GET_INTERVAL__type META_TYPE_FLOAT
#define LOGGER_IPERF_GET_REPEATS__id 4
#define LOGGER_IPERF_GET_REPEATS__str "repeats"
#define LOGGER_IPERF_GET_REPEATS__type META_TYPE_INT32

#define LOGGER_IPERF_SET_PARAM_FLOWS MOD_SET_PARAM_FLOWS
#define LOGGER_IPERF_SET_PARAM_LINKS MOD_SET_PARAM_LINKS
#define LOGGER_IPERF_SET_PARAM_DUAL MOD_SET_PARAM_DUAL
#define LOGGER_IPERF_SET_INTERVAL__id 3
#define LOGGER_IPERF_SET_INTERVAL__str "interval"
#define LOGGER_IPERF_SET_INTERVAL__type META_TYPE_FLOAT
#define LOGGER_IPERF_SET_REPEATS__id 4
#define LOGGER_IPERF_SET_REPEATS__str "repeats"
#define LOGGER_IPERF_SET_REPEATS__type META_TYPE_INT32

#define LOGGER_IPERF_ALERT_FLOWS MOD_ALERT_FLOWS
#define LOGGER_IPERF_ALERT_LINKS MOD_ALERT_LINKS
#define LOGGER_IPERF_ALERT_DUAL MOD_ALERT_DUAL

#endif /* LOGGER_IPERF_INTERNAL_H_ */
