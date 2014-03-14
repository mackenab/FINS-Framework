/*
 * template_internal.h
 *
 *  Created on: Dec 19, 2013
 *      Author: root
 */

#ifndef TEMPLATE_INTERNAL_H_
#define TEMPLATE_INTERNAL_H_

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

#include "template.h"

//module specific constants
#define TEMPLATE_LIST_SIZE 10

//required module info
#define TEMPLATE_LIB "template"
#define TEMPLATE_MAX_FLOWS 1
#define TEMPLATE_FLOW_LOGGER  0

struct template_data {
	//required
	struct linked_list *link_list; 	//linked list of link_record structs, representing links for this module
	uint32_t flows_num; 			//current number of flows in table
	struct fins_module_flow flows[TEMPLATE_MAX_FLOWS]; //link_id for each flow, 0=empty

	//typical
	pthread_t switch_to_template_thread; //main thread of this module
	uint8_t interrupt_flag; 		//signals module thread to stop waiting for FFs & handle a timeout/event

	struct linked_list *if_list; 	//linked list of if_record structs, representing all interfaces
	struct if_record *if_loopback; 	//pointer to if_record representing the loopback interface
	struct if_record *if_main; 		//pointer to if_record representing the main interface

	//optional/module specific
	double timeout; 				//any variables of the module that needs to be stored
	struct linked_list *list; 		//a linked list to store pointers to ints, structs, etc
	struct intsem_to_timer_data *to_data; //struct for the int/semaphore-type of timeout timer
	uint8_t flag; 					//flag set by the int/semaphore-type timeout: 1=TO, 0=none.
};

int template_init(struct fins_module *module, metadata_element *params, struct envi_record *envi);
int template_run(struct fins_module *module, pthread_attr_t *attr);
int template_pause(struct fins_module *module);
int template_unpause(struct fins_module *module);
int template_shutdown(struct fins_module *module);
int template_release(struct fins_module *module);

int template_to_switch(struct fins_module *module, struct finsFrame *ff);
void template_get_ff(struct fins_module *module);

void template_fcf(struct fins_module *module, struct finsFrame *ff);
void template_alert(struct fins_module *module, struct finsFrame *ff);
void template_read_param(struct fins_module *module, struct finsFrame *ff);
void template_set_param(struct fins_module *module, struct finsFrame *ff);
void template_exec(struct fins_module *module, struct finsFrame *ff);
void template_error(struct fins_module *module, struct finsFrame *ff);

void template_in_fdf(struct fins_module *module, struct finsFrame *ff);
void template_out_fdf(struct fins_module *module, struct finsFrame *ff);

void template_interrupt(struct fins_module *module);

#define TEMPLATE_READ_PARAM_FLOWS MOD_READ_PARAM_FLOWS //0
#define TEMPLATE_READ_PARAM_LINKS MOD_READ_PARAM_LINKS //1
#define TEMPLATE_READ_PARAM_DUAL MOD_READ_PARAM_DUAL   //2

#define TEMPLATE_SET_PARAM_FLOWS MOD_SET_PARAM_FLOWS //0
#define TEMPLATE_SET_PARAM_LINKS MOD_SET_PARAM_LINKS //1
#define TEMPLATE_SET_PARAM_DUAL MOD_SET_PARAM_DUAL //2
#define TEMPLATE_SET_TIMEOUT__id 3
#define TEMPLATE_SET_TIMEOUT__str "timeout"
#define TEMPLATE_SET_TIMEOUT__type META_TYPE_FLOAT

#define TEMPLATE_ALERT_FLOWS MOD_ALERT_FLOWS //0
#define TEMPLATE_ALERT_LINKS MOD_ALERT_LINKS //1
#define TEMPLATE_ALERT_DUAL MOD_ALERT_DUAL //2

#endif /* TEMPLATE_INTERNAL_H_ */
