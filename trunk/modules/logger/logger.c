/*
 * logger.c
 *
 *  Created on: Feb 3, 2013
 *      Author: alex
 */
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#include <finstypes.h>
#include <finstime.h>
#include <metadata.h>
#include <finsqueue.h>

#include <switch.h>
static struct fins_proto_module logger_proto = { .module_id = LOGGER_ID, .name = "logger", .running_flag = 1, };

pthread_t switch_to_logger_thread;

uint8_t logger_interrupt_flag;

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

int logger_to_switch(struct finsFrame *ff) {
	return module_to_switch(&logger_proto, ff);
}

void logger_get_ff(void) {

	struct finsFrame *ff;
	do {
		secure_sem_wait(logger_proto.event_sem);
		secure_sem_wait(logger_proto.input_sem);
		ff = read_queue(logger_proto.input_queue);
		sem_post(logger_proto.input_sem);
	} while (logger_proto.running_flag && ff == NULL && !logger_interrupt_flag); //TODO change logic here, combine with switch_to_logger?

	if (!logger_proto.running_flag) {
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
			logger_fcf(ff);
			PRINT_DEBUG("");
		} else if (ff->dataOrCtrl == DATA) {
			if (logger_started) {
				gettimeofday(&logger_end, 0);
				logger_packets++;
				logger_bytes += ff->dataFrame.pduLength;
				//logger_bytes += ff->dataFrame.pduLength-28; //for end-end throughput of exp 2, to remove IP/UDP hdrs
			} else {
				logger_started = 1;
				gettimeofday(&logger_start, 0);
				logger_packets = 1;
				logger_bytes = ff->dataFrame.pduLength;
				//logger_bytes = ff->dataFrame.pduLength-28; //for end-end throughput of exp 2, to remove IP/UDP hdrs

				logger_saved_packets = 0;
				logger_saved_bytes = 0;
				logger_saved_curr = 0;

				timer_once_start(logger_to_data->tid, logger_interval);
				PRINT_IMPORTANT("Logger starting");
			}
			freeFinsFrame(ff);
		} else {
			PRINT_ERROR("todo error");
		}
	} else if (logger_interrupt_flag) {
		logger_interrupt_flag = 0;

		logger_interrupt();
	} else {
		PRINT_ERROR("todo error");
	}
}

void logger_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	//TODO fill out
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
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
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

void logger_interrupt(void) {
	PRINT_DEBUG("Entered");

	if (logger_started) {
		struct timeval current;
		gettimeofday(&current, 0);

		double diff_curr = time_diff(&logger_start, &current) / 1000.0;
		double diff_period = diff_curr - logger_saved_curr;
		int diff_packets = logger_packets - logger_saved_packets;
		int diff_bytes = logger_bytes - logger_saved_bytes;
		double diff_through = 8.0 * diff_bytes / diff_period;
		PRINT_IMPORTANT("period=%f-%f,\t packets=%d,\t bytes=%d,\t through=%f", logger_saved_curr, diff_curr, diff_packets, diff_bytes, diff_through);

		logger_saved_packets = logger_packets;
		logger_saved_bytes = logger_bytes;
		logger_saved_curr = diff_curr;

		//if (diff_curr > 2 * logger_repeats * logger_interval / 1000.0) {
		if (diff_curr >= 1 * logger_repeats * logger_interval / 1000.0) {
			logger_started = 0;

			double test = time_diff(&logger_start, &logger_end) / 1000.0;
			//double through = 8.0 * (logger_bytes - 10 * 1470) / test;
			double through = 8.0 * logger_bytes / test;
			PRINT_IMPORTANT("Logger stopping: total=%f,\t packets=%d,\t bytes=%d,\t through=%f", test, logger_packets, logger_bytes, through);
		} else {
			timer_once_start(logger_to_data->tid, logger_interval);
		}
	} else {
		PRINT_ERROR("run over?");
	}
}

void *switch_to_logger(void *local) {
	PRINT_IMPORTANT("Entered");

	while (logger_proto.running_flag) {
		logger_get_ff();
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Exited");
	//pthread_exit(NULL);
	return NULL;
}

int logger_init_new(struct fins_module *module, metadata *meta, struct envi_record *envi) {
	return 0;
}
int logger_run_new(struct fins_module *module, pthread_attr_t *fins_pthread_attr) {
	return 0;
}
int logger_pause_new(struct fins_module *module) {
	return 0;
}
int logger_unpause_new(struct fins_module *module) {
	return 0;
}
int logger_shutdown_new(struct fins_module *module) {
	return 0;
}
int logger_release_new(struct fins_module *module) {
	return 0;
}

static struct fins_module_ops logger_ops = { .init = logger_init_new, .run = logger_run_new, .pause = logger_pause_new, .unpause = logger_unpause_new,
		.shutdown = logger_shutdown_new, .release = logger_release_new, };

struct fins_module *logger_create_new(uint32_t index, uint32_t id, char *name) {
	PRINT_IMPORTANT("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, "logger");
	module->ops = &logger_ops;
	module->state = FMS_FREE;
	module->num_ports = 0;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, name);

	PRINT_IMPORTANT("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}

void logger_dummy(void) {

}

void logger_init(void) {
	PRINT_IMPORTANT("Entered");
	logger_proto.running_flag = 1;

	module_create_ops(&logger_proto);
	module_register(&logger_proto);

	logger_started = 0;
	logger_interval = 1000;
	logger_repeats = 10;

	logger_to_data = secure_malloc(sizeof(struct intsem_to_timer_data));
	logger_to_data->handler = intsem_to_handler;
	logger_to_data->flag = &logger_flag;
	logger_to_data->interrupt = &logger_interrupt_flag;
	logger_to_data->sem = logger_proto.event_sem;
	timer_create_to((struct to_timer_data *) logger_to_data);
}

void logger_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_IMPORTANT("Entered");

	secure_pthread_create(&switch_to_logger_thread, fins_pthread_attr, switch_to_logger, fins_pthread_attr);
}

void logger_shutdown(void) {
	PRINT_IMPORTANT("Entered");
	logger_proto.running_flag = 0;
	sem_post(logger_proto.event_sem);

	timer_stop(logger_to_data->tid);

	//TODO expand this

	PRINT_IMPORTANT("Joining switch_to_logger_thread");
	pthread_join(switch_to_logger_thread, NULL);
}

void logger_release(void) {
	PRINT_IMPORTANT("Entered");
	module_unregister(logger_proto.module_id);

	//TODO free all module related mem

	//stop threads
	timer_delete(logger_to_data->tid);
	free(logger_to_data);

	PRINT_DEBUG("");
	//post to read/write/connect/etc threads

	module_destroy_ops(&logger_proto);
}
