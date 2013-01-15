/*
 * finstime.c
 *
 *  Created on: Jan 11, 2013
 *      Author: alex
 */

#ifndef FINSTIME_H_
#define FINSTIME_H_

#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

//#include <stdlib.h>
//#include <stdint.h>
//#include <stdio.h>
//#include <stdint.h>

#include "finsdebug.h"
#include "finstypes.h"
//#include "metadata.h"

double time_diff(struct timeval *time1, struct timeval *time2);

struct interrupt_to_thread_data {
	int id;
	int fd;
	uint8_t *running;
	uint8_t *flag;
	uint8_t *interrupt;
};
void *interrupt_to_thread(void *local);

struct sem_to_thread_data {
	uint32_t id;
	int fd;
	uint8_t *running;
	uint8_t *flag;
	uint8_t *waiting;
	sem_t *sem;
};
void *sem_to_thread(void *local);


struct intsem_to_thread_data {
	uint32_t id;
	int fd;
	uint8_t *running;
	uint8_t *flag;
	uint8_t *interrupt;
	sem_t *sem;
};
void *intsem_to_thread(void *local);

void stop_timer(int fd);
void start_timer(int fd, double millis);

#endif /* FINSTIME_H_ */
