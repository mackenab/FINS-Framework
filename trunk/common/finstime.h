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
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef BUILD_FOR_ANDROID
#include <linux/time.h>
#include <sys/endian.h>
//#include <sys/linux-unistd.h>
#else
#include <sys/timerfd.h>
#endif

//#include <stdlib.h>
//#include <stdio.h>

//#include <stdlib.h>
//#include <stdio.h>
//#include <stdint.h>

#include "finsdebug.h"
#include "finstypes.h"
//#include "metadata.h"

double time_diff(struct timeval *time1, struct timeval *time2);

#define TO_MIN 0.00001

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

struct to_timer_data {
	void (*handler)(void *local);
	timer_t tid;
};
void to_handler(int sig, siginfo_t *si, void *uc);

struct interrupt_to_timer_data {
	void (*handler)(void *local);
	timer_t tid;
	uint8_t *flag;
	uint8_t *interrupt;
};
void interrupt_to_handler(void *local);

struct sem_to_timer_data {
	void (*handler)(void *local);
	timer_t tid;
	uint8_t *flag;
	uint8_t *waiting;
	sem_t *sem;
};
void sem_to_handler(void *local);

struct intsem_to_timer_data {
	void (*handler)(void *local);
	timer_t tid;
	uint8_t *flag;
	uint8_t *interrupt;
	sem_t *sem;
};
void intsem_to_handler(void *local);

void register_to_signal(uint32_t signal);
void block_to_signal(void);
void unblock_to_signal(void);

void timer_create_to(struct to_timer_data *data);
void timer_stop(timer_t timerid);
void timer_once_start(timer_t timerid, double millis);
void timer_repeat_start(timer_t timerid, double millis);

#endif /* FINSTIME_H_ */
