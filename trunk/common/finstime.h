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

struct pool_request {
	void *(*work)(void *local);
	void *local;
};

struct pool_worker {
	sem_t *inactive_sem;
	struct linked_list *queue;
	uint32_t *inactive_num;

	pthread_t thread;
	uint32_t id;
	uint8_t running;
	sem_t activate_sem;
	uint8_t inactive;
	uint8_t preload;

	void *(*work)(void *local);
	void *local;
};
void *worker_thread(void *local);

struct pool_worker *worker_create(sem_t *inactive_sem, uint32_t *inactive_num, struct linked_list *queue, uint32_t id);
void worker_shutdown(struct pool_worker *worker);
void worker_free(struct pool_worker *worker);

struct thread_pool {
	struct linked_list *workers;
	sem_t inactive_sem;
	uint32_t inactive_num;
	uint32_t worker_count;

	struct linked_list *queue;
	struct pool_controller *controller;
};

struct thread_pool *pool_create(uint32_t initial, uint32_t max, uint32_t limit);
void pool_start(struct thread_pool *pool, uint32_t threads);
int pool_execute(struct thread_pool *pool, void *(*work)(void *local), void *local);
void pool_shutdown(struct thread_pool *pool);
void pool_free(struct thread_pool *pool);

struct pool_controller {
	struct thread_pool *pool;
	double period;

	pthread_t thread;
	uint32_t id;
	int fd;
	uint8_t running;
};
void *controller_thread(void *local);

struct pool_controller *controller_create(struct thread_pool *pool);
void controller_shutdown(struct pool_controller *controller);
void controller_free(struct pool_controller *controller);

//void *controler_thread(void *local);

#endif /* FINSTIME_H_ */
