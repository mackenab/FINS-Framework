/*
 * finstime.c
 *
 *  Created on: Jan 11, 2013
 *      Author: alex
 */

#include "finstime.h"

double time_diff(struct timeval *time1, struct timeval *time2) { //time2 - time1
	double decimal = 0, diff = 0;

	PRINT_DEBUG("Entered: time1=%p, time2=%p", time1, time2);

	//PRINT_DEBUG("getting seqEndRTT=%d, current=(%d, %d)\n", conn->rtt_seq_end, (int) current.tv_sec, (int)current.tv_usec);

	if (time1->tv_usec > time2->tv_usec) {
		decimal = (1000000.0 + time2->tv_usec - time1->tv_usec) / 1000000.0;
		diff = time2->tv_sec - time1->tv_sec - 1.0;
	} else {
		decimal = (time2->tv_usec - time1->tv_usec) / 1000000.0;
		diff = time2->tv_sec - time1->tv_sec;
	}
	diff += decimal;

	diff *= 1000.0;

	PRINT_DEBUG("diff=%f", diff);
	return diff;
}

void *interrupt_to_thread(void *local) {
	struct interrupt_to_thread_data *to_data = (struct interrupt_to_thread_data *) local;
	int id = to_data->id; //TODO make internall to finstime?
	int fd = to_data->fd;
	uint8_t *running = to_data->running;
	uint8_t *flag = to_data->flag;
	uint8_t *interrupt = to_data->interrupt;
	free(to_data);

	int ret;
	uint64_t exp;

	PRINT_DEBUG("Entered: id=%d, fd=%d", id, fd);
	while (*running) {
		/*#*/PRINT_DEBUG("");
		ret = read(fd, &exp, sizeof(uint64_t)); //blocking read
		if (!(*running)) {
			break;
		}
		if (ret != sizeof(uint64_t)) {
			//read error
			PRINT_ERROR("Read error: id=%d, fd=%d", id, fd);
			continue;
		}

		PRINT_DEBUG("Throwing TO flag: id=%d, fd=%d", id, fd);
		*interrupt = 1;
		*flag = 1;
	}

	PRINT_DEBUG("Exited: id=%d, fd=%d", id, fd);
	pthread_exit(NULL);
}

void *sem_to_thread(void *local) {
	struct sem_to_thread_data *to_data = (struct sem_to_thread_data *) local;
	int id = to_data->id; //TODO make internall to finstime?
	int fd = to_data->fd;
	uint8_t *running = to_data->running;
	uint8_t *flag = to_data->flag;
	uint8_t *waiting = to_data->waiting;
	sem_t *sem = to_data->sem;
	free(to_data);

	int ret;
	uint64_t exp;

	PRINT_DEBUG("Entered: id=%u, fd=%d", id, fd);
	while (*running) {
		/*#*/PRINT_DEBUG("");
		ret = read(fd, &exp, sizeof(uint64_t)); //blocking read
		if (!(*running)) {
			break;
		}
		if (ret != sizeof(uint64_t)) {
			//read error
			PRINT_ERROR("Read error: id=%u, fd=%d", id, fd);
			continue;
		}

		PRINT_DEBUG("throwing flag: id=%u, fd=%d", id, fd);
		*flag = 1;
		if (*waiting) {
			PRINT_DEBUG("posting to wait_sem");
			sem_post(sem);
		}
	}

	PRINT_DEBUG("Exited: id=%u, fd=%d", id, fd);
	pthread_exit(NULL);
}

void *intsem_to_thread(void *local) {
	struct intsem_to_thread_data *to_data = (struct intsem_to_thread_data *) local;
	int id = to_data->id; //TODO make internall to finstime?
	int fd = to_data->fd;
	uint8_t *running = to_data->running;
	uint8_t *flag = to_data->flag;
	uint8_t *interrupt = to_data->interrupt;
	sem_t *sem = to_data->sem;
	free(to_data);

	int ret;
	uint64_t exp;

	PRINT_DEBUG("Entered: id=%u, fd=%d", id, fd);
	while (*running) {
		/*#*/PRINT_DEBUG("");
		ret = read(fd, &exp, sizeof(uint64_t)); //blocking read
		if (!(*running)) {
			break;
		}
		if (ret != sizeof(uint64_t)) {
			//read error
			PRINT_ERROR("Read error: id=%u, fd=%d", id, fd);
			continue;
		}

		PRINT_DEBUG("throwing flag: id=%u, fd=%d", id, fd);
		*interrupt = 1;
		*flag = 1;

		PRINT_DEBUG("posting to wait_sem");
		sem_post(sem);
	}

	PRINT_DEBUG("Exited: id=%u, fd=%d", id, fd);
	pthread_exit(NULL);
}

void stop_timer(int fd) {
	PRINT_DEBUG("Entered: fd=%d", fd);

	struct itimerspec its;
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timerfd_settime(fd, 0, &its, NULL) == -1) {
		PRINT_ERROR("Error setting timer.");
		exit(-1);
	}
}

void start_timer(int fd, double millis) {
	PRINT_DEBUG("Entered: fd=%d, m=%f", fd, millis);

	struct itimerspec its;
	its.it_value.tv_sec = (long int) (millis / 1000);
	its.it_value.tv_nsec = (long int) ((fmod(millis, 1000.0) * 1000000) + 0.5);
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timerfd_settime(fd, 0, &its, NULL) == -1) {
		PRINT_ERROR("Error setting timer.");
		exit(-1);
	}
}
