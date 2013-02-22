/*
 * finstime.c
 *
 *  Created on: Jan 11, 2013
 *      Author: alex
 */

#include "finstime.h"

uint32_t to_signal;

double time_diff(struct timeval *time1, struct timeval *time2) { //time2 - time1
	PRINT_DEBUG("Entered: time1=%p, time2=%p", time1, time2);

	double decimal = 0, diff = 0;
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
	while (1) {
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
	//pthread_exit(NULL);
	return NULL;
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
	while (1) {
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
	//pthread_exit(NULL);
	return NULL;
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
	while (1) {
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
	//pthread_exit(NULL);
	return NULL;
}

#ifndef BUILD_FOR_ANDROID
void stop_timer(int fd) {
	PRINT_DEBUG("Entered: fd=%d", fd);

	struct itimerspec its;
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timerfd_settime(fd, 0, &its, NULL)) {
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

	if (timerfd_settime(fd, 0, &its, NULL)) {
		PRINT_ERROR("Error setting timer.");
		exit(-1);
	}
}
#endif

void to_handler(int sig, siginfo_t *si, void *uc) {
	PRINT_DEBUG("Entered: sig=%d, si=%p, uc=%p", sig, si, uc);

	struct to_timer_data *data = (struct to_timer_data *) si->si_value.sival_ptr;
	data->handler(data);
}

void interrupt_to_handler(void *local) {
	struct interrupt_to_timer_data *data = (struct interrupt_to_timer_data *) local;

	PRINT_DEBUG("Throwing TO flag: data=%p, tid=%ld", data, (long)data->tid);
	*data->interrupt = 1;
	*data->flag = 1;
}

void sem_to_handler(void *local) {
	struct sem_to_timer_data *data = (struct sem_to_timer_data *) local;

	PRINT_DEBUG("Throwing TO flag: data=%p, tid=%ld", data, (long)data->tid);
	*data->flag = 1;
	if (*data->waiting) {
		PRINT_DEBUG("posting to wait_sem");
		sem_post(data->sem);
	}
}

void intsem_to_handler(void *local) {
	struct intsem_to_timer_data *data = (struct intsem_to_timer_data *) local;

	PRINT_DEBUG("Throwing TO flag: data=%p, tid=%ld", data, (long)data->tid);
	*data->interrupt = 1;
	*data->flag = 1;

	PRINT_DEBUG("posting to wait_sem");
	sem_post(data->sem);
}

void register_to_signal(uint32_t signal) {
	PRINT_IMPORTANT("Registering: to_signal=%u", signal);

	struct sigaction sa;
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = to_handler;
	sigemptyset(&sa.sa_mask);

	to_signal = signal;

	if (sigaction(to_signal, &sa, NULL)) {
		PRINT_ERROR("sigaction fault");
		exit(-1);
	}
}

void block_to_signal(void) {
	PRINT_IMPORTANT("Blocking: to_signal=%u", to_signal);

	//Block timer signal temporarily

	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, to_signal);
	if (sigprocmask(SIG_SETMASK, &mask, NULL)) {
		PRINT_ERROR("sigprocmask SIG_SETMASK");
		exit(-1);
	}
}

void unblock_to_signal(void) {
	PRINT_IMPORTANT("Unblocking: to_signal=%u", to_signal);

	//Unlock the timer signal, so that timer notification can be delivered

	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, to_signal);
	if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
		PRINT_ERROR("sigprocmask SIG_UNBLOCK");
		exit(-1);
	}
}

void timer_create_to(struct to_timer_data *data) {
	struct sigevent sev;
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = to_signal;
	sev.sigev_value.sival_ptr = data;

	if (timer_create(CLOCK_REALTIME, &sev, &data->tid)) {
		PRINT_ERROR("timer_create fault");
		exit(-1);
	}
}

void timer_stop(timer_t timerid) {
	PRINT_DEBUG("Entered: timerid=%d", (int)timerid);

	struct itimerspec its;
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timer_settime(timerid, 0, &its, NULL)) {
		PRINT_ERROR("Error setting timer.");
		exit(-1);
	}
}

void timer_once_start(timer_t timerid, double millis) {
	PRINT_DEBUG("Entered: timerid=%d, m=%f", (int)timerid, millis);

	struct itimerspec its;
	its.it_value.tv_sec = (long int) (millis / 1000);
	its.it_value.tv_nsec = (long int) ((fmod(millis, 1000.0) * 1000000) + 0.5);
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timer_settime(timerid, 0, &its, NULL)) {
		PRINT_ERROR("Error setting timer.");
		exit(-1);
	}
}

void timer_repeat_start(timer_t timerid, double millis) {
	PRINT_DEBUG("Entered: timerid=%d, m=%f", (int)timerid, millis);

	struct itimerspec its;
	its.it_value.tv_sec = (long int) (millis / 1000);
	its.it_value.tv_nsec = (long int) ((fmod(millis, 1000.0) * 1000000) + 0.5);
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	if (timer_settime(timerid, 0, &its, NULL)) {
		PRINT_ERROR("Error setting timer.");
		exit(-1);
	}
}
