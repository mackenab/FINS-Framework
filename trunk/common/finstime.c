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

void *worker_thread(void *local) {
	struct pool_worker *worker = (struct pool_worker *) local;

	PRINT_DEBUG("Entered: id=%u", worker->id);

	while (1) {
		secure_sem_wait(worker->inactive_sem);
		*worker->inactive_num++;
		worker->inactive = 1;
		//sem_post(worker->pool_activity_sem)
		PRINT_DEBUG("inactive: worker=%p, inactive_num=%u", worker, *worker->inactive_num);
		sem_post(worker->inactive_sem);

		secure_sem_wait(&worker->activate_sem);
		if (!worker->running) {
			break;
		}

		worker->work(worker->local);
	}

	PRINT_DEBUG("Exited: id=%u", worker->id);
	pthread_exit(NULL);
}

struct pool_worker *worker_create(sem_t *inactive_sem, uint32_t *inactive_num, uint32_t id) {
	PRINT_DEBUG("Entered: inactive_sem=%p, inactive_num=%p, id=%u", inactive_sem, inactive_num, id);

	struct pool_worker *worker = (struct pool_worker *) secure_malloc(sizeof(struct pool_worker));
	worker->inactive_sem = inactive_sem;
	worker->inactive_num = inactive_num;

	worker->id = id;
	worker->running = 1;
	sem_init(&worker->activate_sem, 0, 0);
	worker->inactive = 0;
	worker->work = NULL;
	worker->local = NULL;

	//change back to normal? if fails don't crash
	secure_pthread_create(&worker->thread, NULL, worker_thread, (void *) worker);
	//pthread_detach(&worker->thread);

	PRINT_DEBUG("Exited: inactive_sem=%p, inactive_num=%p, id=%u, worker=%p", inactive_sem, inactive_num, id, worker);
	return worker;
}

void worker_shutdown(struct pool_worker *worker) {
	PRINT_DEBUG("Entered: worker=%p", worker);

	worker->running = 0;
	sem_post(&worker->activate_sem);

	PRINT_DEBUG("joining worker thread");
	pthread_join(worker->thread, NULL);
}

void worker_free(struct pool_worker *worker) {
	PRINT_DEBUG("Entered: worker=%p", worker);

	//TODO finish

	sem_destroy(&worker->activate_sem);

	free(worker);
}

struct thread_pool *pool_create(uint32_t initial, uint32_t max) {
	PRINT_DEBUG("Entered: initial=%u, max=%u", initial, max);

	struct thread_pool *pool = (struct thread_pool *) secure_malloc(sizeof(struct thread_pool));
	pool->list = list_create(max);
	pool->queue = list_create(max);
	sem_init(&pool->inactive_sem, 0, 1);
	pool->inactive_num = 0;
	pool->worker_count = 0;

	struct pool_worker *worker;
	struct list_node *node;

	int i;
	for (i = 0; i < initial; i++) {
		secure_sem_wait(&pool->inactive_sem);
		worker = worker_create(&pool->inactive_sem, &pool->inactive_num, pool->worker_count++);
		node = node_create((uint8_t *) worker, 1);
		list_append(pool->list, node);
		sem_post(&pool->inactive_sem);
	}

	PRINT_DEBUG("Exited: initial=%u, max=%u, pool=%p", initial, max, pool);
	return pool;
}

int worker_inactive_test(struct list_node *node) {
	struct pool_worker *worker = (struct pool_worker *) node->data;
	return worker->running && worker->inactive;
}

int pool_execute(struct thread_pool *pool, void *(*work)(void *local), void *local) {
	PRINT_DEBUG("Entered: pool=%p, work=%p, local=%p", pool, work, local);

	secure_sem_wait(&pool->inactive_sem);
	PRINT_DEBUG("inactive_num=%u", pool->inactive_num);
	if (pool->inactive_num) {
		struct list_node *node = list_find(pool->list, worker_inactive_test);
		PRINT_DEBUG("found node=%p", node);
		if (node) {
			pool->inactive_num--;

			struct pool_worker *worker = (struct pool_worker *) node->data;
			worker->inactive = 0;
			worker->work = work;
			worker->local = local;
			PRINT_DEBUG("activating: worker=%p, inactive_num=%u", worker, *worker->inactive_num);
			sem_post(&pool->inactive_sem);
			sem_post(&worker->activate_sem);

			return 1;
		} else {
			PRINT_ERROR("todo error");
			sem_post(&pool->inactive_sem);
			//TODO shouldn't be possible

			return 0;
		}
	} else {
		if (list_has_space(pool->list, 1)) {
			PRINT_DEBUG("Starting new worker");
			struct pool_worker *worker = worker_create(&pool->inactive_sem, &pool->inactive_num, pool->worker_count++);
			struct list_node *node = node_create((uint8_t *) worker, 1);
			list_append(pool->list, node);
			sem_post(&pool->inactive_sem);

			//TODO wait? or do the find function again? etc preload it.

			return 1;
		} else {
			sem_post(&pool->inactive_sem);

			//TODO queue it? have finishing threads check queue?
			return 0;
		}
	}
}

void pool_shutdown(struct thread_pool *pool) {
	PRINT_DEBUG("Entered: pool=%p", pool);

	//worker_shutdown;

}

void pool_free(struct thread_pool *pool) {
	PRINT_DEBUG("Entered: pool=%p", pool);

	sem_destroy(&pool->inactive_sem);
	//TODO finish

	free(pool);
}
