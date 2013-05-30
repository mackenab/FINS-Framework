/*
 * finsthreads.c
 *
 *  Created on: Feb 7, 2013
 *      Author: alex
 */

#include "finsthreads.h"

void *worker_thread(void *local) {
	struct pool_worker *worker = (struct pool_worker *) local;
	PRINT_DEBUG("Entered: id=%u", worker->id);

	while (1) {
		secure_sem_wait(worker->inactive_sem);
		PRINT_DEBUG("queue=%p", worker->queue);
		if (list_is_empty(worker->queue)) {
			*worker->inactive_num += 1;
			worker->inactive = 1;
			PRINT_DEBUG("inactive: worker=%p, inactive_num=%u", worker, *worker->inactive_num);
			sem_post(worker->inactive_sem);

			secure_sem_wait(&worker->activate_sem);
			if (!worker->running) {
				break;
			}
		} else {
			if (worker->running) {
				struct pool_request *request = (struct pool_request *) list_remove_front(worker->queue);
				worker->work = request->work;
				worker->local = request->local;

				PRINT_DEBUG("Freeing: request=%p", request);
				free(request);
				sem_post(worker->inactive_sem);
			} else {
				sem_post(worker->inactive_sem);
				break;
			}
		}

		worker->work(worker->local);
	}

	PRINT_DEBUG("Exited: id=%u", worker->id);
	return NULL;
}

struct pool_worker *worker_create(sem_t *inactive_sem, uint32_t *inactive_num, struct linked_list *queue, uint32_t id) {
	PRINT_DEBUG("Entered: inactive_sem=%p, inactive_num=%p, queue=%p, id=%u", inactive_sem, inactive_num, queue, id);

	struct pool_worker *worker = (struct pool_worker *) secure_malloc(sizeof(struct pool_worker));
	worker->inactive_sem = inactive_sem;
	worker->inactive_num = inactive_num;
	worker->queue = queue;

	worker->id = id;
	worker->running = 1;
	sem_init(&worker->activate_sem, 0, 0);
	worker->inactive = 0;
	worker->work = NULL;
	worker->local = NULL;

	//change back to normal? if fails don't crash
	secure_pthread_create(&worker->thread, NULL, worker_thread, (void *) worker);
	//pthread_detach(&worker->thread);

	PRINT_DEBUG("Exited: inactive_sem=%p, inactive_num=%p, queue=%p, id=%u, worker=%p", inactive_sem, inactive_num, queue, id, worker);
	return worker;
}

void worker_shutdown(struct pool_worker *worker) {
	PRINT_DEBUG("Entered: worker=%p", worker);

	worker->running = 0;
	sem_post(&worker->activate_sem);

	PRINT_DEBUG("joining worker thread: id=%u", worker->id);
	pthread_join(worker->thread, NULL);
}

void worker_free(struct pool_worker *worker) {
	PRINT_DEBUG("Entered: worker=%p", worker);

	//TODO finish

	sem_destroy(&worker->activate_sem);

	free(worker);
}

void *controller_thread(void *local) {
	struct pool_controller *controller = (struct pool_controller *) local;
	PRINT_DEBUG("Entered: id=%u, fd=%d", controller->id, controller->fd);

	int ret;
	uint64_t exp;

	//check worker num, inactive num, & queue len periodically, optimize values
	while (1) {
		ret = read(controller->fd, &exp, sizeof(uint64_t)); //blocking read
		if (!controller->running) {
			break;
		}

		if (ret != sizeof(uint64_t)) {
			//read error
			PRINT_ERROR("Read error: id=%d, fd=%d", controller->id, controller->fd);
			continue;
		}

		secure_sem_wait(&controller->pool->inactive_sem);
		if (list_is_empty(controller->pool->queue)) {
			//check if should reduce workers
			if (controller->pool->inactive_num) {
				double threads = floor(controller->pool->inactive_num / 2.0);
				//PRINT_DEBUG("workers=%u, inact=%u, queue=%u, space=%u, threads=%f", controller->pool->workers->len, controller->pool->inactive_num, controller->pool->queue->len, space, threads);
				if (threads > 0) {
					//pool_start(controller->pool, (uint32_t) threads);
				}
			} else {
				//do nothing
			}
		} else {
			if (controller->pool->queue->len > controller->pool->inactive_num) {
				uint32_t space = list_space(controller->pool->workers);
				double threads = ceil((controller->pool->queue->len - controller->pool->inactive_num) / 2.0);
				PRINT_DEBUG("workers=%u, inact=%u, queue=%u, space=%u, threads=%f",
						controller->pool->workers->len, controller->pool->inactive_num, controller->pool->queue->len, space, threads);
				if (space > 0) {
					if (threads < space) {
						pool_start(controller->pool, (uint32_t) threads);
					} else {
						pool_start(controller->pool, space);
					}
				}
			} else {
				//queue smaller than inactive, should be able to handle, increase timer rate?
				controller->period /= 2;
			}
		}

		//start_timer(controller->fd, controller->period); //TODO uncomment/fix this by using alert timers
		sem_post(&controller->pool->inactive_sem);
	}

	PRINT_DEBUG("Exited: id=%u", controller->id);
	return NULL;
}

struct pool_controller *controller_create(struct thread_pool *pool) {
	PRINT_DEBUG("Entered: pool=%p", pool);

	struct pool_controller *controller = (struct pool_controller *) secure_malloc(sizeof(struct pool_controller));
	controller->pool = pool;
	controller->period = 1000.000; //observe queue add rates & change time

	controller->id = 0;
	controller->running = 1;

#ifndef BUILD_FOR_ANDROID
	controller->fd = timerfd_create(CLOCK_REALTIME, 0);
	if (controller->fd == -1) {
		PRINT_ERROR("ERROR: unable to create to_fd.");
		exit(-1);
	}
#endif

	//sem_init(&worker->activate_sem, 0, 0);
	//change back to normal? if fails don't crash
	secure_pthread_create(&controller->thread, NULL, controller_thread, (void *) controller);
	//pthread_detach(&controller->thread);

	//start_timer(controller->fd, 0.5);

	return controller;
}

void controller_shutdown(struct pool_controller *controller) {
	PRINT_DEBUG("Entered: controller=%p", controller);

	controller->running = 0;
	//start_timer(controller->fd, TO_MIN);

	PRINT_DEBUG("joining controller thread: id=%u", controller->id);
	pthread_join(controller->thread, NULL);

}

void controller_free(struct pool_controller *controller) {
	PRINT_DEBUG("Entered: controller=%p", controller);

	free(controller);
}

struct thread_pool *pool_create(uint32_t initial, uint32_t max, uint32_t limit) {
	PRINT_DEBUG("Entered: initial=%u, max=%u, limit=%u", initial, max, limit);

	struct thread_pool *pool = (struct thread_pool *) secure_malloc(sizeof(struct thread_pool));
	pool->workers = list_create(max);
	pool->queue = list_create(limit);
	sem_init(&pool->inactive_sem, 0, 1);
	pool->inactive_num = 0;
	pool->worker_count = 0;

	//pool->controller = controller_create(pool);

	secure_sem_wait(&pool->inactive_sem);
	pool_start(pool, initial);
	sem_post(&pool->inactive_sem);

	PRINT_DEBUG("Exited: initial=%u, max=%u, pool=%p", initial, max, pool);
	return pool;
}

void pool_start(struct thread_pool *pool, uint32_t threads) {
	PRINT_DEBUG("Entered: pool=%p, threads=%u", pool, threads);

	int i;
	struct pool_worker *worker;

	for (i = 0; i < threads; i++) {
		worker = worker_create(&pool->inactive_sem, &pool->inactive_num, pool->queue, ++pool->worker_count);
		list_append(pool->workers, worker);
	}

	PRINT_DEBUG("Exited: pool=%p, len=%u", pool, pool->workers->len);
}

int worker_inactive_test(struct pool_worker *worker) {
	return worker->running && worker->inactive;
}

int pool_execute(struct thread_pool *pool, void *(*work)(void *local), void *local) {
	PRINT_DEBUG("Entered: pool=%p, work=%p, local=%p", pool, work, local);

	secure_sem_wait(&pool->inactive_sem);
	PRINT_DEBUG("inactive_num=%u", pool->inactive_num);
	if (pool->inactive_num) {
		struct pool_worker *worker = (struct pool_worker *) list_find(pool->workers, worker_inactive_test);
		PRINT_DEBUG("found worker=%p", worker);
		if (worker != NULL) {
			pool->inactive_num--;

			worker->inactive = 0;
			worker->work = work;
			worker->local = local;
			PRINT_DEBUG("activating: worker=%p, inactive_num=%u", worker, *worker->inactive_num);
			sem_post(&worker->activate_sem);
			sem_post(&pool->inactive_sem);

			return 1;
		} else {
			PRINT_ERROR("todo error");
			sem_post(&pool->inactive_sem);
			//TODO shouldn't be possible

			return 0;
		}
	} else {
		//TODO change to simply queue it, have controller optimize pool size
		//TODO have execute change queue size?
		if (list_has_space(pool->queue)) {
			struct pool_request *request = (struct pool_request *) secure_malloc(sizeof(struct pool_request));
			request->work = work;
			request->local = local;

			list_append(pool->queue, request);
			sem_post(&pool->inactive_sem);

			return 1;
		} else {
			sem_post(&pool->inactive_sem);

			return 0;
		}

		if (0) {
			if (list_has_space(pool->workers)) {
				PRINT_DEBUG("Starting new worker");
				struct pool_worker *worker = worker_create(&pool->inactive_sem, &pool->inactive_num, pool->queue, pool->worker_count++);
				list_append(pool->workers, worker);

				worker->work = work;
				worker->local = local;
				PRINT_DEBUG("activating: worker=%p, inactive_num=%u", worker, *worker->inactive_num);
				sem_post(&worker->activate_sem);
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
}

void pool_shutdown(struct thread_pool *pool) {
	PRINT_DEBUG("Entered: pool=%p", pool);

	//controller_shutdown(pool->controller);

	list_for_each(pool->workers, worker_shutdown);

	//TODO reject queued jobs?
}

void pool_free(struct thread_pool *pool) {
	PRINT_DEBUG("Entered: pool=%p", pool);

	sem_destroy(&pool->inactive_sem);
	//TODO finish

	list_free(pool->workers, worker_free);
	list_free(pool->queue, free);

	free(pool);
}
