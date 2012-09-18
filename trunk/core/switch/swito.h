/*
 * @file swito.h
 *
 *  @date Mar 14, 2011
 *      @author Abdallah Abdallah
 */

#ifndef SWITO_H_
#define SWITO_H_

#include <pthread.h>

#define MAX_Queue_size 100000

void Queues_init(void);

void switch_init(void);
void switch_run(pthread_attr_t *fins_pthread_attr);
void switch_shutdown(void);
void switch_release(void);

#endif /* SWITO_H_ */
