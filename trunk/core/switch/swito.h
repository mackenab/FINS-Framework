/*
 * @file swito.h
 *
 *  @date Mar 14, 2011
 *      @author Abdallah Abdallah
 */

#ifndef SWITO_H_
#define SWITO_H_

#include <pthread.h>

void switch_init(pthread_attr_t *fins_pthread_attr);
void switch_shutdown();
void switch_free();

#endif /* SWITO_H_ */
