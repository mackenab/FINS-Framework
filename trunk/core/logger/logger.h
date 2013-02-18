/*
 * logger.h
 *
 *  Created on: Feb 3, 2013
 *      Author: alex
 */

#ifndef LOGGER_H_
#define LOGGER_H_

#include <netinet/in.h>
#include <pthread.h>
#include <sys/time.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <metadata.h>
#include <finsqueue.h>

//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
#include <sys/endian.h>
#endif

void logger_dummy(void);
void logger_init(void);
void logger_run(pthread_attr_t *fins_pthread_attr);
void logger_shutdown(void);
void logger_release(void);

//#define EXEC_UDP_CLEAR_SENT 0

void logger_fcf(struct finsFrame *ff);
//void logger_exec(struct finsFrame *ff);
//void logger_exec_clear_sent(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
//void logger_error(struct finsFrame *ff);

//void logger_in_fdf(struct finsFrame *ff);
//void logger_out_fdf(struct finsFrame *ff);

void logger_interrupt(void);

#endif /* LOGGER_H_ */
