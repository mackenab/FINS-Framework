/*
 * tcp.h
 *
 *  Created on: Mar 12, 2011
 *      Author: Abdallah Abdallah
 */

#ifndef TCP_H_
#define TCP_H_

#include <finstypes.h>
#include <metadata.h>
#include <finsdebug.h>

void tcp_out(struct finsFrame *ff);

void tcp_in(struct finsFrame *ff);

void tcp_get_FF();


void tcp_init();

#endif /* TCP_H_ */
