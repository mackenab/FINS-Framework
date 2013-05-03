/*
 * daemon.h
 *
 *  Created on: Mar 6, 2011
 *      Author: Abdallah Abdallah
 */

#ifndef DAEMON_H_
#define DAEMON_H_

#include <finsmodule.h>

void daemon_dummy(void);
struct fins_module *daemon_create(uint32_t index, uint32_t id, uint8_t *name);

#endif /* DAEMON_H_ */
