/*
 * logger.h
 *
 *  Created on: Feb 3, 2013
 *      Author: Jonathan Reed
 */

#ifndef LOGGER_H_
#define LOGGER_H_

#include <finsmodule.h>

//TODO move shared structs/params here

void logger_dummy(void);
struct fins_module *logger_create(uint32_t index, uint32_t id, uint8_t *name);

//#define EXEC_UDP_CLEAR_SENT 0

#endif /* LOGGER_H_ */
