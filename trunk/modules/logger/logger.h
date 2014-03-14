/*
 * logger.h
 *
 *  Created on: Feb 3, 2013
 *      Author: Jonathan Reed
 */

#ifndef LOGGER_H_
#define LOGGER_H_

#include <finsmodule.h>

void logger_dummy(void);
struct fins_module *logger_create(uint32_t index, uint32_t id, uint8_t *name);

#endif /* LOGGER_H_ */
