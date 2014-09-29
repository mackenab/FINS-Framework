/*
 * logger_iperf.h
 *
*  Created on: Aug 20, 2014
 *      Author: Jonathan Reed
 */

#ifndef LOGGER_IPERF_H_
#define LOGGER_IPERF_H_

#include <finsmodule.h>

void logger_iperf_dummy(void);
struct fins_module *logger_iperf_create(uint32_t index, uint32_t id, uint8_t *name);

#endif /* LOGGER_IPERF_H_ */
