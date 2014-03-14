/*
 * udp.h
 *
 *  Created on: Jun 28, 2010
 *      Author: Abdallah Abdallah
 */

#ifndef UDP_H_
#define UDP_H_

#include <finsmodule.h>

void udp_dummy(void);
struct fins_module *udp_create(uint32_t index, uint32_t id, uint8_t *name);

#endif
