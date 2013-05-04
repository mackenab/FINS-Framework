/*
 * icmp.h
 *
 *  Created on: Mar 15, 2011
 *      Author: Abdallah Abdallah
 */

#ifndef ICMP_H_
#define ICMP_H_

#include <finsmodule.h>

void icmp_dummy(void);
struct fins_module *icmp_create(uint32_t index, uint32_t id, uint8_t *name);

#endif /* ICMP_H_ */
