/*
 * 	ipv4.h
 *
 *  Created on: Jun 8, 2010
 *      Author: rado
 */

#ifndef IPV4_H_
#define IPV4_H_

#include <finsmodule.h>

void ipv4_dummy(void);
struct fins_module *ipv4_create(uint32_t index, uint32_t id, uint8_t *name);

#endif /* IPV4_H_ */
