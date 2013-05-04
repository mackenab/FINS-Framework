/*
 * @file tcp.h
 * @date Feb 22, 2012
 * @author Jonathan Reed
 */

#ifndef TCP_H_
#define TCP_H_

#include <finsmodule.h>

void tcp_dummy(void);
struct fins_module *tcp_create(uint32_t index, uint32_t id, uint8_t *name);

#endif /* TCP_H_ */

