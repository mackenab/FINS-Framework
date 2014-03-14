/*
 * @file switch.h
 *
 *  @date Mar 14, 2011
 *      @author Abdallah Abdallah
 */

#ifndef SWITCH_H_
#define SWITCH_H_

#include <finsmodule.h>

void switch_dummy(void);
struct fins_module *switch_create(uint32_t index, uint32_t id, uint8_t *name);

#endif /* SWITCH_H_ */
