/*
 * rtm.h
 *
 *  @date June 14, 2011
 *      @author: Abdallah Abdallah
 */


#ifndef RTM_H_
#define RTM_H_

#include <finsmodule.h>

void rtm_dummy(void);
struct fins_module *rtm_create(uint32_t index, uint32_t id, uint8_t *name);

#endif /* RTM_H_ */
