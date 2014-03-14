#ifndef INTERFACE_H_
#define INTERFACE_H_

#include <finsmodule.h>

void interface_dummy(void);
struct fins_module *interface_create(uint32_t index, uint32_t id, uint8_t *name);

#endif /* INTERFACE_H_ */
