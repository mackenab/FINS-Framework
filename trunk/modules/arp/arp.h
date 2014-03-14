/**@file arp.h
 *@brief this files contains all relevant data types and prototypes of the functions for an ARP module
 *@author Jonathan Reed
 *@date  September 5, 2012
 */

#ifndef ARP_H_
#define ARP_H_

#include <finsmodule.h>

void arp_dummy(void);
struct fins_module *arp_create(uint32_t index, uint32_t id, uint8_t *name);

#endif /* ARP_H_ */
