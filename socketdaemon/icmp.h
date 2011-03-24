/*
 * icmp.h
 *
 *  Created on: Mar 15, 2011
 *      Author: Abdallah Abdallah
 */

#ifndef ICMP_H_
#define ICMP_H_
#include <finstypes.h>
#include <metadata.h>
#include <finsdebug.h>
#include <queueModule.h>




void icmp_in(struct finsFrame *ff);
void icmp_out(struct finsFrame *ff);
void icmp_get_FF(struct finsFrame *ff);

void	ICMP_init();

#endif /* ICMP_H_ */
