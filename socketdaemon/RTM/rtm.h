/*
 * rtm.h
 *
 *  @date June 14, 2011
 *      @author: Abdallah Abdallah
 */


#ifndef TCP_H_
#define TCP_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>

#include <finstypes.h>
#include <metadata.h>
#include <finsdebug.h>

void rtm_out(struct finsFrame *ff);

void rtm_in(struct finsFrame *ff);

void rtm_get_FF();


void rtm_init();

#endif /* TCP_H_ */
