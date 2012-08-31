/*
 * @file socketgeni.h
 *
 *  @date Nov 26, 2010
 *      @author Abdallah Abdallah
 */

#ifndef SOCKETGENI_H_
#define SOCKETGENI_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#define MAX_modules	16
#define SNAP_LEN 		4096

int read_configurations();
void commChannel_init();
void Queues_init();

//begin: interceptor merge
//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
#define FINS_TMP_ROOT "/data/data/fins"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

/** The Global socket channel descriptor is used to communicate between the socket
 * interceptor and the socket daemon until they exchange the socket UNIQUE ID, then a separate
 * named pipe gets opened for the newly created socket */
//end: interceptor merge
#endif /* SOCKETGENI_H_ */

