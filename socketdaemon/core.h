/*
 * socketgeni.h
 *
 *  Created on: Nov 26, 2010
 *      Author: Abdallah Abdallah
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
#include <sys/types.h>
#include <sys/stat.h>

#include "wifidemux.h"
#include "Jinni/handlers.h"

#define MAX_modules	16
#define SNAP_LEN 		4096

struct socketUniqueID {
	int processID;
	int socketDesc;
};

struct bind_call_msg {
	int sockfd;
	socklen_t addrlen;
	struct sockaddr addr;

};

void jinni_init();
void Queues_init();

/*-----------------------------------------------------------------------------
 *-----------------------------------------------------------------------------
 */
void print_frame(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);

#endif /* SOCKETGENI_H_ */

