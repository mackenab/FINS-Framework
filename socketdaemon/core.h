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
int read_configurations();
void commChannel_init();
void Queues_init();

/*-----------------------------------------------------------------------------
 *-----------------------------------------------------------------------------
 */
void print_frame(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);

//begin: interceptor merge
struct socketIdentifier {
	unsigned long long uniqueSockID;
	char semaphore_name[30];
	char asemaphore_name[30];

	sem_t *s; /** Named semaphore to protect the client named pipe between interceptor and Jinni */
	sem_t *as; /** Additional named semaphore to force order between reading and writing to the pipe */

};

struct socketIdentifier FinsHistory[MAX_sockets];

//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
	#define FINS_TMP_ROOT "/data/data/fins"
#else
	#define FINS_TMP_ROOT "/tmp/fins"
#endif

/** The Global socket channel descriptor is used to communicate between the socket
 * interceptor and the socket jinni until they exchange the socket UNIQUE ID, then a separate
 * named pipe gets opened for the newly created socket */

int socket_channel_desc;
sem_t *main_channel_semaphore1;
sem_t *main_channel_semaphore2;

sem_t FinsHistory_semaphore;
char main_sem_name1[] = "main_channel1";
char main_sem_name2[] = "main_channel2";
#define MAX_parallel_processes 10
/** Todo document the work on the differences between the use of processes level semaphores
 * and threads level semaphores! and how each one of them is important and where they were employed
 * in FINS code
 */
#define write_call 30
#define ACK 	200

//end: interceptor merge



#endif /* SOCKETGENI_H_ */

