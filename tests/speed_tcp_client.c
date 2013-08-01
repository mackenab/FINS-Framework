#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <netinet/tcp.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

//--------------------------------------------------- //temp stuff to cross compile, remove/implement better eventual?
#ifndef POLLRDNORM
#define POLLRDNORM POLLIN
#endif

#ifndef POLLRDBAND
#define POLLRDBAND POLLIN
#endif

#ifndef POLLWRNORM
#define POLLWRNORM POLLOUT
#endif

#ifndef POLLWRBAND
#define POLLWRBAND POLLOUT
#endif
//---------------------------------------------------

#define xxx(a,b,c,d) 	(16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d))

double time_diff(struct timeval *time1, struct timeval *time2) { //time2 - time1
	double decimal = 0, diff = 0;

	if (time1->tv_usec > time2->tv_usec) {
		decimal = (1000000.0 + time2->tv_usec - time1->tv_usec) / 1000000.0;
		diff = time2->tv_sec - time1->tv_sec - 1.0;
	} else {
		decimal = (time2->tv_usec - time1->tv_usec) / 1000000.0;
		diff = time2->tv_sec - time1->tv_sec;
	}
	diff += decimal;

	diff *= 1000.0;

	//printf("diff=%f\n", diff);
	return diff;
}

int main(int argc, char *argv[]) {
	int sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	int numbytes;
	char send_data[131072 + 1];
	char msg[131092];
	int port;
	int client_port;

	memset(send_data, 89, 131072);
	send_data[131072] = '\0';

	memset(msg, 89, 131072);
	msg[131072] = '\0';

	//if ((sock = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		perror("Socket");
		printf("Failure\n");
		exit(1);
	}

	int optval = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	//int result = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *) &optval, sizeof(int));

#ifdef BUILD_FOR_ANDROID
	port = 44444;
#else
	if (argc > 1) { //doesn't work fro android
		port = atoi(argv[1]);
	} else {
		port = 44444;
	}
#endif

	printf("\nMY DEST PORT BEFORE AND AFTER\n");
	printf("%d, %d\n", port, htons(port));
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = PF_INET;
	//server_addr.sin_addr.s_addr = xxx(192,168,1,3);
	server_addr.sin_addr.s_addr = xxx(128,173,92,33);
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);
	server_addr.sin_port = htons(port);

#ifdef BUILD_FOR_ANDROID
	client_port = 55555;
#else
	if (argc > 2) {
		client_port = atoi(argv[2]);
	} else {
		client_port = 55555;
	}
#endif

	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = PF_INET;
	client_addr.sin_addr.s_addr = INADDR_ANY;
	//client_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	client_addr.sin_addr.s_addr = htonl(client_addr.sin_addr.s_addr);
	client_addr.sin_port = htons(client_port);

	///*
	printf("Binding to client_addr='%s':%d, netw=%u\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_addr.sin_addr.s_addr);
	if (bind(sock, (struct sockaddr *) &client_addr, sizeof(struct sockaddr)) == -1) {
		perror("Bind");
		printf("Failure");
		exit(1);
	}
	//*/

	printf("Connecting to server: addr='%s':%d, netw=%u\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port), server_addr.sin_addr.s_addr);
	while (1) {
		if (connect(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) < 0) {
			printf("failed connect: errno=%d errno='%s'\n", errno, strerror(errno));
			if (errno == EINPROGRESS || errno == EALREADY) {
			} else if (errno == EISCONN) {
				break;
			} else {
				sleep(5);
			}
		} else {
			break;
		}
	}

	printf("Connection establisehed sock=%d to ('%s'/%d) netw=%u\n", sock, inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port),
			server_addr.sin_addr.s_addr);
	fflush(stdout);

	//fgetc(stdin); //wait until user enters

	int nfds = 2;
	struct pollfd fds[nfds];
	fds[0].fd = -1;
	fds[0].events = POLLIN | POLLRDNORM; //| POLLPRI;
	fds[1].fd = sock;
	fds[1].events = POLLOUT | POLLWRNORM;
	printf("fd: sock=%d, events=%x\n", sock, fds[1].events);
	fflush(stdout);
	//int time = -1; //1000;

	double total = 15;
	double speed = 10000000; //bits per sec
	int len = 16000; //msg size

	double time = 8 * len / speed * 1000000;
	int use = (int) (time + .5); //ceil(time);
	printf("desired=%f, time=%f, used=%u\n", speed, time, use);
	fflush(stdout);

	double diff;
	double interval = 1;
	double check = interval;
	struct timeval start, end;
	gettimeofday(&start, 0);

	printf("Looping...\n");
	fflush(stdout);

	int i = 0;
	while (1) {
		numbytes = sendto(sock, send_data, len, 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
		if (numbytes != len) {
			printf("error: len=%d, numbytes=%d\n", len, numbytes);
			fflush(stdout);
			break;
		}
		i++;

		gettimeofday(&end, 0);
		diff = time_diff(&start, &end) / 1000;
		if (check <= diff) {
			printf("time=%f, frames=%d, total=%d, speed=%f\n", diff, i, len * i, 8 * len * i / diff);
			fflush(stdout);
			check += interval;
		}

		if (total <= diff) {
			break;
		}

		usleep(use);
	}

	sleep(5);

	printf("Closing socket\n");
	fflush(stdout);
	close(sock);

	printf("FIN\n");
	fflush(stdout);
	while (1)
		;

	return 0;
}

