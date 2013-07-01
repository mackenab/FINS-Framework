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

/*

 int xxx(char a,char b,char c,char d)
 {

 return ((16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d)));

 }


 */

double time_diff(struct timeval *time1, struct timeval *time2) { //time2 - time1
	double decimal = 0, diff = 0;

	//printf("Entered: time1=%p, time2=%p\n", time1, time2);

	//PRINT_DEBUG("getting seqEndRTT=%d, current=(%d, %d)\n", conn->rtt_seq_end, (int) current.tv_sec, (int)current.tv_usec);

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
	//struct hostent *host;
	char send_data[131072 + 1];
	char msg[131092];
	int port;
	int client_port;
	pid_t pID = 0;

	memset(send_data, 89, 131072);
	send_data[131072] = '\0';

	memset(msg, 89, 131072);
	msg[131072] = '\0';

	//host= (struct hostent *) gethostbyname((char *)"127.0.0.1");

	//if ((sock = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		perror("Socket");
		printf("Failure");
		exit(1);
	}

	//int val = 1;
	//int result = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *) &val, sizeof(int));

#ifdef BUILD_FOR_ANDROID
	port = 44444;
#else
	if (argc > 1) { //doesn't work fro android
		port = atoi(argv[1]);
	} else {
		port = 44444;
	}
#endif

	//int optval = 1;
	//setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	printf("MY DEST PORT BEFORE AND AFTER\n");
	printf("%d, %d\n", port, htons(port));
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = PF_INET;
	server_addr.sin_port = htons(port);

	//server_addr.sin_addr.s_addr = xxx(128,173,92,37);
	//server_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//server_addr.sin_addr.s_addr = xxx(114,53,31,172);
	//server_addr.sin_addr.s_addr = xxx(192,168,1,3);
	server_addr.sin_addr.s_addr = xxx(128,173,92,33);
	//server_addr.sin_addr.s_addr = INADDR_ANY;
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);
	//bzero(&(server_addr.sin_zero), 8);

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
	client_addr.sin_port = htons(client_port);
	//client_addr.sin_addr.s_addr = xxx(128,173,92,37);
	//client_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//client_addr.sin_addr.s_addr = xxx(114,53,31,172);
	//client_addr.sin_addr.s_addr = xxx(192,168,1,16);
	client_addr.sin_addr.s_addr = INADDR_ANY;
	//client_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	client_addr.sin_addr.s_addr = htonl(client_addr.sin_addr.s_addr);

	//client_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	//bzero(&(client_addr.sin_zero), 8); //TODO what's this for?

	/*
	 printf("Binding to client_addr=%s:%d, netw=%u\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_addr.sin_addr.s_addr);
	 if (bind(sock, (struct sockaddr *) &client_addr, sizeof(struct sockaddr)) == -1) {
	 perror("Bind");
	 printf("Failure");
	 exit(1);
	 }
	 //*/

	printf(
			"EACCES=%d EPERM=%d EADDRINUSE=%d EAFNOSUPPORT=%d EAGAIN=%d EALREADY=%d EBADF=%d ECONNREFUSED=%d EFAULT=%d EINPROGRESS=%d EINTR=%d EISCONN=%d ENETUNREACH=%d ENOTSOCK=%d ETIMEDOUT=%d\n",
			EACCES, EPERM, EADDRINUSE, EAFNOSUPPORT, EAGAIN, EALREADY, EBADF, ECONNREFUSED, EFAULT, EINPROGRESS, EINTR, EISCONN, ENETUNREACH, ENOTSOCK,
			ETIMEDOUT);

	//pID = fork();
	if (pID == 0) { // child -- Capture process
		//server_addr.sin_port = htons(port + j - 1);
		printf("\n child pID=%d", pID);
		fflush(stdout);
	} else if (pID < 0) { // failed to fork
		printf("Failed to Fork \n");
		fflush(stdout);
		exit(1);
	} else { //parent
		server_addr.sin_port = htons(port + 1);
		printf("\n parent pID=%d", pID);
		fflush(stdout);
	}

	printf("\n Connecting to server: pID=%d addr=%s:%d, netw=%u", pID, inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port),
			server_addr.sin_addr.s_addr);
	while (1) {
		if (connect(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) < 0) {
			printf("\n failed connect: pID=%d errno=%d errno='%s'", pID, errno, strerror(errno));
			if (errno == EINPROGRESS || errno == EALREADY) {
			} else if (errno == EISCONN) {
				break;
			} else {
				//exit(1);
				sleep(5);
			}
			//sleep(1);
			//exit(1);
		} else {
			break;
		}
	}

	printf("\n Connection establisehed pID=%d sock=%d to (%s/%d) netw=%u", pID, sock, inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port),
			server_addr.sin_addr.s_addr);
	fflush(stdout);

	//return;

	//while (1);

	//gets(send_data);

	int nfds = 2;
	struct pollfd fds[nfds];
	fds[0].fd = -1;
	fds[0].events = POLLIN | POLLRDNORM; //| POLLPRI;
	fds[1].fd = sock;
	fds[1].events = POLLOUT | POLLWRNORM;
	//fds[1].events = POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;
	printf("\n fd: sock=%d, events=%x\n", sock, fds[1].events);
	int time = -1; //1000;

	//pID = fork();

	/*
	 if (0) {
	 int len;
	 int ret;
	 int recv_bytes;

	 int i = 0;
	 int j;
	 int total = 0;
	 while (i < 20) {
	 //i++;
	 //printf("(%d) Input msg (q or Q to quit):", i);
	 //gets(send_data);

	 //len = strlen(send_data);
	 //printf("\nlen=%d, str='%s'\n", len, send_data);
	 //fflush(stdout);

	 //memcpy(msg, send_data, len);
	 //len = 50;
	 len = 131072;
	 //len = 31072;

	 msg[len] = 'a';

	 //if (pID == 0)
	 //	sleep(1);

	 //printf("\nDoing pID=%d\n", pID);
	 //fflush(stdout);

	 if ((len > 0 && len < 1024) || 1) {
	 if (pID == 0) {
	 //ret = poll(fds, nfds, time);
	 //printf("poll: ret=%d, revents=%x, pID=%d\n", ret, fds[ret].revents, pID);
	 }
	 if (ret || 1) {
	 if (0) {
	 printf("poll: ret=%d, revents=%x, pID=%d\n", ret, fds[ret].revents, pID);
	 printf("POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x\n",
	 (fds[ret].revents & POLLIN) > 0, (fds[ret].revents & POLLPRI) > 0, (fds[ret].revents & POLLOUT) > 0,
	 (fds[ret].revents & POLLERR) > 0, (fds[ret].revents & POLLHUP) > 0, (fds[ret].revents & POLLNVAL) > 0,
	 (fds[ret].revents & POLLRDNORM) > 0, (fds[ret].revents & POLLRDBAND) > 0, (fds[ret].revents & POLLWRNORM) > 0,
	 (fds[ret].revents & POLLWRBAND) > 0);
	 fflush(stdout);
	 }

	 if ((fds[ret].revents & (POLLOUT)) || 1) {
	 //numbytes = send(sock, send_data, strlen(send_data), 0);
	 //printf("\n sending: pID=%d", pID);
	 //fflush(stdout);
	 numbytes = send(sock, msg, len, 0);
	 //numbytes = send(sock, msg, len, MSG_DONTWAIT);

	 //for (j = 0, numbytes = 0; j < len; j++) {
	 //	numbytes += send(sock, msg, 1, 0);
	 //}

	 if (numbytes >= 0) {
	 total += numbytes;

	 printf("\n frame=%d, len=%d, total=%d, pID=%d", ++i, numbytes, total, pID);
	 fflush(stdout);

	 if (numbytes == 0) {
	 sleep(1);
	 }
	 }
	 } else {
	 }
	 }
	 } else {
	 printf("Error string len, len=%d\n", len);
	 fflush(stdout);
	 }

	 if (0) {
	 if ((strcmp(send_data, "q") == 0) || strcmp(send_data, "Q") == 0) {
	 break;
	 }
	 } else {
	 if (send_data[0] == 'q' || send_data[0] == 'Q') {
	 break;
	 }
	 }
	 }
	 }
	 */

	if (1) {
		double total = 15;
		double speed = 10000000; //bits per sec
		int len = 1000; //msg size

		double time = 8 * len / speed * 1000000;
		int use = (int) (time + .5); //ceil(time);
		printf("desired=%f, time=%f, used=%u\n", speed, time, use);
		fflush(stdout);

		int *data = (int *) send_data;
		*(data + 1) = 0;

		double diff;
		double interval = 1;
		double check = interval;
		struct timeval start, end;
		gettimeofday(&start, 0);

		//char temp_buff[100];

		int i = 0;
		while (1) {
			//gets(temp_buff);
			//printf("sending=%d\n", i);
			//fflush(stdout);
			//*data = htonl(i);

			numbytes = sendto(sock, send_data, len, 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
			if (numbytes != len) {
				printf("error: len=%d, numbytes=%d\n", len, numbytes);
				fflush(stdout);
				break;
			}
			i++;

			if (1) {
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
			}
			//break;

			usleep(use);
			//sleep(5);
		}
	}

	printf("\n After");
	fflush(stdout);
	//while (1);

	//gets(send_data);

	//msg[0] = 'q';
	//msg[1] = '\0';
	//numbytes = send(sock, msg, 1, 0);

	printf("\n Closing socket");
	fflush(stdout);
	close(sock);

	printf("\n FIN");
	fflush(stdout);
	while (1)
		;
}

