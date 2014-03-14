/* udpserver.c */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <math.h>
#include <sys/time.h>

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

int recv_count = 0;

void termination_handler(int sig) {
	printf("\n**********Number of packers that have been received = %d *******\n", recv_count);
	exit(2);
}

void print_hex(uint32_t msg_len, uint8_t *msg_pt) {
	uint8_t *temp = (uint8_t *) malloc(3 * msg_len + 1);
	uint8_t *pt = temp;
	int i;
	for (i = 0; i < msg_len; i++) {
		if (i == 0) {
			sprintf((char *) pt, "%02x", msg_pt[i]);
			pt += 2;
		} else if (i % 4 == 0) {
			sprintf((char *) pt, ":%02x", msg_pt[i]);
			pt += 3;
		} else {
			sprintf((char *) pt, " %02x", msg_pt[i]);
			pt += 3;
		}
	}
	temp[3 * msg_len] = '\0';
	printf("msg='%s'\n", temp);
	free(temp);
}

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
	uint16_t port;

	(void) signal(SIGINT, termination_handler);
	int sock;
	int sock_client;
	uint32_t addr_len = sizeof(struct sockaddr);
	int bytes_read;
	int recv_buf_size = 65536; //4000;
	char recv_data[recv_buf_size + 1];
	int ret;

	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

#ifdef BUILD_FOR_ANDROID
	port = 44444;
#else
	if (argc > 1) {
		port = atoi(argv[1]);
	} else {
		port = 44444;
	}
#endif

	//if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)) < 0) {
	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("Socket");
		printf("Failure\n");
		exit(1);
	}

	int optval = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	//setsockopt(sock, SOL_TCP, TCP_NODELAY, &optval, sizeof(optval));

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;

	server_addr.sin_addr.s_addr = INADDR_ANY;
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);
	server_addr.sin_port = htons(port);

	printf("\nBinding to server: addr='%s':%d, netw=%u\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port), server_addr.sin_addr.s_addr);
	fflush(stdout);
	if (bind(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		printf("Failure: errno=%u\n", errno);
		perror("Bind");
		exit(1);
	}

	int backlog = 10;
	printf("Listening to server: backlog=%d\n", backlog);
	fflush(stdout);
	if (listen(sock, backlog) < 0) {
		perror("Listen");
		printf("Failure");
		exit(1);
	}

	printf("TCP Server waiting for client: port %d\n", ntohs(server_addr.sin_port));
	fflush(stdout);

	//fgetc(stdin); //wait until user enters

	while (1) {
		sock_client = accept(sock, (struct sockaddr *) &client_addr, (socklen_t *) &addr_len);
		if (sock_client > 0) {
			break;
		} else {
			printf("failed accept: errno=%d errno='%s'\n", errno, strerror(errno));
			fflush(stdout);
			sleep(1);
		}
	}

	printf("Connection establisehed sock_client=%d to ('%s'/%d) netw=%u\n", sock_client, inet_ntoa(client_addr.sin_addr),
			ntohs(client_addr.sin_port), client_addr.sin_addr.s_addr);
	fflush(stdout);

	//fgetc(stdin); //wait until user enters

	int nfds = 2;
	struct pollfd fds[nfds];
	fds[0].fd = -1;
	fds[0].events = POLLIN | POLLPRI | POLLRDNORM;
	fds[1].fd = sock_client;
	fds[1].events = POLLIN | POLLPRI | POLLRDNORM;
	printf("fd: sock=%d, events=%x\n", sock, fds[1].events);
	fflush(stdout);
	int time = 1000;

	struct timeval start, end;
	gettimeofday(&start, 0);
	double diff;
	double interval = 1;
	double check = interval;

	printf("Looping...\n");
	fflush(stdout);

	recv_count = 0;
	int total = 0;
	while (1) {
		ret = poll(fds, nfds, time);
		if (ret || 0) {
			ret = 1;
			if (0) {
				printf("poll: ret=%d, revents=%x\n", ret, fds[ret].revents);
				printf("POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x\n",
						(fds[ret].revents & POLLIN) > 0, (fds[ret].revents & POLLPRI) > 0, (fds[ret].revents & POLLOUT) > 0, (fds[ret].revents & POLLERR) > 0,
						(fds[ret].revents & POLLHUP) > 0, (fds[ret].revents & POLLNVAL) > 0, (fds[ret].revents & POLLRDNORM) > 0,
						(fds[ret].revents & POLLRDBAND) > 0, (fds[ret].revents & POLLWRNORM) > 0, (fds[ret].revents & POLLWRBAND) > 0);
				fflush(stdout);
			}
			if (fds[ret].revents & (POLLIN | POLLRDNORM)) {
				bytes_read = recv(sock_client, recv_data, recv_buf_size, 0);
				if (bytes_read > 0) {
					if (0) {
						print_hex(3 * 4, (uint8_t *) recv_data);
					}
					recv_data[bytes_read] = '\0';
					total += bytes_read;
					recv_count++;

					gettimeofday(&end, 0);
					diff = time_diff(&start, &end) / 1000;
					if (check <= diff) {
						printf("time=%f, frames=%d, total=%d, speed=%f\n", diff, recv_count, total, 8.0 * total / diff);
						fflush(stdout);
						check += interval;
					}

					if ((strcmp(recv_data, "q") == 0) || strcmp(recv_data, "Q") == 0) {
						break;
					}
				} else if (bytes_read == 0) {
					break;
				} else /*if (errno != EWOULDBLOCK && errno != EAGAIN)*/{
					printf("Error recv at the Server: ret=%d errno='%s' (%d)\n", bytes_read, strerror(errno), errno);
					perror("Error:");
					fflush(stdout);
					if (errno != EWOULDBLOCK && errno != EAGAIN)
						break;
				}
			} else if (fds[ret].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				break;
			}
		}
	}

	printf("Closing client socket\n");
	fflush(stdout);
	close(sock_client);

	printf("Closing server socket\n");
	fflush(stdout);
	close(sock);

	printf("FIN\n");
	fflush(stdout);

	while (1)
		;

	return 0;
}

