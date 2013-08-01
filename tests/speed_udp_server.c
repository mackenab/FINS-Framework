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

struct msg_hdr {
	uint64_t id;
	uint64_t seq_num;
	struct timeval stamp;
};

uint64_t recv_count = 0;
uint64_t recv_total = 0;

uint64_t last_seq_num = 0;
uint64_t miss_total = 0;
uint64_t miss_count = 0;

double diff = 0;
struct timeval start, end;

void termination_handler(int sig) {
	gettimeofday(&end, 0);
	diff = time_diff(&start, &end) / 1000;

	printf("\n**********Number of packers that have been received = %llu *******\n", recv_count);
	if (recv_count != 0) {
		printf("\ntime=%f, pkts=%llu, Bytes=%llu, bps=%f, drop=%f (%llu), jump=%f*%llu, last=%llu\n", diff, recv_count, recv_total, 1.0 * recv_total / diff * 8.0,
				100.0 * miss_total / last_seq_num, miss_total, 1.0 * miss_total / miss_count, miss_count, last_seq_num);
	} else {
		printf("\ntime=%f, pkts=%llu, Bytes=%llu, bps=%lf, drop=NA\n", diff, recv_count, recv_total, 1.0 * recv_total / diff * 8.0);
	}
	exit(2);
}

int main(int argc, char *argv[]) {
	uint16_t port = 44444;

	(void) signal(SIGINT, termination_handler);
	int sock;
	uint32_t addr_len = sizeof(struct sockaddr);
	int bytes_read;
	int recv_buf_size = 65536; //4000;
	char recv_data[recv_buf_size + 1];
	int ret;

	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

	//if ((sock = socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)) < 0) {
	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("Socket");
		printf("Failure\n");
		exit(1);
	}

	int optval = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = PF_INET;

	server_addr.sin_addr.s_addr = INADDR_ANY;
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);
	server_addr.sin_port = htons(port);

	printf("Binding to server: addr='%s':%d, netw=%u\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port), server_addr.sin_addr.s_addr);
	fflush(stdout);
	if (bind(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		printf("Failure: errno=%u\n", errno);
		perror("Bind");
		exit(1);
	}

	//fgetc(stdin); //wait until user enters

	int nfds = 2;
	struct pollfd fds[nfds];
	fds[0].fd = -1;
	fds[0].events = POLLIN | POLLPRI | POLLRDNORM;
	fds[1].fd = sock;
	fds[1].events = POLLIN | POLLPRI | POLLRDNORM;
	printf("fd: sock=%d, events=%x\n", sock, fds[1].events);
	fflush(stdout);
	//int time = 1000;

	struct msg_hdr *hdr = (struct msg_hdr *) recv_data;
	uint32_t seq_num_host;

	int init = 1;
	double interval = 1;
	double check = interval;

	printf("Looping...\n");
	fflush(stdout);

	while (1) {
		//ret = poll(fds, nfds, time);
		if (ret || 1) {
			ret = 1;
			if (0) {
				printf("poll: ret=%d, revents=%x\n", ret, fds[ret].revents);
				printf("POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x\n",
						(fds[ret].revents & POLLIN) > 0, (fds[ret].revents & POLLPRI) > 0, (fds[ret].revents & POLLOUT) > 0, (fds[ret].revents & POLLERR) > 0,
						(fds[ret].revents & POLLHUP) > 0, (fds[ret].revents & POLLNVAL) > 0, (fds[ret].revents & POLLRDNORM) > 0,
						(fds[ret].revents & POLLRDBAND) > 0, (fds[ret].revents & POLLWRNORM) > 0, (fds[ret].revents & POLLWRBAND) > 0);
				fflush(stdout);
			}
			if ((fds[ret].revents & (POLLIN | POLLRDNORM)) || 1) {
				bytes_read = recvfrom(sock, recv_data, recv_buf_size, 0, (struct sockaddr *) &client_addr, (socklen_t *) &addr_len);
				if (init) {
					gettimeofday(&start, 0);
					init = 0;
				}
				if (bytes_read > 0) {
					if (0) {
						print_hex(3 * 4, (uint8_t *) recv_data);
					}
					//recv_data[bytes_read] = '\0';
					recv_count++;
					recv_total += bytes_read;

					seq_num_host = ntohl(hdr->seq_num);
					if (seq_num_host < last_seq_num) {
						miss_total--;
					} else if (last_seq_num == 0 && seq_num_host == 0) {
					} else if (last_seq_num + 1 == seq_num_host) {
						last_seq_num = seq_num_host;
					} else {
						miss_total += seq_num_host - last_seq_num - 1;
						miss_count++;

						last_seq_num = seq_num_host;
					}

					gettimeofday(&end, 0);
					diff = time_diff(&start, &end) / 1000;
					if (check <= diff) {
						printf("time=%f, pkts=%llu, Bytes=%llu, bps=%f, drop=%f (%llu), jump=%f*%llu, last=%llu\n", diff, recv_count, recv_total,
								1.0 * recv_total / diff * 8.0, 100.0 * miss_total / last_seq_num, miss_total, 1.0 * miss_total / miss_count, miss_count,
								last_seq_num);
						fflush(stdout);
						check += interval;
					}

					if ((strcmp(recv_data, "q") == 0) || strcmp(recv_data, "Q") == 0) {
						break;
					}
				} else if (bytes_read == 0) {
					break;
				} else {
					printf("Error recv at the Server: ret=%d errno='%s' (%d)\n", bytes_read, strerror(errno), errno);
					perror("Error:");
					fflush(stdout);
					if (errno != EWOULDBLOCK && errno != EAGAIN) {
						break;
					}
				}
			} else if (fds[ret].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				break;
			}
		}
	}
	shutdown(sock, SHUT_WR);

	printf("Closing server socket\n");
	fflush(stdout);
	close(sock);

	printf("FIN\n");
	fflush(stdout);

	while (1)
		;

	return 0;
}

