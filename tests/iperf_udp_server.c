/*
 * iperf_udp_server.c
 *
 * A simple udp traffic sink that can accept frames generated in a format similar to iperf.
 *
 *  Created on: Sep 28, 2014
 *      Author: root
 */

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

	return diff;
}

struct msg_hdr {
	uint32_t id;
	uint32_t seq_num;
};

uint32_t recv_count = 0;
uint32_t recv_total = 0;

double diff = 0;
struct timeval start, end;

int main(int argc, char *argv[]) {
	uint16_t port = 44444;

	int sock;
	uint32_t addr_len = sizeof(struct sockaddr);
	int bytes_read;
	int recv_buf_size = 65536; //4000;
	char recv_data[recv_buf_size + 1];
	int ret;

	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

	//if ((sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)) < 0) {
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("Socket");
		printf("Failure\n");
		exit(1);
	}

	int optval = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;

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

	struct msg_hdr *hdr = (struct msg_hdr *) recv_data;
	int count = 0;

	printf("Looping...\n");
	fflush(stdout);

	while (1) {
		bytes_read = recvfrom(sock, recv_data, recv_buf_size, 0, (struct sockaddr *) &client_addr, (socklen_t *) &addr_len);
		if (recv_count == 0) {
			gettimeofday(&start, 0);
		}
		if (bytes_read > 0) {
			count = ntohl(hdr->id);
			if (count < 0) {
				gettimeofday(&end, 0);
				diff = time_diff(&start, &end);
				
				count = ~count + 1;
				if (count < recv_count + 1) {
					count = recv_count + 1;
				}
				break;
			} else {
				recv_count++;
			}
		} else if (bytes_read == 0) {
			gettimeofday(&end, 0);
			diff = time_diff(&start, &end);
			break;
		} else {
			printf("Error recv at the Server: ret=%d errno='%s' (%d)\n", bytes_read, strerror(errno), errno);
			perror("Error:");
			fflush(stdout);
			if (errno != EWOULDBLOCK && errno != EAGAIN) {
				break;
			}
		}
	}

	//double through = 8.0 * md->bytes / test / 1000000.0;
	double rate = recv_count/diff;
	double through = 8.0 * rate*bytes_read / 1000000.0;
	double eth_through = 8.0 * rate*(bytes_read+46) / 1000000.0;
	double drop = count - recv_count;
	double drop_rate = drop / count;

	if (0) {
		printf( "Logger stopping: t=%f, data_len=%i, pkts=%i, bytes=%i\n", diff, bytes_read, (int)recv_count, (int)(recv_count*bytes_read));
		printf("t=%f, pkt/s=%f, app Mbps=%f, eth Mbps=%f, dropped=%i/%i (%f)\n",
				diff, rate, through, eth_through, (int) drop, count, drop_rate);
		fflush(stdout);
	} else { //only columns & no text, for data collection
		printf("%f, %f, %f, %f, %i, %i, %f\n", diff, rate, through, eth_through, (int)drop, count, drop_rate);
		fflush(stdout);
	}

	shutdown(sock, SHUT_WR);
	//printf("Closing server socket\n");
	//fflush(stdout);
	close(sock);
	printf("FIN\n");
	fflush(stdout);

	return 0;
}

