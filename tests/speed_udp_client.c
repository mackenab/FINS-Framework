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
#include <netinet/tcp.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

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

struct msg_hdr {
	uint64_t id;
	uint64_t seq_num;
	struct timeval stamp;
};

int main(int argc, char *argv[]) {
	int sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	int numbytes;
	char send_data[131072 + 1];
	char msg[131092];

	int port = 44444;
	int client_port = 55555;

	memset(send_data, 89, 131072);
	send_data[131072] = '\0';

	memset(msg, 89, 131072);
	msg[131072] = '\0';

	//if ((sock = socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)) == -1) {
	if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		perror("Socket");
		printf("Failure");
		exit(1);
	}

	int optval = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	//int result = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *) &optval, sizeof(int));

	printf("\nMY DEST PORT BEFORE AND AFTER\n");
	printf("%d, %d\n", port, htons(port));
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = PF_INET;
	//server_addr.sin_addr.s_addr = xxx(192,168,1,3);
	server_addr.sin_addr.s_addr = xxx(128,173,92,32);
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);
	server_addr.sin_port = htons(port);

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
		printf("Failure\n");
		exit(1);
	}
	//*/

	//fgetc(stdin); //wait until user enters

	double total = 15; //seconds
	double speed = 10000000; //bits per sec
	uint64_t len = 1460; //msg size

	double time = 8.0 * len / speed * 1000000;
	int use = (int) (time + .5); //ceil(time);
	printf("desired=%f, time=%f, used=%u\n", speed, time, use);
	fflush(stdout);

	struct msg_hdr *hdr = (struct msg_hdr *) send_data;
	uint64_t id_count = 0;
	uint64_t seq_count = 0;

	double diff;
	double interval = 1;
	double check = interval;
	struct timeval start, end;
	gettimeofday(&start, 0);

	printf("Looping...\n");
	fflush(stdout);

	uint64_t i = 0;
	while (1) {
		hdr->id = htonl(id_count++); //TODO change to random sequence
		hdr->seq_num = htonl(seq_count++);
		gettimeofday(&hdr->stamp, 0);
		numbytes = sendto(sock, send_data, len, 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
		if (numbytes != len) {
			printf("error: len=%llu, numbytes=%d\n", len, numbytes);
			fflush(stdout);
			break;
		}
		i++;

		gettimeofday(&end, 0);
		diff = time_diff(&start, &end) / 1000;
		if (check <= diff) {
			printf("time=%f, pkts=%llu, Bytes=%llu, bps=%f\n", diff, i, len * i, 1.0 * len * i / diff * 8.0);
			fflush(stdout);
			check += interval;
		}

		if (total <= diff) {
			break;
		}

		usleep(use);
	}
	shutdown(sock, SHUT_WR);
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
