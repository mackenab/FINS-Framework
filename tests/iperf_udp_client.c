/*
 * iperf_udp_client.c
 *
 * A simple udp traffic generator similar to iperf that can be set at varying data lengths & throughput rates. There are 4 separate methods that offer differing results.
 *
 *  Created on: Sep 28, 2014
 *      Author: root
 */


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

#include <pthread.h>
#include <semaphore.h>
#include <signal.h>

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

	return diff;
}

struct msg_hdr {
	uint32_t id;
	uint32_t seq_num;
};



//-----------------------------
double duration = 20; //seconds
uint32_t data_len = 18; //1000; //1470; //18; //1470; //app data size

//set one & zero out the other.
double eth_speed = 95000000; //ethernet level bits per sec
double speed = 000000; //6100000; //application level bits per sec
double rate = 0; //400000; //packets per sec
//-----------------------------



int sock;
int numbytes;
char data[1470];
struct msg_hdr *hdr;
uint32_t id_count = 0;
double pkts; //expected total number of packets
struct timeval start, end;
uint8_t stopped;

void to_handler(int sig, siginfo_t *si, void *uc) {
	if (id_count >= pkts) {
		if (stopped) {
			return;
		} else {
			stopped = 1;
			gettimeofday(&end, 0); //TODO change to alert timer and interrupt
		}
	} else {
		hdr->id = htonl(id_count++); //TODO change to random sequence
		numbytes = send(sock, data, data_len, 0);
		if (numbytes != data_len) {
			printf("error: data_len=%u, numbytes=%d\n", data_len, numbytes);
			fflush(stdout);
			exit(-1);
		}
	}
}

int main(int argc, char *argv[]) {
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

	int port = 44444;
	int client_port = 55555;

	//if ((sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)) == -1) {
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		perror("Socket");
		printf("Failure");
		exit(1);
	}

	int optval = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	//server_addr.sin_addr.s_addr = xxx(192,168,1,19);
	server_addr.sin_addr.s_addr = xxx(128,173,92,33);
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);
	server_addr.sin_port = htons(port);

	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = xxx(128,173,92,32);
	//client_addr.sin_addr.s_addr = xxx(192,168,1,20);
	//client_addr.sin_addr.s_addr = INADDR_ANY;
	//client_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	client_addr.sin_addr.s_addr = htonl(client_addr.sin_addr.s_addr);
	client_addr.sin_port = htons(client_port);

	printf("Binding to client_addr='%s':%d, netw=%u\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_addr.sin_addr.s_addr);
	if (bind(sock, (struct sockaddr *) &client_addr, sizeof(struct sockaddr)) == -1) {
		perror("Bind");
		printf("Failure\n");
		exit(1);
	}

	printf("Connecting to server_addr='%s':%d, netw=%u\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port), server_addr.sin_addr.s_addr);
	if (connect(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) == -1) {
		perror("Connect");
		printf("Failure\n");
		exit(1);
	}

	//fgetc(stdin); //wait until user enters

	if (eth_speed != 0) {
	 	rate = eth_speed/8.0/(data_len+46);
		speed = 8.0*rate*data_len;
	} else if (speed != 0) {
		rate = speed / 8.0 / data_len;
		eth_speed = 8.0*rate*(data_len+46);
	} else if (rate != 0) {
		eth_speed = 8.0*rate*(data_len+46);
		speed = 8.0*rate*data_len;
	} else {
		//error! shouldn't occur.
	}

	printf("Target:\n");
	printf("time=%f, data_len=%u, pkt/s=%f, app Mbps=%f, eth Mbps=%f\n", duration, data_len, rate, speed/1000000, eth_speed/1000000);
	fflush(stdout);

	pkts = duration * rate; //expected total number of packets
	double wait_time = 8.0 * data_len / speed * 1000000000;
	int wait_used = (int) (wait_time + .5); //ceil(time); //wait time in nsec
	//wait_used = 1;

	memset(data, 0, 1470);
	hdr = (struct msg_hdr *) data;
	double diff;


	//------------------------- alert timers
	uint32_t to_signal = SIGRTMIN;

	struct sigaction sa;
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = to_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(to_signal, &sa, NULL)) {
		perror("sigaction fault");
		exit(-1);
	}

	timer_t tid;
	struct sigevent sev;
	memset(&sev, 0, sizeof(struct sigevent));
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = to_signal;
	if (timer_create(CLOCK_REALTIME, &sev, &tid)) {
		perror("timer_create fault");
		exit(-1);
	}

	struct itimerspec its;
	its.it_value.tv_sec = (long int) (wait_used / 1000000000.0);
	its.it_value.tv_nsec = (long int) fmod(wait_used, 1000000000.0);
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;
	//-------------------------


	//------------------------- nanosleep
	struct timespec pause;
	pause.tv_sec = 0;
	pause.tv_nsec = wait_used;
	struct timespec rem;
	rem.tv_sec = 0;
	rem.tv_nsec = 0;
	//-------------------------


	if (0) { //alert timer method, generates up to ~30 Mbps over ethernet
		printf("total pkts=%f, wait=%f, used=%d\n", pkts, wait_time, wait_used);
		fflush(stdout);

		gettimeofday(&start, 0);

		if (timer_settime(tid, 0, &its, NULL)) {
			perror("Error setting timer.");
			exit(-1);
		}
		while (!stopped)
			;

		its.it_value.tv_sec = 0;
		its.it_value.tv_nsec = 0;
		its.it_interval.tv_sec = 0;
		its.it_interval.tv_nsec = 0;
		if (timer_settime(tid, 0, &its, NULL)) {
			perror("Error setting timer.");
			exit(-1);
		}

		diff = time_diff(&start, &end);
	}

	if (0) { //sleep / usleep / nanosleep method, gen's up to ~20 Mbps over ethernet
		printf("total pkts=%f, wait=%f, used=%d\n", pkts, wait_time, wait_used);
		fflush(stdout);

		gettimeofday(&start, 0);
		while (id_count < pkts) {
			hdr->id = htonl(id_count++); //TODO change to random sequence
			numbytes = send(sock, data, data_len, 0);
			if (numbytes != data_len) {
				printf("error: data_len=%u, numbytes=%d\n", data_len, numbytes);
				fflush(stdout);
				break;
			}

			//sleep(use);
			//usleep(use);
			nanosleep(&pause, &rem);
		}
		gettimeofday(&end, 0); //TODO change to alert timer and interrupt
		diff = time_diff(&start, &end);
	}

	if (0) { //clock method //reliable up to 70 Mbps over ethernet? "reports" can go up to 100 Mbps, but is unreliable
		//printf("CLOCKS_PER_SEC=%ld\n", CLOCKS_PER_SEC); //CLOCKS_PER_SEC==1000000, so clocks is in usec
		double send_pkts;
		int j;
		clock_t clock_end;

		clock_t clock_start = clock();
		while (id_count < pkts) {
			//diff = 1.0 * (clock() - clock_start) / CLOCKS_PER_SEC;
			clock_end = clock();
			diff = 1.0 * (clock_end - clock_start) / CLOCKS_PER_SEC;
			if (diff >= duration) {
				break;
			}

			send_pkts = pkts * diff / duration - id_count;
			for (j = 0; j < send_pkts; j++) {
				hdr->id = htonl(id_count++);
				numbytes = send(sock, data, data_len, 0);
				if (numbytes != data_len) {
					printf("error: data_len=%u, numbytes=%d\n", data_len, numbytes);
					fflush(stdout);
					exit(-1);
				}

				if (id_count >= pkts) {
					//diff = 1.0 * (clock() - clock_start) / CLOCKS_PER_SEC;
					clock_end = clock();
					diff = 1.0 * (clock_end - clock_start) / CLOCKS_PER_SEC;
					break;
				}
			}
		}
	}

	if (1) { //gettimeofday method, most reliable. Gen's up to 76 Mbps over ethernet
		double send_pkts;
		int j;

		gettimeofday(&start, 0);
		while (id_count < pkts) {
			gettimeofday(&end, 0);
			diff = time_diff(&start, &end);
			if (diff >= duration) {
				break;
			}

			send_pkts = pkts * diff / duration - id_count;
			for (j = 0; j < send_pkts; j++) {
				hdr->id = htonl(id_count++);
				numbytes = send(sock, data, data_len, 0);
				if (numbytes != data_len) {
					printf("error: data_len=%u, numbytes=%d\n", data_len, numbytes);
					fflush(stdout);
					exit(-1);
				}

				if (id_count >= pkts) {
					gettimeofday(&end, 0);
					diff = time_diff(&start, &end);
					break;
				}
			}
		}
	}

	hdr->id = htonl(~(id_count - 1));
	wait_used = 1;

	uint64_t i;
	for (i = 0; i < 20; i++) {
		numbytes = send(sock, data, data_len, 0);
		if (numbytes != data_len) {
			printf("error: data_len=%u, numbytes=%d\n", data_len, numbytes);
			fflush(stdout);
			break;
		}

		usleep(wait_used);
		wait_used *= 2;
	}

	double obs_rate = id_count / diff;
	printf("Generated:\n");
	printf("time=%f, data_len=%u, pkt/s=%f, app Mbps=%f, eth Mbps=%f\n", diff, data_len, obs_rate, 8.0*data_len*obs_rate/1000000, 8.0*(data_len+46)*obs_rate/1000000);
	printf("Total: sent pkts=%u, app sent Bytes=%u, eth sent Bytes=%u\n", id_count, data_len * id_count, (data_len+46) * id_count);
	fflush(stdout);

	shutdown(sock, SHUT_WR);
	//printf("Closing socket\n");
	//fflush(stdout);
	close(sock);
	printf("FIN\n");
	fflush(stdout);

	return 0;
}
