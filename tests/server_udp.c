/* udpserver.c */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>

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

#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

//---------------------------------------------------

#define xxx(a,b,c,d) 	(16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d))

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

int i = 0;

void termination_handler(int sig) {
	printf("\n**********Number of packers that have been received = %d *******\n", i);
	fflush(stdout);
	exit(2);
}

int main(int argc, char *argv[]) {

	printf(
			"EACCES=%d EACCES=%d EPERM=%d EADDRINUSE=%d EAFNOSUPPORT=%d EAGAIN=%d EALREADY=%d EBADF=%d ECONNREFUSED=%d EFAULT=%d EINPROGRESS=%d EINTR=%d EISCONN=%d ENETUNREACH=%d ENOTSOCK=%d ETIMEDOUT=%d\n",
			EACCES, EACCES, EPERM, EADDRINUSE, EAFNOSUPPORT, EAGAIN, EALREADY, EBADF, ECONNREFUSED, EFAULT, EINPROGRESS, EINTR, EISCONN, ENETUNREACH, ENOTSOCK,
			ETIMEDOUT);

	uint16_t port;

	(void) signal(SIGINT, termination_handler);

	int sock;
	socklen_t addr_len = sizeof(struct sockaddr);
	int bytes_read;
	char recv_data[500000];
	int ret;
	pid_t pID = 0;

	struct sockaddr_in server_addr;
	struct sockaddr_in *client_addr;

	if (argc > 1) {
		port = atoi(argv[1]);
	} else {
		port = 45454;
	}

	client_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	//if ((sock = socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1) {
	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		//if ((sock = socket(39, SOCK_DGRAM, 0)) == -1) {
		perror("Socket");
		exit(1);
	}

	printf("Provided with sock=%d\n", sock);

	struct timeval tv_1;
	int size_1 = sizeof(struct timeval);
	getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_1, &size_1);

	struct timeval tv_2;
	int size_2 = sizeof(struct timeval);
	getsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv_2, &size_2);

	printf("size_1=%d, size_2=%d, SO_RCVTIMEO=%u,%u, SO_SNDTIMEO=%u,%u\n", size_1, size_2, (uint32_t) tv_1.tv_sec, (uint32_t) tv_1.tv_usec,
			(uint32_t) tv_2.tv_sec, (uint32_t) tv_2.tv_usec);

	//tv.tv_sec = 30; /* 30 Secs Timeout */

	//int FSO_RCVTIMEO = 0;
	//getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &FSO_RCVTIMEO, sizeof(FSO_RCVTIMEO));
	//int FSO_SNDTIMEO = 0;
	//setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &FSO_SNDTIMEO, sizeof(FSO_SNDTIMEO));

	server_addr.sin_family = PF_INET;
	server_addr.sin_port = htons(port);

	//server_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//server_addr.sin_addr.s_addr = xxx(114,53,31,172);
	//server_addr.sin_addr.s_addr = xxx(172,31,54,87);
	//server_addr.sin_addr.s_addr = xxx(192,168,1,20);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);
	bzero(&(server_addr.sin_zero), 8);

	printf("Binding to server: pID=%d addr=%s:%d, netw=%u\n", pID, inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port), server_addr.sin_addr.s_addr);
	if (bind(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) == -1) {
		perror("Bind");
		printf("Failure");
		exit(1);
	}

	addr_len = sizeof(struct sockaddr);

	printf("\n UDPServer Waiting for client at server_addr=%s/%d, netw=%u", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port),
			server_addr.sin_addr.s_addr);
	fflush(stdout);

	i = 0;

	int nfds = 2;
	struct pollfd fds[nfds];
	fds[0].fd = -1;
	fds[0].events = POLLIN | POLLPRI | POLLRDNORM;
	fds[1].fd = sock;
	fds[1].events = POLLIN | POLLPRI | POLLRDNORM;
	//fds[1].events = POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;
	printf("\n fd: sock=%d, events=%x", sock, fds[1].events);
	int time = -1;

	printf("\n POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x", POLLIN, POLLPRI,
			POLLOUT, POLLERR, POLLHUP, POLLNVAL, POLLRDNORM, POLLRDBAND, POLLWRNORM, POLLWRBAND);
	fflush(stdout);

	int temp = fds[1].events;
	printf("\n POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x val=%d (%x)",
			(temp & POLLIN) > 0, (temp & POLLPRI) > 0, (temp & POLLOUT) > 0, (temp & POLLERR) > 0, (temp & POLLHUP) > 0, (temp & POLLNVAL) > 0,
			(temp & POLLRDNORM) > 0, (temp & POLLRDBAND) > 0, (temp & POLLWRNORM) > 0, (temp & POLLWRBAND) > 0, temp, temp);

	struct timeval tv;

	tv.tv_sec = 0; /* 30 Secs Timeout */
	tv.tv_usec = 0; // Not init'ing this can cause strange errors

	//ret = getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof(struct timeval));
	//printf("\n ret=%d tv.tv_sec=%d tv.tv_usec=%d", ret, tv.tv_sec, tv.tv_usec);
	fflush(stdout);

	int j = 0;
	while (++j <= 3) {
		//pID = fork();
		if (pID == 0) { // child -- Capture process
			continue;
		} else if (pID < 0) { // failed to fork
			printf("Failed to Fork \n");
			fflush(stdout);
			exit(1);
		} else { // parent
			//port += j - 1;
			break;
		}
	}

	if (pID == 0) {
		//while (1);
	}

	if (1) {
		j = 0;
		int k = 0;
		while (1) {
			//printf("\n pID=%d poll before", pID);
			//fflush(stdout);
			//ret = poll(fds, nfds, time);
			//printf("\n poll: pID=%d, ret=%d, revents=%x", pID, ret, fds[ret].revents);
			//fflush(stdout);
			if (ret || 1) {
				if (0) {
					printf("\n poll: ret=%d, revents=%x", ret, fds[ret].revents);
					printf("\n POLLIN=%d POLLPRI=%d POLLOUT=%d POLLERR=%d POLLHUP=%d POLLNVAL=%d POLLRDNORM=%d POLLRDBAND=%d POLLWRNORM=%d POLLWRBAND=%d ",
							(fds[ret].revents & POLLIN) > 0, (fds[ret].revents & POLLPRI) > 0, (fds[ret].revents & POLLOUT) > 0,
							(fds[ret].revents & POLLERR) > 0, (fds[ret].revents & POLLHUP) > 0, (fds[ret].revents & POLLNVAL) > 0,
							(fds[ret].revents & POLLRDNORM) > 0, (fds[ret].revents & POLLRDBAND) > 0, (fds[ret].revents & POLLWRNORM) > 0,
							(fds[ret].revents & POLLWRBAND) > 0);
					fflush(stdout);
				}

				if ((fds[ret].revents & (POLLIN | POLLRDNORM)) || 1) {
					//bytes_read = recvfrom(sock, recv_data, 200000, MSG_DONTWAIT, (struct sockaddr *) client_addr, &addr_len);
					bytes_read = recvfrom(sock, recv_data, 200000, 0, (struct sockaddr *) client_addr, &addr_len);
					//bytes_read = recvfrom(sock,recv_data,1024,0,NULL, NULL);
					//bytes_read = recv(sock,recv_data,1024,0);
					if (bytes_read > 0) {
						if (1) {
							print_hex(3*4, recv_data);
						}
						recv_data[bytes_read] = '\0';
						printf("\n frame=%d, pID=%d, client=%s:%u: said='%s'\n", ++k, pID, inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port),
								recv_data);
						fflush(stdout);

						//bytes_read = sendto(sock, recv_data, 1, 0, (struct sockaddr *) client_addr, sizeof(struct sockaddr_in));

						if ((strcmp(recv_data, "q") == 0) || strcmp(recv_data, "Q") == 0) {
							break;
						}
					} else /*if (errno != EWOULDBLOCK && errno != EAGAIN)*/{
						printf("\n Error recv at the Server: ret=%d errno='%s' (%d)\n", bytes_read, strerror(errno), errno);
						perror("Error:");
						fflush(stdout);
						sleep(2);
					}
				}
			}
			j++;
			//break;
		}
	}
	if (0) {
		i = 0;
		while (1) {
			//printf("\n pID=%d recvfrom before", pID);
			//fflush(stdout);
			bytes_read = recvfrom(sock, recv_data, 2000, 0, (struct sockaddr *) client_addr, &addr_len);
			//printf("\n pID=%d recvfrom after", pID);
			//fflush(stdout);
			//bytes_read = recvfrom(sock,recv_data,1024,0,NULL, NULL);
			//bytes_read = recv(sock,recv_data,1024,0);
			if (bytes_read > 0) {
				recv_data[bytes_read] = '\0';
				printf("\n frame=%d, pID=%d, client=%s:%u: said='%s'\n", ++i, pID, inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), recv_data);
				fflush(stdout);

				if (0) {

				}

				//bytes_read = sendto(sock, recv_data, 1, 0, (struct sockaddr *) client_addr, sizeof(struct sockaddr_in));

				if ((strcmp(recv_data, "q") == 0) || strcmp(recv_data, "Q") == 0) {
					break;
				}
			} else if (errno != EWOULDBLOCK && errno != EAGAIN) {
				printf("\n Error recv at the Server: ret=%d errno='%s' (%d)\n", bytes_read, strerror(errno), errno);
				perror("Error:");
				fflush(stdout);
				break;
			}
		}
	}

	if (0) {
		struct timeval start, end;
		int its = 10000;
		//len = 1000;

		int data_len = 1000;
		while (data_len < 4000) {
			//data_len += 100;
			//data_len = 1000;

			int total_bytes = 0;
			double total_time = 0;
			int total_success = 0;
			double diff;

			int i = 0;
			while (i < its) {
				i++;

				gettimeofday(&start, 0);
				//numbytes = sendto(sock, send_data, data_len, 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr));
				bytes_read = recvfrom(sock, recv_data, 2000, 0, (struct sockaddr *) client_addr, &addr_len);
				gettimeofday(&end, 0);
				diff = time_diff(&start, &end);

				if (bytes_read > 0) {
					total_success++;
					total_bytes += bytes_read;
					total_time += diff;
				} else {
					perror("error");
				}
			}

			//printf("\n diff=%f, len=%d, avg=%f ms, calls=%f, bits=%f", diff, data_len, diff / its, 1000 / (diff / its), 1000 / (diff / its) * data_len);
			printf("\n len=%d, time=%f, suc=%d, bytes=%d, avg=%f ms, eff=%f, thr=%f, calls=%f, act=%f", data_len, total_time, total_success, total_bytes,
					total_time / total_success, total_success / (double) its, total_bytes / (double) its / data_len, 1000 / (total_time / total_success),
					1000 / (total_time / total_success) * data_len * 8);
			fflush(stdout);

			sleep(5);
		}
	}

	printf("\n Closing server socket");
	fflush(stdout);
	close(sock);

	printf("\n FIN");
	fflush(stdout);

	while (1)
		;

	return 0;
}

