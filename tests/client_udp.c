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
#include <linux/errqueue.h>
#include <math.h>
#include <time.h>

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

	printf("Entered: time1=%p, time2=%p\n", time1, time2);

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

	printf("diff=%f\n", diff);
	return diff;
}

int main(int argc, char *argv[]) {
	printf("SOCK_RAW=%u\n", SOCK_RAW);
	printf("SOCK_STREAM=%u\n", SOCK_STREAM);
	printf("SOCK_DGRAM=%u\n", SOCK_DGRAM);

	printf("IPPROTO_ICMP=%u\n", IPPROTO_ICMP);
	printf("IPPROTO_TCP=%u\n", IPPROTO_TCP);
	printf("IPPROTO_IP=%u\n", IPPROTO_IP);

	int sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	int addr_len = sizeof(struct sockaddr);
	int numbytes;
	//struct hostent *host;
	char send_data[1024];
	int port;
	int client_port;
	pid_t pID;

	memset(send_data, 89, 1000);
	send_data[1000] = '\0';

	//host= (struct hostent *) gethostbyname((char *)"127.0.0.1");

	//if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) {
	if ((sock = socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1) {
		//if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	int val = 0;
	setsockopt(sock, SOL_IP, IP_MTU_DISCOVER, &val, sizeof(val));
	val = 1;
	setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &val, sizeof(val));
	val = 1;
	setsockopt(sock, SOL_IP, IP_RECVTTL, &val, sizeof(val));
	val = 1;
	setsockopt(sock, SOL_IP, IP_RECVERR, &val, sizeof(val));

	//fcntl64(3, F_SETFL, O_RDONLY|O_NONBLOCK) = 0
	//fstat64(1, {st_dev=makedev(0, 11), st_ino=3, st_mode=S_IFCHR|0620, st_nlink=1, st_uid=1000, st_gid=5, st_blksize=1024, st_blocks=0, st_rdev=makedev(136, 0), st_atime=2012/10/16-22:31:09, st_mtime=2012/10/16-22:31:09, st_ctime=2012/10/16-19:33:02}) = 0

	val = 3;
	setsockopt(sock, SOL_IP, IP_TTL, &val, sizeof(val));

	if (argc > 1) {
		port = atoi(argv[1]);
	} else {
		port = 45454;
	}

	printf("MY DEST PORT BEFORE AND AFTER\n");
	printf("%d, %d\n", port, htons(port));
	server_addr.sin_family = PF_INET;
	//server_addr.sin_port = htons(port);
	server_addr.sin_port = htons(53);

	//server_addr.sin_addr.s_addr = xxx(192,168,1,20);
	server_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//server_addr.sin_addr.s_addr = xxx(74,125,224,72);
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);
	bzero(&(server_addr.sin_zero), 8);

	printf("\n UDP Client sending to server at server_addr=%s:%d, netw=%u\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port),
			server_addr.sin_addr.s_addr);

	if (argc > 2) {
		client_port = atoi(argv[2]);
	} else {
		client_port = 55555;
	}
	client_addr.sin_family = PF_INET;
	client_addr.sin_port = htons(client_port);

	//client_addr.sin_addr.s_addr = xxx(127,0,0,1);
	client_addr.sin_addr.s_addr = INADDR_ANY;
	//client_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	client_addr.sin_addr.s_addr = htonl(client_addr.sin_addr.s_addr);
	//bzero(&(client_addr.sin_zero), 8);

	printf("Binding to client_addr=%s:%d, netw=%u\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_addr.sin_addr.s_addr);
	if (bind(sock, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in)) == -1) {
		perror("Bind");
		printf("Failure");
		exit(1);
	}

	printf("Bound to client_addr=%s:%d, netw=%u\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_addr.sin_addr.s_addr);

	int nfds = 2;
	struct pollfd fds[nfds];
	fds[0].fd = -1;
	fds[0].events = POLLIN | POLLERR; //| POLLPRI;
	fds[1].fd = sock;
	fds[1].events = POLLIN | 0;
	//fds[1].events = POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;
	printf("\n fd: sock=%d, events=%x", sock, fds[1].events);
	int time = 1000;

	//pID = fork();
	if (pID == 0) { // child -- Capture process
		send_data[0] = 65;
	} else if (pID < 0) { // failed to fork
		printf("Failed to Fork \n");
		fflush(stdout);
		exit(1);
	} else { //parent
		send_data[0] = 89;
	}

	int len;
	int ret = 0;

	struct msghdr recv_msg;
	int name_len = 64;
	char name_buf[name_len];
	struct iovec iov[1];
	int recv_len = 1000;
	char recv_buf[recv_len];
	int control_len = 4000;
	char control_buf[control_len];
	iov[0].iov_len = recv_len;
	iov[0].iov_base = recv_buf;

	recv_msg.msg_namelen = name_len;
	recv_msg.msg_name = name_buf;

	recv_msg.msg_iovlen = 1;
	recv_msg.msg_iov = iov;

	recv_msg.msg_controllen = control_len;
	recv_msg.msg_control = control_buf;

	struct cmsghdr *cmsg;
	int *ttlptr;
	int received_ttl;

	struct timeval curr;
	struct timeval *stamp;

	int i = 0;
	while (i < 100) {
		i++;
		if (1) {
			printf("(%d) Input msg (q or Q to quit):", i);
			gets(send_data);

			len = strlen(send_data);
			printf("\nlen=%d, str='%s'\n", len, send_data);
			fflush(stdout);
			if (len > 0 && len < 1024) {
				gettimeofday(&curr, 0);
				numbytes = sendto(sock, send_data, strlen(send_data), 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
				//sleep(1);

				ret = poll(fds, nfds, time);

				if (ret || 0) {
					///*
					printf("poll: ret=%d, revents=%x\n", ret, fds[ret].revents);
					printf("POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x\n",
							(fds[ret].revents & POLLIN) > 0, (fds[ret].revents & POLLPRI) > 0, (fds[ret].revents & POLLOUT) > 0,
							(fds[ret].revents & POLLERR) > 0, (fds[ret].revents & POLLHUP) > 0, (fds[ret].revents & POLLNVAL) > 0,
							(fds[ret].revents & POLLRDNORM) > 0, (fds[ret].revents & POLLRDBAND) > 0, (fds[ret].revents & POLLWRNORM) > 0,
							(fds[ret].revents & POLLWRBAND) > 0);
					fflush(stdout);
					//*/

					int recv_bytes;
					if ((fds[ret].revents & (POLLERR)) || 0) {
						recv_bytes = recvmsg(sock, &recv_msg, MSG_ERRQUEUE);
						if (recv_bytes > 0) {
							printf("recv_bytes=%d, msg_controllen=%d\n", recv_bytes, recv_msg.msg_controllen);

							/* Receive auxiliary data in msgh */
							for (cmsg = CMSG_FIRSTHDR(&recv_msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&recv_msg, cmsg)) {
								printf("cmsg_len=%u, cmsg_level=%u, cmsg_type=%u\n", cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

								if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL) {
									received_ttl = *(int *) CMSG_DATA(cmsg);
									printf("received_ttl=%d\n", received_ttl);
									//break;
								} else if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
									struct sock_extended_err *err = (struct sock_extended_err *) CMSG_DATA(cmsg);
									printf("ee_errno=%u, ee_origin=%u, ee_type=%u, ee_code=%u, ee_pad=%u, ee_info=%u, ee_data=%u\n", err->ee_errno,
											err->ee_origin, err->ee_type, err->ee_code, err->ee_pad, err->ee_info, err->ee_data);

									struct sockaddr_in *offender = (struct sockaddr_in *) SO_EE_OFFENDER(err);
									printf("family=%u, addr=%s/%u\n", offender->sin_family, inet_ntoa(offender->sin_addr), ntohs(offender->sin_port));
								} else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP) {
									struct timeval *stamp = (struct timeval *) CMSG_DATA(cmsg);
									printf("stamp=%u.%u\n", (uint32_t) stamp->tv_sec, (uint32_t) stamp->tv_usec);
									printf("diff=%f\n", time_diff(&curr, stamp));
								}
							}
							if (cmsg == NULL) {
								/*
								 * Error: IP_TTL not enabled or small buffer
								 * or I/O error.
								 */
							}

						} else {
							printf("errno=%d\n", errno);
							perror("recvmsg");
						}
					} else if ((fds[ret].revents & (POLLIN | POLLRDNORM)) || 0) {
						recv_bytes = recvmsg(sock, &recv_msg, 0);
						if (recv_bytes > 0) {
							printf("recv_bytes=%d, msg_controllen=%d\n", recv_bytes, recv_msg.msg_controllen);

							/* Receive auxiliary data in msgh */
							for (cmsg = CMSG_FIRSTHDR(&recv_msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&recv_msg, cmsg)) {
								printf("cmsg_len=%u, cmsg_level=%u, cmsg_type=%u\n", cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

								if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL) {
									received_ttl = *(int *) CMSG_DATA(cmsg);
									printf("received_ttl=%d\n", received_ttl);
									//break;
								} else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP) {
									struct timeval *stamp = (struct timeval *) CMSG_DATA(cmsg);
								}
							}
							if (cmsg == NULL) {
								/*
								 * Error: IP_TTL not enabled or small buffer
								 * or I/O error.
								 */
							}

						}
					}
				}
			} else {
				printf("Error string len, len=%d\n", len);
			}
		}

		if (0) {
			if (pID == 0) {
				numbytes = sendto(sock, send_data, 1, 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
				printf("\n sent=%d", numbytes);
				numbytes = sendto(sock, send_data, 1, 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
				printf("\n sent=%d", numbytes);
			} else {
				//numbytes = recvfrom(sock, send_data, 1024, 0, (struct sockaddr *) &client_addr, &addr_len);
				printf("\n read=%d", numbytes);
			}
			fflush(stdout);
		}

		if ((strcmp(send_data, "q") == 0) || strcmp(send_data, "Q") == 0) {
			break;
		}
	}

	printf("\n Closing socket");
	fflush(stdout);
	close(sock);

	printf("\n FIN");
	fflush(stdout);
	while (1)
		;

	return 0;
}

