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
//#include <netinet/in.h>
//#include <netinet/ip.h>
#include <linux/errqueue.h>

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

struct icmp_packet {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t param_1;
	uint16_t param_2;
	uint8_t data[1];
};

uint16_t icmp_checksum(uint8_t *pt, uint32_t len) {
	//PRINT_DEBUG("Entered: pt=%p, len=%u", pt, len);
	uint32_t sum = 0;
	uint32_t i;

	for (i = 1; i < len; i += 2, pt += 2) {
		//PRINT_DEBUG("%u=%2x (%u), %u=%2x (%u)", i-1, *(pt), *(pt), i, *(pt+1), *(pt+1));
		sum += (*pt << 8) + *(pt + 1);
	}
	if (len & 0x1) {
		//PRINT_DEBUG("%u=%2x (%u), uneven", len-1, *(pt), *(pt));
		sum += *pt << 8;
	}

	while ((sum >> 16)) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	sum = ~sum;

	//hdr->checksum = htons((uint16_t) sum);

	//PRINT_DEBUG("checksum=%x", (uint16_t) sum);
	return (uint16_t) sum;
}

int main(int argc, char *argv[]) {
	int sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	//int addr_len = sizeof(struct sockaddr);
	int numbytes;
	//struct hostent *host;
	char send_data[1024];
	char msg[1032];
	int port;
	int client_port;
	pid_t pID = 0;

	struct icmp_packet *pkt = (struct icmp_packet *) msg;
	pkt->type = 8;
	pkt->code = 0;
	pkt->param_1 = 0;
	pkt->param_2 = 0;

	//\x08\x00\x5d\x74\x25\x05\x00\x01\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f

	memset(send_data, 89, 1000);
	send_data[1000] = '\0';

	//host= (struct hostent *) gethostbyname((char *)"127.0.0.1");

	//if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) {
	//if ((sock = socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1) {
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
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

	val = 10;
	setsockopt(sock, SOL_IP, IP_TTL, &val, sizeof(val));

	if (argc > 1) {
		port = atoi(argv[1]);
	} else {
		port = 45454;
	}

	printf("MY DEST PORT BEFORE AND AFTER\n");
	printf("%d, %d\n", port, htons(port));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = 0; //htons(port);

	server_addr.sin_addr.s_addr = xxx(192,168,1,15);
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
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = 0; //htons(client_port);

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

	printf("Connecting to server: pID=%d addr=%s:%d, netw=%u\n", pID, inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port), server_addr.sin_addr.s_addr);

	if (connect(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) < 0) {
		perror("Connect");
		printf("Failure");
		exit(1);
	}

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

	int i = 0;
	int j = 0;
	while (i < 100) {
		i++;
		if (1) {
			printf("(%d) Input msg (q or Q to quit):", i);
			gets(send_data);

			len = strlen(send_data);
			printf("\nlen=%d, str='%s'\n", len, send_data);
			fflush(stdout);

			if (len > 0 && len < 1024) {
				memcpy(pkt->data, send_data, len);

				pkt->checksum = 0;
				pkt->param_1 = htons(i);
				pkt->param_2 = htons(j++);

				pkt->checksum = htons(icmp_checksum((uint8_t *)msg, len + 8));

				//numbytes = sendto(sock, msg, len + 8, 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
				numbytes = send(sock, msg, len + 8, 0);
				continue;
				int ret = 0;
				ret = poll(fds, nfds, time);

				if (0) {
					struct msghdr recv_msg;
					struct iovec iov[1];
					int recv_len = 1000;
					char recv_buf[recv_len];
					int control_len = 4000;
					char control_buf[control_len];
					iov[0].iov_len = recv_len;
					iov[0].iov_base = recv_buf;

					recv_msg.msg_iovlen = 1;
					recv_msg.msg_iov = iov;

					recv_msg.msg_controllen = control_len;
					recv_msg.msg_control = control_buf;

					int recv_bytes;
					recv_bytes = recvmsg(sock, &recv_msg, 0 & MSG_ERRQUEUE);

					printf("recv_bytes=%d", recv_bytes);
					if (recv_bytes < 0) {
						printf("errno=%d\n", errno);
						perror("recvmsg");
					}
				} else

				if (ret || 0) {
					///*
					printf("poll: ret=%d, revents=%x\n", ret, fds[ret].revents);
					printf("POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x\n",
							(fds[ret].revents & POLLIN) > 0, (fds[ret].revents & POLLPRI) > 0, (fds[ret].revents & POLLOUT) > 0, (fds[ret].revents & POLLERR)
									> 0, (fds[ret].revents & POLLHUP) > 0, (fds[ret].revents & POLLNVAL) > 0, (fds[ret].revents & POLLRDNORM) > 0,
							(fds[ret].revents & POLLRDBAND) > 0, (fds[ret].revents & POLLWRNORM) > 0, (fds[ret].revents & POLLWRBAND) > 0);
					fflush(stdout);
					//*/
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

					int recv_bytes;
					if ((fds[ret].revents & (POLLERR)) || 0) {
						recv_bytes = recvmsg(sock, &recv_msg, MSG_ERRQUEUE);
						if (recv_bytes > 0) {
							printf("recv_bytes=%d, msg_controllen=%d\n", recv_bytes, recv_msg.msg_controllen);

							struct cmsghdr *cmsg;
							//int *ttlptr;
							int received_ttl;

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

							struct cmsghdr *cmsg;
							//int *ttlptr;
							int received_ttl;

							/* Receive auxiliary data in msgh */
							for (cmsg = CMSG_FIRSTHDR(&recv_msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&recv_msg, cmsg)) {
								printf("cmsg_len=%u, cmsg_level=%u, cmsg_type=%u\n", cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

								if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL) {
									received_ttl = *(int *) CMSG_DATA(cmsg);
									printf("received_ttl=%d\n", received_ttl);
									//break;
								} else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP) {
									struct timeval *stamp = (struct timeval *) CMSG_DATA(cmsg);
									printf("stamp=%u.%u\n", (uint32_t) stamp->tv_sec, (uint32_t) stamp->tv_usec);
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
