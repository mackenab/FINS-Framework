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

#define xxx(a,b,c,d) 	(16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d))

int i = 0;

void termination_handler(int sig) {
	printf("\n**********Number of packers that have been received = %d *******\n", i);
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
	char recv_data[4000];
	int ret;
	pid_t pID = 0;

	struct sockaddr_in server_addr;
	struct sockaddr_in *client_addr;

	if (argc > 1)

		port = atoi(argv[1]);
	else
		port = 45454;

	client_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	//if ((sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1) {
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("Socket");
		exit(1);
	}

	printf("Provided with sock=%d\n", sock);

	server_addr.sin_family = AF_INET;
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
	int time = -1;

	printf("\n POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x ", POLLIN, POLLPRI,
			POLLOUT, POLLERR, POLLHUP, POLLNVAL, POLLRDNORM, POLLRDBAND, POLLWRNORM, POLLWRBAND);
	fflush(stdout);

	struct timeval tv;

	tv.tv_sec = 0; /* 30 Secs Timeout */
	tv.tv_usec = 0; // Not init'ing this can cause strange errors

	//ret = getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof(struct timeval));
	//printf("\n ret=%d tv.tv_sec=%d tv.tv_usec=%d", ret, tv.tv_sec, tv.tv_usec);
	fflush(stdout);

	int j = 0;
	while (++j <= 10) {
		//pID = fork();
		if (pID == 0) { // child -- Capture process
			continue;
		} else if (pID < 0) { // failed to fork
			printf("Failed to Fork \n");
			fflush(stdout);
			exit(1);
		} else { // parent
			port += j - 1;
			break;
		}
	}

	if (pID == 0) {
		//while (1);
	}

	while (1) {
		//ret = poll(fds, nfds, time);
		if (ret || 1) {
			/*
			 printf("\n poll: ret=%d, revents=%x", ret, fds[0].revents);
			 printf("\n POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x ",
			 (fds[0].revents & POLLIN) > 0, (fds[0].revents & POLLPRI) > 0, (fds[0].revents & POLLOUT) > 0, (fds[0].revents & POLLERR) > 0,
			 (fds[0].revents & POLLHUP) > 0, (fds[0].revents & POLLNVAL) > 0, (fds[0].revents & POLLRDNORM) > 0, (fds[0].revents & POLLRDBAND) > 0,
			 (fds[0].revents & POLLWRNORM) > 0, (fds[0].revents & POLLWRBAND) > 0);
			 fflush(stdout);
			 */
			if ((fds[0].revents & (POLLIN | POLLRDNORM)) || 1) {
				bytes_read = recvfrom(sock, recv_data, 4000, 0, (struct sockaddr *) client_addr, &addr_len);
				//bytes_read = recvfrom(sock,recv_data,1024,0,NULL, NULL);
				//bytes_read = recv(sock,recv_data,1024,0);
				if (bytes_read > 0) {
					recv_data[bytes_read] = '\0';
					printf("\n frame=%d, pID=%d, client=%s:%u: said='%s'\n", ++i, pID, inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port),
							recv_data);
					fflush(stdout);

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

