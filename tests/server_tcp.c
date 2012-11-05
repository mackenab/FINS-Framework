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

#define xxx(a,b,c,d) 	(16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d))

int i = 0;

int interface_setNonblocking(int fd) { //TODO move to common file?
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	return ioctl(fd, FIOBIO, &flags);
#endif
}

void termination_handler(int sig) {
	printf("\n**********Number of packers that have been received = %d *******\n", i);
	exit(2);
}

void *poll_thread(void *local) {
	/*
	 int nfds = 1;
	 struct pollfd fds[nfds];
	 fds[0].fd = sock;
	 fds[0].events = POLLIN | POLLPRI | POLLOUT | POLLRDNORM | POLLWRNORM;
	 int time = -1;

	 printf("\n POLLIN=%x POLLPRI=%x POLLOUT=%x POLLRDNORM=%x POLLWRNORM=%x", POLLIN, POLLPRI, POLLOUT, POLLRDNORM, POLLWRNORM);
	 fflush(stdout);

	 ret = poll(fds, nfds, time);
	 printf("\n poll: ret=%d, revents=%x", ret, fds[0].revents);
	 printf("\n POLLIN=%x POLLPRI=%x POLLOUT=%x POLLRDNORM=%x POLLWRNORM=%x", (fds[0].revents & POLLIN) > 0, (fds[0].revents & POLLPRI) > 0,
	 (fds[0].revents & POLLOUT) > 0, (fds[0].revents & POLLRDNORM) > 0, (fds[0].revents & POLLWRNORM) > 0);
	 fflush(stdout);
	 */
}

int main(int argc, char *argv[]) {

	printf(
			"EACCES=%d EACCES=%d EPERM=%d EADDRINUSE=%d EAFNOSUPPORT=%d EAGAIN=%d EALREADY=%d EBADF=%d ECONNREFUSED=%d EFAULT=%d EINPROGRESS=%d EINTR=%d EISCONN=%d ENETUNREACH=%d ENOTSOCK=%d ETIMEDOUT=%d\n",
			EACCES, EACCES, EPERM, EADDRINUSE, EAFNOSUPPORT, EAGAIN, EALREADY, EBADF, ECONNREFUSED, EFAULT, EINPROGRESS, EINTR, EISCONN, ENETUNREACH, ENOTSOCK,
			ETIMEDOUT);

	uint16_t port;

	(void) signal(SIGINT, termination_handler);
	int sock;
	int sock_client;
	int addr_len = sizeof(struct sockaddr);
	int bytes_read;
	int recv_buf_size = 4000;
	char recv_data[4000];
	int ret;
	pid_t pID = 0;

	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;

	if (argc > 1)

		port = atoi(argv[1]);
	else
		port = 44444;

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

	//client_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	if ((sock = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)) < 0) {
		//if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("Socket");
		printf("Failure");
		exit(1);
	}

	int optval = 1;
	//fcntl(sock, F_SETFL, O_RDWR | O_NONBLOCK);
	//setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	//setsockopt(sock, SOL_TCP, TCP_NODELAY, &optval, sizeof(optval));

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = PF_INET;

	//server_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//server_addr.sin_addr.s_addr = xxx(114,53,31,172);
	//server_addr.sin_addr.s_addr = xxx(192,168,1,11);
	//server_addr.sin_addr.s_addr = xxx(192,168,1,20);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);
	server_addr.sin_port = htons(port);

	//	server_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//          server_addr.sin_addr.s_addr = INADDR_LOOPBACK;

	//	server_addr.sin_addr.s_addr = xxx(172,31,54,87);
	//bzero(&(server_addr.sin_zero), 8); //TODO is for what?

	printf("Binding to server: pID=%d addr=%s:%d, netw=%u\n", pID, inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port), server_addr.sin_addr.s_addr);
	if (bind(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		perror("Bind");
		printf("Failure");
		exit(1);
	}

	//pID = fork();
	if (pID == 0) { // child -- Capture process
	} else if (pID < 0) { // failed to fork
		printf("Failed to Fork \n");
		fflush(stdout);
		exit(1);
	} else { // parent
	}

	int backlog = (pID ? 1 : 0) + 10;

	printf("Listening to server: pID=%d backlog=%d\n", pID, backlog);
	if (listen(sock, backlog) < 0) {
		perror("Listen");
		printf("Failure");
		exit(1);
	}

	//addr_len = sizeof(struct sockaddr);

	//gets(recv_data);

	printf("\n TCP Server waiting for client: pID=%d port %d", pID, ntohs(server_addr.sin_port));
	fflush(stdout);

	while (1) {
		sock_client = accept(sock, (struct sockaddr *) &client_addr, &addr_len);
		if (sock_client > 0) {
			break;
		} else {
			printf("\n failed accept: errno=%d errno='%s'", errno, strerror(errno));
			fflush(stdout);
			//sleep(1);
		}
	}
	//*/

	printf("\n Connection establisehed pID=%d sock_client=%d to (%s/%d) netw=%u", pID, sock_client, inet_ntoa(client_addr.sin_addr),
			ntohs(client_addr.sin_port), client_addr.sin_addr.s_addr);
	fflush(stdout);

	//interface_setNonblocking(sock_client);

	int nfds = 2;
	struct pollfd fds[nfds];
	fds[0].fd = -1;
	fds[0].events = POLLIN | POLLPRI | POLLRDNORM;
	fds[1].fd = sock_client;
	fds[1].events = POLLIN | POLLPRI | POLLRDNORM;
	//fds[1].events = POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;
	printf("\n fd: sock=%d, events=%x", sock, fds[1].events);
	int time = 1000;

	///*
	printf("\n POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x ", POLLIN, POLLPRI,
			POLLOUT, POLLERR, POLLHUP, POLLNVAL, POLLRDNORM, POLLRDBAND, POLLWRNORM, POLLWRBAND);
	fflush(stdout);
	//*/

	//pID = fork();
	if (pID == 0) { // child -- Capture process
		printf("\n child pID=%d", pID);
		fflush(stdout);
	} else if (pID < 0) { // failed to fork
		printf("Failed to Fork \n");
		fflush(stdout);
		exit(1);
	} else { //parent
		printf("\n parent pID=%d", pID);
		fflush(stdout);
	}

	//while (1);

	i = 0;
	while (i < 10000) {
		//ret = poll(fds, nfds, time);
		if (ret || 1) {
			/*
			 printf("\n poll: ret=%d, revents=%x", ret, fds[ret].revents);
			 printf("\n POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x ",
			 (fds[ret].revents & POLLIN) > 0, (fds[ret].revents & POLLPRI) > 0, (fds[ret].revents & POLLOUT) > 0, (fds[ret].revents & POLLERR) > 0,
			 (fds[ret].revents & POLLHUP) > 0, (fds[ret].revents & POLLNVAL) > 0, (fds[ret].revents & POLLRDNORM) > 0,
			 (fds[ret].revents & POLLRDBAND) > 0, (fds[ret].revents & POLLWRNORM) > 0, (fds[ret].revents & POLLWRBAND) > 0);
			 fflush(stdout);
			 //*/
			if ((fds[ret].revents & (POLLIN | POLLRDNORM)) || 1) {
				if (pID || 1) {
					bytes_read = recv(sock_client, recv_data, recv_buf_size, 0);
				} else {
					sleep(2);
					bytes_read = recv(sock_client, recv_data, recv_buf_size, MSG_DONTWAIT);
				}
				//bytes_read = recvfrom(sock,recv_data,1024,0,NULL, NULL);
				//bytes_read = recv(sock,recv_data,1024,0);
				if (bytes_read > 0) {
					recv_data[bytes_read] = '\0';
					//printf("\n(%s:%d) said : ", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
					//printf("(%d , %d) said : ",(client_addr->sin_addr).s_addr,ntohs(client_addr->sin_port));
					printf("\n frame=%d, pID=%d, client_port=%u: said='%s'\n", ++i, pID, ntohs(client_addr.sin_port), recv_data);
					fflush(stdout);

					if ((strcmp(recv_data, "q") == 0) || strcmp(recv_data, "Q") == 0) {
						break;
					}
				} else /*if (errno != EWOULDBLOCK && errno != EAGAIN)*/{
					printf("\n Error recv at the Server: pID=%d ret=%d errno='%s' (%d)\n", pID, bytes_read, strerror(errno), errno);
					perror("Error:");
					fflush(stdout);
					if (errno != EWOULDBLOCK && errno != EAGAIN)
						break;
				}
			}
		}
		//break;
	}

	printf("After\n");

	while (1)
		;

	printf("\n Closing client socket");
	fflush(stdout);
	close(sock_client);

	printf("\n Closing server socket");
	fflush(stdout);
	close(sock);

	printf("\n FIN");
	fflush(stdout);

	while (1)
		;

	return 0;
}

