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

#define xxx(a,b,c,d) 	(16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d))

/*

 int xxx(char a,char b,char c,char d)
 {

 return ((16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d)));

 }


 */

int main(int argc, char *argv[]) {
	int sock;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	int numbytes;
	struct hostent *host;
	char send_data[1024];
	int port;
	int client_port;
	pid_t pID = 0;

	memset(send_data, 89, 1000);
	send_data[1000] = '\0';

	//host= (struct hostent *) gethostbyname((char *)"127.0.0.1");

	//if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		perror("Socket");
		printf("Failure");
		exit(1);
	}

	if (argc > 1) {
		port = atoi(argv[1]);
	} else {
		port = 44444;
	}

	int optval = 1;
	//setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	printf("MY DEST PORT BEFORE AND AFTER\n");
	printf("%d, %d\n", port, htons(port));
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	//server_addr.sin_addr.s_addr = xxx(128,173,92,37);
	//server_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//server_addr.sin_addr.s_addr = xxx(114,53,31,172);
	server_addr.sin_addr.s_addr = xxx(192,168,1,5);
	//server_addr.sin_addr.s_addr = INADDR_ANY;
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);
	//bzero(&(server_addr.sin_zero), 8);

	if (argc > 2) {
		client_port = atoi(argv[2]);
	} else {
		client_port = 55555;
	}

	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(client_port);
	//client_addr.sin_addr.s_addr = xxx(128,173,92,37);
	//client_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//client_addr.sin_addr.s_addr = xxx(114,53,31,172);
	//client_addr.sin_addr.s_addr = xxx(192,168,1,20);
	client_addr.sin_addr.s_addr = INADDR_ANY;
	//client_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	client_addr.sin_addr.s_addr = htonl(client_addr.sin_addr.s_addr);

	//client_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	//bzero(&(client_addr.sin_zero), 8); //TODO what's this for?

	/*
	 printf("Binding to client_addr=%s:%d, netw=%u\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_addr.sin_addr.s_addr);
	 if (bind(sock, (struct sockaddr *) &client_addr, sizeof(struct sockaddr)) == -1) {
	 perror("Bind");
	 printf("Failure");
	 exit(1);
	 }
	 //*/

	printf(
			"EACCES=%d EPERM=%d EADDRINUSE=%d EAFNOSUPPORT=%d EAGAIN=%d EALREADY=%d EBADF=%d ECONNREFUSED=%d EFAULT=%d EINPROGRESS=%d EINTR=%d EISCONN=%d ENETUNREACH=%d ENOTSOCK=%d ETIMEDOUT=%d\n",
			EACCES, EPERM, EADDRINUSE, EAFNOSUPPORT, EAGAIN, EALREADY, EBADF, ECONNREFUSED, EFAULT, EINPROGRESS, EINTR, EISCONN, ENETUNREACH, ENOTSOCK,
			ETIMEDOUT);

	//pID = fork();
	if (pID == 0) { // child -- Capture process
		//server_addr.sin_port = htons(port + j - 1);
		printf("\n child pID=%d", pID);
		fflush(stdout);
	} else if (pID < 0) { // failed to fork
		printf("Failed to Fork \n");
		fflush(stdout);
		exit(1);
	} else { //parent
		server_addr.sin_port = htons(port + 1);
		printf("\n parent pID=%d", pID);
		fflush(stdout);
	}

	printf("\n Connecting to server: pID=%d addr=%s:%d, netw=%u", pID, inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port),
			server_addr.sin_addr.s_addr);
	while (1) {
		if (connect(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) < 0) {
			printf("\n failed connect: pID=%d errno=%d errno='%s'", pID, errno, strerror(errno));
			if (errno == EINPROGRESS || errno == EALREADY) {
			} else if (errno == EISCONN) {
				break;
			} else {
				//exit(1);
				sleep(5);
			}
			sleep(1);
			//exit(1);
		} else {
			break;
		}
	}

	printf("\n Connection establisehed pID=%d sock=%d to (%s/%d) netw=%u", pID, sock, inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port),
			server_addr.sin_addr.s_addr);
	fflush(stdout);

	//return;

	//while (1);

	int nfds = 2;
	struct pollfd fds[nfds];
	fds[0].fd = -1;
	fds[0].events = POLLIN | POLLRDNORM; //| POLLPRI;
	fds[1].fd = sock;
	fds[1].events = POLLOUT | POLLWRNORM;
	//fds[1].events = POLLIN | POLLPRI | POLLOUT | POLLERR | POLLHUP | POLLNVAL | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;
	printf("\n fd: sock=%d, events=%x", sock, fds[1].events);
	int time = 1000;

	int ret;
	int i = 0;
	while (i < 10000) {
		printf("(%d) Input msg (q or Q to quit):", i++);
		gets(send_data);

		ret = poll(fds, nfds, time);
		if (ret || 0) {
			///*
			printf("\n poll: ret=%d, revents=%x", ret, fds[ret].revents);
			printf("\n POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x ",
					(fds[ret].revents & POLLIN) > 0, (fds[ret].revents & POLLPRI) > 0, (fds[ret].revents & POLLOUT) > 0, (fds[ret].revents & POLLERR) > 0,
					(fds[ret].revents & POLLHUP) > 0, (fds[ret].revents & POLLNVAL) > 0, (fds[ret].revents & POLLRDNORM) > 0,
					(fds[ret].revents & POLLRDBAND) > 0, (fds[ret].revents & POLLWRNORM) > 0, (fds[ret].revents & POLLWRBAND) > 0);
			fflush(stdout);
			//*/
			if ((fds[ret].revents & (POLLIN | POLLRDNORM)) || 0) {
			} else if ((fds[ret].revents & (POLLOUT | POLLWRNORM)) || 0) {
				printf("%s", send_data);
				numbytes = send(sock, send_data, strlen(send_data), 0);
			}
		}

		if (0) {
			printf("(%d) Input msg (q or Q to quit):", i++);
			gets(send_data);
			printf("%s", send_data);
			numbytes = send(sock, send_data, strlen(send_data), 0);
		} else {
			//sleep(1);
			//numbytes = send(sock, send_data, 1, 0);
		}
		if (numbytes > 0) {
			//numbytes = sendto(sock, send_data, strlen(send_data), 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr));
			printf("\n %d", numbytes);
			fflush(stdout);

			if ((strcmp(send_data, "q") == 0) || strcmp(send_data, "Q") == 0) {
				break;
			}
		} else {
			printf("\n failed send: errno=%d errno='%s'", errno, strerror(errno));
		}
	}

	printf("\n Closing socket");
	fflush(stdout);
	close(sock);

	printf("\n FIN");
	fflush(stdout);
	while (1)
		;
}

