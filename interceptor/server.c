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

#define xxx(a,b,c,d) 	(16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d))

int i = 0;

void termination_handler(int sig) {
	printf("\n**********Number of packers that have been received = %d *******\n", i);
	exit(2);
}

int main(int argc, char *argv[]) {

	uint16_t port;

	(void) signal(SIGINT, termination_handler);
	int sock;
	int addr_len = sizeof(struct sockaddr);
	int bytes_read;
	char recv_data[4000];

	struct sockaddr_in server_addr;
	struct sockaddr_in *client_addr;

	if (argc > 1)

		port = atoi(argv[1]);
	else
		port = 5000;

	client_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("Socket");
		exit(1);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	//server_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//server_addr.sin_addr.s_addr = xxx(114,53,31,172);
	//server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;

	//	server_addr.sin_addr.s_addr = xxx(172,31,54,87);
	bzero(&(server_addr.sin_zero), 8);

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

	while (1) {

		bytes_read = recvfrom(sock, recv_data, 4000, 0, (struct sockaddr *) client_addr, &addr_len);
		//      bytes_read = recvfrom(sock,recv_data,1024,0,NULL, NULL);
		//	bytes_read = recv(sock,recv_data,1024,0);
		i = i + 1;
		printf("\n (%d) frame number", i);
		if (bytes_read > 0) {
			recv_data[bytes_read] = '\0';
			printf("\n(%s:%d, n=%u) said : ", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), client_addr->sin_addr.s_addr);
			//printf("(%d , %d) said : ",(client_addr->sin_addr).s_addr,ntohs(client_addr->sin_port));
			printf(" (%s) to the Server\n", recv_data);
		} else {
			printf("\n Error recv at the Server\n", recv_data);
		}
		fflush(stdout);

	}
	return 0;
}

