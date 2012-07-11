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

	memset(send_data, 89, 1000);
	send_data[1000] = '\0';

	//host= (struct hostent *) gethostbyname((char *)"127.0.0.1");
	printf("SOCK_NONBLOCK=%d SOCK_STREAM=%d SOCK_DGRAM=%d SOCK_RAW=%d \n", SOCK_NONBLOCK, SOCK_STREAM, SOCK_DGRAM, SOCK_RAW);

	//if ((sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1) {
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	if (argc > 1)

		port = atoi(argv[1]);
	else
		port = 44444;

	printf("MY DEST PORT BEFORE AND AFTER\n");
	printf("%d, %d\n", port, htons(port));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	server_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//server_addr.sin_addr.s_addr = xxx(128,173,92,37);
	//server_addr.sin_addr.s_addr = xxx(192,168,1,11);
	//server_addr.sin_addr.s_addr = xxx(192,168,1,20);
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
	client_addr.sin_port = htons(client_port);

	client_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//client_addr.sin_addr.s_addr = xxx(128,173,92,37);
	//client_addr.sin_addr.s_addr = xxx(192,168,1,20); //TODO remove after loopback/INADDR_ANY caught
	//client_addr.sin_addr.s_addr = INADDR_ANY;
	//client_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	client_addr.sin_addr.s_addr = htonl(client_addr.sin_addr.s_addr);
	bzero(&(client_addr.sin_zero), 8);
	///*
	if (bind(sock, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in)) == -1) {
		perror("Bind");
		printf("Failure");
		exit(1);
	} //*/

	printf("Bound to client_addr=%s:%d, netw=%u\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_addr.sin_addr.s_addr);

	int i = 0;
	while (1) {

		printf("Type Something (q or Q to quit):");
		gets(send_data);
		printf("%s", send_data);
		i = i + 1;
		sleep(1);
		if ((strcmp(send_data, "q") == 0) || strcmp(send_data, "Q") == 0)
			break;

		else {
			//	if (i % 100 ==0 )
			numbytes = sendto(sock, send_data, strlen(send_data), 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
			printf("\n %d", numbytes);
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

