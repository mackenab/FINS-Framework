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

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		perror("Socket");
		printf("Failure");
		exit(1);
	}

	if (argc > 1)
		port = atoi(argv[1]);
	else
		port = 5000;

	printf("MY DEST PORT BEFORE AND AFTER\n");
	printf("%d, %d\n", port, htons(port));
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	//server_addr.sin_addr.s_addr = xxx(128,173,92,37);
	server_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//server_addr.sin_addr.s_addr = xxx(114,53,31,172);
	server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	//bzero(&(server_addr.sin_zero), 8);

	//if (argc > 2) {
	//client_port = atoi(argv[2]);
	client_port = 5050;

	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(client_port);
	//client_addr.sin_addr.s_addr = xxx(128,173,92,37);
	client_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//client_addr.sin_addr.s_addr = xxx(114,53,31,172);
	client_addr.sin_addr.s_addr = htonl(client_addr.sin_addr.s_addr);
	//client_addr.sin_addr.s_addr = INADDR_ANY;

	//client_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	//bzero(&(client_addr.sin_zero), 8); //TODO what's this for?

	if (bind(sock, (struct sockaddr *) &client_addr, sizeof(struct sockaddr)) == -1) {
		perror("Bind");
		printf("Failure");
		exit(1);
	}
	//}

	if (connect(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) < 0) {
		perror("Connect");
		printf("Failure");
		exit(1);
	}

	printf("\n Connection establisehed sock=%d to (%s/%d) netw=%u", sock, inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port),
			server_addr.sin_addr.s_addr);

	int i = 0;
	while (1) {
		printf("(%d) Input msg (q or Q to quit):", i++);
		gets(send_data);
		printf("%s", send_data);
		sleep(1);
		numbytes = send(sock, send_data, strlen(send_data), 0);
		//numbytes = sendto(sock, send_data, strlen(send_data), 0, (struct sockaddr *) &server_addr, sizeof(struct sockaddr));
		printf("\n %d", numbytes);
		fflush(stdout);

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
}

