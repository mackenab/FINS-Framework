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
	int level;
	int optname;
	int optval;
	int optlen;
	int ret;

	struct sockaddr_in server_addr;
	struct sockaddr_in *client_addr;

	int max_processes;

	if (argc > 1) {
		port = atoi(argv[1]);

		if (argc > 2) {
			max_processes = atoi(argv[2]);
		} else {
			max_processes = 1;
		}
	} else {
		port = 5000;
	}

	client_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("Socket");
		exit(1);
	}

	server_addr.sin_family = PF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = INADDR_ANY;

	level = IPPROTO_IP; //SOL_SOCKET;
	optname = SO_REUSEADDR;
	printf("Sockopt: level=%d optname=%d\n", level, optname);

	optval = -1;
	optlen = -1;
	ret = getsockopt(sock, level, optname, &optval, (socklen_t *) &optlen);
	if (ret) {
		printf("Sockopt fail ret=%d\n", ret);
	} else {
		printf("Sockopt: get optval=%d optlen=%d\n", optval, optlen);
	}

	optval = 1;
	optlen = sizeof(int);
	ret = setsockopt(sock, level, optname, &optval, optlen);
	if (ret) {
		printf("Sockopt fail ret=%d\n", ret);
	} else {
		printf("Sockopt: set optval=%d optlen=%d\n", optval, optlen);
	}

	optval = -1;
	optlen = -1;
	ret = getsockopt(sock, level, optname, &optval, (socklen_t *) &optlen);
	if (ret) {
		printf("Sockopt fail ret=%d\n", ret);
	} else {
		printf("Sockopt: get optval=%d optlen=%d\n", optval, optlen);
	}

	//	server_addr.sin_addr.s_addr = xxx(127,0,0,1);
	//          server_addr.sin_addr.s_addr = INADDR_LOOPBACK;

	//	server_addr.sin_addr.s_addr = xxx(172,31,54,87);
	bzero(&(server_addr.sin_zero), 8);

	if (bind(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) == -1) {
		perror("Bind");
		printf("Failure");
		exit(1);
	}

	addr_len = sizeof(struct sockaddr);

	pid_t pID = 0;
	int processes;

	for (processes = 1; processes <= max_processes - 1; processes++) {
		pID = fork();
		if (pID == 0) { // child
			break;
		} else if (pID < 0) { // failed to fork
			//stderr << "Failed to fork" << endl;
			exit(1);
		} else { //parent
		}
	}

	if (pID == 0) {
		processes = 0;
	}
	int pID_p = getpid();

	printf("UDPServer (%d: %d/%d) Waiting for client on port %d\n ", processes, pID, pID_p, ntohs(server_addr.sin_port));
	fflush(stdout);

	i = 0;

	while (1) {
		bytes_read = recvfrom(sock, recv_data, 4000, 0, (struct sockaddr *) client_addr, (socklen_t *) &addr_len);
		//      bytes_read = recvfrom(sock,recv_data,1024,0,NULL, NULL);
		//	bytes_read = recv(sock,recv_data,1024,0);
		i = i + 1;
		recv_data[bytes_read] = '\0';
		printf("(%d) frame number\n", i);
		printf("(%d/%d, %s:%d) : ", pID, pID_p, inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
		//printf("(%d , %d) : ", (client_addr->sin_addr).s_addr, ntohs(client_addr->sin_port));
		//printf("(%d , %d) : ", processes, pID);
		printf(" (%s) to the Server\n", recv_data);

		fflush(stdout);

		//if (pID != 0) {
		printf("closing(%d/%d)\n", pID, pID_p);
		close(sock);
		printf("waiting...\n");
		while (1)
			;
		break;

		//}
	}

	printf("Program end (%d/%d).\n", pID, pID_p);

	return 0;
}
