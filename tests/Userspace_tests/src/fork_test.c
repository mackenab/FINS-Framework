#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <wait.h>
#include <unistd.h>

#define AF_FINS	AF_IPX
#define PF_FINS	AF_FINS

#define READ_END	0
#define WRITE_END	1

int main(){
	if(SOCK_MODE == SOCK_DGRAM){
		printf("Testing SOCK_DGRAM mode\n");
		fflush(stdout);
	}else if(SOCK_MODE == SOCK_RAW){
		printf("Testing SOCK_RAW mode\n");
		fflush(stdout);
	}else if(SOCK_MODE == SOCK_STREAM){
		printf("Testing SOCK_STREAM mode\n");
		fflush(stdout);
	}

	// Calling socket:  Maps to FINS_create_socket
	int sockfd;
	sockfd = socket(AF_FINS, SOCK_MODE, PF_FINS);
	if(sockfd != -1){
		printf("The socket file descriptor returned was: %d\n", sockfd);
		fflush(stdout);
	}else{
		perror("The socket() call returned with an error ");
	}

	int pfds[2];	// Holds the file descriptors for the pipe
	if(pipe(pfds) == -1){
		perror("pipe ");
	}
		
	pid_t pid;
	int status;

	if((pid = fork()) < 0){
		perror("The call to fork() caused an error ");
	}else if(pid == 0){	/* child */
		printf("CHILD: initial socket id: %d\n", sockfd);
		fflush(stdout);

		// Child: Call listen on original socket
		if(listen(sockfd, 5)){
			perror("CHILD: The listen() call returned with an error ");
		}else{
			printf("CHILD: listen succeeded\n");
		}

//		// Child: Calling shutdown (This doesn't close the socket)
//		if(shutdown(sockfd, SHUT_RDWR)){
//			perror("CHILD: The shutdown() call returned with an error ");
//		}else{
//			printf("CHILD: shutdown succeeded\n");
//		}

		// Child: Call close (closes file descriptor for this process)
		if(close(sockfd)){
			perror("CHILD: The close() call returned with an error ");
		}else{
			printf("CHILD: close succeeded\n");
		}

		// Send a character on pipe to release Parent's spinlock
		char cbuf[10];
		cbuf[0] = 'a';
		if(write(pfds[WRITE_END], &cbuf, 1) != 1){
			fprintf(stderr, "CHILD: write to pipe failed\n");
			fflush(stderr);
		}
		
//		// Child: Call listen on original socket (After close, this returns an error, as expected)
//		if(listen(sockfd, 5)){
//			perror("CHILD: The listen() call returned with an error ");
//		}else{
//			printf("CHILD: listen succeeded\n");
//		}

		// Child: Create a second socket
		int childsockfd = socket(AF_FINS, SOCK_MODE, PF_FINS);
		printf("CHILD: secondary socket id: %d\n", childsockfd);
		fflush(stdout);		

		// Child: Call listen on new socket
		if(listen(childsockfd, 5)){
			perror("CHILD: The listen() call returned with an error ");
		}else{
			printf("CHILD: listen succeeded\n");
		}

		exit(0);

	}else{	/* parent */
		printf("PARENT: intial socket id: %d\n", sockfd);
		fflush(stdout);

		// Parent: Call listen on original socket
		if(listen(sockfd, 5)){
			perror("PARENT: The listen() call returned with an error ");
		}else{
			printf("PARENT: listen succeeded\n");
		}

		// Block until child is ready to let parent continue
		char pbuf[10];
		while(read(pfds[READ_END], &pbuf, 1) == 0){} //Spinlock to sync
		printf("PARENT: Passed spinlock\n");

		// Parent: Call listen on original socket
		if(listen(sockfd, 5)){
			perror("PARENT: The listen() call returned with an error ");
		}else{
			printf("PARENT: listen succeeded\n");
		}

		// Parent: Create another socket
		int parentsockfd = socket(AF_FINS, SOCK_MODE, PF_FINS);
		printf("PARENT: secondary socket id: %d\n", parentsockfd);
		fflush(stdout);

		
		// Parent: Call listen on new socket 
		if(listen(parentsockfd, 5)){
			perror("PARENT: The listen() call returned with an error ");
		}else{
			printf("PARENT: listen succeeded\n");
		}


		if((pid = waitpid(pid, &status, 0)) < 0){
			perror("waitpid() caused an error ");
		}
		printf("Child pid %d terminated.\n", pid);
		exit(0);
	}

/////////////////////////////////////////////////////////////////////////////////////
//  NOTHING BELOW HERE GETS EXECUTED
/////////////////////////////////////////////////////////////////////////////////////

	// Calling bind:	
	if(bind(sockfd, NULL, 0)){
		perror("The bind() call returned with an error ");
	}else{
		printf("bind succeeded\n");
	}

	// Calling connect:
	if(connect(sockfd, NULL, 0)){
		perror("The connect() call returned with an error ");
	}else{
		printf("connect succeeded\n");
	}

	// 	This works, but commented it out so that we can continue testing other stuff
	//	// Calling close:
	//	if(close(sockfd)){
	//		perror("The close() call returned with an error ");
	//	}else{
	//		printf("close succeeded\n");
	//	}

	// Calling listen:
	if(listen(sockfd, 5)){
		perror("The listen() call returned with an error ");
	}else{
		printf("listen succeeded\n");
	}

	// Calling accept:
	int acceptfd;
	acceptfd = accept(sockfd, NULL, 0);
	if(acceptfd != -1){
		printf("The accepted socket file descriptor returned was: %d\n", acceptfd);
		fflush(stdout);
	}else{
		perror("The accept() call returned with an error ");
	}

	// Calling socketpair:
	int socket_pair[2];
	if(socketpair(AF_FINS, SOCK_MODE, 0, socket_pair)){
		perror("The socketpair() call returned with an error ");
	}else{
		printf("socketpair succeeded\n");
	}

	// Calling send:  Maps to FINS_send_msg
	ssize_t num_sent;
	num_sent = send(sockfd, NULL, 0, 0);
	if(num_sent != -1){
		printf("The number of characters sent (send) was: %d\n", num_sent);
	}else{
		perror("The send() call returned with an error ");
	}	

	// Calling sendto:  Maps to FINS_send_msg
	num_sent = sendto(sockfd, NULL, 0, 0, NULL, 0);
	if(num_sent != -1){
		printf("The number of characters sent (sendto) was: %d\n", num_sent);
	}else{
		perror("The sendto() call returned with an error ");
	}

	// Calling sendmsg:  Maps to FINS_send_msg
	num_sent = sendmsg(sockfd, NULL, 0);
	if(num_sent != -1){
		printf("The number of characters sent (sendmsg) was: %d\n", num_sent);
	}else{
		perror("The sendmsg() call returned with an error ");
	}

	// Calling recv:  Maps to FINS_recv_msg
	ssize_t num_received;
	num_received = recv(sockfd, NULL, 0, 0);
	if(num_received != -1){
		printf("The number of characters received (recv) was: %d\n", num_received);
	}else{
		perror("The recv() call returned with an error ");
	}

	// Calling recvfrom:  Maps to FINS_recv_msg
	num_received = recvfrom(sockfd, NULL, 0, 0, NULL, 0);
	if(num_received != -1){
		printf("The number of characters received (recvfrom) was: %d\n", num_received);
	}else{
		perror("The recvfrom() call returned with an error ");
	}

	// Calling recvmsg:  Maps to FINS_recv_msg
	num_received = recvmsg(sockfd, NULL, 0);
	if(num_received != -1){
		printf("The number of characters received (recvmsg) was: %d\n", num_received);
	}else{
		perror("The recvmsg() call returned with an error ");
	}


	// Calling write:  Maps to FINS_send_msg
	ssize_t num_written;
	num_written = write(sockfd, NULL, 0);
	if(num_written != -1){
		printf("The number of characters written was: %d\n", num_written);
	}else{
		perror("The write() call returned an error ");
	}

	// Calling read:  Maps to FINS_recv_msg
	ssize_t num_read;
	char buf[5];
	num_read = read(sockfd, &buf, 3);
	if(num_read != -1){
		printf("The number of characters read was: %d\n", num_read);
	}else{
		perror("The read() call returned with an error ");
	}	

	// Calling getsockopt:  Maps to FINS_getsockopt
	if(getsockopt(sockfd, 0, 0, NULL, 0)){
		perror("The getsockopt() call returned with an error ");
	}else{
		printf("getsockopt() succeeded\n");
	}

	// Calling setsockopt:  Maps to FINS_setsockopt
	if(setsockopt(sockfd, 0, 0, NULL, 0)){
		perror("The setsockopt() call returned with an error ");
	}else{
		printf("setsockopt() succeeded\n");
	}

	// Calling ioctl:  Maps to FINS_ioctl
	int ioctlbuf;
	if(ioctl(sockfd, FIONREAD, &ioctlbuf)){
		perror("The ioctl() call returned with an error ");
	}else{
		printf("ioctl() succeeded\n");
	}

	// Calling poll:  Maps to FINS_poll
	struct pollfd mypollfd = {
		.fd = sockfd,
		.events = 0,
		.revents = 0,
	};

	if(poll(&mypollfd, 1, 1)){
		perror("The poll() call returned with an error ");
	}else{
		printf("poll() succeeded\n");
	}

	// Calling getsockname:  Maps to FINS_getname
	struct sockaddr socknamebuf;
	int addrlen = sizeof(struct sockaddr);
	if(getsockname(sockfd, &socknamebuf, &addrlen)){
		perror("The getsockname() call returned with an error ");
	}else{
		printf("getsockname() succeeded\n");
	}

	// Calling getpeername:  Maps to FINS_getname
	if(getpeername(sockfd, &socknamebuf, &addrlen)){
		perror("The getpeername() call returned with an errror ");
	}else{
		printf("getpeername() succeeded\n");
	}

	// Calling shutdown:  Maps to FINS_shutdown
	if(shutdown(sockfd, SHUT_RD)){
		perror("The shutdown() call returned with an error ");
	}else{
		printf("shutdown() succeeded\n");
	}

	return 0;
}
