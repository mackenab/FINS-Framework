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

struct argstruct {
	int sockfd;
	int pfds[2];
};

void *child(struct argstruct *threadargs){
	int sockfd = threadargs->sockfd;

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
	if(write(threadargs->pfds[WRITE_END], &cbuf, 1) != 1){
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

	pthread_exit(NULL);
}


int main(){
	struct argstruct *threadargs = malloc(sizeof(struct argstruct));

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

	if(pipe(threadargs->pfds) == -1){
		perror("pipe ");
	}

	
	printf("Creating child thread.\n");
	fflush(stdout);
	pthread_t child_thread;

	threadargs->sockfd = sockfd;

	if(pthread_create(&child_thread, NULL, child, (void *) threadargs) != 0){
		perror("Thread creation failed");
	}


	// "Parent" code follows

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
	while(read(threadargs->pfds[READ_END], &pbuf, 1) == 0){} //Spinlock to sync
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

	free(threadargs);
	
	pthread_exit(NULL);
	exit(0);
}
