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
#include <signal.h>

#define xxx(a,b,c,d) 	(16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d))

	/*
	
	int xxx(char a,char b,char c,char d) 
	{

	return ((16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d)));

	}


	*/



int i=0;

int packets_per_second=0;

void alarm_handler(int sig)
{
  printf("\n**********Number of packers that have been received = %d *******\n", packets_per_second );
  exit(2);
}






int main(int argc, char *argv[])
{



	uint16_t port;
	
	

	if (argc > 1)	
		
		port = atoi(argv[1]);
	else 	
		port = 5000;

	int sock1,sock2,sock3;
	struct sockaddr_in server_addr1;
	int numbytes1,numbytes2,numbytes3;
	struct hostent *host;
	char send_data[4096];

	int datasize = 10;
	int addrlength = sizeof(struct sockaddr_in);

	memset (send_data,89,datasize);
	send_data[datasize]='\0';

	//host= (struct hostent *) gethostbyname((char *)"127.0.0.1");


	if ((sock1 = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("socket");
		exit(1);
	}

	
	server_addr1.sin_family = AF_INET;
	server_addr1.sin_port = htons(port);


	


	server_addr1.sin_addr.s_addr = xxx(192,168,1,129);
	
	server_addr1.sin_addr.s_addr = htonl(server_addr1.sin_addr.s_addr);
	
	bzero(&(server_addr1.sin_zero),8);
	bind(sock1,(struct sockaddr *) &server_addr1, addrlength);
	getsockname(sock1,(struct sockaddr *) &server_addr1, &addrlength);
		printf("aya2");
	printf("\n%s, %d\n", inet_ntoa(server_addr1.sin_addr), server_addr1.sin_port);
		printf("aya");


	server_addr1.sin_family = AF_INET;
	server_addr1.sin_port = htons(port+2000);


	


	server_addr1.sin_addr.s_addr = xxx(192,168,5,129);
	
	server_addr1.sin_addr.s_addr = htonl(server_addr1.sin_addr.s_addr);
	
	bzero(&(server_addr1.sin_zero),8);	


	connect(sock1,(struct sockaddr *) &server_addr1, addrlength);

//	getpeername(sock1,(struct sockaddr *) &server_addr1, &addrlength);
//		printf("aya2");
//	printf("\n%s, %d\n", inet_ntoa(server_addr1.sin_addr), server_addr1.sin_port);
//      /* Will point to the segments of the (noncontiguous)            */
	      /* outgoing message.                                            */
	   struct iovec iov[3];

	      /* This structure contains parameter information for sendmsg.   */
	   struct msghdr mh;		


	  iov[0] .iov_base = &send_data;
	   iov[0] .iov_len = datasize;
	   iov[1] .iov_base = &send_data;
	   iov[1] .iov_len = datasize;
	   iov[2] .iov_base = &send_data;
	   iov[2] .iov_len = datasize;


server_addr1.sin_addr.s_addr = xxx(192,168,5,180);
	
	server_addr1.sin_addr.s_addr = htonl(server_addr1.sin_addr.s_addr);
	

	  mh.msg_name =  &server_addr1;
	   mh.msg_namelen = sizeof(struct sockaddr_in);
	   mh.msg_iov = iov;
	   mh.msg_iovlen = 3;
	 
	
	fflush(stdout);
	int i =1;
	while(i< 60)
		{
		sleep(1);
		sendmsg(sock1, &mh, 0); 
	//sendto(sock1, send_data, strlen(send_data) , 0,(struct sockaddr *)&server_addr1, sizeof(struct sockaddr));
		printf("\n Message %d",i);
		i++;
			}

	return;

}

