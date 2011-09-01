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






int main()
{



	int sock;
	struct sockaddr_in server_addr;
	int numbytes;
	struct hostent *host;
	char send_data[4096];

	int datasize = 10;
	

	memset (send_data,89,datasize);
	send_data[datasize]='\0';

	//host= (struct hostent *) gethostbyname((char *)"127.0.0.1");


	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("socket");
		exit(1);
	}


	int port =5000;
	printf("MY DEST PORT BEFORE AND AFTER\n%d, %d",port, htons(port));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

//	server_addr.sin_addr.s_addr = xxx(192,168,1,2);
//	server_addr.sin_addr.s_addr = xxx(172,31,54,87);

	server_addr.sin_addr.s_addr = xxx(127,0,0,1);

	server_addr.sin_addr.s_addr = htonl(server_addr.sin_addr.s_addr);


	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	bzero(&(server_addr.sin_zero),8);

//sock = socket(AF_INET, SOCK_DGRAM, 0);
//sock = socket(AF_INET, SOCK_DGRAM, 0);
//sock = socket(AF_INET, SOCK_DGRAM, 0);


/**	  while (1)
*		{
*
*
*		}
*/

 
	int i =0 ;
	   while ( i < 100)
	   {
		 sleep (1);	 /** sleep for one second */
		//	usleep (100);	  /** sleep 1000 MicroSecond = 1 Milli-Second */
			
			i = i+1; 

		//    printf("Type Something (q or Q to quit):");
			  // gets(send_data);
			
		/*
			    if ((strcmp(send_data , "q") == 0) || strcmp(send_data , "Q") == 0)
				{

				}
			    else
				{   */
			//	if (i % 100 ==0 )

			      numbytes= sendto(sock, send_data, strlen(send_data) , 0,
				      (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
				printf("\n %d....packet #  %d ",numbytes,i);	     	
			//	}
			//fflush(stdout);
	   }





}

