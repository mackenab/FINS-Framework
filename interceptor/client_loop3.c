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
	struct sockaddr_in server_addr1,server_addr2,server_addr3;
	int numbytes1,numbytes2,numbytes3;
	struct hostent *host;
	char send_data[4096];

	int datasize = 10;
	

	memset (send_data,89,datasize);
	send_data[datasize]='\0';

	//host= (struct hostent *) gethostbyname((char *)"127.0.0.1");


	if ((sock1 = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("socket");
		exit(1);
	}

	if ((sock2 = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		{
			perror("socket");
			exit(1);
		}

	if ((sock3 = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		{
			perror("socket");
			exit(1);
		}

	

	
	printf("MY DEST PORT BEFORE AND AFTER\n%d, %d",port, htons(port));
	server_addr1.sin_family = AF_INET;
	server_addr1.sin_port = htons(port);

	server_addr2.sin_family = AF_INET;
	server_addr2.sin_port = htons(port);

	server_addr3.sin_family = AF_INET;
	server_addr3.sin_port = htons(port);


	server_addr1.sin_addr.s_addr = xxx(127,0,0,1);
	server_addr2.sin_addr.s_addr = xxx(127,0,0,1);
	server_addr3.sin_addr.s_addr = xxx(127,0,0,1);
//	server_addr.sin_addr.s_addr = xxx(172,31,54,87);

//	server_addr.sin_addr.s_addr = xxx(127,0,0,1);

	server_addr1.sin_addr.s_addr = htonl(server_addr1.sin_addr.s_addr);
	server_addr2.sin_addr.s_addr = htonl(server_addr2.sin_addr.s_addr);
	server_addr3.sin_addr.s_addr = htonl(server_addr3.sin_addr.s_addr);
	//server_addr.sin_addr.s_addr = INADDR_LOOPBACK;
	bzero(&(server_addr1.sin_zero),8);
	bzero(&(server_addr2.sin_zero),8);
	bzero(&(server_addr3.sin_zero),8);


//	  while (1)		{		}


	if ( connect(sock1, (struct sockaddr *)&server_addr1 , sizeof(struct sockaddr)) == -1       )
	{
		perror("socket");
		exit(1);
	}

	if ( connect(sock2, (struct sockaddr *)&server_addr2 , sizeof(struct sockaddr)) == -1)
		{
			perror("socket");
			exit(1);
		}

	if ( connect(sock3, (struct sockaddr *)&server_addr3 , sizeof(struct sockaddr)) == -1)
		{
			perror("socket");
			exit(1);
		}

 
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

			      numbytes1= send(sock1, send_data, strlen(send_data) , 0);
			//	 numbytes2= send(sock2, send_data, strlen(send_data) , 0);

			//	 numbytes3= send(sock3, send_data, strlen(send_data) , 0);

				printf("\n %d....packet #  %d ",numbytes1,i);	     	
			//	printf("\n %d....packet #  %d ",numbytes2,i);	     	
			//	printf("\n %d....packet #  %d ",numbytes3,i);	     	
			//	}
			//fflush(stdout);
	   }





}

