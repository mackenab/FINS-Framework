/*
 * @file: mysocketstub.c
 * @author: Abdallah S. Abdallah
 *
 * Compile:
 * gcc -fPIC -c -o mysocketstub_test1.o mysocketstub_test1.c
 * gcc -shared -o mysocketstub_test1.so mysocketstub_test1.o -ldl -lpcap
 *
 * Use:
 * LD_PRELOAD="./mysocketstub_test1.so" application_command
 *
 */

// To make sure that The  symbols  RTLD_DEFAULT  and  RTLD_NEXT  are defined by <dlfcn.h>
// _GNU_SOURCE has to be defined before the include :)  
#define _GNU_SOURCE  
#include <dlfcn.h>
#define _FCNTL_H
#include <bits/fcntl.h>

#include <stdio.h>
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
#include <inttypes.h>

/*additional headers for testing */
#include "finsdebug.h"
//#include "arp.c"  

/* to handle forking + pipes operations */
#include <unistd.h>
#include <sys/types.h>
/* to handle pcap functions */
#include <pcap.h>
#include "wifimod.c"
#include "mysocketstub_test1.h"
/*defines for sockets domains and types */ 
/*
#define SOCK_STREAM 1
#define	SOCK_DGRAM  2
#define	SOCK_RAW 3
*/



/** Define DEBUG to enable PRINT_DEBUG */
//#define DEBUG

#define MAX_sockets 10
#define PROTOCOLADDRSLEN 4
#define DEBUG

int pipedesc[2];
int sockFileDesc[2];

/* packet inject handle */
pcap_t *inject_handle;

/* packet capture handle */
pcap_t *capture_handle;




//static struct board fesha[MAX_sockets];
struct board fesha[MAX_sockets+1];


extern int errorno;


/* functions needed for functionality of the test */

uint32_t gen_IP_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{	return (16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d));
}









/* Definitions of Functions pointers of the sockets related functions*/
int (*_socket) (int domain, int type, int protocol);
int (*_socketpair) (int __domain, int __type, int __protocol,int __fds[2]);
int (*_bind) (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);
int (*_getsockname) (int __fd, __SOCKADDR_ARG __addr,socklen_t *__restrict __len);
int (*_connect) (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);
int (*_getpeername) (int __fd, __SOCKADDR_ARG __addr,socklen_t *__restrict __len);
ssize_t (*_send) (int __fd, __const void *__buf, size_t __n, int __flags);
ssize_t (*_recv) (int __fd, void *__buf, size_t __n, int __flags);

ssize_t (*_sendto) (int __fd, __const void *__buf, size_t __n,
		       int __flags, __CONST_SOCKADDR_ARG __addr,
		       socklen_t __addr_len);


ssize_t (*_recvfrom) (int __fd, void *__restrict __buf, size_t __n,
			 int __flags, __SOCKADDR_ARG __addr,
			 socklen_t *__restrict __addr_len);


ssize_t (*_sendmsg) (int __fd, __const struct msghdr *__message,
			int __flags);

ssize_t (*_recvmsg) (int __fd, struct msghdr *__message, int __flags);


int (*_getsockopt) (int __fd, int __level, int __optname,
		       void *__restrict __optval,
		       socklen_t *__restrict __optlen);


int (*_setsockopt) (int __fd, int __level, int __optname,
		       __const void *__optval, socklen_t __optlen);

int (*_listen) (int __fd, int __n);


int (*_accept) (int __fd, __SOCKADDR_ARG __addr,
		   socklen_t *__restrict __addr_len);


int (*_accept4) (int __fd, __SOCKADDR_ARG __addr,
		    socklen_t *__restrict __addr_len, int __flags);

int (*_shutdown) (int __fd, int __how);






void print_protocol(int domain, int type, int protocol)
{
	switch (domain)
	{
		case AF_UNIX:
			printf(" AF_UNIX \n");
			break;
		case AF_INET:
			printf(" AF_INET %d\n",AF_INET);
			break;
		case AF_INET6:
			printf(" AF_INET6 \n");
			break;
		case AF_NETLINK:
			printf(" AF_NETLINK \n");
			break;
		case AF_PACKET:
			printf(" AF_PACKET \n");
			break;
		default:
			 printf(" unknown domain number %d\n", domain);
	}
	
	return;
}




int fins_socket(int domain, int type, int protocol)
{


static int number_of_sockets =100;

number_of_sockets = number_of_sockets + 1;

fesha[number_of_sockets-100].socketID = number_of_sockets;


PRINT_DEBUG("fins_socket has been called, this is socket# %d", number_of_sockets);
return (number_of_sockets);



}



int socket(int domain, int type, int protocol)
{

	static int numberOfSockets=0;
	int retval;
	struct socket *sock;
	int flags;
	int fins_sock;
		
	numberOfSockets = numberOfSockets +1;
	printf("#Sockets = %d \n",numberOfSockets);
	print_protocol(domain, type, protocol);

	 _socket = (int (*)(int domain, int type, int protocol)) dlsym(RTLD_NEXT, "socket");

		if( (domain == AF_UNIX) | (domain == AF_INET6 ) | (domain == AF_NETLINK )
				| (domain == AF_PACKET) )
		{

			retval = _socket(domain, type, protocol);
			return (retval);
		}
		else if ( domain == AF_INET )

		{
			if (type == SOCK_DGRAM )
				{
				retval = fins_socket(domain,type, protocol);
				return(retval);
				}
			else
				{
				PRINT_DEBUG("original socket will be called, not a udp socket");
				PRINT_DEBUG("domain = %d,type = %d",domain, type);
				retval = _socket(domain, type, protocol);
				return(retval);
				}

		}

		else
			{
				printf("UNKNOWN SOCKET FAMILY !!!!! \n");
				PRINT_DEBUG("domain = %d,type = %d",domain, type);
				return (-1);
			}

}


int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{

	 pid_t   childpid;

		_bind = ( int (*) (int sockfd, const struct sockaddr *addr, socklen_t addrlen) ) dlsym(RTLD_NEXT, "bind");

		//fesha[sockfd].input_fd[0]

		if (sockfd >=101 && sockfd<= 111)
		{
			PRINT_DEBUG ("sockfd sent by application = %d",sockfd);
			if ( fesha[sockfd-100].socketID != sockfd )
				{

				printf("socketID has not been written correctly on the socket initialization step \n ");
				return (-1);

				}
			else
			{
			 // we are in the correct place
				PRINT_DEBUG("we are in the correct place, we will fork now");
				//pipe(fesha[sockfd].input_fd);
				pipe(sockFileDesc);
						pipedesc[0] =  fesha[sockfd].input_fd[0];
						pipedesc[1] =  fesha[sockfd].input_fd[1];
						//sockFileDesc = sockfd;
						 if((childpid = fork()) == -1)

								{
										perror("fork");
										exit(1);
								}
				// for did not fail
						 PRINT_DEBUG("fork successfully done ");
						 if(childpid == 0)  // child working as a writer only
						 				{
						 						PRINT_DEBUG("child process");
						 						capture_init();


						 				}
						 				else  // the parent continue the receiving work
						 				{
						 					//close(fesha[sockfd].input_fd[1]);
						 					close(sockFileDesc[1]);
					 						PRINT_DEBUG("parent process ... Correct binding is done");


						 					fesha[sockfd].srcport = ((struct sockaddr_in *)addr)-> sin_port ;

						 					fesha[sockfd].dstport = -1;  // it is a server so there is no need for dest port to be used


						 					//fesha[sockfd].host_IP_netformat =(addr->sin_addr).s_addr ;  /*A funciton to get the IPAddress will be used later */
						 					fesha[sockfd].host_IP_netformat = htonl(gen_IP_addrs (127,0,0,1));



						 					return (1);  // return any value but (-1) which is the error value

						 				} //end of the parent only code




			}




		}
		else
		{
			PRINT_DEBUG("original bind has been called, socket descriptor is out of range");
			return (  _bind(sockfd, addr, addrlen)    );
		}








} // end of bind fun





/*----------------------------------------------------------------------------*/
/****************** END OF the bind function ---------------------------------*/
/*----------------------------------------------------------------------------*/



ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen)
{


_recvfrom = ( ssize_t (*) (int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen) ) dlsym(RTLD_NEXT, "recvfrom");

int bytesread;
PRINT_DEBUG ("sockfd got into recvfrom = %d",sockfd);

	if (sockfd >=101 && sockfd<= 111)
	{

			if ( fesha[sockfd-100].socketID != sockfd )
			{

			printf("socketID has not been written correctly on the socket initialization step \n ");
			return (-1);

			}

			else  /* handling the recvfrom functionality */
			{


			src_addr->sa_family = AF_INET;
			bzero(&(src_addr->sa_data),14);
			//pipe (fesha[sockfd].input_fd ) ;
			/*        src_addr->sin_port = htons(0xffff);
					(src_addr->sin_addr).s_addr = htonl(gen_IP_addrs (127,0,0,1));
					bzero(&(src_addr->sin_zero),8);
			*/

			/* testing code should be removed as soon as the writing is done from outside*/


						//bytesread = read(fesha[sockfd].input_fd[0], (char *)buf, len);
			bytesread = read(sockFileDesc[0], (char *)buf, len);
						//PRINT_DEBUG("recvfrom- the correct condition %s",(char *) buf);

						//free(readbuffer);
						return(bytesread);





			}
			}
	else

	{

		PRINT_DEBUG("The original recvfrom should not be called ,something is WRONG!!!");
		return (_recvfrom(sockfd,buf, len, flags,src_addr,addrlen));
	}



}




/*----------------------------------------------------------------------------*/
/****************** END OF the recvfrom function------------------------------*/
/*----------------------------------------------------------------------------*/









ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{


_recvmsg = ( ssize_t (*) (int sockfd, struct msghdr *msg, int flags) ) dlsym(RTLD_NEXT, "recvmsg"); 








}


ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen)

{

_sendto = ( ssize_t (*) (int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen)) dlsym(RTLD_NEXT, "sendto"); 

printf("This is sendto System call--------");
return (_sendto(sockfd,buf,len,flags,dest_addr,addrlen) );




}


ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{

_sendmsg = (ssize_t (*) (int sockfd, const struct msghdr *msg, int flags) ) dlsym(RTLD_NEXT, "sendmsg");
 

return( sendmsg(sockfd, msg, flags) );

}
