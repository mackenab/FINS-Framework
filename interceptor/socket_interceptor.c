/**
 * @file: socket_interceptor.c
 * @author: Abdallah Abdallah
 *	@brief Notice that we dont need to use dlopen before using dlsym because someone had
 *	@brief definitely asked to load the GNU LibC earlier
 * Compile:
 * gcc -fPIC -c -o socket_interceptor.o socket_interceptor.c
 * gcc -shared -o socket_interceptor.so socket_interceptor.o -ldl -lpcap -lpthread
 *
 *
 * Use:
 * LD_PRELOAD="./socket_interceptor.so" application_command
 *
 */
/** Notice that the process level semaphores are shared through the
 * /dev/shm folder
 * This is where you should go to delete them after every run in case the run did not
 * exit correctly
 *
 * Running Order:
 * -------------------------------------
 * 1. run fins.sh under the socket daemon folder
 * 2. run fins.sh under the socket interceptor folder
 * 3. Kill the socket daemon side
 * 4. Kill the interceptor side
 *
 */

// TODO Using Mutex with Conditional locking may be a better way than
// The continuous trials to use semaphores
// TODO Using MUtex with Conditional Variables

// To make sure that The  symbols  RTLD_DEFAULT  and  RTLD_NEXT  are defined by <dlfcn.h>
// _GNU_SOURCE has to be defined before the include :)
#define _GNU_SOURCE
#include <dlfcn.h>
#define _FCNTL_H
#include <bits/fcntl.h>

#include <fcntl.h>
/* to handle pcap functions */
#include <pcap.h>
#include "socket_interceptor.h"
/*defines for sockets domains and types */
/*
 #define SOCK_STREAM 1
 #define	SOCK_DGRAM  2
 #define	SOCK_RAW 3
 */

/** Define DEBUG to enable PRINT_DEBUG */
//#define DEBUG

#define PROTOCOLADDRSLEN 4
//#define DEBUG
#define _GNU_SOURCE

extern int errorno;

int numberOfcalls = 1000;
int numberOfSockets = 0;








/** @brief Obtain a backtrace of the calls led to the current thread
 * and print it to stdout, the function is copied from
 * http://www.delorie.com/gnu/docs/glibc/libc_665.html
 *
 *  @param void
 *
 *  @return void
 */

static print_trace (void)
{
  void *array[10];
  size_t size;
  char **strings;
  size_t i;

  size = backtrace (array, 10);
  strings = backtrace_symbols (array, size);

  printf ("Obtained %zd stack frames.\n", size);

  for (i = 0; i < size; i++)
     printf ("%s\n", strings[i]);

  free (strings);
}


/** functions needed for functionality of the test */

/** @brief
 *
 *  @param
 *
 *  @return
 */

uint32_t gen_IP_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
	return (16777216ul * (a) + (65536ul * (b)) + (256ul * (c)) + (d));
}

/**--------------------------------------------------------------------
 *
 */

int checkFinsHistory(pid_t target1, int target2) {
	int i = 0;
	for (i = 0; i < MAX_sockets; i++) {
		if ((FinsHistory[i].processID == target1) && (FinsHistory[i].socketDesc
				== target2))
			return (1);
	}
	return (0);
}
/**--------------------------------------------------------------------
 *
 */

int searchFinsHistory(pid_t target1, int target2) {
	int i = 0;
	for (i = 0; i < MAX_sockets; i++) {
		if ((FinsHistory[i].processID == target1) && (FinsHistory[i].socketDesc
				== target2))
			return (i);
	}
	return (-1);
}

/**--------------------------------------------------------------------
 *
 */


int insertFinsHistory(pid_t value1, int value2, int value3) {
	int i = 0;
	for (i = 0; i < MAX_sockets; i++) {
		if (FinsHistory[i].processID == -1) {
			FinsHistory[i].processID = value1;
			FinsHistory[i].socketDesc = value2;
			FinsHistory[i].fakeID = value3;
			sprintf(FinsHistory[i].semaphore_name, "socket%d_%d",
					FinsHistory[i].processID, FinsHistory[i].fakeID);
			sprintf(FinsHistory[i].asemaphore_name, "socket%d_%da",
					FinsHistory[i].processID, FinsHistory[i].fakeID);

			PRINT_DEBUG("%s, %s",FinsHistory[i].semaphore_name,FinsHistory[i].asemaphore_name );
			/** the semaphore is initially locked
			 * If O_CREAT is specified in oflag, then
			 the semaphore is created if it does not already exist.
			 */

		//	FinsHistory[i].s = sem_open(FinsHistory[i].semaphore_name, O_CREAT,0644,0);
		//		FinsHistory[i].as = sem_open(FinsHistory[i].asemaphore_name, O_CREAT,0644,0);

			//	FinsHistory[i].s  = sem_open(FinsHistory[i].semaphore_name, 0);
			//	FinsHistory[i].as = sem_open(FinsHistory[i].asemaphore_name, 0);
			PRINT_DEBUG("");
			errno = 0;
			//	if ( errno  == EEXIST )
			//{
			//	PRINT_DEBUG("errno is %d",errno);


			do {
				FinsHistory[i].s = sem_open(FinsHistory[i].semaphore_name, 0);
			}while (errno == ENOENT);

			PRINT_DEBUG("");

			do {
				FinsHistory[i].as = sem_open(FinsHistory[i].asemaphore_name, 0);
				//PRINT_DEBUG("");
			} while (errno == ENOENT);

			//}

		//	FinsHistory[i].s = sem_open(FinsHistory[i].semaphore_name, 0);
	//		FinsHistory[i].as = sem_open(FinsHistory[i].asemaphore_name, 0);


			PRINT_DEBUG("");
			if (errno == ENOENT)
				PRINT_DEBUG("errno is %d",errno);
			if (FinsHistory[i].s == SEM_FAILED || FinsHistory[i].as
					== SEM_FAILED) {
				if (FinsHistory[i].s == SEM_FAILED) {
					PRINT_DEBUG("");
					sem_unlink(FinsHistory[i].semaphore_name);
				}
				if (FinsHistory[i].as == SEM_FAILED) {
					PRINT_DEBUG("");
					sem_unlink(FinsHistory[i].asemaphore_name);
				}
				exit(1);

			}
			//	sem_post(FinsHistory[i].s);
			return (1);

		}
	} PRINT_DEBUG("reached maximum # of processes to be served, FINS is out of sockets");
	return (0);
}


/**--------------------------------------------------------------------
 *
 */



int removeFinsHistory(pid_t target1, int target2) {

	int i = 0;
	for (i = 0; i < MAX_sockets; i++) {
		if ((FinsHistory[i].processID == target1) && (FinsHistory[i].socketDesc
				== target2)) {
			FinsHistory[i].processID = -1;
			FinsHistory[i].socketDesc = -1;
			FinsHistory[i].fakeID = -1;
			sem_close(FinsHistory[i].s);
			sem_unlink(FinsHistory[i].semaphore_name);
			sem_close(FinsHistory[i].as);
			sem_unlink(FinsHistory[i].asemaphore_name);
			sprintf(FinsHistory[i].semaphore_name, "NULL");

			return (1);
		}
	}
	return (0);

}

/**--------------------------------------------------------------------
 *
 */



/** @brief
 *
 *  @param
 *
 *  @return
 */

/**
 * TODO free and close/DESTORY all the semaphores before exit !!!
 *
 */
void init_socketChannel() {

	int i;
	/** Notice that the main_channel_Semaphore is a semaphore shared among processes
	 * (It is processes level semaphore, NOT threads level)
	 */

	/** Needs NPTL because LinuxThreads does not support sharing semaphores between processes */

	/** the semaphore is initially locked */

	//main_channel_semaphore1 = sem_open(main_sem_name1,O_CREAT|O_EXCL,0644,0);
	main_channel_semaphore1 = sem_open(main_sem_name1, 0, 0644, 0);
	PRINT_DEBUG();
	if (main_channel_semaphore1 == SEM_FAILED) {

		main_channel_semaphore1 = sem_open(main_sem_name1, 0);
		PRINT_DEBUG();

	}
	if (main_channel_semaphore1 == SEM_FAILED) {
		perror("unable to create semaphore");
		sem_unlink(main_sem_name1);
		exit(-1);
	}

	// main_channel_semaphore2 = sem_open(main_sem_name2,O_CREAT|O_EXCL,0644,0);
	main_channel_semaphore2 = sem_open(main_sem_name2, 0, 0644, 0);
	PRINT_DEBUG();
	if (main_channel_semaphore2 == SEM_FAILED) {
		main_channel_semaphore2 = sem_open(main_sem_name2, 0);
		PRINT_DEBUG();

	}
	if (main_channel_semaphore2 == SEM_FAILED) {
		perror("unable to create semaphore");
		sem_unlink(main_sem_name2);
		exit(-1);
	}

//	PRINT_DEBUG("Blocking on the main_socket_channel THE FINS CORE HAS NOT BEEN STARTED");
//	PRINT_DEBUG("Kill the application, run the core, then run the application process again");

	//	mkfifo(MAIN_SOCKET_CHANNEL,0777);
	socket_channel_desc = open(MAIN_SOCKET_CHANNEL, O_WRONLY);

	int tester;
	sem_getvalue(main_channel_semaphore1, &tester);
	PRINT_DEBUG("tester = %d",tester);
	//sem_wait(main_channel_semaphore);
	PRINT_DEBUG("222");

	PRINT_DEBUG("333");

	/** initialize the sockets database
	 * this is a simplified version from the full detailed database available
	 * on the socket jinni side
	 * */

	sem_init(&FinsHistory_semaphore, 1, 1);
	for (i = 0; i < MAX_sockets; i++) {
		FinsHistory[i].processID = -1;
		FinsHistory[i].socketDesc = -1;
		FinsHistory[i].fakeID = -1;

	}

}

/** @brief
 *  @param
 *  @return
 */

void print_protocol(int domain, int type, int protocol) {
	switch (domain) {
	case AF_UNIX:
		printf(" AF_UNIX \n");
		break;
	case AF_INET:
		printf(" AF_INET %d\n", AF_INET);
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

/** @brief fins_socket is responsible for creating and maintaining the socket descriptors
 * array. These are the descriptors being returned to the applications
 *  @param domain
 *  @param type
 *  @param protocol
 */


//int fins_socket(int domain, int type, int protocol) {
//
//	int processID;
//	//static int numberOfcalls = 1000;
//	numberOfcalls = numberOfcalls + 1;
//	 processID = getpid();
//	PRINT_DEBUG("ProcessID = %d , number of calls is %d",processID ,numberOfcalls);
//	fflush(stdout);
//	return(numberOfcalls);
//
//
//
//}



int fins_socket(int domain, int type, int protocol) {
	/**TODO These static vars are not thread safe
	 * we either find another way to keep tracking or
	 * protect them with multi-processes semaphore
	 */
//	static int numberOfcalls = 1000;
	int numOfBytes = -1;
	u_int callcode;
	char clientname[240];
	int tempdescriptor;
	int fakeid;
	int flags;
	int writtenBytes = -1;
	int confirmation;
	pid_t processid;
	int index;
	processid = getpid();
	callcode = socket_call;
	// TODO lock the locker protect the static variable
	numberOfcalls = numberOfcalls + 1;
	PRINT_DEBUG("number of calls is %d", numberOfcalls);
	// TODO unlock the locker protect the static variable
	if (numberOfcalls > 1000 + MAX_sockets) {
		PRINT_DEBUG("max number of sockets has been violated, FINS QUIT");
		exit(1);
	}
	fakeid = numberOfcalls;

	PRINT_DEBUG("34535");

	/** TODO lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */

	PRINT_DEBUG("%d", processid);

	sem_wait(main_channel_semaphore2);
	writtenBytes = write(socket_channel_desc, &processid, sizeof(pid_t));
	writtenBytes = write(socket_channel_desc, &callcode, sizeof(u_int));
	writtenBytes = write(socket_channel_desc, &domain, sizeof(int));
	writtenBytes = write(socket_channel_desc, &type, sizeof(int));
	writtenBytes = write(socket_channel_desc, &protocol, sizeof(int));
	//write(socket_channel_desc,&tempdescriptor, sizeof (int) );
	/** send the fakeid twice once as fake ID and once as a real pipe descriptor */
	writtenBytes = write(socket_channel_desc, &fakeid, sizeof(int));
	writtenBytes = write(socket_channel_desc, &fakeid, sizeof(int));

	sem_post(main_channel_semaphore1);
	/** Remember to unlock the MAIN CHANNEL */
	sem_post(main_channel_semaphore2);

	if (writtenBytes > 0) {
		PRINT_DEBUG("written bytes %d", writtenBytes);

		PRINT_DEBUG("34535..2342");

	}
	sprintf(clientname, CLIENT_CHANNEL_RX, processid, fakeid);
	/** The default will be NON_BLOCKING so that the jinni can open for writing successfully
	 *
	 *  later we can set/reset the blocking option
	 * according to the later desire of the application
	 * */

	/** client pipe is initialized as NONBlOCKING to be able to open and
	 * proceed even if the writing side did not open yet OR
	 * EVEN IF MKFIFO HAS NOT BEEN CALLED YET !!
	 */

	/** 1.The interceptor will MAKE FIFO THEN OPEN IT as a blocking reading until the Jinni side opens for writing !
	 * 2. Jinni side opens the semaphore & WAIT , then OPEN the file for writing
	 * 3. The block on this side will release then it we call WAIT on the semaphore
	 * 4. Since semaphore has been already taken by the Jinni then we avoided any dead lock
	 *  */
	//mkfifo(clientname,0777);
	//PRINT_DEBUG("0000");
	//tempdescriptor = open (namebuffer,O_RDONLY | O_NONBLOCK);


	//tempdescriptor = open(clientname,O_RDONLY | O_NONBLOCK);
	tempdescriptor = open(clientname, O_RDONLY);
	PRINT_DEBUG("0001");

	sem_wait(&FinsHistory_semaphore);
	/** insertFinsHistory takes care of initializing the new socket
	 * and its corresponding Clinet channel semaphore name and semaphore pointer
	 */
	insertFinsHistory(processid, tempdescriptor, fakeid);
	sem_post(&FinsHistory_semaphore);

	PRINT_DEBUG("0002");

	/** TODO We depend on the initialization value of the semaphore since it is producing-consuming also known
	 * as writing-reading semaphore !  to make sure not to fail into dead lock
	 * but in case this fails then we have to implement our own synchronization to avoid
	 * dead lock between the client reading side (the interceptor),and the writing side (socket Jinni)
	 */
	index = searchFinsHistory(processid, tempdescriptor);

	if (index < 0) {
		PRINT_DEBUG("incorrect index !! Crash");
		exit(1);

	}

	PRINT_DEBUG("index = %d",index); PRINT_DEBUG("");
	sem_wait(FinsHistory[index].as);
	sem_wait(FinsHistory[index].s);
	PRINT_DEBUG("");

	numOfBytes = read(tempdescriptor, &confirmation, sizeof(int));

	/** locking the semaphore has been moved below to make sure that deadlock does not occure....*/

	if (confirmation != processid) {

		PRINT_DEBUG("READING ERROR!! Probably Sync Failed!!");
		sem_post(FinsHistory[searchFinsHistory(processid, tempdescriptor)].s);

		return (-1);

	}
	numOfBytes = read(tempdescriptor, &confirmation, sizeof(int));
	if (confirmation != fakeid) {

		PRINT_DEBUG("READING ERROR!! Probably Sync Failed!!");
		sem_post(FinsHistory[searchFinsHistory(processid, tempdescriptor)].s);
		return (-1);
	}
	numOfBytes = read(tempdescriptor, &confirmation, sizeof(int));
	sem_post(FinsHistory[searchFinsHistory(processid, tempdescriptor)].s);

	if (confirmation != ACK) {

		PRINT_DEBUG("READING ERROR!! Probably Sync Failed!!");

		return (-1);
	}
	/**
	 * Writing a new record to our database after receiving a confirmation
	 * that a new recorded has been created and added to the master database
	 */

	PRINT_DEBUG();
	return (tempdescriptor);

} // end of fins_socket


/** @brief Filters the socket system call received from the applications. Redirect the calls
 * to the right destination which is either the fins_socket function or sending it to the
 * original corresponding function in the GNU C library
 *  @param domain
 *  @param type
 *  @param protocol
 */
int socket(int domain, int type, int protocol) {

	/**TODO These static vars are not thread safe
	 * we either find another way to keep tracking or
	 * protect them with multi-processes semaphore
	 */
	// static int numberOfcalls=0;
	// Define a locker object to protect the static variable
	//static int numberOfSockets = 0;
	int retval;
	struct socket *sock;
	int flags;
	int fins_sock;
	char *errormsg;

	/** with the first interception takes place , we initialize the socket channel */
	if (numberOfSockets == 0) {
		init_socketChannel();
	}

	PRINT_DEBUG("#Sockets = %d \n",numberOfSockets);
	print_protocol(domain, type, protocol);

	_socket = (int(*)(int domain, int type, int protocol)) dlsym(RTLD_NEXT,
			"socket");

	errormsg = dlerror();
	if (errormsg != NULL) {
		PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
	}

	if ((domain == AF_UNIX) | (domain == AF_INET6) | (domain == AF_NETLINK)
			| (domain == AF_PACKET)) {

		retval = _socket(domain, type, protocol);
		return (retval);
	} else if (domain == AF_INET)

	{	/**
		 * Handle the TCP, UDP , and ICMP calls and sent others to original stack
		 */
		if (  (type == SOCK_DGRAM ) ||
				((type == SOCK_RAW) && (protocol ==  IPPROTO_ICMP)) )
		{
			PRINT_DEBUG("123");

			retval = fins_socket(domain, type, protocol);
			if (retval != -1) {
				// TODO lock the locker protect the static variable
				numberOfSockets = numberOfSockets + 1;
				PRINT_DEBUG(" numberOfSockets = %d",numberOfSockets);

				// TODO unlock the locker protect the static variable

			}
			return (retval);
		} else /** Handle sockets other than UDP  */
		{
			PRINT_DEBUG("original socket will be called, not a udp/tcp/ICMP socket");
			PRINT_DEBUG("domain = %d,type = %d",domain, type);

			retval = _socket(domain, type, protocol);
			return (retval);
		}

	}

	else {
		printf("UNKNOWN SOCKET DOMAIN!!!!! \n");
		PRINT_DEBUG("domain = %d,type = %d",domain, type);
		return (-1);
	}

}

/*----------------------------------------------------------------------------*/
/****************** END OF the socket function -------------------------------*/
/*----------------------------------------------------------------------------*/




int fins_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

	int numOfBytes = -1;
	u_int opcode;
	char namebuffer[240];
	int tempdescriptor;
	pid_t processid;
	int confirmation;
	int sockfd_alter;
	int index;

	processid = getpid();
	opcode = bind_call;

	index = searchFinsHistory(processid, sockfd);
	if (index < 0) {
		PRINT_DEBUG("incorrect index !! Crash");
		exit(1);

	}
	sockfd_alter = FinsHistory[index].fakeID;

	PRINT_DEBUG();

	/** TODO lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */
	sem_wait(main_channel_semaphore2);
	write(socket_channel_desc, &processid, sizeof(pid_t));
	write(socket_channel_desc, &opcode, sizeof(u_int));
	write(socket_channel_desc, &sockfd_alter, sizeof(int));
	write(socket_channel_desc, &addrlen, sizeof(socklen_t));
	/** TODO check if writing the whole struct sockaddr at once working properly or not */
	write(socket_channel_desc, addr, addrlen);
	sem_post(main_channel_semaphore1);
	/**TODO remember to unlock the main channel */
	sem_post(main_channel_semaphore2);
	PRINT_DEBUG();

	/** The code below needs to force kind of synchronization
	 * it might be hard to achieve , test this code throughly later
	 */
	sem_wait(FinsHistory[index].as);
	sem_wait(FinsHistory[index].s);
	PRINT_DEBUG();

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != processid) {
		sem_post(FinsHistory[index].s);
		return (-1);
	}

	numOfBytes = read(sockfd, &confirmation, sizeof(int));

	if (confirmation != sockfd_alter) {
		sem_post(FinsHistory[index].s);
		return (-1);

	}

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	sem_post(FinsHistory[index].s);
	if (confirmation != ACK) {

		return (-1);
	}

	/** on success ZERo is returned and on failures , it return (-1) */
	return (0);

}

/** @brief Filters the bind system call received from the applications. Redirect the calls
 * to the right destination which is either the fins_bind function or sending it to the
 * original corresponding function in the GNU C library
 * Filtering is done based on the file descriptor received. If the file descriptor belongs to the
 * FINS pool of descriptors or not.
 *  @param domain
 *  @param type
 *  @param protocol
 *  @return success any value but -1. Return -1 at failure
 */
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

	int retval;
	char *errormsg;
	_bind
			= (int(*)(int sockfd, const struct sockaddr *addr,
					socklen_t addrlen)) dlsym(RTLD_NEXT, "bind");

	errormsg = dlerror();
	if (errormsg != NULL) {
		PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
	}

	if (checkFinsHistory(getpid(), sockfd) != 0) {
		retval = fins_bind(sockfd, addr, addrlen);
		return (retval);
	} else {
		PRINT_DEBUG("original bind has been called, socket descriptor is out of range");
		return (_bind(sockfd, addr, addrlen));
	}

} // end of bind fun


/*----------------------------------------------------------------------------*/
/****************** END OF the bind function ---------------------------------*/
/*----------------------------------------------------------------------------*/

/** @brief fins_connect is responsible for assigning a certain destination's address
 * to a certain socket descriptor. read the man pages to find the difference between
 * its uses among different protocols UDP and TCP
 *  @param sockfd
 *  @param addr
 *  @param addrlen
 */
int fins_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

	int numOfBytes = -1;
	u_int opcode;
	char namebuffer[240];
	int tempdescriptor;
	pid_t processid;
	int confirmation;
	int sockfd_alter;
	int index;

	processid = getpid();
	opcode = connect_call;

	index = searchFinsHistory(processid, sockfd);
	if (index < 0) {
		PRINT_DEBUG("incorrect index !! Crash");
		exit(1);

	}
	sockfd_alter = FinsHistory[index].fakeID;

	PRINT_DEBUG();

	/** TODO lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */
	sem_wait(main_channel_semaphore2);
	write(socket_channel_desc, &processid, sizeof(pid_t));
	write(socket_channel_desc, &opcode, sizeof(u_int));
	write(socket_channel_desc, &sockfd_alter, sizeof(int));
	write(socket_channel_desc, &addrlen, sizeof(socklen_t));
	/** TODO check if writing the whole struct sockaddr at once working properly or not */
	write(socket_channel_desc, addr, addrlen);
	sem_post(main_channel_semaphore1);
	/**TODO remember to unlock the main channel */
	sem_post(main_channel_semaphore2);
	PRINT_DEBUG();

	/** The code below needs to force kind of synchronization
	 * it might be hard to achieve , test this code throughly later
	 */
	sem_wait(FinsHistory[index].as);
	sem_wait(FinsHistory[index].s);
	PRINT_DEBUG();

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != processid) {
		sem_post(FinsHistory[index].s);
		return (-1);
	}

	numOfBytes = read(sockfd, &confirmation, sizeof(int));

	if (confirmation != sockfd_alter) {
		sem_post(FinsHistory[index].s);
		return (-1);

	}

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	sem_post(FinsHistory[index].s);
	if (confirmation != ACK) {

		return (-1);
	}

	/** on success ZERo is returned and on failures , it return (-1) */
	return (0);

} // end of fins_connect


/** @brief Filters the connect system call received from the applications.
 * Redirect the calls to the right destination which is either the fins_connect function or
 * sending it to the original corresponding function in the GNU C library
 *  @param sockfd
 *  @param addr
 *  @param addrlen
 *  @return zero at success to assign address, (-1) otherwise
 */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

	int retval;
	char *errormsg;
	_connect = (int(*)(int sockfd, const struct sockaddr *addr,
			socklen_t addrlen)) dlsym(RTLD_NEXT, "connect");

	errormsg = dlerror();
	if (errormsg != NULL) {
		PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
	}

	if (checkFinsHistory(getpid(), sockfd) != 0) {
		PRINT_DEBUG("CONNECT");
		retval = fins_connect(sockfd, addr, addrlen);
		return (retval);
	} else {
		PRINT_DEBUG("original connect has been called, socket descriptor is out of range");
		return (_connect(sockfd, addr, addrlen));
	}

} // end of function connet

/**............................................................................*/
/********************** END OF connect function -------------------------------*/
/*.............................................................................*/

ssize_t fins_recv(int sockfd, void *buf, size_t len, int flags) {

	int bytesread;

	int numOfBytes = -1;
	u_int opcode;
	int index;
	int sockfd_alter;
	opcode = recv_call;

	pid_t processid;
	int confirmation;
	processid = getpid();

	index = searchFinsHistory(processid, sockfd);
	sockfd_alter = FinsHistory[index].fakeID;

	/** TODO lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */
	PRINT_DEBUG();
	sem_wait(main_channel_semaphore2);
	write(socket_channel_desc, &processid, sizeof(pid_t));
	write(socket_channel_desc, &opcode, sizeof(u_int));
	write(socket_channel_desc, &sockfd_alter, sizeof(int));
	write(socket_channel_desc, &len, sizeof(size_t));
	write(socket_channel_desc, &flags, sizeof(int));

	sem_post(main_channel_semaphore1);
	sem_post(main_channel_semaphore2);

	/**TODO remember to unlock the main channel */

	PRINT_DEBUG();

	sem_wait(FinsHistory[index].as);
	PRINT_DEBUG();
	sem_wait(FinsHistory[index].s);
	PRINT_DEBUG();
	numOfBytes = read(sockfd, &confirmation, sizeof(int));

	if (confirmation != processid) {

		sem_post(FinsHistory[index].s);

		return (-1);
	}

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != sockfd_alter) {
		sem_post(FinsHistory[index].s);

		return (-1);
	}
	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != ACK) {
		sem_post(FinsHistory[index].s);

		return (-1);

	}

	/** The socket jinni sent us, the number of bytes to be received
	 * we have to check that our buffer size is enough to read
	 * */
	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (numOfBytes <= 0) {
		sem_post(FinsHistory[index].s);

		return (-1);

	}
	if (confirmation <= len) {
		bytesread = read(sockfd, buf, confirmation);
		sem_post(FinsHistory[index].s);
		if (bytesread < 0) {

			return (-1);

		}
	}

	else {

		sem_post(FinsHistory[index].s);
		PRINT_DEBUG("passed buffer length sent from the application is not enough to hold the data");
		return (-1);

	}

	/**TODO remember to unlock the RX_CHANNEL */

	PRINT_DEBUG();

	return (bytesread);

} // end of fins_recv

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {

	_recv = (ssize_t(*)(int sockfd, void *buf, size_t len, int flags)) dlsym(
			RTLD_NEXT, "recv");
	char *errormsg;
	errormsg = dlerror();
	if (errormsg != NULL) {
		PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
	}

	int bytesread;

	PRINT_DEBUG ("sockfd from process %d got into recv = %d",getpid(),sockfd);

	if (checkFinsHistory(getpid(), sockfd) != 0) {
		bytesread = fins_recv(sockfd, buf, len, flags);
		return (bytesread);

	} else

	{

		PRINT_DEBUG("The original recvf should not be called ,something is WRONG!!!");
		return (_recv(sockfd, buf, len, flags));
	}

}

/*------------------------------------------------------------------------*/
/*----------------- END OF the recv function------------------------------*/
/*------------------------------------------------------------------------*/

ssize_t fins_recvfrom(int sockfd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen)
{
	int bytesread;

	int numOfBytes = -1;
	u_int opcode;
	int index;
	int sockfd_alter;
	int symbol = 1; //default value unless passes address equal NULL
	opcode = recvfrom_call;

	pid_t processid;
	int confirmation;
	processid = getpid();

	index = searchFinsHistory(processid, sockfd);
	sockfd_alter = FinsHistory[index].fakeID;

	/** TODO lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */
	PRINT_DEBUG();
	sem_wait(main_channel_semaphore2);
	write(socket_channel_desc, &processid, sizeof(pid_t));
	write(socket_channel_desc, &opcode, sizeof(u_int));
	write(socket_channel_desc, &sockfd_alter, sizeof(int));
	write(socket_channel_desc, &len, sizeof(size_t));
	write(socket_channel_desc, &flags, sizeof(int));
	if (src_addr != NULL)
		write(socket_channel_desc, &symbol, sizeof(int));
	else {
		symbol = 0;
		write(socket_channel_desc, &symbol, sizeof(int));
	}

	sem_post(main_channel_semaphore1);
	sem_post(main_channel_semaphore2);

	/**TODO remember to unlock the main channel */

	PRINT_DEBUG();

	sem_wait(FinsHistory[index].as);
	PRINT_DEBUG();
	sem_wait(FinsHistory[index].s);
	PRINT_DEBUG();
	numOfBytes = read(sockfd, &confirmation, sizeof(int));

	if (confirmation != processid) {

		sem_post(FinsHistory[index].s);

		return (-1);
	}

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != sockfd_alter) {
		sem_post(FinsHistory[index].s);

		return (-1);
	}
	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != ACK) {
		sem_post(FinsHistory[index].s);

		return (-1);

	}
	if (symbol == 1) {
		numOfBytes = read(sockfd, src_addr, sizeof(struct sockaddr_in));
		if (numOfBytes != sizeof(struct sockaddr_in)) {
			sem_post(FinsHistory[index].s);
			return (-1);

		}
	}
	//	sem_post(FinsHistory[index].s);
	/** The socket jinni sent us, the number of bytes to be received
	 * we have to check that our buffer size is enough to read
	 * */
	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (numOfBytes <= 0) {
		sem_post(FinsHistory[index].s);

		return (-1);

	}
	if (confirmation <= len) {
		bytesread = read(sockfd, buf, confirmation);
		sem_post(FinsHistory[index].s);
		if (bytesread < 0) {

			return (-1);

		}
	}

	else {

		PRINT_DEBUG("passed buffer length sent from the application is not enough to hold the data"
				"we read only up to the passed buffer's length");
		bytesread = read(sockfd, buf, len);
		sem_post(FinsHistory[index].s);
		if (bytesread < 0) {

			return (-1);

		}

	}

	/**TODO remember to unlock the RX_CHANNEL */

	PRINT_DEBUG();

	return (bytesread);

} // end of fins_recvfrom


ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen) {

	_recvfrom = (ssize_t(*)(int sockfd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen)) dlsym(RTLD_NEXT,
			"recvfrom");
	char *errormsg;
	errormsg = dlerror();
	if (errormsg != NULL) {
		PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
	}

	int bytesread;

	PRINT_DEBUG ("sockfd got into recvfrom = %d",sockfd);

	if (checkFinsHistory(getpid(), sockfd) != 0) {
		bytesread = fins_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
		return (bytesread);

	} else

	{

		PRINT_DEBUG("The original recvfrom should not be called ,something is WRONG!!!");
		return (_recvfrom(sockfd, buf, len, flags, src_addr, addrlen));
	}

}

/*----------------------------------------------------------------------------*/
/****************** END OF the recvfrom function------------------------------*/
/*----------------------------------------------------------------------------*/

ssize_t fins_recvmsg(int sockfd, struct msghdr *msg, int flags) {

		int bytesread;

		int numOfBytes = -1;
		u_int opcode;
		int index;

		int sockfd_alter;
		int symbol = 1; 		//default value unless passes msg->msg_name equal NULL
		opcode = recvmsg_call;
		int dataToReadLength=0;
		/**
		 * To handle the
		 *
		 */
		int controlFlag=0;
		pid_t processid;
		int confirmation;
		processid = getpid();

		index = searchFinsHistory(processid, sockfd);
		sockfd_alter = FinsHistory[index].fakeID;

		if( (msg->msg_controllen !=0)  && (msg->msg_control != NULL))
			controlFlag =1;
		if (msg->msg_name == NULL)
			symbol = 0;
		/** TODO lock access to the MAIN SOCKET CHANNEL
		 * to force synchronization with the socket jinni ,
		 * we need also to lock access to the
		 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
		 * RX_channel but the current thread
		 * */
		PRINT_DEBUG();
		sem_wait(main_channel_semaphore2);
		write(socket_channel_desc, &processid, sizeof(pid_t));
		write(socket_channel_desc, &opcode, sizeof(u_int));
		write(socket_channel_desc, &sockfd_alter, sizeof(int));
		write(socket_channel_desc, &flags, sizeof(int));


		write(socket_channel_desc, &symbol, sizeof(int));

		write(socket_channel_desc, &(msg->msg_flags), sizeof(int));

		write(socket_channel_desc, &controlFlag, sizeof(int));
		if(controlFlag){
		write(socket_channel_desc, &(msg->msg_controllen) , sizeof(socklen_t));
		write(socket_channel_desc, msg->msg_control , msg->msg_controllen);
		}

		sem_post(main_channel_semaphore1);
		sem_post(main_channel_semaphore2);

		/**TODO remember to unlock the main channel */

		PRINT_DEBUG();

		sem_wait(FinsHistory[index].as);
		PRINT_DEBUG();
		sem_wait(FinsHistory[index].s);
		PRINT_DEBUG();
		numOfBytes = read(sockfd, &confirmation, sizeof(int));

		if (confirmation != processid) {

			sem_post(FinsHistory[index].s);

			return (-1);
		}

		numOfBytes = read(sockfd, &confirmation, sizeof(int));
		if (confirmation != sockfd_alter) {
			sem_post(FinsHistory[index].s);

			return (-1);
		}
		numOfBytes = read(sockfd, &confirmation, sizeof(int));
		if (confirmation != ACK) {
			sem_post(FinsHistory[index].s);

			return (-1);

		}

		if (symbol == 1) {

			numOfBytes = read(sockfd, &(msg->msg_namelen), sizeof(socklen_t));
						if (numOfBytes > sizeof(struct sockaddr_in)) {
							sem_post(FinsHistory[index].s);
							PRINT_DEBUG("address length is incorrect");
							return (-1);

						}
			numOfBytes = read(sockfd, msg->msg_name, msg->msg_namelen);
			if (numOfBytes != msg->msg_namelen) {
				sem_post(FinsHistory[index].s);
				PRINT_DEBUG("address length is incorrect");
				return (-1);

			}
		}
		//	sem_post(FinsHistory[index].s);
		/** The socket jinni sent us, the number of bytes to be received
		 * we have to check that our buffer size is enough to read
		 * */
		numOfBytes = read(sockfd, &dataToReadLength, sizeof(int));
		if (numOfBytes <= 0) {
			sem_post(FinsHistory[index].s);

			return (-1);

		}

		msg->msg_iov->iov_len = dataToReadLength;
		msg->msg_iov->iov_base = (u_char *)malloc(dataToReadLength);
		bytesread = read(sockfd, msg->msg_iov->iov_base, dataToReadLength);
			sem_post(FinsHistory[index].s);
			if (bytesread < 0) {

				msg->msg_iov->iov_len = 0;
				free(msg->msg_iov->iov_base);
				msg->msg_iov->iov_base = NULL;
				msg->msg_iovlen =0;
				PRINT_DEBUG();
				return (-1);

			}


			else {

				msg->msg_iovlen =1 ;
				PRINT_DEBUG();

				return(bytesread);

				}









} // end of fins_recvmsg


ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {

	_recvmsg = (ssize_t(*)(int sockfd, struct msghdr *msg, int flags)) dlsym(
			RTLD_NEXT, "recvmsg");

	char *errormsg;
	errormsg = dlerror();
	if (errormsg != NULL) {
		PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
	}

	PRINT_DEBUG ("sockfd got into recvmsg = %d",sockfd);

	if (checkFinsHistory(getpid(), sockfd) != 0) {
		return (fins_recvmsg(sockfd, msg, flags));

	} else

	{

		PRINT_DEBUG("The original recvmsg should not be called ,something is WRONG!!!");
		return (_recvmsg(sockfd, msg, flags));
	}

} // end of recvmsg


/*----------------------------------------------------------------------------*/
/****************** END OF the recvmsg function------------------------------*/
/*----------------------------------------------------------------------------*/

ssize_t fins_send(int sockfd, const void *buf, size_t len, int flags) {

	/** TODO in case the flags value equal to -1000
	 * then the handler in socket jinni should knows that this is not a regular
	 * sendto call but that was originally actually a direct (write) to socket
	 * descriptor call
	 */
	// return ( fins_sendto (sockfd, buf, len,flags, NULL, 0)) ;

	PRINT_DEBUG("");
	int bytesread;
	int numOfBytes = -1;
	u_int opcode;
	opcode = send_call;
	pid_t processid;
	int confirmation;
	int sockfd_alter;
	int index;

	processid = getpid();

	index = searchFinsHistory(processid, sockfd);
	sockfd_alter = FinsHistory[index].fakeID;

	PRINT_DEBUG("");

	/** TODO lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */
	sem_wait(main_channel_semaphore2);
	PRINT_DEBUG("");
	write(socket_channel_desc, &processid, sizeof(pid_t));
	write(socket_channel_desc, &opcode, sizeof(u_int));
	write(socket_channel_desc, &sockfd_alter, sizeof(int));
	write(socket_channel_desc, &len, sizeof(size_t));
	write(socket_channel_desc, buf, len);
	write(socket_channel_desc, &flags, sizeof(int));
	sem_post(main_channel_semaphore1);
	PRINT_DEBUG("");
	sem_post(main_channel_semaphore2);

	PRINT_DEBUG("");

	/**TODO remember to unlock the main channel */
	/** The code below needs to force kind of synchronization
	 * it might be hard to achieve , test this code throughly later
	 */
	sem_wait(FinsHistory[index].as);
	sem_wait(FinsHistory[index].s);
	PRINT_DEBUG("");

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	PRINT_DEBUG("");
	if (confirmation != processid) {
		//sem_post(main_channel_semaphore1);
		sem_post(FinsHistory[index].s);
		PRINT_DEBUG("read processid = %d", confirmation);

		return (-1);
	} PRINT_DEBUG("");

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != sockfd_alter) {
		//sem_post(main_channel_semaphore1);
		sem_post(FinsHistory[index].s);
		PRINT_DEBUG("read sockfd = %d", confirmation);

		return (-1);
	} PRINT_DEBUG("");

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	//sem_post(main_channel_semaphore1);
	sem_post(FinsHistory[index].s);
	PRINT_DEBUG("");

	if (confirmation != ACK)
		return (-1);

	/** On Success returns the number of characters sent
	 * On Failure , it returns (-1)
	 *  */PRINT_DEBUG("");

	return (len);

} // end of fins_send

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {

	_send = (ssize_t(*)(int sockfd, const void *buf, size_t len, int flags)) dlsym(
					RTLD_NEXT, "send");
	char *errormsg;
	errormsg = dlerror();
	if (errormsg != NULL) {
		PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
	}

	PRINT_DEBUG ("sockfd got into send = %d",sockfd);

	if (checkFinsHistory(getpid(), sockfd) != 0) {
		return (fins_send(sockfd, buf, len, flags));

	} else

	{

		PRINT_DEBUG("The original send should not be called ,something is WRONG!!!");
		return (_send(sockfd, buf, len, flags));
	}

} // end of send


/*----------------------------------------------------------------------------*/
/****************** END OF the send function------------------------------*/
/*----------------------------------------------------------------------------*/

ssize_t fins_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen) {

	PRINT_DEBUG("");
	int bytesread;
	int numOfBytes = -1;
	u_int opcode;
	opcode = sendto_call;
	pid_t processid;
	int confirmation;
	int sockfd_alter;
	int index;

	processid = getpid();

	index = searchFinsHistory(processid, sockfd);
	sockfd_alter = FinsHistory[index].fakeID;

	PRINT_DEBUG("");

	/** TODO lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */
	sem_wait(main_channel_semaphore2);
	PRINT_DEBUG("");
	write(socket_channel_desc, &processid, sizeof(pid_t));
	write(socket_channel_desc, &opcode, sizeof(u_int));
	write(socket_channel_desc, &sockfd_alter, sizeof(int));
	write(socket_channel_desc, &len, sizeof(size_t));
	write(socket_channel_desc, buf, len);
	write(socket_channel_desc, &flags, sizeof(int));
	write(socket_channel_desc, &addrlen, sizeof(socklen_t));
	write(socket_channel_desc, dest_addr, addrlen);
	sem_post(main_channel_semaphore1);
	PRINT_DEBUG("");
	sem_post(main_channel_semaphore2);

	PRINT_DEBUG("");

	/**TODO remember to unlock the main channel */
	/** The code below needs to force kind of synchronization
	 * it might be hard to achieve , test this code throughly later
	 */
	sem_wait(FinsHistory[index].as);
	sem_wait(FinsHistory[index].s);
	PRINT_DEBUG("");

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	PRINT_DEBUG("");
	if (confirmation != processid) {
		//sem_post(main_channel_semaphore1);
		sem_post(FinsHistory[index].s);
		PRINT_DEBUG("read processid = %d", confirmation);

		return (-1);
	} PRINT_DEBUG("");

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != sockfd_alter) {
		//sem_post(main_channel_semaphore1);
		sem_post(FinsHistory[index].s);
		PRINT_DEBUG("read sockfd = %d", confirmation);

		return (-1);
	} PRINT_DEBUG("");

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	//sem_post(main_channel_semaphore1);
	sem_post(FinsHistory[index].s);
	PRINT_DEBUG("");

	if (confirmation != ACK)
		return (-1);

	/** On Success returns the number of characters sent
	 * On Failure , it returns (-1)
	 *  */PRINT_DEBUG("");

	return (len);

} // end of fins_sendto


ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen) {

	_sendto = (ssize_t(*)(int sockfd, const void *buf, size_t len, int flags,
			const struct sockaddr *dest_addr, socklen_t addrlen)) dlsym(
			RTLD_NEXT, "sendto");
	char *errormsg;
	errormsg = dlerror();
	if (errormsg != NULL) {
		PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
	}

	PRINT_DEBUG ("sockfd got into sendto = %d",sockfd);

	if (checkFinsHistory(getpid(), sockfd) != 0) {
		return (fins_sendto(sockfd, buf, len, flags, dest_addr, addrlen));

	} else

	{

		PRINT_DEBUG("The original sendto should not be called ,something is WRONG!!!");
		return (_sendto(sockfd, buf, len, flags, dest_addr, addrlen));
	}

} // end of sendto


/*----------------------------------------------------------------------------*/
/****************** END OF the sendto function------------------------------*/
/*----------------------------------------------------------------------------*/

ssize_t fins_sendmsg(int sockfd, const struct msghdr *msg, int flags) {

	int bytessent;
	int numOfBytes = -1;
	u_int opcode;
	int index;
	int sockfd_alter;
	int controlFlag = 0;
	u_char *dataToSend;
	int dataLength=0;
	int shift=0;

	int symbol = 1; 	/**default value unless passes address equal NULL */
	opcode = sendmsg_call;

	pid_t processid;
	int confirmation;
	int i=0;

	processid = getpid();
	index = searchFinsHistory(processid, sockfd);
	sockfd_alter = FinsHistory[index].fakeID;

	if (msg->msg_controllen !=0)
		controlFlag = 1;


	for (i=0 ; i < (msg->msg_iovlen); i++)
		{
			dataLength = dataLength + (msg->msg_iov[i]).iov_len;
		}

	dataToSend = (u_char *) malloc(dataLength);
	dataLength = 0 ;
	i = 0;

	PRINT_DEBUG("Number of elements in the vector =  %d", (msg->msg_iovlen));

	for (i=0 ; i < (msg->msg_iovlen); i++)
	{

		memcpy(dataToSend + dataLength, (msg->msg_iov[i]).iov_base, (msg->msg_iov[i]).iov_len);

		dataLength = dataLength + (msg->msg_iov[i]).iov_len;

		PRINT_DEBUG("current element %d , element length = %d", i ,(msg->msg_iov[i]).iov_len );

	}

	/** TODO lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */

	if (msg->msg_name == NULL )
		symbol = 0;
	PRINT_DEBUG();
	sem_wait(main_channel_semaphore2);
	write(socket_channel_desc, &processid, sizeof(pid_t));
	write(socket_channel_desc, &opcode, sizeof(u_int));
	write(socket_channel_desc, &sockfd_alter, sizeof(int));
	write(socket_channel_desc, &flags, sizeof(int));
	write(socket_channel_desc, &(msg->msg_namelen), sizeof(socklen_t));
	write(socket_channel_desc, &symbol, sizeof(int));
	write(socket_channel_desc, msg->msg_name, msg->msg_namelen);
	write(socket_channel_desc, &(msg->msg_flags), sizeof(int));
	write(socket_channel_desc, &controlFlag, sizeof(int));
	if(controlFlag){

		write(socket_channel_desc, &(msg->msg_controllen) , sizeof(socklen_t));
		write(socket_channel_desc, msg->msg_control , msg->msg_controllen);

	}

	/**
	 * Notice that the compiler takes  (msg->msg_iov[i]) as a struct not a pointer to struct
	 * */
	write(socket_channel_desc, &dataLength , sizeof(int));
	write(socket_channel_desc, dataToSend, dataLength );


	sem_post(main_channel_semaphore1);
	sem_post(main_channel_semaphore2);

	/**TODO remember to unlock the main channel */

	PRINT_DEBUG();

	sem_wait(FinsHistory[index].as);
	PRINT_DEBUG();
	sem_wait(FinsHistory[index].s);
	PRINT_DEBUG();
	numOfBytes = read(sockfd, &confirmation, sizeof(int));

	if (confirmation != processid) {

		sem_post(FinsHistory[index].s);

		return (-1);
	}

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != sockfd_alter) {
		sem_post(FinsHistory[index].s);

		return (-1);
	}
	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	sem_post(FinsHistory[index].s);

	if (confirmation != ACK) {

		return (-1);

	}

/**
 * More accurate is to get the bytes sent from the Core process.
 * Maybe buffer handling causes not writing part of the message
 */

	/**TODO remember to unlock the RX_CHANNEL */

	PRINT_DEBUG("BytesSent by sendmsg = %d", dataLength);

	return (dataLength);




} // end of fins_sendmsg


ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {

	_sendmsg
			= (ssize_t(*)(int sockfd, const struct msghdr *msg, int flags)) dlsym(
					RTLD_NEXT, "sendmsg");

	char *errormsg;
	errormsg = dlerror();
	if (errormsg != NULL) {
		PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
	}

	PRINT_DEBUG ("sockfd got into sendmsg = %d",sockfd);

	if (checkFinsHistory(getpid(), sockfd) != 0) {
		return (fins_sendmsg(sockfd, msg, flags));

	} else

	{

		PRINT_DEBUG("The original sendmsg should not be called ,something is WRONG!!!");
		return (_sendmsg(sockfd, msg, flags));
	}

} // end of sendmsg


/*----------------------------------------------------------------------------*/
/****************** END OF the sendmsg function------------------------------*/
/*----------------------------------------------------------------------------*/

int fins_shutdown(int sockfd, int how) {

	int bytesread;

	int numOfBytes = -1;
	u_int opcode;
	int index;
	int sockfd_alter;

	opcode = close_call;

	pid_t processid;
	int confirmation;
	processid = getpid();

	index = searchFinsHistory(processid, sockfd);
	sockfd_alter = FinsHistory[index].fakeID;

	/** TODO lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */
	PRINT_DEBUG();
	sem_wait(main_channel_semaphore2);
		write(socket_channel_desc, &processid, sizeof(pid_t));
		write(socket_channel_desc, &opcode, sizeof(u_int));
		write(socket_channel_desc, &sockfd_alter, sizeof(int));
		write(socket_channel_desc, &how, sizeof(int));
	sem_post(main_channel_semaphore1);
	sem_post(main_channel_semaphore2);



	/**TODO remember to unlock the main channel */

		PRINT_DEBUG();

		sem_wait(FinsHistory[index].as);
		PRINT_DEBUG();
		sem_wait(FinsHistory[index].s);
		PRINT_DEBUG();
		numOfBytes = read(sockfd, &confirmation, sizeof(int));

		if (confirmation != processid) {

			sem_post(FinsHistory[index].s);

			return (-1);
		}

		numOfBytes = read(sockfd, &confirmation, sizeof(int));
		if (confirmation != sockfd_alter) {
			sem_post(FinsHistory[index].s);

			return (-1);
		}
		numOfBytes = read(sockfd, &confirmation, sizeof(int));
		sem_post(FinsHistory[index].s);

		if (confirmation != ACK) {

			return (-1);

		}



		/**TODO remember to unlock the RX_CHANNEL */

		PRINT_DEBUG();

		return (0); //return 0 on success



} // end of fins_shutdown


int shutdown(int sockfd, int how) {
	_shutdown = (int(*)(int fd, int how)) dlsym(RTLD_NEXT, "shutdown");
	char *errormsg;
	errormsg = dlerror();
	if (errormsg != NULL) {
		PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
	}

	PRINT_DEBUG ("sockfd from process %d got into shutdown = %d",getpid(),sockfd);

	if (checkFinsHistory(getpid(), sockfd) != 0) {
		return (fins_shutdown(sockfd, how));

	} else

	{

		PRINT_DEBUG("The original _shutdown should not be called ,something is WRONG!!!");
		return (_shutdown(sockfd, how));
	}

}

/*----------------------------------------------------------------------------*/
/****************** END OF the shutdown function------------------------------*/
/*----------------------------------------------------------------------------*/

ssize_t fins_write(int fd, const void *buf, size_t count) {
	/** write is the same as send but without flags
	 * so we send an invalid -ve value as flag and check for the flag value
	 * when we receive this value on the callee
	 */
	PRINT_DEBUG("fins_write has been specifically called");
	return (fins_send(fd, buf, count, -1000));

} // end of fins_write


ssize_t write(int sockfd, const void *buf, size_t count) {

	_write = (ssize_t(*)(int sockfd, const void *buf, size_t count)) dlsym(
			RTLD_NEXT, "write");
	if (checkFinsHistory(getpid(), sockfd) != 0) {
		PRINT_DEBUG();
		return (fins_write(sockfd, buf, count));

	} else

	{

		PRINT_DEBUG("The original (write) has been called, The passed Descriptor does not "
				"belong to FINS");
		return (_write(sockfd, buf, count));
	}

}

/*----------------------------------------------------------------------------*/
/****************** END OF the write function------------------------------*/
/*----------------------------------------------------------------------------*/

int fins_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

	int bytesread;

	int numOfBytes = -1;
	u_int opcode;
	int index;
	int sockfd_alter;
	int symbol = 1; //default value unless passes address equal NULL
	opcode = getpeername_call;

	pid_t processid;
	int confirmation;
	processid = getpid();

	index = searchFinsHistory(processid, sockfd);
	sockfd_alter = FinsHistory[index].fakeID;

	/** Tlock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */
	PRINT_DEBUG();
	sem_wait(main_channel_semaphore2);
	write(socket_channel_desc, &processid, sizeof(pid_t));
	write(socket_channel_desc, &opcode, sizeof(u_int));
	write(socket_channel_desc, &sockfd_alter, sizeof(int));
	sem_post(main_channel_semaphore1);
	sem_post(main_channel_semaphore2);

	/**TODO remember to unlock the main channel */

	PRINT_DEBUG();

	sem_wait(FinsHistory[index].as);
	PRINT_DEBUG();
	sem_wait(FinsHistory[index].s);
	PRINT_DEBUG();
	numOfBytes = read(sockfd, &confirmation, sizeof(int));

	if (confirmation != processid) {

		sem_post(FinsHistory[index].s);

		return (-1);
	}

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != sockfd_alter) {
		sem_post(FinsHistory[index].s);

		return (-1);
	}
	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != ACK) {
		sem_post(FinsHistory[index].s);

		return (-1);

	}

	numOfBytes = read(sockfd, addrlen, sizeof(int));

	if (numOfBytes != sizeof(int)) {
		sem_post(FinsHistory[index].s);
		return (-1);

	} PRINT_DEBUG("%d",*addrlen);
	numOfBytes = read(sockfd, addr, *addrlen);
	sem_post(FinsHistory[index].s);
	if (numOfBytes != *addrlen) {
		sem_post(FinsHistory[index].s);
		return (-1);

	}

	PRINT_DEBUG("%d, %d", ((struct sockaddr_in *)addr)->sin_addr.s_addr , ((struct sockaddr_in *)addr)->sin_port ) ;

	/**TODO remember to unlock the RX_CHANNEL */

	PRINT_DEBUG();

	return (0); //return 0 on success

} // end of fins_getpeername


int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

	_getpeername = (int(*)(int sockfd, struct sockaddr *addr,
			socklen_t *addrlen)) dlsym(RTLD_NEXT, "getpeername");

	char *errormsg;
	errormsg = dlerror();
	if (errormsg != NULL) {
		PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
	}

	PRINT_DEBUG();

	if (checkFinsHistory(getpid(), sockfd) != 0) {
		PRINT_DEBUG("getpeername");
		return (fins_getpeername(sockfd, addr, addrlen));

	} else

	{

		PRINT_DEBUG("The original (getpeername) has been called, The passed Descriptor does not "
				"belong to FINS");
		return (_getpeername(sockfd, addr, addrlen));
	}

}

/*----------------------------------------------------------------------------*/
/****************** END OF the getpeername function------------------------------*/
/*----------------------------------------------------------------------------*/


int fins_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{


	int bytesread;

	int numOfBytes = -1;
	u_int opcode;
	int index;
	int sockfd_alter;
	int symbol = 1; //default value unless passes address equal NULL
	opcode = getsockopt_call;

	pid_t processid;
	int confirmation;
	processid = getpid();

	index = searchFinsHistory(processid, sockfd);
	sockfd_alter = FinsHistory[index].fakeID;

	/** lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */
	PRINT_DEBUG();
	sem_wait(main_channel_semaphore2);
	write(socket_channel_desc, &processid, sizeof(pid_t));
	write(socket_channel_desc, &opcode, sizeof(u_int));
	write(socket_channel_desc, &sockfd_alter, sizeof(int));
	write(socket_channel_desc, &level, sizeof(int));
	write(socket_channel_desc, &optname, sizeof(int));
	write(socket_channel_desc, optlen, sizeof(socklen_t));
	sem_post(main_channel_semaphore1);
	sem_post(main_channel_semaphore2);



	/**TODO remember to unlock the main channel */

		PRINT_DEBUG();

		sem_wait(FinsHistory[index].as);
		PRINT_DEBUG();
		sem_wait(FinsHistory[index].s);
		PRINT_DEBUG();
		numOfBytes = read(sockfd, &confirmation, sizeof(int));

		if (confirmation != processid) {

			sem_post(FinsHistory[index].s);

			return (-1);
		}

		numOfBytes = read(sockfd, &confirmation, sizeof(int));
		if (confirmation != sockfd_alter) {
			sem_post(FinsHistory[index].s);

			return (-1);
		}
		numOfBytes = read(sockfd, &confirmation, sizeof(int));
		if (confirmation != ACK) {
			sem_post(FinsHistory[index].s);

			return (-1);

		}

		numOfBytes = read(sockfd, optlen, sizeof(socklen_t));

		if (numOfBytes != sizeof(int)) {
			sem_post(FinsHistory[index].s);
			return (-1);

		}
		PRINT_DEBUG("%d",*optlen);
		numOfBytes = read(sockfd, optval, *optlen);
		sem_post(FinsHistory[index].s);
		if (numOfBytes != *optlen) {
			return (-1);

		}

		PRINT_DEBUG("%d", 	*((uint32_t *)optval) ) ;

		/**TODO remember to unlock the RX_CHANNEL */

		PRINT_DEBUG();

		return (0); //return 0 on success





}



int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{

	_getsockopt = (int(*)(int sockfd, int level, int optname, void *optval,
			socklen_t *optlen)) dlsym(RTLD_NEXT, "getsockopt");


		char *errormsg;
		errormsg = dlerror();
		if (errormsg != NULL) {
			PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
		}

		PRINT_DEBUG();

		if (checkFinsHistory(getpid(), sockfd) != 0) {
			PRINT_DEBUG("getsockopt");
			return (fins_getsockopt(sockfd, level, optname, optval, optlen));

		} else

		{

			PRINT_DEBUG("The original (getsockopt) has been called, The passed Descriptor does not "
					"belong to FINS");
			return (_getsockopt(sockfd, level, optname, optval, optlen));
		}




}

/** ------------------------------------------------------------------
 *----------------- end of the getsockopt function ------
 ------------------------------------------------------------------*/



int fins_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{



	int bytesread;

	int numOfBytes = -1;
	u_int opcode;
	int index;
	int sockfd_alter;

	opcode = setsockopt_call;

	pid_t processid;
	int confirmation;
	processid = getpid();

	index = searchFinsHistory(processid, sockfd);
	sockfd_alter = FinsHistory[index].fakeID;

	/** lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */
	PRINT_DEBUG();
	sem_wait(main_channel_semaphore2);
	write(socket_channel_desc, &processid, sizeof(pid_t));
	write(socket_channel_desc, &opcode, sizeof(u_int));
	write(socket_channel_desc, &sockfd_alter, sizeof(int));
	write(socket_channel_desc, &level, sizeof(int));
	write(socket_channel_desc, &optname, sizeof(int));
	write(socket_channel_desc, &optlen, sizeof(socklen_t));
	write(socket_channel_desc, optval, optlen);

	sem_post(main_channel_semaphore1);
	sem_post(main_channel_semaphore2);



	/**TODO remember to unlock the main channel */

		PRINT_DEBUG();

		sem_wait(FinsHistory[index].as);
		PRINT_DEBUG();
		sem_wait(FinsHistory[index].s);
		PRINT_DEBUG();
		numOfBytes = read(sockfd, &confirmation, sizeof(int));

		if (confirmation != processid) {

			sem_post(FinsHistory[index].s);

			return (-1);
		}

		numOfBytes = read(sockfd, &confirmation, sizeof(int));
		if (confirmation != sockfd_alter) {
			sem_post(FinsHistory[index].s);

			return (-1);
		}
		numOfBytes = read(sockfd, &confirmation, sizeof(int));
		sem_post(FinsHistory[index].s);

		if (confirmation != ACK) {

			return (-1);

		}



		/**TODO remember to unlock the RX_CHANNEL */

		PRINT_DEBUG();

		return (0); //return 0 on success









}






int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{



	_setsockopt = ( int(*) (int sockfd, int level, int optname, const void *optval,
			socklen_t optlen)) dlsym(RTLD_NEXT, "setsockopt");



		char *errormsg;
		errormsg = dlerror();
		if (errormsg != NULL) {
			PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
		}

		PRINT_DEBUG();

		if (checkFinsHistory(getpid(), sockfd) != 0) {
			PRINT_DEBUG("setsockopt");
			return (fins_setsockopt(sockfd, level, optname, optval, optlen));

		} else

		{

			PRINT_DEBUG("The original (setsockopt) has been called, The passed Descriptor does not "
					"belong to FINS");
			return (_setsockopt(sockfd, level, optname, optval, optlen));
		}


}



/**
 * **************** END OF setsockopt Fucntion ******************************
 *
 */




int fins_close(int sockfd){


	int bytesread;

	int numOfBytes = -1;
	u_int opcode;
	int index;
	int sockfd_alter;

	opcode = close_call;

	pid_t processid;
	int confirmation;
	processid = getpid();

	index = searchFinsHistory(processid, sockfd);
	sockfd_alter = FinsHistory[index].fakeID;

	/** lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */
	PRINT_DEBUG();
	sem_wait(main_channel_semaphore2);
	write(socket_channel_desc, &processid, sizeof(pid_t));
	write(socket_channel_desc, &opcode, sizeof(u_int));
	write(socket_channel_desc, &sockfd_alter, sizeof(int));
	sem_post(main_channel_semaphore1);
	sem_post(main_channel_semaphore2);



	/**TODO remember to unlock the main channel */

		PRINT_DEBUG();

		sem_wait(FinsHistory[index].as);
		PRINT_DEBUG();
		sem_wait(FinsHistory[index].s);
		PRINT_DEBUG();
		numOfBytes = read(sockfd, &confirmation, sizeof(int));

		if (confirmation != processid) {

			sem_post(FinsHistory[index].s);

			return (-1);
		}

		numOfBytes = read(sockfd, &confirmation, sizeof(int));
		if (confirmation != sockfd_alter) {
			sem_post(FinsHistory[index].s);

			return (-1);
		}
		numOfBytes = read(sockfd, &confirmation, sizeof(int));
		sem_post(FinsHistory[index].s);

		if (confirmation != ACK) {

			return (-1);

		}



		/**TODO remember to unlock the RX_CHANNEL */

		PRINT_DEBUG();

		return (0); //return 0 on success


}





int close(int sockfd)
{



	_close = ( int(*)(int fd) ) dlsym(RTLD_NEXT, "close");


		char *errormsg;
		errormsg = dlerror();
		if (errormsg != NULL) {
			PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
		}

		PRINT_DEBUG();

		if (checkFinsHistory(getpid(), sockfd) != 0) {
			PRINT_DEBUG("close");
			return (fins_close(sockfd));

		} else

		{

			PRINT_DEBUG("The original close has been called, The passed Descriptor does not "
					"belong to FINS");
			return (_close(sockfd));
		}


}


/**
 * **************** END OF Close Fucntion ******************************
 *
 */



int fins_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen){

	int bytesread;

	int numOfBytes = -1;
	u_int opcode;
	int index;
	int sockfd_alter;

	opcode = getsockname_call;


	pid_t processid;
	int confirmation;
	processid = getpid();

	index = searchFinsHistory(processid, sockfd);
	sockfd_alter = FinsHistory[index].fakeID;

	/** lock access to the MAIN SOCKET CHANNEL
	 * to force synchronization with the socket jinni ,
	 * we need also to lock access to the
	 * CLIENT_CHANNEL_RX to make sure no one (NO OTHER THREAD from the same application) reads from the
	 * RX_channel but the current thread
	 * */
	PRINT_DEBUG();
	sem_wait(main_channel_semaphore2);
		write(socket_channel_desc, &processid, sizeof(pid_t));
		write(socket_channel_desc, &opcode, sizeof(u_int));
		write(socket_channel_desc, &sockfd_alter, sizeof(int));
	sem_post(main_channel_semaphore1);
	sem_post(main_channel_semaphore2);



	/**TODO remember to unlock the main channel */

	PRINT_DEBUG();

	sem_wait(FinsHistory[index].as);
	PRINT_DEBUG();
	sem_wait(FinsHistory[index].s);
	PRINT_DEBUG();
	numOfBytes = read(sockfd, &confirmation, sizeof(int));

	if (confirmation != processid) {

		sem_post(FinsHistory[index].s);

		return (-1);
	}

	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != sockfd_alter) {
		sem_post(FinsHistory[index].s);

		return (-1);
	}
	numOfBytes = read(sockfd, &confirmation, sizeof(int));
	if (confirmation != ACK) {
		sem_post(FinsHistory[index].s);

		return (-1);

	}

	numOfBytes = read(sockfd, addrlen, sizeof(int));
	if (*addrlen <= 0) {
		sem_post(FinsHistory[index].s);

		return (-1);

	}
	numOfBytes = read(sockfd, addr, *addrlen);
	sem_post(FinsHistory[index].s);

		if (numOfBytes != *addrlen) {

			return (-1);

		}


	/**TODO remember to unlock the RX_CHANNEL */

	PRINT_DEBUG();

	return (0); //return 0 on success


}


int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen){


	_getsockname = ( int(*)( int sockfd, struct sockaddr *addr, socklen_t *addrlen
					) ) dlsym(RTLD_NEXT, "getsockname");


		char *errormsg;
		errormsg = dlerror();
		if (errormsg != NULL) {
			PRINT_DEBUG("\n failed to load the original symbol %s", errormsg);
		}

		PRINT_DEBUG();

		if (checkFinsHistory(getpid(), sockfd) != 0) {
			PRINT_DEBUG("getsockname");
			return (fins_getsockname(sockfd, addr, addrlen));

		} else

		{

			PRINT_DEBUG("The original (getsockname) has been called, The passed Descriptor does not "
					"belong to FINS");
			return (  _getsockname(sockfd, addr, addrlen)   );
		}



}



/**
 * **************** END OF getsockname Fucntion ******************************
 *
 */




//void main()
//{
//
//
//
//	PRINT_DEBUG("LOADED ");
//
//
//
//
//
//
//}




/** --------------------------------------------------------------------------*/
ssize_t write_msghdr_to_pipe(int sockfd, struct msghdr *msg) {

	int byteswritten;

	return (byteswritten);
}

