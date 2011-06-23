/*
 * 		@file socketgeni.c
 * *  	@date Nov 26, 2010
 *      @author Abdallah Abdallah
 *      @brief This is the FINS CORE including (the Jinni name pipes based
 *      server)
 *      notice that A read call will normally block; that is, it will cause the process to
 *       wait until data becomes available. If the other end of the pipe has been closed,
 *       then no process has the pipe open for writing, and the read blocks. Because this isn’t
 *       very helpful, a read on a pipe that isn’t open for writing returns zero rather than
 *       blocking. This allows the reading process to detect the pipe equivalent of end of file
 *       and act appropriately. Notice that this isn’t the same as reading an invalid file
 *       descriptor, which read considers an error and indicates by returning –1.
 *       */

#include "core.h"
#include <ipv4.h>
#include <udp.h>
#include <tcp.h>
#include <arp.h>
#include <swito.h>
#include <rtm.h>

/** Global parameters of the socketjinni
 *
 */

/**
 * TODO free and close/DESTORY all the semaphores before exit !!!
 * POSIX does not clean the garbage of semaphores at exiting
 * It must be cleaned manually incase the program crashes
 *
 *
 */

struct finssocket jinniSockets[MAX_sockets];
struct socketIdentifier FinsHistory[MAX_sockets];

/** The list of major Queues which connect the modules to each other
 * including the switch module
 * The list of Semaphores which protect the Queues
 */

finsQueue Jinni_to_Switch_Queue;
finsQueue Switch_to_Jinni_Queue;

finsQueue Switch_to_RTM_Queue;
finsQueue RTM_to_Switch_Queue;

finsQueue Switch_to_UDP_Queue;
finsQueue UDP_to_Switch_Queue;

finsQueue Switch_to_TCP_Queue;
finsQueue TCP_to_Switch_Queue;

finsQueue Switch_to_ARP_Queue;
finsQueue ARP_to_Switch_Queue;

finsQueue Switch_to_IPv4_Queue;
finsQueue IPv4_to_Switch_Queue;

finsQueue Switch_to_EtherStub_Queue;
finsQueue EtherStub_to_Switch_Queue;

finsQueue Switch_to_ICMP_Queue;
finsQueue ICMP_to_Switch_Queue;


sem_t Jinni_to_Switch_Qsem;
sem_t Switch_to_Jinni_Qsem;

/** RunTimeManager Module to connect to the user interface  */
sem_t RTM_to_Switch_Qsem;
sem_t Switch_to_RTM_Qsem;

sem_t Switch_to_UDP_Qsem;
sem_t UDP_to_Switch_Qsem;

sem_t ICMP_to_Switch_Qsem;
sem_t Switch_to_ICMP_Qsem;

sem_t Switch_to_TCP_Qsem;
sem_t TCP_to_Switch_Qsem;

sem_t Switch_to_IPv4_Qsem;
sem_t IPv4_to_Switch_Qsem;

sem_t Switch_to_ARP_Qsem;
sem_t ARP_to_Switch_Qsem;

sem_t Switch_to_EtherStub_Qsem;
sem_t EtherStub_to_Switch_Qsem;

finsQueue modules_IO_queues[MAX_modules];
sem_t *IO_queues_sem[MAX_modules];

/** ----------------------------------------------------------*/

int socket_channel_desc = -1;
int capture_pipe_fd; /** capture file descriptor to read from capturer */
int inject_pipe_fd; /** inject file descriptor to read from capturer */
int rtm_in_fd;
int rtm_out_fd;

sem_t *meen_channel_semaphore1;
sem_t *meen_channel_semaphore2;

char meen_sem_name1[] = "main_channel1";
char meen_sem_name2[] = "main_channel2";


/** Ethernet Stub Variables  */
#define CAPTURE_PIPE "/tmp/fins/fins_capture"
#define INJECT_PIPE "/tmp/fins/fins_inject"



/**
 * @brief initialize the jinni sockets array by filling with value of -1
 * @param
 * @return nothing
 */
void init_jinnisockets() {
	int i;
	for (i = 0; i < MAX_sockets; i++) {
		jinniSockets[i].processid = -1;
		jinniSockets[i].sockfd = -1;
		jinniSockets[i].fakeID = -1;
		jinniSockets[i].connection_status = 0;
	}

}

void Queues_init() {

	Jinni_to_Switch_Queue = init_queue("jinni2switch", MAX_Queue_size);
	Switch_to_Jinni_Queue = init_queue("switch2jinni", MAX_Queue_size);
	modules_IO_queues[0] = Jinni_to_Switch_Queue;
	modules_IO_queues[1] = Switch_to_Jinni_Queue;
	sem_init(&Jinni_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_Jinni_Qsem, 0, 1);
	IO_queues_sem[0] = &Jinni_to_Switch_Qsem;
	IO_queues_sem[1] = &Switch_to_Jinni_Qsem;

	UDP_to_Switch_Queue = init_queue("udp2switch", MAX_Queue_size);
	Switch_to_UDP_Queue = init_queue("switch2udp", MAX_Queue_size);
	modules_IO_queues[2] = UDP_to_Switch_Queue;
	modules_IO_queues[3] = Switch_to_UDP_Queue;
	sem_init(&UDP_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_UDP_Qsem, 0, 1);
	IO_queues_sem[2] = &UDP_to_Switch_Qsem;
	IO_queues_sem[3] = &Switch_to_UDP_Qsem;

	TCP_to_Switch_Queue = init_queue("tcp2switch", MAX_Queue_size);
	Switch_to_TCP_Queue = init_queue("switch2tcp", MAX_Queue_size);
	modules_IO_queues[4] = TCP_to_Switch_Queue;
	modules_IO_queues[5] = Switch_to_TCP_Queue;
	sem_init(&TCP_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_TCP_Qsem, 0, 1);
	IO_queues_sem[4] = &TCP_to_Switch_Qsem;
	IO_queues_sem[5] = &Switch_to_TCP_Qsem;

	IPv4_to_Switch_Queue = init_queue("ipv42switch", MAX_Queue_size);
	Switch_to_IPv4_Queue = init_queue("switch2ipv4", MAX_Queue_size);
	modules_IO_queues[6] = IPv4_to_Switch_Queue;
	modules_IO_queues[7] = Switch_to_IPv4_Queue;
	sem_init(&IPv4_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_IPv4_Qsem, 0, 1);
	IO_queues_sem[6] = &IPv4_to_Switch_Qsem;
	IO_queues_sem[7] = &Switch_to_IPv4_Qsem;

	ARP_to_Switch_Queue = init_queue("arp2switch", MAX_Queue_size);
	Switch_to_ARP_Queue = init_queue("switch2arp", MAX_Queue_size);
	modules_IO_queues[8] = ARP_to_Switch_Queue;
	modules_IO_queues[9] = Switch_to_ARP_Queue;
	sem_init(&ARP_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_ARP_Qsem, 0, 1);
	IO_queues_sem[8] = &ARP_to_Switch_Qsem;
	IO_queues_sem[9] = &Switch_to_ARP_Qsem;

	EtherStub_to_Switch_Queue = init_queue("etherstub2switch", MAX_Queue_size);
	Switch_to_EtherStub_Queue = init_queue("switch2etherstub", MAX_Queue_size);
	modules_IO_queues[10] = EtherStub_to_Switch_Queue;
	modules_IO_queues[11] = Switch_to_EtherStub_Queue;
	sem_init(&EtherStub_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_EtherStub_Qsem, 0, 1);
	IO_queues_sem[10] = &EtherStub_to_Switch_Qsem;
	IO_queues_sem[11] = &Switch_to_EtherStub_Qsem;

	ICMP_to_Switch_Queue = init_queue("icmp2switch", MAX_Queue_size);
	Switch_to_ICMP_Queue = init_queue("switch2icmp", MAX_Queue_size);
	modules_IO_queues[12] = ICMP_to_Switch_Queue;
	modules_IO_queues[13] = Switch_to_ICMP_Queue;
	sem_init(&ICMP_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_ICMP_Qsem, 0, 1);
	IO_queues_sem[12] = &ICMP_to_Switch_Qsem;
	IO_queues_sem[13] = &Switch_to_ICMP_Qsem;


	RTM_to_Switch_Queue = init_queue("rtm2switch", MAX_Queue_size);
	Switch_to_RTM_Queue = init_queue("switch2rtm", MAX_Queue_size);
		modules_IO_queues[14] = RTM_to_Switch_Queue;
		modules_IO_queues[15] = Switch_to_RTM_Queue;
		sem_init(&RTM_to_Switch_Qsem, 0, 1);
		sem_init(&Switch_to_RTM_Qsem, 0, 1);
		IO_queues_sem[14] = &RTM_to_Switch_Qsem;
		IO_queues_sem[15] = &Switch_to_RTM_Qsem;




}

void jinni_init() {

	/** the semaphore is initially locked */
	//meen_channel_semaphore1 = sem_open(meen_sem_name1,O_CREAT|O_EXCL,0644,0);
	meen_channel_semaphore1 = sem_open(meen_sem_name1, O_CREAT, 0644, 0);

	/**	if (meen_channel_semaphore1 == SEM_FAILED)
	 {
	 meen_channel_semaphore1 = sem_open(meen_sem_name1,0);


	 } */
	if (meen_channel_semaphore1 == SEM_FAILED) {
		PRINT_DEBUG("meen_channel_semaphore failed to launch");
		sem_unlink(meen_sem_name1);
		exit(1);

	}
	//meen_channel_semaphore2 = sem_open(meen_sem_name2,O_CREAT|O_EXCL,0644,0);
	meen_channel_semaphore2 = sem_open(meen_sem_name2, O_CREAT, 0644, 0);
	/**	if (meen_channel_semaphore2 == SEM_FAILED)
	 {

	 meen_channel_semaphore2 = sem_open(meen_sem_name2,0);


	 } */
	if (meen_channel_semaphore2 == SEM_FAILED) {
		PRINT_DEBUG("meen_channel_semaphore failed to launch");
		sem_unlink(meen_sem_name2);
		exit(1);

	}

	PRINT_DEBUG("6666");

	PRINT_DEBUG("Jinni was blocked waiting at mkfifo, it had just cross it");
	socket_channel_desc = open(MAIN_SOCKET_CHANNEL, O_RDONLY);
	PRINT_DEBUG("5555");

	if (socket_channel_desc == -1) {
		PRINT_DEBUG("socket geni failed to open the socket channel \n");
		exit(EXIT_FAILURE);
	}

	/** Notice that the meen_channel_semaphore is a semaphore shared among processes
	 * (It is processes level semaphore, NOT threads level)
	 */
	/** Needs NPTL because LinuxThreads does not support sharing semaphores between processes */

}

void *Switch_to_Jinni() {

	struct finsFrame *ff;
	int protocol;
	int index;
	int status;
	uint16_t dstport, hostport;
	uint32_t dstip, hostip;
	PRINT_DEBUG("readFromSwitch_to_Jinni THREAD");

	while (1) {
		sem_wait(&Switch_to_Jinni_Qsem);
		ff = read_queue(Switch_to_Jinni_Queue);
		sem_post(&Switch_to_Jinni_Qsem);

		if (ff == NULL) {

			continue;
		}

		if (ff->dataOrCtrl == CONTROL) {

		} else if (ff->dataOrCtrl == DATA) {

			metadata_readFromElement(ff->dataFrame.metaData, "portdst",&dstport);
			metadata_readFromElement(ff->dataFrame.metaData, "portsrc",&hostport);
			metadata_readFromElement(ff->dataFrame.metaData, "ipdst", &dstip);
			metadata_readFromElement(ff->dataFrame.metaData, "ipsrc", &hostip);

			metadata_readFromElement(ff->dataFrame.metaData, "protocol",
					&protocol);
			PRINT_DEBUG("NETFORMAT %d,%d,%d,%d,%d,",protocol,hostip,dstip,hostport,dstport);

			protocol = ntohs(protocol);
			dstport = ntohs(dstport);
			hostport = ntohs(hostport);
			dstip = ntohl(dstip);
			hostip = ntohl(hostip);

			PRINT_DEBUG("NETFORMAT %d,%d,%d,%d,%d,",protocol,hostip,dstip,hostport,dstport);
			index = matchjinniSocket(dstport, dstip, protocol);
			PRINT_DEBUG("index %d", index);
			if (index != -1) {
				sem_wait(&(jinniSockets[index].Qs));
				write_queue(ff, jinniSockets[index].dataQueue);
				sem_post(&(jinniSockets[index].Qs));
				PRINT_DEBUG("pdu lenght %d",ff->dataFrame.pduLength);

			}

			else {
				PRINT_DEBUG();

				freeFinsFrame(ff);
			}
		} else {
			PRINT_DEBUG();

		} // end of if , else if , else statement


	} // end of while
} // end of function


void *interceptor_to_jinni() {

	static int numberOfSockets = 0;
	//int socket_channel_desc;
	struct socketUniqueID socketID;
	char client_pipe[256];
	int numOfBytes = 0;
	u_int opcode;
	pid_t sender;

	/** 1. init the Jinni sockets database
	 * 2. Init the queues connecting Jinnin to thw FINS Switch
	 */

	//	init_jinnisockets();
	//	Queues_init();
	jinni_init();

	int counter = 0;
	PRINT_DEBUG("");
	sem_post(meen_channel_semaphore2);
	while (1) {

		/**TODO lock the pipe before reading
		 *	to make sure no other thread read at the same time
		 * */

		PRINT_DEBUG("COUNTER = %d",counter);
		int tester;
		errno = 0;
		/**	sem_getvalue(meen_channel_semaphore1,&tester);
		 PRINT_DEBUG ("errno %d", errno);
		 PRINT_DEBUG("tester = %d",tester);
		 */
		sem_wait(meen_channel_semaphore1);
		sem_wait(meen_channel_semaphore2);
		PRINT_DEBUG("7777");

		numOfBytes = read(socket_channel_desc, &sender, sizeof(pid_t));
		numOfBytes = read(socket_channel_desc, &opcode, sizeof(u_int));
		PRINT_DEBUG("%d", sender);
		//read(socket_channel_desc, &sender,sizeof(int));
		//read(socket_channel_desc, &opcode, sizeof(int));
		//sem_post(meen_channel_semaphore);

		if (numOfBytes <= 0) {
			PRINT_DEBUG("READING ERROR");
			counter++;
			continue;

		}

		PRINT_DEBUG("8888");

		switch (opcode) {

		case socket_call:
			socket_call_handler(sender);
			break;
		case socketpair_call:
			socketpair_call_handler();
			break;
		case bind_call:
			bind_call_handler(sender);
			break;
		case getsockname_call:
			getsockname_call_handker();
			break;
		case connect_call:
			connect_call_handler(sender);
			break;
		case getpeername_call:
			getpeername_call_handler(sender);
			break;
		case send_call:
			send_call_handler(sender);
			break;
		case recv_call:
			recv_call_handler(sender);
			break;
		case sendto_call:
			sendto_call_handler(sender);
			break;
		case recvfrom_call:
			recvfrom_call_handler(sender);
			break;
		case sendmsg_call:
			sendmsg_call_handler();
			break;
		case recvmsg_call:
			recvmsg_call_handler();
			break;
		case getsockopt_call:
			getsockopt_call_handler();
			break;
		case setsockopt_call:
			setsockopt_call_handler();
			break;
		case listen_call:
			listen_call_handler();
			break;
		case accept_call:
			accept_call_handler();
			break;
		case accept4_call:
			accept4_call_handler();
			break;
		case shutdown_call:
			shutdown_call_handler();
			break;
		default: {
			PRINT_DEBUG("unknown opcode read from the socket main channel ! CRASHING");
			/** a function must be called to clean and reset the pipe
			 * to original conditions before crashing
			 */
			exit(1);
		}

		} /** end of switch */

		counter++;
	}/**end of while */

} /** end of main function */

void *Capture() {

	char *data;
	int datalen;
	int numBytes;
	int capture_pipe_fd;
	struct finsFrame *ff = NULL;

	metadata *ether_meta;

	struct sniff_ethernet *ethernet_header;
	u_char ethersrc[ETHER_ADDR_LEN];
	u_char etherdst[ETHER_ADDR_LEN];
	u_short protocol_type;

	capture_pipe_fd = open(CAPTURE_PIPE, O_RDONLY);
	if (capture_pipe_fd == -1) {
		PRINT_DEBUG("opening capture_pipe did not work");
		exit(EXIT_FAILURE);
	}

	while (1) {

		numBytes = read(capture_pipe_fd, &datalen, sizeof(int));
		if (numBytes <= 0) {
			PRINT_DEBUG("numBytes written %d\n", numBytes);
			break;
		}
		data = (char *) malloc(datalen);

		numBytes = read(capture_pipe_fd, data, datalen);

		if (numBytes <= 0) {
			PRINT_DEBUG("numBytes written %d\n", numBytes);
			break;
		}

		PRINT_DEBUG("A frame of length %d has been written-----", datalen);

		//print_frame(data,datalen);

		ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));

		PRINT_DEBUG("%d", ff);

		/** TODO
		 * 1. extract the Ethernet Frame
		 * 2. pre-process the frame in order to extract the metadata
		 * 3. build a finsFrame and insert it into EtherStub_to_Switch_Queue
		 */
		ether_meta = (metadata *) malloc(sizeof(metadata));
		metadata_create(ether_meta);

		memcpy(ethersrc, ((struct sniff_ethernet *) data)->ether_shost,
				ETHER_ADDR_LEN);
		PRINT_DEBUG();
		memcpy(etherdst, ((struct sniff_ethernet *) data)->ether_dhost,
				ETHER_ADDR_LEN);
		PRINT_DEBUG();
		protocol_type = ntohs(((struct sniff_ethernet *) data)->ether_type);

		PRINT_DEBUG();

		ff->dataOrCtrl = DATA;
		(ff->destinationID).id = IPV4ID;
		(ff->destinationID).next = NULL;

		(ff->dataFrame).directionFlag = UP;
		ff->dataFrame.metaData = ether_meta;
		ff->dataFrame.pduLength = datalen - SIZE_ETHERNET;
		ff->dataFrame.pdu = data + SIZE_ETHERNET;

		//memcpy( ff->dataFrame.pdu , data + SIZE_ETHERNET ,datalen- SIZE_ETHERNET);

		//	PRINT_DEBUG("%d", &(ff->dataFrame).pdu);
		//	PRINT_DEBUG("%d", & ((ff->dataFrame).pdu) );
		//	PRINT_DEBUG("%d", data);

		PRINT_DEBUG();

		sem_wait(&EtherStub_to_Switch_Qsem);
		write_queue(ff, EtherStub_to_Switch_Queue);
		sem_post(&EtherStub_to_Switch_Qsem);
		PRINT_DEBUG();

	} // end of while loop


}

void *Inject() {

	//char data[]="loloa7aa7a";
	char *frame;
	int datalen = 10;
	int framelen;
	int inject_pipe_fd;
	int numBytes;
	struct finsFrame *ff = NULL;
	struct ipv4_packet *packet;
	IP4addr destination;
	struct hostent *loop_host;
	uint32_t dstip;

	inject_pipe_fd = open(INJECT_PIPE, O_WRONLY);
	if (inject_pipe_fd == -1) {
		PRINT_DEBUG("opening inject_pipe did not work");
		exit(EXIT_FAILURE);
	}

	PRINT_DEBUG();

	while (1) {

		/** TO DO
		 * 1) read fins frames from the Switch_EthernetStub_queue
		 * 2) extract the data (Ethernet Frame) to be sent
		 * 3) Inject the Ethernet Frame into the injection Pipe
		 */
		sem_wait(&Switch_to_EtherStub_Qsem);
		ff = read_queue(Switch_to_EtherStub_Queue);
		sem_post(&Switch_to_EtherStub_Qsem);
		/** ff->finsDataFrame is an IPv4 packet */
		if (ff == NULL)
			continue;


		PRINT_DEBUG("\n At least one frame has been read from the Switch to Etherstub");

		//	metadata_readFromElement(ff->dataFrame.metaData,"dstip",&destination);
		//	loop_host = (struct hostent *) gethostbyname((char *)"");
		//	if ( destination !=  ((struct in_addr *)(loop_host->h_addr))->s_addr )
		//	{
		/* TODO send ARP REQUEST TO GET THE CORRESPONDING MAC ADDRESS
		 * *
		 */
		//		PRINT_DEBUG("NEED MAC ADDRESS");
		//		freeFinsFrame(ff);
		//		continue;

		//	}


		framelen = ff->dataFrame.pduLength;
		frame = (char *) malloc(framelen + SIZE_ETHERNET);

		/** TODO Fill the dest and src with the correct MAC addresses
		 * you receive from the ARP module
		 */
		char dest[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		char src[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		//char dest[]={0x00,0x1c,0xbf,0x8b,0x9c,0x9d};
		//char src[]={0x00,0x1c,0xbf,0x87,0x1a,0xfd};


		memcpy(((struct sniff_ethernet *) frame)->ether_dhost, dest,
				ETHER_ADDR_LEN);
		memcpy(((struct sniff_ethernet *) frame)->ether_shost, src,
				ETHER_ADDR_LEN);
		((struct sniff_ethernet *) frame)->ether_type = htons(0x0800);

		memcpy(frame + SIZE_ETHERNET, (ff->dataFrame).pdu, framelen);
		datalen = framelen + SIZE_ETHERNET;
		//	print_finsFrame(ff);
		PRINT_DEBUG("jinni inject to ethernet stub \n");
		numBytes = write(inject_pipe_fd, &datalen, sizeof(int));
		if (numBytes <= 0) {
			PRINT_DEBUG("numBytes written %d\n", numBytes);
			return (0);
		}

		numBytes = write(inject_pipe_fd, frame, datalen);

		if (numBytes <= 0) {
			PRINT_DEBUG("numBytes written %d\n", numBytes);
			return (0);
		}

		freeFinsFrame(ff);
		free(frame);
	} // end of while loop


} // end of Inject Function


void *UDP() {

	udp_init();

}

void *RTM() {

	rtm_init();

}


void *TCP() {
	tcp_init();

}

void *IPv4() {
	ipv4_init();

}

void *ICMP() {

	ICMP_init();

}

void *ARP() {

	ARP_init();

}

void *fins_switch() {

	init_switch();

}

void cap_inj_init() {

}

int main() {
	/** 	initialize the datebase
	 * initialize the major queues
	 */

	init_jinnisockets();
	Queues_init();

	cap_inj_init();

	pthread_t interceptor_to_jinni_thread;
	pthread_t Switch_to_jinni_thread;

	pthread_t udp_thread;
	pthread_t icmp_thread;
	pthread_t rtm_thread;
	//	pthread_t udp_outgoing;

	pthread_t tcp_thread;
	//	pthread_t tcp_outgoing;

	pthread_t ipv4_thread;
	//	pthread_t ip_outgoing;

	pthread_t arp_thread;
	//	pthread_t arp_outgoing;

	pthread_t etherStub_capturing;
	pthread_t etherStub_injecting;
	pthread_t switch_thread;

	pthread_create(&interceptor_to_jinni_thread, NULL, interceptor_to_jinni, NULL);
	pthread_create(&Switch_to_jinni_thread, NULL, Switch_to_Jinni, NULL);

	pthread_create(&udp_thread, NULL, UDP, NULL);
//	pthread_create(&rtm_thread, NULL, RTM, NULL);

//	pthread_create(&icmp_thread,NULL,ICMP,NULL);
//	pthread_create(&tcp_thread,NULL,TCP,NULL);

	pthread_create(&ipv4_thread, NULL, IPv4, NULL);
	//pthread_create(&arp_thread,NULL,ARP,NULL);

	pthread_create(&switch_thread, NULL, fins_switch, NULL);

	pthread_create(&etherStub_capturing, NULL, Capture, NULL);
	pthread_create(&etherStub_injecting, NULL, Inject, NULL);


/**
 *************************************************************
 */
	pthread_join(interceptor_to_jinni_thread, NULL);
	pthread_join(Switch_to_jinni_thread, NULL);
	pthread_join(etherStub_capturing, NULL);
	pthread_join(etherStub_injecting, NULL);

	pthread_join(switch_thread, NULL);
	pthread_join(udp_thread, NULL);
	pthread_join(tcp_thread, NULL);
	pthread_join(icmp_thread, NULL);
	pthread_join(ipv4_thread, NULL);
	pthread_join(arp_thread, NULL);




	while (1) {

	}

	return (1);

}

/*--------------------------------------------------------------------*/

/** special functions to print the data within a frame for testing*/
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;

} //end of print_hex_ascii_line()


void print_frame(const u_char *payload, int len) {

	PRINT_DEBUG("passed len = %d", len);
	int len_rem = len;
	int line_width = 16; /* number of bytes per line */
	int line_len;
	int offset = 0; /* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		PRINT_DEBUG("calling hex_ascii_line");
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for (;;) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
} // end of print_frame
/** ---------------------------------------------------------*/

