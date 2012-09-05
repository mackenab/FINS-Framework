/*
 * 		@file socketgeni.c
 * *  	@date Nov 26, 2010
 *      @author Abdallah Abdallah
 *      @brief This is the FINS CORE including (the Daemon name pipes based
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
#include <daemon.h>
#include <ipv4.h>
#include <udp.h>
#include <tcp.h>
#include <arp.h>
#include <swito.h>
#include <rtm.h>
#include <icmp.h>
#include <interface.h>
#include <sys/types.h>
#include <signal.h>
//#include <stdlib.h> //added
//#include <stdio.h> //added
//kernel stuff

/** Global parameters of the socketdaemon
 *
 */

/**
 * TODO free and close/DESTORY all the semaphores before exit !!!
 * POSIX does not clean the garbage of semaphores at exiting
 * It must be cleaned manually incase the program crashes
 *
 *
 */

/*
 * Semaphore for recvfrom_udp/tcp/icmp threads created b/c of blocking
 * in UDPreadFrom_fins. Only lock/unlock when changing daemonSockets,
 * since recvfrom_udp just reads data.
 */
sem_t daemonSockets_sem;
struct fins_daemon_socket daemonSockets[MAX_SOCKETS];

int recv_thread_index;
int thread_count; //TODO move?
sem_t thread_sem;

/** The list of major Queues which connect the modules to each other
 * including the switch module
 * The list of Semaphores which protect the Queues
 */

pthread_t daemon_thread;

pthread_t udp_thread;
//	pthread_t udp_outgoing;

pthread_t icmp_thread;

pthread_t rtm_thread;

pthread_t tcp_thread;
//	pthread_t tcp_outgoing;

pthread_t ipv4_thread;
//	pthread_t ip_outgoing;

pthread_t arp_thread;
//	pthread_t arp_outgoing;

pthread_t interface_thread;

pthread_t switch_thread;

finsQueue Daemon_to_Switch_Queue;
finsQueue Switch_to_Daemon_Queue;

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

finsQueue Switch_to_Interface_Queue;
finsQueue Interface_to_Switch_Queue;

finsQueue Switch_to_ICMP_Queue;
finsQueue ICMP_to_Switch_Queue;

sem_t Daemon_to_Switch_Qsem;
sem_t Switch_to_Daemon_Qsem;

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

sem_t Switch_to_Interface_Qsem;
sem_t Interface_to_Switch_Qsem;

finsQueue modules_IO_queues[MAX_modules];
sem_t *IO_queues_sem[MAX_modules];

/** ----------------------------------------------------------*/

int capture_pipe_fd; /** capture file descriptor to read from capturer */
int inject_pipe_fd; /** inject file descriptor to read from capturer */
int rtm_in_fd;
int rtm_out_fd;

//bu_mark kernel stuff
//end kernel stuff

/**
 * @brief read the core parameters from the configuraions file called fins.cfg
 * @param
 * @return nothing
 */
int read_configurations() {

	config_t cfg;
	//config_setting_t *setting;
	//const char *str;

	config_init(&cfg);

	/* Read the file. If there is an error, report it and exit. */
	if (!config_read_file(&cfg, "fins.cfg")) {
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return EXIT_FAILURE;
	}

	config_destroy(&cfg);
	return EXIT_SUCCESS;
}

/**
 * @brief initialize the daemon sockets array by filling with value of -1
 * @param
 * @return nothing
 */
void init_daemonSockets() {
	int i;

	sem_init(&daemonSockets_sem, 0, 1);
	for (i = 0; i < MAX_SOCKETS; i++) {
		daemonSockets[i].uniqueSockID = -1;
		daemonSockets[i].state = SS_FREE;
	}

	sem_init(&thread_sem, 0, 1);
	recv_thread_index = 0;
	thread_count = 0;
}

void Queues_init() {

	Daemon_to_Switch_Queue = init_queue("daemon2switch", MAX_Queue_size);
	Switch_to_Daemon_Queue = init_queue("switch2daemon", MAX_Queue_size);
	modules_IO_queues[0] = Daemon_to_Switch_Queue;
	modules_IO_queues[1] = Switch_to_Daemon_Queue;
	sem_init(&Daemon_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_Daemon_Qsem, 0, 1);
	IO_queues_sem[0] = &Daemon_to_Switch_Qsem;
	IO_queues_sem[1] = &Switch_to_Daemon_Qsem;

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

	Interface_to_Switch_Queue = init_queue("etherstub2switch", MAX_Queue_size);
	Switch_to_Interface_Queue = init_queue("switch2etherstub", MAX_Queue_size);
	modules_IO_queues[10] = Interface_to_Switch_Queue;
	modules_IO_queues[11] = Switch_to_Interface_Queue;
	sem_init(&Interface_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_Interface_Qsem, 0, 1);
	IO_queues_sem[10] = &Interface_to_Switch_Qsem;
	IO_queues_sem[11] = &Switch_to_Interface_Qsem;

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

void *Daemon(void *local) {
	pthread_attr_t *fins_pthread_attr = (pthread_attr_t *) local;

	daemon_init(fins_pthread_attr);

	pthread_exit(NULL);
}

void *Interface(void *local) {
	pthread_attr_t *fins_pthread_attr = (pthread_attr_t *) local;

	interface_init(fins_pthread_attr);

	pthread_exit(NULL);
}

void *UDP(void *local) {
	pthread_attr_t *fins_pthread_attr = (pthread_attr_t *) local;

	udp_init(fins_pthread_attr);

	pthread_exit(NULL);
}

void *RTM(void *local) {
	pthread_attr_t *fins_pthread_attr = (pthread_attr_t *) local;

	rtm_init(fins_pthread_attr);

	pthread_exit(NULL);
}

void *TCP(void *local) {
	pthread_attr_t *fins_pthread_attr = (pthread_attr_t *) local;

	tcp_init(fins_pthread_attr);

	pthread_exit(NULL);
}

void *IPv4(void *local) {
	pthread_attr_t *fins_pthread_attr = (pthread_attr_t *) local;

	ipv4_init(fins_pthread_attr);

	pthread_exit(NULL);
}

void *ICMP(void *local) {
	pthread_attr_t *fins_pthread_attr = (pthread_attr_t *) local;

	icmp_init(fins_pthread_attr);

	pthread_exit(NULL);
}

void *ARP(void *local) {
	pthread_attr_t *fins_pthread_attr = (pthread_attr_t *) local;

	arp_init(fins_pthread_attr);

	pthread_exit(NULL);
}

void *Switch(void *local) {
	pthread_attr_t *fins_pthread_attr = (pthread_attr_t *) local;

	switch_init(fins_pthread_attr);

	pthread_exit(NULL);
}

void termination_handler(int sig) {
	PRINT_DEBUG("**********Terminating *******");

	//TODO shutdown all module threads
	udp_shutdown();
	tcp_shutdown();
	ipv4_shutdown();
	arp_shutdown();

	//join driving thread for each module
	pthread_join(arp_thread, NULL);
	pthread_join(ipv4_thread, NULL);
	pthread_join(tcp_thread, NULL);
	pthread_join(udp_thread, NULL);
	//pthread_join(etherStub_capturing, NULL);
	//pthread_join(etherStub_injecting, NULL);
	//pthread_join(switch_thread, NULL);
	//pthread_join(Switch_to_daemon_thread, NULL);
	//pthread_join(wedge_to_daemon_thread, NULL);

	//TODO move que/sem free to module
	udp_free();
	tcp_free();
	ipv4_free();
	arp_free();

	//free daemonSockets
	int i = 0, j = 0;
	int THREADS = 100;

	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemonSockets[i].uniqueSockID != -1) {
			daemonSockets[i].uniqueSockID = -1;

			//TODO stop all threads related to

			for (j = 0; j < THREADS; j++) {
				sem_post(&daemonSockets[i].control_sem);
			}

			for (j = 0; j < THREADS; j++) {
				sem_post(&daemonSockets[i].data_sem);
			}

			daemonSockets[i].state = SS_FREE;
			term_queue(daemonSockets[i].controlQueue);
			term_queue(daemonSockets[i].dataQueue);
		}
	}

	PRINT_DEBUG("FIN");
	exit(2);
}

int main() {
	//init the netlink socket connection to daemon
	//int nl_sockfd;
	//sem_init();
	nl_sockfd = init_fins_nl();
	if (nl_sockfd == -1) { // if you get an error here, check to make sure you've inserted the FINS LKM first.
		perror("init_fins_nl() caused an error");
		exit(-1);
	}

	//prime the kernel to establish daemon's PID
	int daemoncode = daemon_start_call;
	int ret_val;
	ret_val = send_wedge(nl_sockfd, (u_char *) &daemoncode, sizeof(int), 0);
	if (ret_val != 0) {
		perror("sendfins() caused an error");
		exit(-1);
	}
	PRINT_DEBUG("Connected to wedge at %d", nl_sockfd);

	//set ip, loopback, etc //TODO move?
	my_host_ip_addr = IP4_ADR_P2H(192,168,1,20);
	//my_host_ip_addr = IP4_ADR_P2H(172,31,50,160);
	loopback_ip_addr = IP4_ADR_P2H(127,0,0,1);
	any_ip_addr = IP4_ADR_P2H(0,0,0,0);

	//added to include code from fins_daemon.sh -- mrd015 !!!!! //TODO move this to RTM module
	if (mkfifo(RTM_PIPE_IN, 0777) != 0) {
		if (errno == EEXIST) {
			PRINT_DEBUG("mkfifo(" RTM_PIPE_IN ", 0777) already exists.");
		} else {
			PRINT_DEBUG("mkfifo(" RTM_PIPE_IN ", 0777) failed.");
			exit(1);
		}
	}
	if (mkfifo(RTM_PIPE_OUT, 0777) != 0) {
		if (errno == EEXIST) {
			PRINT_DEBUG("mkfifo(" RTM_PIPE_OUT ", 0777) already exists.");
		} else {
			PRINT_DEBUG("mkfifo(" RTM_PIPE_OUT ", 0777) failed.");
			exit(1);
		}
	}

	// added in semaphore clearing
#ifndef BUILD_FOR_ANDROID
	if (system("rm " SEMAPHORE_ROOT "/sem*.*") != 0) {
		PRINT_DEBUG("Cannot remove semaphore files in " SEMAPHORE_ROOT "!\n");
	} else {
		PRINT_DEBUG(SEMAPHORE_ROOT" cleaned successfully.\n\n");
	}
#endif
	// END of added section !!!!!

	/** 1. init the Daemon sockets database
	 * 2. Init the queues connecting Daemonn to thw FINS Switch
	 * 3.
	 */
	//	read_configurations();
	init_daemonSockets(); //TODO move to daemon module?
	Queues_init(); //TODO split & move to each module

	//register termination handler
	signal(SIGINT, termination_handler);

	// Start the driving thread of each module
	pthread_attr_t fins_pthread_attr;
	pthread_attr_init(&fins_pthread_attr);

	//pthread_create(&wedge_to_daemon_thread, &fins_pthread_attr, Wedge_to_Daemon, &fins_pthread_attr); //this has named pipe input from wedge
	//pthread_create(&switch_to_daemon_thread, &fins_pthread_attr, Switch_to_Daemon, &fins_pthread_attr);
	//pthread_create(&etherStub_capturing, &fins_pthread_attr, Capture, &fins_pthread_attr);
	//pthread_create(&etherStub_injecting, &fins_pthread_attr, Inject, &fins_pthread_attr);

	pthread_create(&daemon_thread, &fins_pthread_attr, Daemon, &fins_pthread_attr);
	pthread_create(&switch_thread, &fins_pthread_attr, Switch, &fins_pthread_attr);
	pthread_create(&interface_thread, &fins_pthread_attr, Interface, &fins_pthread_attr);
	pthread_create(&udp_thread, &fins_pthread_attr, UDP, &fins_pthread_attr);
	pthread_create(&tcp_thread, &fins_pthread_attr, TCP, &fins_pthread_attr);
	pthread_create(&ipv4_thread, &fins_pthread_attr, IPv4, &fins_pthread_attr);
	pthread_create(&arp_thread, &fins_pthread_attr, ARP, &fins_pthread_attr);
	//^^^^^ end added !!!!!

	PRINT_DEBUG("created all threads");

	//TODO custom test, remove later
	char recv_data[4000];
	gets(recv_data);

	PRINT_DEBUG("Sending ARP req");
	struct finsFrame *ff_req = (struct finsFrame*) malloc(sizeof(struct finsFrame));
	if (ff_req == NULL) {
		PRINT_DEBUG("todo error");
		return 0;
	}

	metadata *params_req = (metadata *) malloc(sizeof(metadata));
	if (params_req == NULL) {
		PRINT_ERROR("failed to create matadata: ff=%p", ff_req);
		return 0;
	}
	metadata_create(params_req);

	uint32_t dst_ip = IP4_ADR_P2H(192, 168, 1, 11);
	uint32_t src_ip = IP4_ADR_P2H(192, 168, 1, 20);

	uint32_t exec_call = EXEC_ARP_GET_ADDR;
	metadata_writeToElement(params_req, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params_req, "dst_ip", &dst_ip, META_TYPE_INT);
	metadata_writeToElement(params_req, "src_ip", &src_ip, META_TYPE_INT);

	ff_req->dataOrCtrl = CONTROL;
	ff_req->destinationID.id = ARPID;
	ff_req->metaData = params_req;
	ff_req->ctrlFrame.opcode = CTRL_EXEC;

	arp_to_switch(ff_req); //doesn't matter which queue

	/**
	 *************************************************************
	 */
	pthread_join(arp_thread, NULL);
	pthread_join(ipv4_thread, NULL);
	pthread_join(tcp_thread, NULL);
	pthread_join(udp_thread, NULL);
	//pthread_join(etherStub_capturing, NULL);
	//pthread_join(etherStub_injecting, NULL);
	pthread_join(interface_thread, NULL);
	pthread_join(switch_thread, NULL);
	pthread_join(daemon_thread, NULL);
	//pthread_join(switch_to_daemon_thread, NULL);
	//pthread_join(wedge_to_daemon_thread, NULL);
	//pthread_join(icmp_thread, NULL);

	while (1) {

	}

	return (1);

}

