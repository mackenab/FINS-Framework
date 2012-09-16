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

/** The list of major Queues which connect the modules to each other
 * including the switch module
 * The list of Semaphores which protect the Queues
 */

//TODO move to each separate module
finsQueue Daemon_to_Switch_Queue;
finsQueue Switch_to_Daemon_Queue;
sem_t Daemon_to_Switch_Qsem;
sem_t Switch_to_Daemon_Qsem;

/** RunTimeManager Module to connect to the user interface  */
finsQueue Switch_to_RTM_Queue;
finsQueue RTM_to_Switch_Queue;
sem_t RTM_to_Switch_Qsem;
sem_t Switch_to_RTM_Qsem;

finsQueue Switch_to_UDP_Queue;
finsQueue UDP_to_Switch_Queue;
sem_t Switch_to_UDP_Qsem;
sem_t UDP_to_Switch_Qsem;

finsQueue Switch_to_TCP_Queue;
finsQueue TCP_to_Switch_Queue;
sem_t Switch_to_TCP_Qsem;
sem_t TCP_to_Switch_Qsem;

finsQueue Switch_to_ARP_Queue;
finsQueue ARP_to_Switch_Queue;
sem_t Switch_to_ARP_Qsem;
sem_t ARP_to_Switch_Qsem;

finsQueue Switch_to_IPv4_Queue;
finsQueue IPv4_to_Switch_Queue;
sem_t Switch_to_IPv4_Qsem;
sem_t IPv4_to_Switch_Qsem;

finsQueue Switch_to_Interface_Queue;
finsQueue Interface_to_Switch_Queue;
sem_t Switch_to_Interface_Qsem;
sem_t Interface_to_Switch_Qsem;

finsQueue Switch_to_ICMP_Queue;
finsQueue ICMP_to_Switch_Queue;
sem_t ICMP_to_Switch_Qsem;
sem_t Switch_to_ICMP_Qsem;

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

void *Daemon(void *local) {
	daemon_run();

	pthread_exit(NULL);
}

void *Interface(void *local) {
	interface_run();

	pthread_exit(NULL);
}

void *UDP(void *local) {
	udp_run();

	pthread_exit(NULL);
}

void *RTM(void *local) {
	//TODO change to rtm_init & rtm_run
	rtm_init(NULL);

	pthread_exit(NULL);
}

void *TCP(void *local) {
	tcp_run();

	pthread_exit(NULL);
}

void *IPv4(void *local) {
	ipv4_run();

	pthread_exit(NULL);
}

void *ICMP(void *local) {
	//TODO change to rtm_init & rtm_run
	icmp_init(NULL);

	pthread_exit(NULL);
}

void *ARP(void *local) {
	arp_run();

	pthread_exit(NULL);
}

void *Switch(void *local) {
	switch_run();

	pthread_exit(NULL);
}

void termination_handler(int sig) {
	PRINT_DEBUG("**********Terminating *******");

	//TODO shutdown all module threads
	udp_shutdown();
	tcp_shutdown();
	ipv4_shutdown();
	arp_shutdown();

	daemon_shutdown(); //TODO finish
	interface_shutdown(); //TODO finish
	switch_shutdown(); //TODO finish

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
	udp_release();
	tcp_release();
	ipv4_release();
	arp_release();

	daemon_release();
	interface_release();
	switch_release();

	PRINT_DEBUG("FIN");
	exit(-1);
}

int main() {
	//############# //TODO move to Daemon
	//init the netlink socket connection to daemon
	nl_sockfd = init_fins_nl();
	if (nl_sockfd == -1) {
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
	//#############

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
			exit(-1);
		}
	}
	if (mkfifo(RTM_PIPE_OUT, 0777) != 0) {
		if (errno == EEXIST) {
			PRINT_DEBUG("mkfifo(" RTM_PIPE_OUT ", 0777) already exists.");
		} else {
			PRINT_DEBUG("mkfifo(" RTM_PIPE_OUT ", 0777) failed.");
			exit(-1);
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
	//init_daemonSockets(); //TODO move to daemon module?
	//register termination handler
	signal(SIGINT, termination_handler);

	// Start the driving thread of each module
	pthread_attr_t fins_pthread_attr;
	pthread_attr_init(&fins_pthread_attr);

	//######################################## //TODO register modules:
	/*
	 //Have in swito.c
	 struct module_ops {
	 int id;
	 void (*init)(struct net *net, int kern); //TODO change this to inputs
	 void (*run)(void);
	 void (*shutdown)(void);
	 void (*release)(void);
	 struct finsQueue *in_queue;	//TODO check pointers/etc
	 sem_t in_sem;
	 struct finsQueue *out_queue;
	 sem_t out_sem;
	 };
	 static const struct module_ops *modules[MAX_ID];
	 int module_register(const struct module_ops *ops) { modules[ops->module_id] = ops;} //TODO add checks/expand

	 //Have in daemon.c
	 finsQueue Daemon_to_Switch_Queue;
	 finsQueue Switch_to_Daemon_Queue;
	 sem_t Daemon_to_Switch_Qsem;
	 sem_t Switch_to_Daemon_Qsem;

	 Daemon_to_Switch_Queue = init_queue("daemon_to_switch", MAX_Queue_size);
	 Switch_to_Daemon_Queue = init_queue("switch_to_daemon", MAX_Queue_size);
	 sem_init(&Daemon_to_Switch_Qsem, 0, 1);
	 sem_init(&Switch_to_Daemon_Qsem, 0, 1);

	 static struct module_ops daemon_ops = {
	 .id = DAEMON_ID, .init = daemon_init, .run = daemon_run, .shutdown =  daemon_shutdown, .release = daemon_release,
	 .in_queue = Switch_to_Daemon_Queue, .in_sem = Switch_to_Daemon_Qsem,
	 .out_queue = Daemon_to_Switch_Queue, .out_sem = Daemon_to_Switch_Qsem,
	 };

	 module_register(&daemon_ops); //potentially do in init?

	 switch_run()
	 if (modules[i]) {
	 sem_wait(modules[i]->out_sem);
	 ff = read_queue(modules[i]->out_queue);
	 sem_post(modules[i]->out_sem);
	 ...
	 if (ff->destinationID.id < MAX_ID){
	 //PRINT_DEBUG("ARP Queue +1, ff=%p", ff);
	 sem_wait(modules[i]->in_sem);
	 write_queue(ff, modules[i]->in_queue);
	 sem_post(modules[i]->in_sem);
	 }

	 */

	//module init
	//module run in thread //TODO start threads here? or in init?
	//########################################
//TODO do this by registration
	switch_init(&fins_pthread_attr); //should always be first
	daemon_init(&fins_pthread_attr);
	interface_init(&fins_pthread_attr);
	udp_init(&fins_pthread_attr);
	tcp_init(&fins_pthread_attr);
	ipv4_init(&fins_pthread_attr);
	arp_init(&fins_pthread_attr);

	pthread_create(&switch_thread, &fins_pthread_attr, Switch, NULL);
	pthread_create(&daemon_thread, &fins_pthread_attr, Daemon, NULL);
	pthread_create(&interface_thread, &fins_pthread_attr, Interface, NULL);
	pthread_create(&udp_thread, &fins_pthread_attr, UDP, NULL);
	pthread_create(&tcp_thread, &fins_pthread_attr, TCP, NULL);
	pthread_create(&ipv4_thread, &fins_pthread_attr, IPv4, NULL);
	pthread_create(&arp_thread, &fins_pthread_attr, ARP, NULL);
	//pthread_create(&icmp_thread, &fins_pthread_attr, ICMP, NULL);
	//^^^^^ end added !!!!!

	PRINT_DEBUG("created all threads");

//TODO custom test, remove later
	char recv_data[4000];

	while (1) {
		gets(recv_data);

		PRINT_DEBUG("Sending ARP req");
		struct finsFrame *ff_req = (struct finsFrame*) malloc(sizeof(struct finsFrame));
		if (ff_req == NULL) {
			PRINT_ERROR("todo error");
			exit(-1);
		}

		metadata *params_req = (metadata *) malloc(sizeof(metadata));
		if (params_req == NULL) {
			PRINT_ERROR("failed to create matadata: ff=%p", ff_req);
			exit(-1);
		}
		metadata_create(params_req);

		uint32_t dst_ip = IP4_ADR_P2H(192, 168, 1, 11);
//uint32_t dst_ip = IP4_ADR_P2H(172, 31, 50, 152);
		uint32_t src_ip = IP4_ADR_P2H(192, 168, 1, 20);
//uint32_t src_ip = IP4_ADR_P2H(172, 31, 50, 160);

		uint32_t exec_call = EXEC_ARP_GET_ADDR;
		metadata_writeToElement(params_req, "exec_call", &exec_call, META_TYPE_INT);
		metadata_writeToElement(params_req, "dst_ip", &dst_ip, META_TYPE_INT);
		metadata_writeToElement(params_req, "src_ip", &src_ip, META_TYPE_INT);

		ff_req->dataOrCtrl = CONTROL;
		ff_req->destinationID.id = ARP_ID;
		ff_req->metaData = params_req;
		ff_req->ctrlFrame.opcode = CTRL_EXEC;

		arp_to_switch(ff_req); //doesn't matter which queue
	}

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

