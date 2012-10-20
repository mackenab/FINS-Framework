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
#include <swito.h>
#include <daemon.h>
#include <interface.h>
#include <ipv4.h>
#include <arp.h>
#include <udp.h>
#include <tcp.h>
#include <icmp.h>
#include <rtm.h>
#include <signal.h>

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

void termination_handler(int sig) {
	PRINT_DEBUG("**********Terminating *******");

	//shutdown all module threads in backwards order of startup
	//rtm_shutdown();
	udp_shutdown();
	tcp_shutdown();
	icmp_shutdown();
	ipv4_shutdown();
	arp_shutdown();

	interface_shutdown(); //TODO finish
	daemon_shutdown(); //TODO finish
	switch_shutdown(); //TODO finish

	//have each module free data & que/sem //TODO finish each of these
	//rtm_release();
	udp_release();
	tcp_release();
	icmp_release();
	ipv4_release();
	arp_release();

	interface_release();
	daemon_release();
	switch_release();

	PRINT_DEBUG("FIN");
	exit(-1);
}

extern sem_t control_serial_sem; //TODO remove & change gen process to RNG

int main() {
	//set ip, loopback, etc //TODO do this from config file eventually
	my_host_mac_addr = 0x080027445566;
	my_host_ip_addr = IP4_ADR_P2H(192,168,1,20);
	//my_host_ip_addr = IP4_ADR_P2H(172,31,50,160);
	my_host_mask = IP4_ADR_P2H(255, 255, 255, 0);

	loopback_ip_addr = IP4_ADR_P2H(127,0,0,1);
	any_ip_addr = IP4_ADR_P2H(0,0,0,0);

	sem_init(&control_serial_sem, 0, 1);

	//added to include code from fins_daemon.sh -- mrd015 !!!!! //TODO move this to RTM module
	if (mkfifo(RTM_PIPE_IN, 0777) != 0) {
		if (errno == EEXIST) {
			PRINT_DEBUG("mkfifo(" RTM_PIPE_IN ", 0777) already exists.");
		} else {
			PRINT_ERROR("mkfifo(" RTM_PIPE_IN ", 0777) failed.");
			exit(-1);
		}
	}
	if (mkfifo(RTM_PIPE_OUT, 0777) != 0) {
		if (errno == EEXIST) {
			PRINT_DEBUG("mkfifo(" RTM_PIPE_OUT ", 0777) already exists.");
		} else {
			PRINT_ERROR("mkfifo(" RTM_PIPE_OUT ", 0777) failed.");
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

	signal(SIGINT, termination_handler); //register termination handler

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

	 for each module:
	 module[i]->init();
	 module[i]->run(fins_pthread_attr); //TODO move thread creation to here


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

	 module init:
	 initialize data structures
	 create queues (?)
	 register module (?)

	 module run:
	 start module threads

	 module shutdown:
	 stop module threads

	 module release:
	 unregister module (?)
	 free queues (?)
	 free data structures
	 */
	//########################################
	// Start the driving thread of each module
	PRINT_DEBUG("Initialize Modules");
	switch_init(); //should always be first
	daemon_init(); //TODO set mac/ip
	interface_init();

	arp_init();
	arp_register_interface(my_host_mac_addr, my_host_ip_addr);

	ipv4_init();
	set_interface(my_host_ip_addr, my_host_mask);

	icmp_init();
	tcp_init();
	udp_init();
	//rtm_init();

	pthread_attr_t fins_pthread_attr;
	pthread_attr_init(&fins_pthread_attr);

	PRINT_DEBUG("Run/start Modules");
	switch_run(&fins_pthread_attr);
	daemon_run(&fins_pthread_attr);
	interface_run(&fins_pthread_attr);
	arp_run(&fins_pthread_attr);
	ipv4_run(&fins_pthread_attr);
	icmp_run(&fins_pthread_attr);
	tcp_run(&fins_pthread_attr);
	udp_run(&fins_pthread_attr);
	//rtm_run(&fins_pthread_attr);

	//############################# //TODO custom test, remove later
	char recv_data[4000];

	while (1) {
		gets(recv_data);

		PRINT_DEBUG("Sending ARP req");

		metadata *params_req = (metadata *) malloc(sizeof(metadata));
		if (params_req == NULL) {
			PRINT_ERROR("metadata alloc fail");
			exit(-1);
		}
		metadata_create(params_req);

		uint32_t dst_ip = IP4_ADR_P2H(192, 168, 1, 11);
		//uint32_t dst_ip = IP4_ADR_P2H(172, 31, 50, 152);
		uint32_t src_ip = IP4_ADR_P2H(192, 168, 1, 20);
		//uint32_t src_ip = IP4_ADR_P2H(172, 31, 50, 160);

		metadata_writeToElement(params_req, "dst_ip", &dst_ip, META_TYPE_INT);
		metadata_writeToElement(params_req, "src_ip", &src_ip, META_TYPE_INT);

		struct finsFrame *ff_req = (struct finsFrame*) malloc(sizeof(struct finsFrame));
		if (ff_req == NULL) {
			PRINT_ERROR("todo error");
			//metadata_destroy(params_req);
			exit(-1);
		}

		ff_req->dataOrCtrl = CONTROL;
		ff_req->destinationID.id = ARP_ID;
		ff_req->destinationID.next = NULL;
		ff_req->metaData = params_req;

		ff_req->ctrlFrame.senderID = IP_ID;
		ff_req->ctrlFrame.serial_num = gen_control_serial_num();
		ff_req->ctrlFrame.opcode = CTRL_EXEC;
		ff_req->ctrlFrame.param_id = EXEC_ARP_GET_ADDR;

		arp_to_switch(ff_req); //doesn't matter which queue
	}
	//#############################

	while (1)
		;

	return (1);
}

