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
	//###################################################################### //TODO get this from config file eventually
	//host interface
	my_host_mac_addr = 0x080027445566;
	my_host_ip_addr = IP4_ADR_P2H(192,168,1,20);
	my_host_mask = IP4_ADR_P2H(255,255,255,0);

	//loopback interface
	loopback_ip_addr = IP4_ADR_P2H(127,0,0,1);
	loopback_mask = IP4_ADR_P2H(255,0,0,0);

	//any
	any_ip_addr = IP4_ADR_P2H(0,0,0,0);
	//######################################################################

	sem_init(&control_serial_sem, 0, 1); //TODO remove after gen_control_serial_num() converted to RNG

	signal(SIGINT, termination_handler); //register termination handler

	// Start the driving thread of each module
	PRINT_DEBUG("Initialize Modules");
	switch_init(); //should always be first
	daemon_init(); //TODO improve how sets mac/ip
	interface_init();

	arp_init();
	arp_register_interface(my_host_mac_addr, my_host_ip_addr);

	ipv4_init();
	set_interface(my_host_ip_addr, my_host_mask);
	set_loopback(loopback_ip_addr, loopback_mask);

	icmp_init();
	tcp_init();
	udp_init();
	//rtm_init(); //TODO when updated/fully implemented

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
	/*
	 if (0) {
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

	 metadata_writeToElement(params_req, "dst_ip", &dst_ip, META_TYPE_INT32);
	 metadata_writeToElement(params_req, "src_ip", &src_ip, META_TYPE_INT32);

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

	 ff_req->ctrlFrame.data_len = 0;
	 ff_req->ctrlFrame.data = NULL;

	 arp_to_switch(ff_req); //doesn't matter which queue
	 }
	 }
	 //#############################
	 */

	while (1)
		;

	return (1);
}

