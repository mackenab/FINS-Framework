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

#include <signal.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <finstime.h>
#include <switch.h>
//#include <daemon.h>
//#include <interface.h>
//#include <ipv4.h>
//#include <arp.h>
//#include <udp.h>
//#include <tcp.h>
//#include <icmp.h>
//#include <rtm.h>
//#include <logger.h>

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
		PRINT_ERROR("%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return EXIT_FAILURE;
	}

	config_destroy(&cfg);
	return EXIT_SUCCESS;
}

extern sem_t control_serial_sem; //TODO remove & change gen process to RNG

void core_termination_handler(int sig) {
	PRINT_IMPORTANT("**********Terminating *******");

	//shutdown all module threads in backwards order of startup
	//logger_shutdown();
	//rtm_shutdown();

	//udp_shutdown();
	//tcp_shutdown();
	//icmp_shutdown();
	//ipv4_shutdown();
	//arp_shutdown();

	//interface_shutdown(); //TODO finish
	//daemon_shutdown(); //TODO finish
	switch_shutdown(); //TODO finish

	//have each module free data & que/sem //TODO finish each of these
	//logger_release();
	//rtm_release();

	//udp_release();
	//tcp_release();
	//icmp_release();
	//ipv4_release();
	//arp_release();

	//interface_release();
	//daemon_release();
	switch_release();

	sem_destroy(&control_serial_sem);

	PRINT_IMPORTANT("FIN");
	exit(-1);
}

void *test_thread(void *local) {
	PRINT_DEBUG("Entered: local=%p", local);
	int id = *((int *) local);
	free(local);

	PRINT_DEBUG("Entered: id=%d", id);

	int count = 0;
	while (count < 10) {
		PRINT_DEBUG("id=%d, count=%d", id, count);
		count++;
		sleep(1);
		//usleep(200);
	}

	return NULL;
}

void *test_thread_2(void *local) {
	PRINT_DEBUG("Entered: local=%p", local);

	int count = 0;
	while (count < 10) {
		PRINT_DEBUG("count_2=%d", count);
		count++;
		sleep(1);
	}

	return NULL;
}

void core_main() {
	/*
	if (0) { //TODO remove, testing code
		struct thread_pool *pool = pool_create(1, 10, 10);
		PRINT_DEBUG("setup done");

		char srecv_data[4000];
		gets(srecv_data);

		PRINT_DEBUG("executing");
		int i;
		for (i = 0; i < 10; i++) {
			PRINT_DEBUG("executing: id=%d", i);
			int *buf = (int *) secure_malloc(sizeof(int));
			*buf = i;
			pool_execute(pool, test_thread, buf);
			usleep(200);
		}

		//	PRINT_DEBUG("waiting");
		//	gets(srecv_data);

		//pool_execute(pool, test_thread_2, NULL);

		gets(srecv_data);

		PRINT_DEBUG("pool shutdown");
		pool_shutdown(pool);

		PRINT_DEBUG("FIN");
		while (1)
			sleep(1);

		return;
	}
	*/

	//###################################################################### //TODO get this from config file eventually
	//host interface

	//strcpy(my_host_if_name, "lo");
	//strcpy(my_host_if_name, "eth0");
	//strcpy(my_host_if_name, "eth1");
	//strcpy(my_host_if_name, "eth2");
	//strcpy(my_host_if_name, "wlan0");
	strcpy(my_host_if_name, "wlan4");

	//my_host_mac_addr = 0x080027445566ull; //vbox eth2
	//my_host_mac_addr = 0x001d09b35512ull; //laptop eth0
	//my_host_mac_addr = 0x001cbf86d2daull; //laptop wlan0
	my_host_mac_addr = 0x00184d8f2a32ull; //laptop wlan4 card

	my_host_ip_addr = IP4_ADR_P2H(192,168,1,3); //home testing
	my_host_mask = IP4_ADR_P2H(255,255,255,0); //home testing
	//my_host_ip_addr = IP4_ADR_P2H(172,31,49,250); //lab testing
	//my_host_mask = IP4_ADR_P2H(255,255,248,0); //lab testing

	//loopback interface
	loopback_ip_addr = IP4_ADR_P2H(127,0,0,1);
	loopback_mask = IP4_ADR_P2H(255,0,0,0);

	//any
	any_ip_addr = IP4_ADR_P2H(0,0,0,0);
	//######################################################################

	register_to_signal(SIGRTMIN);

	sem_init(&control_serial_sem, 0, 1); //TODO remove after gen_control_serial_num() converted to RNG

	signal(SIGINT, core_termination_handler); //register termination handler

	// Start the driving thread of each module
	PRINT_IMPORTANT("Initialize Modules");
	switch_init(); //should always be first
	//daemon_init(); //TODO improve how sets mac/ip
	//interface_init();

	//arp_init();
	//arp_register_interface(my_host_mac_addr, my_host_ip_addr);

	//ipv4_init();
	//ipv4_set_interface(my_host_ip_addr, my_host_mask);
	//ipv4_set_loopback(loopback_ip_addr, loopback_mask);
	//ipv4_register_interface(my_host_mac_addr, my_host_ip_addr);

	//icmp_init();
	//tcp_init();
	//udp_init();

	//rtm_init(); //TODO when updated/fully implemented
	//logger_init();

	pthread_attr_t fins_pthread_attr;
	pthread_attr_init(&fins_pthread_attr);

	PRINT_IMPORTANT("Run/start Modules");
	switch_run(&fins_pthread_attr);
	//daemon_run(&fins_pthread_attr);
	//interface_run(&fins_pthread_attr);

	//arp_run(&fins_pthread_attr);
	//ipv4_run(&fins_pthread_attr);
	//icmp_run(&fins_pthread_attr);
	//tcp_run(&fins_pthread_attr);
	//udp_run(&fins_pthread_attr);

	//rtm_run(&fins_pthread_attr);
	//logger_run(&fins_pthread_attr);

	//############################# //TODO custom test, remove later
	/*
	if (0) {
		char recv_data[4000];

		while (1) {
			gets(recv_data);

			PRINT_DEBUG("Sending ARP req");

			metadata *params_req = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(params_req);

			uint32_t dst_ip = IP4_ADR_P2H(192, 168, 1, 11);
			//uint32_t dst_ip = IP4_ADR_P2H(172, 31, 50, 152);
			uint32_t src_ip = IP4_ADR_P2H(192, 168, 1, 20);
			//uint32_t src_ip = IP4_ADR_P2H(172, 31, 50, 160);

			secure_metadata_writeToElement(params_req, "dst_ip", &dst_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(params_req, "src_ip", &src_ip, META_TYPE_INT32);

			struct finsFrame *ff_req = (struct finsFrame*) secure_malloc(sizeof(struct finsFrame));
			ff_req->dataOrCtrl = CONTROL;
			ff_req->destinationID.id = ARP_ID;
			ff_req->destinationID.next = NULL;
			ff_req->metaData = params_req;

			ff_req->ctrlFrame.senderID = IPV4_ID;
			ff_req->ctrlFrame.serial_num = gen_control_serial_num();
			ff_req->ctrlFrame.opcode = CTRL_EXEC;
			ff_req->ctrlFrame.param_id = EXEC_ARP_GET_ADDR;

			ff_req->ctrlFrame.data_len = 0;
			ff_req->ctrlFrame.data = NULL;

			arp_to_switch(ff_req); //doesn't matter which queue
		}
	}
	if (0) {
		char recv_data[4000];
		while (1) {
			gets(recv_data);

			PRINT_IMPORTANT("start timing");

			struct timeval start, end;
			gettimeofday(&start, 0);

			int its = 30000;
			int len = 1000;

			int i = 0;
			while (i < its) {
				uint8_t *data = (uint8_t *) secure_malloc(len);
				memset(data, 56, len);

				metadata *params = (metadata *) secure_malloc(sizeof(metadata));
				metadata_create(params);

				uint32_t host_ip = IP4_ADR_P2H(192, 168, 1, 20);
				uint32_t host_port = 55454;
				uint32_t dst_ip = IP4_ADR_P2H(192, 168, 1, 6);
				uint32_t dst_port = 44444;
				uint32_t ttl = 64;
				uint32_t tos = 64;

				secure_metadata_writeToElement(params, "send_src_ip", &host_ip, META_TYPE_INT32);
				secure_metadata_writeToElement(params, "send_src_port", &host_port, META_TYPE_INT32);
				secure_metadata_writeToElement(params, "send_dst_ip", &dst_ip, META_TYPE_INT32);
				secure_metadata_writeToElement(params, "send_dst_port", &dst_port, META_TYPE_INT32);
				secure_metadata_writeToElement(params, "send_ttl", &ttl, META_TYPE_INT32);
				secure_metadata_writeToElement(params, "send_tos", &tos, META_TYPE_INT32);

				if (daemon_fdf_to_switch(UDP_ID, data, len, params)) {
					i++;
				} else {
					PRINT_ERROR("error sending");
					metadata_destroy(params);
					free(data);
					break;
				}
			}

			//struct timeval start, end;
			//gettimeofday(&start, 0);
			gettimeofday(&end, 0);
			double diff = time_diff(&start, &end);
			PRINT_IMPORTANT("diff=%f, len=%d, avg=%f ms, calls=%f, bits=%f", diff, len, diff/its, 1000/(diff/its), 8*1000/(diff/its)*len);
		}
	}
	*/
	//#############################


	while (1)
		sleep(1);
}

#ifndef BUILD_FOR_ANDROID
int  main() {
	core_main();
	return 0;
}
#endif
