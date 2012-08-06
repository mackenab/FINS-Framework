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
#include <ipv4.h>
#include <udp.h>
#include <tcp.h>
#include <arp.h>
#include <swito.h>
#include <rtm.h>
#include <icmp.h>
#include <sys/types.h>
#include <signal.h>
//#include <stdlib.h> //added
//#include <stdio.h> //added
//kernel stuff

int CORE_TEMP = 0;

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

pthread_t wedge_to_daemon_thread;
pthread_t Switch_to_daemon_thread; //TODO move to "Daemon" module

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

finsQueue Switch_to_EtherStub_Queue;
finsQueue EtherStub_to_Switch_Queue;

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

sem_t Switch_to_EtherStub_Qsem;
sem_t EtherStub_to_Switch_Qsem;

finsQueue modules_IO_queues[MAX_modules];
sem_t *IO_queues_sem[MAX_modules];

/** ----------------------------------------------------------*/

int capture_pipe_fd; /** capture file descriptor to read from capturer */
int inject_pipe_fd; /** inject file descriptor to read from capturer */
int rtm_in_fd;
int rtm_out_fd;

/** Ethernet Stub Variables  */
#ifdef BUILD_FOR_ANDROID
#define FINS_TMP_ROOT "/data/data/fins"
#define CAPTURE_PIPE FINS_TMP_ROOT "/fins_capture"
#define INJECT_PIPE FINS_TMP_ROOT "/fins_inject"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#define CAPTURE_PIPE FINS_TMP_ROOT "/fins_capture"
#define INJECT_PIPE FINS_TMP_ROOT "/fins_inject"
#define SEMAPHORE_ROOT "/dev/shm"
#endif

//bu_mark kernel stuff
#define RECV_BUFFER_SIZE	1024// Pick an appropriate value here
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

void *Switch_to_Daemon() {

	struct finsFrame *ff;
	int protocol = 0;
	int index = 0;
	socket_state state = 0;
	uint32_t exec_call = 0;
	uint16_t dstport, hostport = 0;
	uint32_t dstport_buf = 0, hostport_buf = 0;
	uint32_t dstip = 0, hostip = 0;
	uint32_t host_ip = 0, host_port = 0, rem_ip = 0, rem_port = 0;

	while (1) {
		sem_wait(&Switch_to_Daemon_Qsem);
		ff = read_queue(Switch_to_Daemon_Queue);
		sem_post(&Switch_to_Daemon_Qsem);

		if (ff == NULL) {

			continue;
		}

		if (ff->dataOrCtrl == CONTROL) {
			host_ip = 0;
			host_port = 0;
			rem_ip = 0;
			rem_port = 0;

			PRINT_DEBUG("control ff: ff=%x meta=%x opcode=%d", (int)ff, (int)ff->ctrlFrame.metaData, ff->ctrlFrame.opcode);
			switch (ff->ctrlFrame.opcode) {
			case CTRL_ALERT:
				PRINT_DEBUG("Not yet implmented");
				freeFinsFrame(ff); //ftm
				break;
			case CTRL_ALERT_REPLY:
				PRINT_DEBUG("Not yet implmented");
				freeFinsFrame(ff); //ftm
				break;
			case CTRL_READ_PARAM:
				PRINT_DEBUG("Not yet implmented");
				freeFinsFrame(ff); //ftm
				break;
			case CTRL_READ_PARAM_REPLY:
				if (ff->ctrlFrame.metaData) {
					metadata *params = ff->ctrlFrame.metaData;
					int ret = 0;
					ret += metadata_readFromElement(params, "state", &state) == 0;

					if (state > SS_UNCONNECTED) {
						ret += metadata_readFromElement(params, "host_ip", &host_ip) == 0;
						ret += metadata_readFromElement(params, "host_port", &host_port) == 0;
						ret += metadata_readFromElement(params, "rem_ip", &rem_ip) == 0;
						ret += metadata_readFromElement(params, "rem_port", &rem_port) == 0;
						ret += metadata_readFromElement(params, "protocol", &protocol) == 0;

						if (ret) {
							//TODO error
							PRINT_DEBUG("error ret=%d", ret);
							freeFinsFrame(ff);
							continue;
						}

						PRINT_DEBUG("");
						sem_wait(&daemonSockets_sem);
						index = match_daemon_connection(host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port, protocol);
						if (index != -1) {
							PRINT_DEBUG("Matched: ff=%x index=%d", (int)ff, index);
							sem_wait(&daemonSockets[index].Qs);

							/**
							 * TODO Replace The data Queue with a pipeLine at least for
							 * the RAW DATA in order to find a natural way to support
							 * Blocking and Non-Blocking mode
							 */
							if (write_queue(ff, daemonSockets[index].controlQueue)) {
								PRINT_DEBUG("");
								sem_post(&daemonSockets[index].control_sem);
								PRINT_DEBUG("");
								sem_post(&daemonSockets[index].Qs);
								PRINT_DEBUG("");
								sem_post(&daemonSockets_sem);
							} else {
								PRINT_DEBUG("");
								sem_post(&daemonSockets[index].Qs);
								PRINT_DEBUG("");
								sem_post(&daemonSockets_sem);
								freeFinsFrame(ff);
							}
						} else {
							PRINT_DEBUG("");
							sem_post(&daemonSockets_sem);

							PRINT_DEBUG("No socket found, dropping");
							freeFinsFrame(ff);
						}
					} else {
						ret += metadata_readFromElement(params, "host_ip", &host_ip) == 0;
						ret += metadata_readFromElement(params, "host_port", &host_port) == 0;
						ret += metadata_readFromElement(params, "protocol", &protocol) == 0;

						if (ret) {
							//TODO error
							PRINT_DEBUG("error ret=%d", ret);
							freeFinsFrame(ff);
							continue;
						}

						PRINT_DEBUG("");
						sem_wait(&daemonSockets_sem);
						index = match_daemon_connection(host_ip, (uint16_t) host_port, 0, 0, protocol);
						if (index != -1) {
							PRINT_DEBUG("Matched: ff=%x index=%d", (int)ff, index);
							sem_wait(&daemonSockets[index].Qs);

							/**
							 * TODO Replace The data Queue with a pipeLine at least for
							 * the RAW DATA in order to find a natural way to support
							 * Blocking and Non-Blocking mode
							 */
							if (write_queue(ff, daemonSockets[index].controlQueue)) {
								PRINT_DEBUG("");
								sem_post(&daemonSockets[index].control_sem);
								PRINT_DEBUG("");
								sem_post(&daemonSockets[index].Qs);
								PRINT_DEBUG("");
								sem_post(&daemonSockets_sem);
							} else {
								PRINT_DEBUG("");
								sem_post(&daemonSockets[index].Qs);
								PRINT_DEBUG("");
								sem_post(&daemonSockets_sem);
								freeFinsFrame(ff);
							}
						} else {
							PRINT_DEBUG("");
							sem_post(&daemonSockets_sem);

							PRINT_DEBUG("No socket found, dropping");
							freeFinsFrame(ff);
						}
					}
				} else {
					//TODO error
					PRINT_DEBUG("error");
					freeFinsFrame(ff);
				}
				break;
			case CTRL_SET_PARAM:
				PRINT_DEBUG("Not yet implmented");
				freeFinsFrame(ff); //ftm
				break;
			case CTRL_SET_PARAM_REPLY:
				PRINT_DEBUG("Not yet implmented");
				freeFinsFrame(ff); //ftm
				break;
			case CTRL_EXEC:
				PRINT_DEBUG("Not yet implmented");
				freeFinsFrame(ff); //ftm
				break;
			case CTRL_EXEC_REPLY:
				if (ff->ctrlFrame.metaData) {
					metadata *params = ff->ctrlFrame.metaData;
					int ret = 0;
					ret += metadata_readFromElement(params, "state", &state) == 0;

					if (state > SS_UNCONNECTED) {
						ret += metadata_readFromElement(params, "host_ip", &host_ip) == 0;
						ret += metadata_readFromElement(params, "host_port", &host_port) == 0;
						ret += metadata_readFromElement(params, "rem_ip", &rem_ip) == 0;
						ret += metadata_readFromElement(params, "rem_port", &rem_port) == 0;
						ret += metadata_readFromElement(params, "protocol", &protocol) == 0;

						if (ret) {
							//TODO error
							PRINT_DEBUG("error ret=%d", ret);
							freeFinsFrame(ff);
							continue;
						}

						//##################
						struct sockaddr_in *temp = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
						//memset(temp->sin_addr, 0, sizeof(struct sockaddr_in));
						if (host_ip) {
							temp->sin_addr.s_addr = (int) htonl(host_ip);
						} else {
							temp->sin_addr.s_addr = 0;
						}
						//temp->sin_port = 0;
						struct sockaddr_in *temp2 = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
						//memset(temp2, 0, sizeof(struct sockaddr_in));
						if (rem_ip) {
							temp2->sin_addr.s_addr = (int) htonl(rem_ip);
						} else {
							temp2->sin_addr.s_addr = 0;
						}
						//temp2->sin_port = 0;
						PRINT_DEBUG("host=%s/%d (%u)", inet_ntoa(temp->sin_addr), (host_port), temp->sin_addr.s_addr);
						PRINT_DEBUG("dst=%s/%d (%u)", inet_ntoa(temp2->sin_addr), (rem_port), temp2->sin_addr.s_addr);
						free(temp);
						free(temp2);
						//##################

						PRINT_DEBUG("");
						sem_wait(&daemonSockets_sem);
						index = match_daemon_connection(host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port, protocol);
						if (index != -1) {
							PRINT_DEBUG("Matched: ff=%x index=%d", (int)ff, index);
							sem_wait(&daemonSockets[index].Qs);

							/**
							 * TODO Replace The data Queue with a pipeLine at least for
							 * the RAW DATA in order to find a natural way to support
							 * Blocking and Non-Blocking mode
							 */
							if (write_queue(ff, daemonSockets[index].controlQueue)) {
								PRINT_DEBUG("");
								sem_post(&daemonSockets[index].control_sem);
								PRINT_DEBUG("");
								sem_post(&daemonSockets[index].Qs);
								PRINT_DEBUG("");
								sem_post(&daemonSockets_sem);
							} else {
								PRINT_DEBUG("");
								sem_post(&daemonSockets[index].Qs);
								PRINT_DEBUG("");
								sem_post(&daemonSockets_sem);
								freeFinsFrame(ff);
							}
						} else {
							ret += metadata_readFromElement(params, "exec_call", &exec_call) == 0;
							ret += metadata_readFromElement(params, "protocol", &protocol) == 0;

							if (ret == 0 && (exec_call == EXEC_TCP_CONNECT || exec_call == EXEC_TCP_ACCEPT)) {
								index = match_daemon_connection(host_ip, (uint16_t) host_port, 0, 0, protocol);
								if (index != -1) {
									PRINT_DEBUG("Matched: ff=%x index=%d", (int)ff, index);
									sem_wait(&daemonSockets[index].Qs);

									/**
									 * TODO Replace The data Queue with a pipeLine at least for
									 * the RAW DATA in order to find a natural way to support
									 * Blocking and Non-Blocking mode
									 */
									if (write_queue(ff, daemonSockets[index].controlQueue)) {
										PRINT_DEBUG("");
										sem_post(&daemonSockets[index].control_sem);
										PRINT_DEBUG("");
										sem_post(&daemonSockets[index].Qs);
										PRINT_DEBUG("");
										sem_post(&daemonSockets_sem);
									} else {
										PRINT_DEBUG("");
										sem_post(&daemonSockets[index].Qs);
										PRINT_DEBUG("");
										sem_post(&daemonSockets_sem);
										freeFinsFrame(ff);
									}
								} else {
									PRINT_DEBUG("");
									sem_post(&daemonSockets_sem);

									PRINT_DEBUG("No socket found, dropping");
									freeFinsFrame(ff);
								}
							} else {
								PRINT_DEBUG("");
								sem_post(&daemonSockets_sem);

								PRINT_DEBUG("No socket found, dropping");
								freeFinsFrame(ff);
							}
						}
					} else {
						ret += metadata_readFromElement(params, "host_ip", &host_ip) == 0;
						ret += metadata_readFromElement(params, "host_port", &host_port) == 0;
						ret += metadata_readFromElement(params, "protocol", &protocol) == 0;

						if (ret) {
							//TODO error
							PRINT_DEBUG("error ret=%d", ret);
							freeFinsFrame(ff);
							continue;
						}

						//##################
						struct in_addr *temp = (struct in_addr *) malloc(sizeof(struct in_addr));
						if (hostip) {
							temp->s_addr = host_ip;
						} else {
							temp->s_addr = 0;
						}
						PRINT_DEBUG("NETFORMAT host=%s/%d", inet_ntoa(*temp), (host_port));
						PRINT_DEBUG("NETFORMAT host=%u/%d", (*temp).s_addr, (host_port));
						free(temp);
						//##################

						PRINT_DEBUG("");
						sem_wait(&daemonSockets_sem);
						index = match_daemon_connection(host_ip, (uint16_t) host_port, 0, 0, protocol);
						if (index != -1) {
							PRINT_DEBUG("Matched: ff=%x index=%d", (int)ff, index);
							sem_wait(&daemonSockets[index].Qs);

							/**
							 * TODO Replace The data Queue with a pipeLine at least for
							 * the RAW DATA in order to find a natural way to support
							 * Blocking and Non-Blocking mode
							 */
							if (write_queue(ff, daemonSockets[index].controlQueue)) {
								PRINT_DEBUG("");
								sem_post(&daemonSockets[index].control_sem);
								PRINT_DEBUG("");
								sem_post(&daemonSockets[index].Qs);
								PRINT_DEBUG("");
								sem_post(&daemonSockets_sem);
							} else {
								PRINT_DEBUG("");
								sem_post(&daemonSockets[index].Qs);
								PRINT_DEBUG("");
								sem_post(&daemonSockets_sem);
								freeFinsFrame(ff);
							}
						} else {
							PRINT_DEBUG("");
							sem_post(&daemonSockets_sem);

							PRINT_DEBUG("No socket found, dropping");
							freeFinsFrame(ff);
						}
					}
				} else {
					//TODO error
					PRINT_DEBUG("error");
					freeFinsFrame(ff);
				}
				break;
			case CTRL_ERROR:
				PRINT_DEBUG("Not yet implmented");
				freeFinsFrame(ff); //ftm
				break;
			default:
				PRINT_DEBUG("Unknown opcode");
				freeFinsFrame(ff); //ftm
				break;
			}
		} else if (ff->dataOrCtrl == DATA) {
			PRINT_DEBUG("data ff: ff=%x meta=%x len=%d", (int)ff, (int)ff->dataFrame.metaData, ff->dataFrame.pduLength);

			dstport = 0;
			hostport = 0;
			dstip = 0;
			hostip = 0;
			protocol = 0;

			int ret = 0;
			ret += metadata_readFromElement(ff->dataFrame.metaData, "src_ip", &hostip) == 0;
			ret += metadata_readFromElement(ff->dataFrame.metaData, "src_port", &hostport_buf) == 0;
			ret += metadata_readFromElement(ff->dataFrame.metaData, "dst_ip", &dstip) == 0;
			ret += metadata_readFromElement(ff->dataFrame.metaData, "dst_port", &dstport_buf) == 0;
			ret += metadata_readFromElement(ff->dataFrame.metaData, "protocol", &protocol) == 0;

			if (ret) {
				PRINT_ERROR("prob reading metadata ret=%d", ret);
				freeFinsFrame(ff);
				continue;
			}

			dstport = (uint16_t) dstport_buf;
			hostport = (uint16_t) hostport_buf;

			//##############################################
			struct in_addr *temp = (struct in_addr *) malloc(sizeof(struct in_addr));
			if (hostip) {
				temp->s_addr = htonl(hostip);
			} else {
				temp->s_addr = 0;
			}
			struct in_addr *temp2 = (struct in_addr *) malloc(sizeof(struct in_addr));
			if (dstip) {
				temp2->s_addr = htonl(dstip);
			} else {
				temp2->s_addr = 0;
			}
			PRINT_DEBUG("prot=%d, ff=%x", protocol, (int)ff);
			PRINT_DEBUG("host=%s:%d (%u)", inet_ntoa(*temp), (hostport), (*temp).s_addr);
			PRINT_DEBUG("dst=%s:%d (%u)", inet_ntoa(*temp2), (dstport), (*temp2).s_addr);

			free(temp);
			free(temp2);
			//##############################################

			/**
			 * check if this received datagram destIP and destport matching which socket hostIP
			 * and hostport insidee our sockets database
			 */
			sem_wait(&daemonSockets_sem);
			if (protocol == IPPROTO_ICMP) {
				index = match_daemonSocket(0, hostip, protocol);
			} else if (protocol == TCP_PROTOCOL) {
				index = match_daemon_connection(hostip, hostport, dstip, dstport, protocol);
				if (index == -1) {
					index = match_daemon_connection(hostip, hostport, 0, 0, protocol);
				}
			} else { //udp
				index = match_daemonSocket(dstport, dstip, protocol); //TODO change for multicast

				//if (index != -1 && daemonSockets[index].connection_status > 0) { //TODO review this logic might be bad
				if (index != -1 && daemonSockets[index].state > SS_UNCONNECTED) { //TODO review this logic might be bad
					PRINT_DEBUG("ICMP should not enter here at all ff=%x", (int)ff);
					if ((hostport != daemonSockets[index].dst_port) || (hostip != daemonSockets[index].dst_ip)) {
						PRINT_DEBUG("Wrong address, the socket is already connected to another destination");
						sem_post(&daemonSockets_sem);

						freeFinsFrame(ff);
						continue;
					}
				}
			}

			PRINT_DEBUG("ff=%x index=%d", (int) ff, index);
			if (index != -1 && daemonSockets[index].uniqueSockID != -1) {
				PRINT_DEBUG( "Matched: host=%u/%u, dst=%u/%u, prot=%u",
						daemonSockets[index].host_ip, daemonSockets[index].host_port, daemonSockets[index].dst_ip, daemonSockets[index].dst_port, daemonSockets[index].protocol);

				/**
				 * check if this datagram comes from the address this socket has been previously
				 * connected to it (Only if the socket is already connected to certain address)
				 */

				int value;
				sem_getvalue(&(daemonSockets[index].Qs), &value);
				PRINT_DEBUG("sem: ind=%d, val=%d", index, value);
				sem_wait(&daemonSockets[index].Qs);

				/**
				 * TODO Replace The data Queue with a pipeLine at least for
				 * the RAW DATA in order to find a natural way to support
				 * Blocking and Non-Blocking mode
				 */
				if (write_queue(ff, daemonSockets[index].dataQueue)) {
					daemonSockets[index].buf_data += ff->dataFrame.pduLength;
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].data_sem);
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].Qs);
					PRINT_DEBUG("");
					sem_post(&daemonSockets_sem);

					//PRINT_DEBUG("pdu=\"%s\"", ff->dataFrame.pdu);

					char *buf;
					buf = (char *) malloc(ff->dataFrame.pduLength + 1);
					if (buf == NULL) {
						PRINT_ERROR("error allocation");
						exit(1);
					}
					memcpy(buf, ff->dataFrame.pdu, ff->dataFrame.pduLength);
					buf[ff->dataFrame.pduLength] = '\0';
					PRINT_DEBUG("pdu='%s'", buf);
					free(buf);

					PRINT_DEBUG("pdu length %d", ff->dataFrame.pduLength);
				} else {
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].Qs);
					PRINT_DEBUG("");
					sem_post(&daemonSockets_sem);
					freeFinsFrame(ff);
				}
			} else {
				PRINT_DEBUG("No match, freeing ff");
				sem_post(&daemonSockets_sem);

				freeFinsFrame(ff);
			}
		} else {

			PRINT_DEBUG("unknown FINS Frame type NOT DATA NOT CONTROL !!!Probably FORMAT ERROR");
			freeFinsFrame(ff);

		} // end of if , else if , else statement
	} // end of while

	pthread_exit(NULL);
} // end of function

void *wedge_to_daemon() {
	int ret_val;
	//int nl_sockfd;
	/*
	 nl_sockfd = init_fins_nl();
	 if (nl_sockfd == -1) { // if you get an error here, check to make sure you've inserted the FINS LKM first.
	 perror("init_fins_nl() caused an error");
	 exit(-1);
	 }
	 */
	// Begin receive message section
	// Allocate a buffer to hold contents of recvfrom call
	void *recv_buf;
	recv_buf = malloc(RECV_BUFFER_SIZE + 16); //16 = NLMSGHDR size
	if (recv_buf == NULL) {
		PRINT_ERROR("buffer allocation failed");
		exit(-1);
	}

	struct sockaddr sockaddr_sender; // Needed for recvfrom
	socklen_t sockaddr_senderlen = sizeof(sockaddr_sender); // Needed for recvfrom
	memset(&sockaddr_sender, 0, sockaddr_senderlen);

	struct nlmsghdr *nlh;
	void *nl_buf; // Pointer to your actual data payload
	ssize_t nl_len, part_len; // Size of your actual data payload
	u_char *part_pt;

	u_char *msg_buf = NULL;
	ssize_t msg_len = -1;
	u_char *msg_pt = NULL;

	struct nl_wedge_to_daemon *hdr;
	int okFlag, doneFlag = 0;
	ssize_t test_msg_len;

	int pos;

	unsigned long long uniqueSockID;
	int index;
	u_int call_type; //Integer representing what socketcall type was placed (for testing purposes)
	int call_threads;
	u_int call_id;
	int call_index;

	PRINT_DEBUG("Waiting for message from kernel\n");

	int counter = 0;
	while (1) {

		PRINT_DEBUG("NL counter = %d", counter++);
		ret_val = recvfrom(nl_sockfd, recv_buf, RECV_BUFFER_SIZE + 16, 0, &sockaddr_sender, &sockaddr_senderlen);
		if (ret_val == -1) {
			perror("recvfrom() caused an error");
			exit(-1);
		}
		//PRINT_DEBUG("%d", sockaddr_sender);

		nlh = (struct nlmsghdr *) recv_buf;

		if ((okFlag = NLMSG_OK(nlh, ret_val))) {
			switch (nlh->nlmsg_type) {
			case NLMSG_NOOP:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_NOOP");
				break;
			case NLMSG_ERROR:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_ERROR");
			case NLMSG_OVERRUN:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_OVERRUN");
				okFlag = 0;
				break;
			case NLMSG_DONE:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_DONE");
				doneFlag = 1;
			default:
				PRINT_DEBUG("nlh->nlmsg_type=default");
				nl_buf = NLMSG_DATA(nlh);
				nl_len = NLMSG_PAYLOAD(nlh, 0);

				PRINT_DEBUG("nl_len= %d", nl_len);

				part_pt = nl_buf;
				test_msg_len = *(ssize_t *) part_pt;
				part_pt += sizeof(ssize_t);

				//PRINT_DEBUG("test_msg_len=%d, msg_len=%d", test_msg_len, msg_len);

				if (msg_len == -1) {
					msg_len = test_msg_len;
				} else if (test_msg_len != msg_len) {
					okFlag = 0;
					PRINT_DEBUG("test_msg_len != msg_len");
					//could just malloc msg_buff again
					break;//might comment out or make so start new
				}

				part_len = *(ssize_t *) part_pt;
				part_pt += sizeof(ssize_t);
				if (part_len > RECV_BUFFER_SIZE) {
					PRINT_DEBUG("part_len (%d) > RECV_BUFFER_SIZE (%d)", part_len, RECV_BUFFER_SIZE);
				}

				//PRINT_DEBUG("part_len=%d", part_len);

				pos = *(int *) part_pt;
				part_pt += sizeof(int);
				if (pos > msg_len || pos != msg_pt - msg_buf) {
					if (pos > msg_len) {
						PRINT_DEBUG("pos > msg_len");
					} else {
						PRINT_DEBUG("pos != msg_pt - msg_buf");
					}
				}

				//PRINT_DEBUG("pos=%d", pos);

				PRINT_DEBUG("msg_len=%d part_len=%d pos=%d seq=%d", msg_len, part_len, pos, nlh->nlmsg_seq);

				if (nlh->nlmsg_seq == 0) {
					if (msg_buf != NULL) {
						PRINT_DEBUG("error: msg_buf != NULL at new sequence, freeing");
						free(msg_buf);
					}
					msg_buf = (u_char *) malloc(msg_len);
					if (msg_buf == NULL) {
						PRINT_ERROR("msg buffer allocation failed");
						exit(-1);
					}
					msg_pt = msg_buf;
				}

				if (msg_pt != NULL) {
					msg_pt = msg_buf + pos; //atm redundant, is for if out of sync msgs
					memcpy(msg_pt, part_pt, part_len);
					msg_pt += part_len;
				} else {
					PRINT_DEBUG("error: msg_pt is NULL");
				}

				if ((nlh->nlmsg_flags & NLM_F_MULTI) == 0) {
					//doneFlag = 1; //not multi-part msg //removed multi
				}
				break;
			}
		}

		if (okFlag != 1) {
			doneFlag = 0;
			PRINT_DEBUG("okFlag != 1");
			//send kernel a resend request
			//with pos of part being passed can store msg_buf, then recopy new part when received
		}

		if (doneFlag) {
			if (msg_len < sizeof(struct nl_wedge_to_daemon)) {
				//TODOD error
				PRINT_DEBUG("todo error");
			}

			hdr = (struct nl_wedge_to_daemon *) msg_buf;
			uniqueSockID = hdr->uniqueSockID;
			index = hdr->index;
			call_type = hdr->call_type;
			call_threads = hdr->call_threads;
			call_id = hdr->call_id;
			call_index = hdr->call_index;

			msg_pt = msg_buf + sizeof(struct nl_wedge_to_daemon);
			msg_len -= sizeof(struct nl_wedge_to_daemon);

			PRINT_DEBUG("callType=%d sockID=%llu", call_type, uniqueSockID);
			PRINT_DEBUG("msg_len=%d", msg_len);

			//############################### Debug
			unsigned char *temp;
			temp = (unsigned char *) malloc(msg_len + 1);
			memcpy(temp, msg_pt, msg_len);
			temp[msg_len] = '\0';
			PRINT_DEBUG("msg='%s'", temp);
			free(temp);

			unsigned char *pt;
			temp = (unsigned char *) malloc(3 * msg_len + 1);
			pt = temp;
			int i;
			for (i = 0; i < msg_len; i++) {
				if (i == 0) {
					sprintf((char *) pt, "%02x", msg_pt[i]);
					pt += 2;
				} else if (i % 4 == 0) {
					sprintf((char *) pt, ":%02x", msg_pt[i]);
					pt += 3;
				} else {
					sprintf((char *) pt, " %02x", msg_pt[i]);
					pt += 3;
				}
			}
			temp[3 * msg_len] = '\0';
			PRINT_DEBUG("msg='%s'", temp);
			free(temp);
			//###############################

			PRINT_DEBUG("uniqueSockID=%llu, calltype=%d, threads=%d", uniqueSockID, call_type, call_threads);

			switch (call_type) {
			case socket_call:
				socket_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case bind_call:
				bind_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case listen_call:
				listen_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case connect_call:
				connect_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case accept_call:
				accept_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case getname_call:
				getname_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case ioctl_call:
				ioctl_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case sendmsg_call:
				sendmsg_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len); //TODO finish
				break;
			case recvmsg_call:
				recvmsg_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case getsockopt_call:
				getsockopt_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case setsockopt_call:
				setsockopt_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case release_call:
				release_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case poll_call:
				poll_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case mmap_call:
				mmap_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case socketpair_call:
				socketpair_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case shutdown_call:
				shutdown_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case close_call:
				/**
				 * TODO fix the problem into remove daemonsockets
				 * the Queue Terminate function has a bug as explained into it
				 */
				close_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case sendpage_call:
				sendpage_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			default:
				PRINT_DEBUG("unknown opcode received (%d), dropping", call_type);
				/** a function must be called to clean and reset the pipe
				 * to original conditions before crashing
				 */
				//exit(1);
				break;
			}

			free(msg_buf);
			doneFlag = 0;
			msg_buf = NULL;
			msg_pt = NULL;
			msg_len = -1;
		}
	}

	free(recv_buf);
	close(nl_sockfd);
	pthread_exit(NULL);
}

void *Capture() {

	char *data;
	int datalen;
	int numBytes;
	int capture_pipe_fd;
	struct finsFrame *ff = NULL;

	metadata *ether_meta;

	//struct sniff_ethernet *ethernet_header;
	u_char ethersrc[ETHER_ADDR_LEN + 1];
	u_char etherdst[ETHER_ADDR_LEN + 1];
	u_short protocol_type;

	//####
	ethersrc[ETHER_ADDR_LEN] = '\0';
	etherdst[ETHER_ADDR_LEN] = '\0';
	//####

	capture_pipe_fd = open(CAPTURE_PIPE, O_RDONLY); //responsible for socket/ioctl call
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
		if (data == NULL) {
			PRINT_ERROR("allocation fail");
			exit(1);
		}

		numBytes = read(capture_pipe_fd, data, datalen);

		if (numBytes <= 0) {
			PRINT_DEBUG("numBytes written %d\n", numBytes);
			free(data);
			break;
		}

		if (numBytes != datalen) {
			PRINT_DEBUG("bytes read not equal to datalen,  numBytes=%d\n", numBytes);
			free(data);
			continue;
		}

		if (numBytes < sizeof(struct sniff_ethernet)) {

		}

		PRINT_DEBUG("A frame of length %d has been written-----", datalen);

		//print_frame(data,datalen);

		ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));

		PRINT_DEBUG("%d", (int) ff);

		/** TODO
		 * 1. extract the Ethernet Frame
		 * 2. pre-process the frame in order to extract the metadata
		 * 3. build a finsFrame and insert it into EtherStub_to_Switch_Queue
		 */
		ether_meta = (metadata *) malloc(sizeof(metadata));
		metadata_create(ether_meta);

		memcpy(ethersrc, ((struct sniff_ethernet *) data)->ether_shost, ETHER_ADDR_LEN);
		//PRINT_DEBUG("");
		memcpy(etherdst, ((struct sniff_ethernet *) data)->ether_dhost, ETHER_ADDR_LEN);
		//PRINT_DEBUG("");
		protocol_type = ntohs(((struct sniff_ethernet *) data)->ether_type);

		PRINT_DEBUG("Capture: got frame: ethersrc=%2.2x-%2.2x-%2.2x-%2.2x-%2.2x-%2.2x, etherdst=%2.2x-%2.2x-%2.2x-%2.2x-%2.2x-%2.2x, proto=%d",
				(uint8_t)ethersrc[0], (uint8_t )ethersrc[1], (uint8_t )ethersrc[2], (uint8_t )ethersrc[3], (uint8_t )ethersrc[4], (uint8_t )ethersrc[5], (uint8_t )etherdst[0], (uint8_t )etherdst[1], (uint8_t )etherdst[2], (uint8_t )etherdst[3], (uint8_t )etherdst[4], (uint8_t )etherdst[5], protocol_type);

		ff->dataOrCtrl = DATA;
		ff->dataFrame.metaData = ether_meta;

		if (protocol_type == 0x0800) { //0x0800 == 2048, IPv4
			PRINT_DEBUG("IPv4: proto=%x (%u)", protocol_type, protocol_type);
			(ff->destinationID).id = IPV4ID;
			(ff->destinationID).next = NULL;
		} else if (protocol_type == 0x0806) { //0x0806 == 2054, ARP
			PRINT_DEBUG("ARP: proto=%x (%u)", protocol_type, protocol_type);
			(ff->destinationID).id = ARPID;
			(ff->destinationID).next = NULL;
		} else if (protocol_type == 0x86dd) { //0x86dd == 34525, IPv6
			PRINT_DEBUG("IPv6: proto=%x (%u)", protocol_type, protocol_type);
			//drop, don't handle & don't catch sys calls
			//freeFinsFrame(ff);
			//continue;
			(ff->destinationID).id = IPV4ID;
			(ff->destinationID).next = NULL;
		} else {
			PRINT_DEBUG("default: proto=%x (%u)", protocol_type, protocol_type);
			//drop
			//freeFinsFrame(ff);
			//continue;
			(ff->destinationID).id = IPV4ID;
			(ff->destinationID).next = NULL;
		}

		(ff->dataFrame).directionFlag = UP;
		ff->dataFrame.pduLength = datalen - SIZE_ETHERNET;
		ff->dataFrame.pdu = (u_char *) data + SIZE_ETHERNET; //mem leak

		//memcpy( ff->dataFrame.pdu , data + SIZE_ETHERNET ,datalen- SIZE_ETHERNET);

		PRINT_DEBUG("ff=%x pdu=%x, data=%x", (int)ff, (int) &(ff->dataFrame).pdu, (int) data);

		sem_wait(&EtherStub_to_Switch_Qsem);
		if (!write_queue(ff, EtherStub_to_Switch_Queue)) {
			freeFinsFrame(ff);
		}
		PRINT_DEBUG("");
		sem_post(&EtherStub_to_Switch_Qsem);
	} // end of while loop

	pthread_exit(NULL);
}

void *Inject() {

	//char data[]="loloa7aa7a";
	char *frame;
	int datalen = 10;
	int framelen;
	int inject_pipe_fd;
	int numBytes;
	struct finsFrame *ff;
	//struct ipv4_packet *packet;
	//IP4addr destination;
	//struct hostent *loop_host;
	//uint32_t dstip;

	inject_pipe_fd = open(INJECT_PIPE, O_WRONLY);
	if (inject_pipe_fd == -1) {
		PRINT_DEBUG("opening inject_pipe did not work");
		exit(EXIT_FAILURE);
	}

	PRINT_DEBUG("");

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

		PRINT_DEBUG("\n At least one frame has been read from the Switch to Etherstub ff=%x", (int)ff);

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
		PRINT_DEBUG("framelen=%d", framelen);
		frame = (char *) malloc(framelen + SIZE_ETHERNET);
		PRINT_DEBUG("");
		/** TODO Fill the dest and src with the correct MAC addresses
		 * you receive from the ARP module
		 */
		//char dest[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		//char src[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		//char dest[] = { 0x00, 0x1c, 0xbf, 0x86, 0xd2, 0xda }; // Mark Machine
		//char dest[] = { 0x00, 0x1c, 0xbf, 0x87, 0x1a, 0xfd }; //same to itself
		//jreed MAC addresses
		//char src[] = { 0x08, 0x00, 0x27, 0x12, 0x34, 0x56 }; //made up
		char src[] = { 0x08, 0x00, 0x27, 0x44, 0x55, 0x66 }; //HAF FINS-dev_env eth0, bridged
		//char src[] = { 0x08, 0x00, 0x27, 0x11, 0x22, 0x33 }; //HAF FINS-dev_env eth1, nat
		//char src[] = { 0x08, 0x00, 0x27, 0xa5, 0x5f, 0x13 }; //HAF Vanilla-dev_env eth0
		//char src[] = { 0x08, 0x00, 0x27, 0x16, 0xc7, 0x9b }; //HAF Vanilla-dev_env eth1

		//char dest[] = { 0xf4, 0x6d, 0x04, 0x49, 0xba, 0xdd }; //HAF host
		char dest[] = { 0x08, 0x00, 0x27, 0x44, 0x55, 0x66 }; //HAF FINS-dev_env eth0, bridged
		//char dest[] = { 0x08, 0x00, 0x27, 0x11, 0x22, 0x33 }; //HAF FINS-dev_env eth1, nat
		//char dest[] = { 0x08, 0x00, 0x27, 0x16, 0xc7, 0x9b }; //HAF Vanilla-dev eth 1
		//char dest[] = { 0xa0, 0x21, 0xb7, 0x71, 0x0c, 0x87 }; //Router 192.168.1.1 //LAN port
		//char dest[] = { 0xa0, 0x21, 0xb7, 0x71, 0x0c, 0x88 }; //Router 192.168.1.1 //INET port

		memcpy(((struct sniff_ethernet *) frame)->ether_dhost, dest, ETHER_ADDR_LEN);
		memcpy(((struct sniff_ethernet *) frame)->ether_shost, src, ETHER_ADDR_LEN);

		int ret = 0;
		int protocol = 0;
		ret += metadata_readFromElement(ff->dataFrame.metaData, "protocol", &protocol) == 0;

		if (protocol == 0x0806) {
			((struct sniff_ethernet *) frame)->ether_type = htons(0x0806);
		} else {
			((struct sniff_ethernet *) frame)->ether_type = htons(0x0800);
		}

		memcpy(frame + SIZE_ETHERNET, (ff->dataFrame).pdu, framelen);
		datalen = framelen + SIZE_ETHERNET;
		//	print_finsFrame(ff);
		PRINT_DEBUG("daemon inject to ethernet stub \n");

		//numBytes = 1;

		numBytes = write(inject_pipe_fd, &datalen, sizeof(int));
		if (numBytes <= 0) {
			PRINT_DEBUG("numBytes written %d\n", numBytes);
			freeFinsFrame(ff);
			free(frame);
			return (0);
		}

		numBytes = write(inject_pipe_fd, frame, datalen);
		if (numBytes <= 0) {
			PRINT_DEBUG("numBytes written %d\n", numBytes);
			freeFinsFrame(ff);
			free(frame);
			return (0);
		}

		freeFinsFrame(ff);
		free(frame);
	} // end of while loop

	pthread_exit(NULL);
} // end of Inject Function

void *UDP() {

	udp_init();

	pthread_exit(NULL);
}

void *RTM() {

	rtm_init();

	pthread_exit(NULL);
}

void *TCP() {

	tcp_init();

	pthread_exit(NULL);
}

void *IPv4() {

	ipv4_init();

	pthread_exit(NULL);
}

void *ICMP() {

	icmp_init();

	pthread_exit(NULL);
}

void *ARP() {

	arp_init();

	pthread_exit(NULL);
}

void *fins_switch() {

	switch_init();

	pthread_exit(NULL);
}

void cap_inj_init() {

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

	/*
	 FILE *f;
	 unsigned int temp;
	 uint8_t num[3000];
	 int i = 0;
	 int rv;
	 int num_values;

	 f = fopen("udp_input_3.txt", "r");
	 if (f == NULL) {
	 printf("file doesnt exist?!\n");
	 return 1;
	 }

	 while (i < 3000) {
	 rv = fscanf(f, "%x", &temp);
	 if (rv != 1)
	 break;
	 num[i] = (uint8_t) temp;
	 printf("%d: %x (%u)\n", i, temp, num[i]);

	 i++;
	 }
	 fclose(f);
	 printf("i=%d\n", i);

	 //uint32_t src_ip = xxx(192,168,1,11);
	 uint32_t src_ip = xxx(192,168,1,20);
	 //uint32_t dst_ip = xxx(66,69,232,38);
	 uint32_t dst_ip = xxx(192,168,1,11);
	 //src_ip = htonl(src_ip);
	 //dst_ip = htonl(dst_ip);
	 //struct udp_packet *pkt = (struct udp_packet *) num;
	 struct udp_packet *pkt = (struct udp_packet *) malloc(sizeof(struct udp_packet));
	 pkt->u_src = (55555);
	 pkt->u_dst = (44444);
	 pkt->u_len = 8;
	 pkt->u_cksum = 0;
	 pkt->u_cksum = 0xf5cd;

	 uint16_t checksum = pkt->u_cksum;
	 uint16_t calc = UDP_checksum(pkt, (src_ip), (dst_ip));
	 PRINT_DEBUG("checksum (h): %4x %4x", (checksum), (calc));

	 return 0;
	 //*/

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
	loopback_ip_addr = IP4_ADR_P2H(127,0,0,1);
	any_ip_addr = IP4_ADR_P2H(0,0,0,0);

	//added to include code from fins_daemon.sh -- mrd015 !!!!!
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

	//initialize capturer and injecter
	cap_inj_init();

	//register termination handler
	signal(SIGINT, termination_handler);

	// Start the driving thread of each module
	pthread_attr_t fins_pthread_attr;
	pthread_attr_init(&fins_pthread_attr);
	pthread_create(&wedge_to_daemon_thread, &fins_pthread_attr, wedge_to_daemon, NULL); //this has named pipe input from wedge
	pthread_create(&Switch_to_daemon_thread, &fins_pthread_attr, Switch_to_Daemon, NULL);
	pthread_create(&switch_thread, &fins_pthread_attr, fins_switch, NULL);
	pthread_create(&etherStub_capturing, &fins_pthread_attr, Capture, NULL);
	pthread_create(&etherStub_injecting, &fins_pthread_attr, Inject, NULL);
	pthread_create(&udp_thread, &fins_pthread_attr, UDP, NULL);
	pthread_create(&tcp_thread, &fins_pthread_attr, TCP, NULL);
	pthread_create(&ipv4_thread, &fins_pthread_attr, IPv4, NULL);
	pthread_create(&arp_thread, &fins_pthread_attr, ARP, NULL);
	//^^^^^ end added !!!!!

	PRINT_DEBUG("created all threads\n");

	//TODO custom test, remove later
	//char recv_data[4000];
	//gets(recv_data);
	CORE_TEMP = 1;

	/**
	 *************************************************************
	 */
	pthread_join(arp_thread, NULL);
	pthread_join(ipv4_thread, NULL);
	pthread_join(tcp_thread, NULL);
	pthread_join(udp_thread, NULL);
	pthread_join(etherStub_capturing, NULL);
	pthread_join(etherStub_injecting, NULL);
	pthread_join(switch_thread, NULL);
	pthread_join(Switch_to_daemon_thread, NULL);
	pthread_join(wedge_to_daemon_thread, NULL);
	//	//	pthread_join(icmp_thread, NULL);

	while (1) {

	}

	return (1);

}

