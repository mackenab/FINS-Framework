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
#include <interface.h>
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
pthread_t switch_to_daemon_thread; //TODO move to "Daemon" module

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

void *Switch_to_Daemon(void *local) {

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

			PRINT_DEBUG("control ff: ff=%p meta=%p opcode=%d", ff, ff->metaData, ff->ctrlFrame.opcode);
			switch (ff->ctrlFrame.opcode) {
			case CTRL_ALERT:
				PRINT_DEBUG("Not yet implmented")
				;
				freeFinsFrame(ff); //ftm
				break;
			case CTRL_ALERT_REPLY:
				PRINT_DEBUG("Not yet implmented")
				;
				freeFinsFrame(ff); //ftm
				break;
			case CTRL_READ_PARAM:
				PRINT_DEBUG("Not yet implmented")
				;
				freeFinsFrame(ff); //ftm
				break;
			case CTRL_READ_PARAM_REPLY:
				if (ff->metaData) {
					metadata *params = ff->metaData;
					int ret = 0;
					ret += metadata_readFromElement(params, "state", &state) == CONFIG_FALSE;

					if (state > SS_UNCONNECTED) {
						ret += metadata_readFromElement(params, "host_ip", &host_ip) == CONFIG_FALSE;
						ret += metadata_readFromElement(params, "host_port", &host_port) == CONFIG_FALSE;
						ret += metadata_readFromElement(params, "rem_ip", &rem_ip) == CONFIG_FALSE;
						ret += metadata_readFromElement(params, "rem_port", &rem_port) == CONFIG_FALSE;
						ret += metadata_readFromElement(params, "protocol", &protocol) == CONFIG_FALSE;

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
							PRINT_DEBUG("Matched: ff=%p index=%d", ff, index);
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
						ret += metadata_readFromElement(params, "host_ip", &host_ip) == CONFIG_FALSE;
						ret += metadata_readFromElement(params, "host_port", &host_port) == CONFIG_FALSE;
						ret += metadata_readFromElement(params, "protocol", &protocol) == CONFIG_FALSE;

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
							PRINT_DEBUG("Matched: ff=%p index=%d", ff, index);
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
				PRINT_DEBUG("Not yet implmented")
				;
				freeFinsFrame(ff); //ftm
				break;
			case CTRL_SET_PARAM_REPLY:
				PRINT_DEBUG("Not yet implmented")
				;
				freeFinsFrame(ff); //ftm
				break;
			case CTRL_EXEC:
				PRINT_DEBUG("Not yet implmented")
				;
				freeFinsFrame(ff); //ftm
				break;
			case CTRL_EXEC_REPLY:
				if (ff->metaData) {
					metadata *params = ff->metaData;
					int ret = 0;
					ret += metadata_readFromElement(params, "state", &state) == CONFIG_FALSE;

					if (state > SS_UNCONNECTED) {
						ret += metadata_readFromElement(params, "host_ip", &host_ip) == CONFIG_FALSE;
						ret += metadata_readFromElement(params, "host_port", &host_port) == CONFIG_FALSE;
						ret += metadata_readFromElement(params, "rem_ip", &rem_ip) == CONFIG_FALSE;
						ret += metadata_readFromElement(params, "rem_port", &rem_port) == CONFIG_FALSE;
						ret += metadata_readFromElement(params, "protocol", &protocol) == CONFIG_FALSE;

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
							PRINT_DEBUG("Matched: ff=%p index=%d", ff, index);
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
							ret += metadata_readFromElement(params, "exec_call", &exec_call) == CONFIG_FALSE;
							ret += metadata_readFromElement(params, "protocol", &protocol) == CONFIG_FALSE;

							if (ret == 0 && (exec_call == EXEC_TCP_CONNECT || exec_call == EXEC_TCP_ACCEPT)) {
								index = match_daemon_connection(host_ip, (uint16_t) host_port, 0, 0, protocol);
								if (index != -1) {
									PRINT_DEBUG("Matched: ff=%p index=%d", ff, index);
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
						ret += metadata_readFromElement(params, "host_ip", &host_ip) == CONFIG_FALSE;
						ret += metadata_readFromElement(params, "host_port", &host_port) == CONFIG_FALSE;
						ret += metadata_readFromElement(params, "protocol", &protocol) == CONFIG_FALSE;

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
							PRINT_DEBUG("Matched: ff=%p index=%d", ff, index);
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
				PRINT_DEBUG("Not yet implmented")
				;
				freeFinsFrame(ff); //ftm
				break;
			default:
				PRINT_DEBUG("Unknown opcode")
				;
				freeFinsFrame(ff); //ftm
				break;
			}
		} else if (ff->dataOrCtrl == DATA) {
			PRINT_DEBUG("data ff: ff=%p meta=%p len=%d", ff, ff->metaData, ff->dataFrame.pduLength);

			dstport = 0;
			hostport = 0;
			dstip = 0;
			hostip = 0;
			protocol = 0;

			int ret = 0;
			ret += metadata_readFromElement(ff->metaData, "src_ip", &hostip) == CONFIG_FALSE;
			ret += metadata_readFromElement(ff->metaData, "src_port", &hostport_buf) == CONFIG_FALSE;
			ret += metadata_readFromElement(ff->metaData, "dst_ip", &dstip) == CONFIG_FALSE;
			ret += metadata_readFromElement(ff->metaData, "dst_port", &dstport_buf) == CONFIG_FALSE;
			ret += metadata_readFromElement(ff->metaData, "protocol", &protocol) == CONFIG_FALSE;

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
			PRINT_DEBUG("prot=%d, ff=%p", protocol, ff);
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
					PRINT_DEBUG("ICMP should not enter here at all ff=%p", ff);
					if ((hostport != daemonSockets[index].dst_port) || (hostip != daemonSockets[index].dst_ip)) {
						PRINT_DEBUG("Wrong address, the socket is already connected to another destination");
						sem_post(&daemonSockets_sem);

						freeFinsFrame(ff);
						continue;
					}
				}
			}

			PRINT_DEBUG("ff=%p index=%d", ff, index);
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

void *Wedge_to_Daemon(void *local) {
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
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_NOOP")
				;
				break;
			case NLMSG_ERROR:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_ERROR")
				;
			case NLMSG_OVERRUN:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_OVERRUN")
				;
				okFlag = 0;
				break;
			case NLMSG_DONE:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_DONE")
				;
				doneFlag = 1;
			default:
				PRINT_DEBUG("nlh->nlmsg_type=default")
				;
				nl_buf = NLMSG_DATA(nlh);
				nl_len = NLMSG_PAYLOAD(nlh, 0);

				PRINT_DEBUG("nl_len= %d", nl_len)
				;

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

				PRINT_DEBUG("msg_len=%d part_len=%d pos=%d seq=%d", msg_len, part_len, pos, nlh->nlmsg_seq)
				;

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
			uniqueSockID = hdr->sock_id;
			index = hdr->sock_index;
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
				mmap_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len); //TODO dummy
				break;
			case socketpair_call:
				socketpair_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len); //TODO dummy
				break;
			case shutdown_call:
				shutdown_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len); //TODO dummy
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
				PRINT_DEBUG("unknown opcode received (%d), dropping", call_type)
				;
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

void *FINS_Switch(void *local) {
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

	pthread_create(&wedge_to_daemon_thread, &fins_pthread_attr, Wedge_to_Daemon, &fins_pthread_attr); //this has named pipe input from wedge
	pthread_create(&switch_to_daemon_thread, &fins_pthread_attr, Switch_to_Daemon, &fins_pthread_attr);

	pthread_create(&switch_thread, &fins_pthread_attr, FINS_Switch, &fins_pthread_attr);

	//pthread_create(&etherStub_capturing, &fins_pthread_attr, Capture, &fins_pthread_attr);
	//pthread_create(&etherStub_injecting, &fins_pthread_attr, Inject, &fins_pthread_attr);
	pthread_create(&interface_thread, &fins_pthread_attr, Interface, &fins_pthread_attr);

	pthread_create(&udp_thread, &fins_pthread_attr, UDP, &fins_pthread_attr);
	pthread_create(&tcp_thread, &fins_pthread_attr, TCP, &fins_pthread_attr);
	pthread_create(&ipv4_thread, &fins_pthread_attr, IPv4, &fins_pthread_attr);
	pthread_create(&arp_thread, &fins_pthread_attr, ARP, &fins_pthread_attr);
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
	//pthread_join(etherStub_capturing, NULL);
	//pthread_join(etherStub_injecting, NULL);
	pthread_join(interface_thread, NULL);
	pthread_join(switch_thread, NULL);
	pthread_join(switch_to_daemon_thread, NULL);
	pthread_join(wedge_to_daemon_thread, NULL);
	//pthread_join(icmp_thread, NULL);

	while (1) {

	}

	return (1);

}

