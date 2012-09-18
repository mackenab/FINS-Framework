/**
 * @file swito.c
 *
 *  @date Mar 14, 2011
 *      @author Abdallah Abdallah
 */

#include "swito.h"
#include <finstypes.h>
#include <metadata.h>
#include <queueModule.h>
#include <arpa/inet.h>

int switch_running;
pthread_t switch_thread;

#define MAX_modules 16
extern finsQueue Daemon_to_Switch_Queue;
extern finsQueue Switch_to_Daemon_Queue;

extern finsQueue RTM_to_Switch_Queue;
extern finsQueue Switch_to_RTM_Queue;

extern finsQueue Switch_to_UDP_Queue;
extern finsQueue UDP_to_Switch_Queue;

extern finsQueue Switch_to_TCP_Queue;
extern finsQueue TCP_to_Switch_Queue;

extern finsQueue Switch_to_ARP_Queue;
extern finsQueue ARP_to_Switch_Queue;

extern finsQueue Switch_to_IPv4_Queue;
extern finsQueue IPv4_to_Switch_Queue;

extern finsQueue Switch_to_Interface_Queue;
extern finsQueue Interface_to_Switch_Queue;

extern finsQueue Switch_to_ICMP_Queue;
extern finsQueue ICMP_to_Switch_Queue;

extern sem_t ICMP_to_Switch_Qsem;
extern sem_t Switch_to_ICMP_Qsem;

extern sem_t RTM_to_Switch_Qsem;
extern sem_t Switch_to_RTM_Qsem;

extern sem_t Daemon_to_Switch_Qsem;
extern sem_t Switch_to_Daemon_Qsem;

extern sem_t Switch_to_UDP_Qsem;
extern sem_t UDP_to_Switch_Qsem;

extern sem_t Switch_to_TCP_Qsem;
extern sem_t TCP_to_Switch_Qsem;

extern sem_t Switch_to_IPv4_Qsem;
extern sem_t IPv4_to_Switch_Qsem;

extern sem_t Switch_to_ARP_Qsem;
extern sem_t ARP_to_Switch_Qsem;

extern sem_t Switch_to_Interface_Qsem;
extern sem_t Interface_to_Switch_Qsem;

finsQueue modules_IO_queues[MAX_modules];
sem_t *IO_queues_sem[MAX_modules];

void Queues_init(void) {
	Daemon_to_Switch_Queue = init_queue("daemon_to_switch", MAX_Queue_size);
	Switch_to_Daemon_Queue = init_queue("switch_to_daemon", MAX_Queue_size);
	modules_IO_queues[0] = Daemon_to_Switch_Queue;
	modules_IO_queues[1] = Switch_to_Daemon_Queue;
	sem_init(&Daemon_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_Daemon_Qsem, 0, 1);
	IO_queues_sem[0] = &Daemon_to_Switch_Qsem;
	IO_queues_sem[1] = &Switch_to_Daemon_Qsem;

	UDP_to_Switch_Queue = init_queue("udp_to_switch", MAX_Queue_size);
	Switch_to_UDP_Queue = init_queue("switch_to_udp", MAX_Queue_size);
	modules_IO_queues[2] = UDP_to_Switch_Queue;
	modules_IO_queues[3] = Switch_to_UDP_Queue;
	sem_init(&UDP_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_UDP_Qsem, 0, 1);
	IO_queues_sem[2] = &UDP_to_Switch_Qsem;
	IO_queues_sem[3] = &Switch_to_UDP_Qsem;

	TCP_to_Switch_Queue = init_queue("tcp_to_switch", MAX_Queue_size);
	Switch_to_TCP_Queue = init_queue("switch_to_tcp", MAX_Queue_size);
	modules_IO_queues[4] = TCP_to_Switch_Queue;
	modules_IO_queues[5] = Switch_to_TCP_Queue;
	sem_init(&TCP_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_TCP_Qsem, 0, 1);
	IO_queues_sem[4] = &TCP_to_Switch_Qsem;
	IO_queues_sem[5] = &Switch_to_TCP_Qsem;

	IPv4_to_Switch_Queue = init_queue("ipv4_to_switch", MAX_Queue_size);
	Switch_to_IPv4_Queue = init_queue("switch_to_ipv4", MAX_Queue_size);
	modules_IO_queues[6] = IPv4_to_Switch_Queue;
	modules_IO_queues[7] = Switch_to_IPv4_Queue;
	sem_init(&IPv4_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_IPv4_Qsem, 0, 1);
	IO_queues_sem[6] = &IPv4_to_Switch_Qsem;
	IO_queues_sem[7] = &Switch_to_IPv4_Qsem;

	ARP_to_Switch_Queue = init_queue("arp_to_switch", MAX_Queue_size);
	Switch_to_ARP_Queue = init_queue("switch_to_arp", MAX_Queue_size);
	modules_IO_queues[8] = ARP_to_Switch_Queue;
	modules_IO_queues[9] = Switch_to_ARP_Queue;
	sem_init(&ARP_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_ARP_Qsem, 0, 1);
	IO_queues_sem[8] = &ARP_to_Switch_Qsem;
	IO_queues_sem[9] = &Switch_to_ARP_Qsem;

	Interface_to_Switch_Queue = init_queue("etherstub_to_switch", MAX_Queue_size);
	Switch_to_Interface_Queue = init_queue("switch_to_etherstub", MAX_Queue_size);
	modules_IO_queues[10] = Interface_to_Switch_Queue;
	modules_IO_queues[11] = Switch_to_Interface_Queue;
	sem_init(&Interface_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_Interface_Qsem, 0, 1);
	IO_queues_sem[10] = &Interface_to_Switch_Qsem;
	IO_queues_sem[11] = &Switch_to_Interface_Qsem;

	ICMP_to_Switch_Queue = init_queue("icmp_to_switch", MAX_Queue_size);
	Switch_to_ICMP_Queue = init_queue("switch_to_icmp", MAX_Queue_size);
	modules_IO_queues[12] = ICMP_to_Switch_Queue;
	modules_IO_queues[13] = Switch_to_ICMP_Queue;
	sem_init(&ICMP_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_ICMP_Qsem, 0, 1);
	IO_queues_sem[12] = &ICMP_to_Switch_Qsem;
	IO_queues_sem[13] = &Switch_to_ICMP_Qsem;

	RTM_to_Switch_Queue = init_queue("rtm_to_switch", MAX_Queue_size);
	Switch_to_RTM_Queue = init_queue("switch_to_rtm", MAX_Queue_size);
	modules_IO_queues[14] = RTM_to_Switch_Queue;
	modules_IO_queues[15] = Switch_to_RTM_Queue;
	sem_init(&RTM_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_RTM_Qsem, 0, 1);
	IO_queues_sem[14] = &RTM_to_Switch_Qsem;
	IO_queues_sem[15] = &Switch_to_RTM_Qsem;
}

void *switch_loop(void *local) {

	int i;
	struct finsFrame *ff;

	int counter = 0;

	while (switch_running) {
		/** the receiving Queues are only the even numbers
		 * 0,2,4,6,8,10,12,14. This is why we increase the counter by 2
		 */
		for (i = 0; i < MAX_modules; i = i + 2) {

			sem_wait(IO_queues_sem[i]);
			ff = read_queue(modules_IO_queues[i]);
			sem_post(IO_queues_sem[i]);

			if (ff != NULL) {
				counter++;
				PRINT_DEBUG("Counter %d", counter);

				switch (ff->destinationID.id) {
				case ARP_ID:
					PRINT_DEBUG("ARP Queue +1, ff=%p", ff);
					sem_wait(&Switch_to_ARP_Qsem);
					write_queue(ff, Switch_to_ARP_Queue);
					sem_post(&Switch_to_ARP_Qsem);
					break;
				case RTM_ID:
					PRINT_DEBUG("RTM Queue +1, ff=%p", ff);
					sem_wait(&Switch_to_RTM_Qsem);
					write_queue(ff, Switch_to_RTM_Queue);
					sem_post(&Switch_to_RTM_Qsem);
					break;
				case DAEMON_ID:
					PRINT_DEBUG("Daemon Queue +1, ff=%p", ff);
					sem_wait(&Switch_to_Daemon_Qsem);
					write_queue(ff, Switch_to_Daemon_Queue);
					sem_post(&Switch_to_Daemon_Qsem);
					break;
				case UDP_ID:
					PRINT_DEBUG("UDP Queue +1, ff=%p", ff);
					sem_wait(&Switch_to_UDP_Qsem);
					write_queue(ff, Switch_to_UDP_Queue);
					sem_post(&Switch_to_UDP_Qsem);
					break;
				case TCP_ID:
					PRINT_DEBUG("TCP Queue +1, ff=%p", ff);
					sem_wait(&Switch_to_TCP_Qsem);
					write_queue(ff, Switch_to_TCP_Queue);
					sem_post(&Switch_to_TCP_Qsem);
					break;
				case IPV4_ID:
					PRINT_DEBUG("IP Queue +1, ff=%p", ff);
					sem_wait(&Switch_to_IPv4_Qsem);
					write_queue(ff, Switch_to_IPv4_Queue);
					sem_post(&Switch_to_IPv4_Qsem);
					break;
				case INTERFACE_ID:
					PRINT_DEBUG("EtherStub Queue +1, ff=%p", ff);
					sem_wait(&Switch_to_Interface_Qsem);
					write_queue(ff, Switch_to_Interface_Queue);
					sem_post(&Switch_to_Interface_Qsem);
					break;
				case ICMP_ID:
					PRINT_DEBUG("ICMP Queue +1, ff=%p", ff);
					sem_wait(&Switch_to_ICMP_Qsem);
					write_queue(ff, Switch_to_ICMP_Queue);
					sem_post(&Switch_to_ICMP_Qsem);
					break;
				default:
					PRINT_DEBUG("Unknown Destination");
					freeFinsFrame(ff);
					break;
				} // end of Switch statement
			} // end of if (ff != NULL )
			else { //PRINT_DEBUG("No frame read from Queue # %d", i);

			}

		} //end of for For loop (Round Robin reading from Modules)

	} // end of while loop

	PRINT_DEBUG("Exiting");
	pthread_exit(NULL);
} // end of switch_init Function

void switch_init(void) {
	PRINT_DEBUG("Entered");
	switch_running = 1;

	Queues_init(); //TODO split & move to each module
	//TODO not much, init queues here?
}

void switch_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_DEBUG("Entered");

	pthread_create(&switch_thread, fins_pthread_attr, switch_loop, fins_pthread_attr);
}

void switch_shutdown(void) {
	PRINT_DEBUG("Entered");
	switch_running = 0;

	//TODO expand this

	pthread_join(switch_thread, NULL);
}

void switch_release(void) {
	PRINT_DEBUG("Entered");
	//TODO free all module related mem
}
