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

#define MAX_modules 16
extern finsQueue Jinni_to_Switch_Queue;
extern finsQueue Switch_to_Jinni_Queue;

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

extern finsQueue Switch_to_EtherStub_Queue;
extern finsQueue EtherStub_to_Switch_Queue;

extern finsQueue Switch_to_ICMP_Queue;
extern finsQueue ICMP_to_Switch_Queue;

extern sem_t ICMP_to_Switch_Qsem;
extern sem_t Switch_to_ICMP_Qsem;

extern sem_t RTM_to_Switch_Qsem;
extern sem_t Switch_to_RTM_Qsem;

extern sem_t Jinni_to_Switch_Qsem;
extern sem_t Switch_to_Jinni_Qsem;

extern sem_t Switch_to_UDP_Qsem;
extern sem_t UDP_to_Switch_Qsem;

extern sem_t Switch_to_TCP_Qsem;
extern sem_t TCP_to_Switch_Qsem;

extern sem_t Switch_to_IPv4_Qsem;
extern sem_t IPv4_to_Switch_Qsem;

extern sem_t Switch_to_ARP_Qsem;
extern sem_t ARP_to_Switch_Qsem;

extern sem_t Switch_to_EtherStub_Qsem;
extern sem_t EtherStub_to_Switch_Qsem;

extern finsQueue modules_IO_queues[MAX_modules];
extern sem_t *IO_queues_sem[MAX_modules];

void init_switch() {

	PRINT_DEBUG("SWITCH Module started");
	int i;
	struct finsFrame *ff = NULL;
	int protocol;
	int index;
	int status;
	uint16_t dstport, hostport;
	uint32_t dstip, hostip;

	int counter = 0;

	while (1) {
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
				/*
				//###################################
				dstport = -1;
				hostport = -1;
				dstip = -1;
				hostip = -1;
				protocol = -1;

				metadata_readFromElement(ff->dataFrame.metaData, "portdst",
						&dstport);
				metadata_readFromElement(ff->dataFrame.metaData, "portsrc",
						&hostport);
				metadata_readFromElement(ff->dataFrame.metaData, "ipdst", &dstip);
				metadata_readFromElement(ff->dataFrame.metaData, "ipsrc", &hostip);

				metadata_readFromElement(ff->dataFrame.metaData, "protocol",
						&protocol);
				PRINT_DEBUG("NETFORMAT %d, host=%d/%d, dst=%d/%d,", protocol, hostip, hostport, dstip, dstport);

				protocol = ntohs(protocol);
				dstport = ntohs(dstport);
				hostport = ntohs(hostport);
				dstip = ntohl(dstip);
				hostip = ntohl(hostip);

				PRINT_DEBUG("NETFORMAT %d, host=%d/%d, dst=%d/%d,", protocol, hostip, hostport, dstip, dstport);
				struct in_addr *temp = (struct in_addr *) malloc(sizeof(struct in_addr));
				temp->s_addr = hostip;
				struct in_addr *temp2 = (struct in_addr *) malloc(sizeof(struct in_addr));
				temp2->s_addr = dstip;
				PRINT_DEBUG("NETFORMAT %d, host=%s/%d, dst=%s/%d,", protocol,inet_ntoa(*temp), (hostport), inet_ntoa(*temp2), (dstport));
				//PRINT_DEBUG("NETFORMAT %d, host=%d/%d, dst=%d/%d,", protocol,(*temp).s_addr, (hostport), (*temp2).s_addr, (dstport));

				PRINT_DEBUG("ff->dataFrame.pduLength=%d", ff->dataFrame.pduLength);
				//###################################
				*/

				switch (ff->destinationID.id) {

				case ARPID: {

					PRINT_DEBUG("ARP Queue +1");
					sem_wait(&Switch_to_ARP_Qsem);
					write_queue(ff, Switch_to_ARP_Queue);
					sem_post(&Switch_to_ARP_Qsem);
					break;

				}

				case RTMID: {

					PRINT_DEBUG("RTM Queue +1");
					sem_wait(&Switch_to_RTM_Qsem);
					write_queue(ff, Switch_to_RTM_Queue);
					sem_post(&Switch_to_RTM_Qsem);
					break;

				}

				case JINNIID: {

					PRINT_DEBUG("Jinni Queue +1");
					sem_wait(&Switch_to_Jinni_Qsem);
					write_queue(ff, Switch_to_Jinni_Queue);
					sem_post(&Switch_to_Jinni_Qsem);

					break;
				}
				case UDPID: {

					PRINT_DEBUG("UDP Queue +1");
					sem_wait(&Switch_to_UDP_Qsem);
					write_queue(ff, Switch_to_UDP_Queue);
					sem_post(&Switch_to_UDP_Qsem);
					break;
				}
				case TCPID: {

					PRINT_DEBUG("TCP Queue +1");
					sem_wait(&Switch_to_TCP_Qsem);
					write_queue(ff, Switch_to_TCP_Queue);
					sem_post(&Switch_to_TCP_Qsem);
					break;
				}
				case IPV4ID: {

					PRINT_DEBUG("IP Queue +1");
					sem_wait(&Switch_to_IPv4_Qsem);
					write_queue(ff, Switch_to_IPv4_Queue);
					sem_post(&Switch_to_IPv4_Qsem);
					break;
				}
				case ETHERSTUBID: {

					PRINT_DEBUG("EtherStub Queue +1");
					sem_wait(&Switch_to_EtherStub_Qsem);
					write_queue(ff, Switch_to_EtherStub_Queue);
					sem_post(&Switch_to_EtherStub_Qsem);
					break;
				}
				case ICMPID: {

					PRINT_DEBUG("ICMP Queue +1");
					sem_wait(&Switch_to_ICMP_Qsem);
					write_queue(ff, Switch_to_ICMP_Queue);
					sem_post(&Switch_to_ICMP_Qsem);
					break;
				}
				default: {

					PRINT_DEBUG("Unknown Destination");
					//	free(ff);
					break;

				}

				} // end of Switch statement
			} // end of if (ff != NULL )
			else { //PRINT_DEBUG("No frame read from Queue # %d", i);

			}

		} //end of for For loop (Round Robin reading from Modules)


	} // end of while loop


} // end of switch_init Function
