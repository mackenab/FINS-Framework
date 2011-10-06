/*
 * icmp.h
 *
 *  Created on: Mar 15, 2011
 *      Author: Abdallah Abdallah
 */

#ifndef ICMP_H_
#define ICMP_H_

#include <finstypes.h>
#include <metadata.h>
#include <finsdebug.h>
#include <queueModule.h>
#include <stdint.h>
#include "icmp_types.h"
//#include <ctype.h>

//typedef unsigned long IP4addr; /*  internet address			*/

//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
	#include <sys/endian.h>
#endif

//Define some common ICMP message types (Common values for the "Type" field of the ICMP header)
#define TYPE_ECHOREPLY		0	//Echo reply
#define TYPE_DESTUNREACH	3	//Destination unreachable
#define TYPE_SOURCEQUENCH	4	//Source quench
#define TYPE_REDIRECT		5	//Redirect message
#define TYPE_ECHOREQUEST	8	//Echo request
#define TYPE_ROUTERAD		9	//Router advertisement
#define TYPE_ROUTERSOLICIT	10	//Router solicitation
#define TYPE_TTLEXCEED		11	//Time Exceeded
#define TYPE_PARAMPROB		12	//Parameter problem
#define TYPE_TIMESTAMP		13	//Timestamp request
#define TYPE_TIMESTAMPREPLY	14	//Timestamp reply
#define TYPE_INFOREQUEST	15	//Information request
#define TYPE_INFOREPLY		16	//Information reply
#define TYPE_ADDMASKREQ		17	//Address mask request
#define TYPE_ADDMASKREPLY	18	//Address mask reply

//Define some common codes for the "Code" field of the ICMP header
//For echo requests and replies
#define CODE_ECHO				0
//For destination unreachable
#define CODE_NETUNREACH			0	//Destination network unreachable
#define CODE_HOSTUNREACH		1	//Destination host unreachable
#define CODE_PROTOUNREACH		2	//Destination protocol unreachable
#define CODE_PORTUNREACH		3	//Destination port unreachable
#define CODE_FRAGNEEDED			4	//Fragmentation required, and DF flag set
#define CODE_SRCROUTEFAIL		5	//Source route failed
#define CODE_DESTNETUNKOWN		6	//Destination network unknown
#define CODE_DESTHOSTUNKNOWN	7	//Destination host unknown
#define CODE_SRCHOSTISOLATED	8	//Source host isolated
#define CODE_NETADMINPROHIBIT	9	//Network administratively prohibited
#define CODE_HOSTADMINPROHIBIT	10	//Host administratively prohibited
#define CODE_NETTOSUNREACH		11	//Network unreachable for TOS
#define CODE_HOSTTOSUNREACH		12	//Host unreachable for TOS
#define CODE_PROHIBITED			13	//Communication administratively prohibited

//For Time Exceeded
#define CODE_TTLEXCEEDED		0
#define CODE_DEFRAGTIMEEXCEEDED	1

//Generic use
#define ICMP_HEADER_SIZE	8
#define ICMP_PROTOCOL		1	//Protocol number for ICMP packets
#define UDP_PROTOCOL		17	//Protocol number for UDP packets
#define UNREACH_INCLUDE_DATA_SIZE	64	//How many bytes of data are included in destination unreachable and TTL exceeded ICMP messages.
										// Defined here as a macro for simplicity. 512 bits seems reasonable in my opinion, but it can be tweaked.

void ICMP_in(struct finsFrame *ff);						//Processes an ICMP message that just came in
void ICMP_out(struct finsFrame *ff);					//Processes an ICMP message that's headed out
void ICMP_get_FF(struct finsFrame *ff);					//Gets a finsFrame from the queue and starts processing
void ICMP_send_FF(struct finsFrame *ff);				//Put a finsFrame onto the queue to go out

void			ICMP_init();							//Get our ICMP engine up and running
unsigned short 	ICMP_checksum(struct finsFrame * ff);	//Calculate a checksum for an ICMP package
void			ICMP_ping_reply(struct finsFrame* ff);	//Create a ping reply from a ping request package
void			IMCP_create_unreach(struct finsFrame* ff);	//Create a "destination unreachable" message from data we receive from the UDP //removed in vt_mark?
int				ICMP_copy_finsFrame(struct finsFrame* src, struct finsFrame* dst);	//Copy one finsFrame to another. Placeholder for now, as I'm not sure if there's some function that does this that I should use. Returns 0 on error

void			ICMP_control_handler(struct finsFrame *ff);	//Handle control frames sent from other modules, creating new messages as needed and sending them out.
void			ICMP_create_error(struct finsFrame *ff, uint8_t Type, uint8_t Code);	//Create and send out an error from this type and code
void			ICMP_create_control_error(struct finsFrame* ff, uint8_t Type, uint8_t Code);	//Create a control frame to TCP/UDP out of ICMP error that came in

#endif /* ICMP_H_ */
