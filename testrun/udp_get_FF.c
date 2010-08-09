/**@file udp_get_FF.c
 * udp_get_FF.c
 *
 *  Created on: Jul 8, 2010
 *      Author: alex
 */


/**
 * @brief fetches the FF packet and sends it to the proper function in the UDP module
 *
 * The function first copies the FF into local memory. From there a few checks are made to determine
 * the Fins Frame's destination within the UDP module.
 *
 */

#include "udp.h"



extern struct udp_statistics udpStat;

void udp_get_FF(){
	struct finsFrame ff;
	UDP_InputQueue_Read_local(&ff);





udpStat.totalRecieved++;
	if(ff.dataOrCtrl == CONTROL){
		// send to something to deal with FCF
	}
	if(ff.dataOrCtrl == DATA && ff.dataFrame.directionFlag == UP){
		udp_in(&ff);
	}
	if(ff.dataOrCtrl == DATA && ff.dataFrame.directionFlag == DOWN){
		udp_out(&ff);
	}



}
