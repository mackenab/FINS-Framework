/*
 * icmp.c
 *
 *  Created on: Mar 15, 2011
 *      Author: Abdallah Abdallah
 */

#include "icmp.h"


extern sem_t ICMP_to_Switch_Qsem;
extern finsQueue ICMP_to_Switch_Queue;

extern sem_t Switch_to_ICMP_Qsem;
extern finsQueue Switch_to_ICMP_Queue;




void icmp_in(struct finsFrame *ff)
{






}


void icmp_out(struct finsFrame *ff)
{






}






void icmp_get_FF(struct finsFrame *ff)
{


	do {
				sem_wait (&Switch_to_ICMP_Qsem);
					ff = read_queue(Switch_to_ICMP_Queue);
				sem_post (&Switch_to_ICMP_Qsem);
			} while (ff == NULL);


	if(ff->dataOrCtrl == CONTROL){
			// send to something to deal with FCF
			PRINT_DEBUG("send to CONTROL HANDLER !");
		}
		if( (ff->dataOrCtrl == DATA) && ( (ff->dataFrame).directionFlag == UP) )
		{
			icmp_in(ff);
		}
		if( (ff->dataOrCtrl == DATA) && ( (ff->dataFrame).directionFlag == DOWN))
		{
			icmp_out(ff);
		}



}


void ICMP_init()
{

	PRINT_DEBUG("ICMP Started");
/**
	struct finsFrame *pff;
		while (1)
		{

			icmp_get_FF(pff);
			PRINT_DEBUG("%d",(int)pff);
			free(pff);


		}

*/

}


