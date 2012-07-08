/*
 * mysocketstub_test1.h
 *
 *  Created on: Oct 21, 2010
 *      Author: alex
 */

#ifndef MYSOCKETSTUB_TEST1_H_
#define MYSOCKETSTUB_TEST1_H_
struct board {

	int socketID ;
	uint16_t srcport;
	uint16_t dstport;
	uint32_t host_IP_netformat;
	int     input_fd[2];
	int     output_fd[2];

};

#endif /* MYSOCKETSTUB_TEST1_H_ */
