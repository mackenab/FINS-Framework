/*
 * @file switch.h
 *
 *  @date Mar 14, 2011
 *      @author Abdallah Abdallah
 */

#ifndef SWITCH_H_
#define SWITCH_H_

//#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <metadata.h>
#include <queueModule.h>

#define MAX_Queue_size 100000

struct fins_proto_module {
	int module_id;
	char name[30];
	uint8_t running_flag; //TODO include?

	finsQueue input_queue;
	sem_t *input_sem;

	finsQueue output_queue;
	sem_t *output_sem;

	sem_t *event_sem;
};

void module_create_ops(struct fins_proto_module *module);
void module_destroy_ops(struct fins_proto_module *module);
int module_register(struct fins_proto_module *module);
void module_unregister(int module_id);
int module_to_switch(struct fins_proto_module *module, struct finsFrame *ff);


void Queues_init(void);

void switch_init(void);
void switch_run(pthread_attr_t *fins_pthread_attr);
void switch_shutdown(void);
void switch_release(void);

#endif /* SWITCH_H_ */
