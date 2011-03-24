/**
 * @file queueModule.h
 *
 *  @date Nov 23, 2010
 *      @author Abdallah Abdallah
 */

#ifndef QUEUEMODULE_H_
#define QUEUEMODULE_H_

#include <finstypes.h>
#include <semaphore.h>
#include <queue.h>
#include <sys/sem.h>
#include <pthread.h>    /* POSIX Threads */





typedef Queue finsQueue;




finsQueue init_queue(const char* name, int size);
int checkEmpty( finsQueue Q );
int TerminateFinsQueue(finsQueue Q);
int DisposeFinsQueue(finsQueue Q);
int term_queue(finsQueue q);

int write_queue(struct finsFrame *ff, finsQueue q);

struct finsFrame * read_queue(finsQueue q);

struct finsFrame * buildFinsFrame(void);

int freeFinsFrame (struct finsFrame *f);





void cpy_fins_to_fins(struct finsFrame *src, struct finsFrame *dst);

void print_finsFrame(struct finsFrame *fins_in);







#endif /* QUEUEMODULE_H_ */
