/**
 *
 * @file queueModule.h FOR COPYRIGHTS This code is a modified version from a code which
 * has been copied from an unknown code exists online. We dont claim the ownership of
 * the original code. But we claim the ownership of the modifications.
 *
 * @author Abdallah Abdallah
 * @date Nov 2, 2010
 *
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
int checkEmpty(finsQueue Q);
int TerminateFinsQueue(finsQueue Q);
int DisposeFinsQueue(finsQueue Q);
int term_queue(finsQueue q);

int write_queue(struct finsFrame *ff, finsQueue q);

struct finsFrame * read_queue(finsQueue q);

struct finsFrame * buildFinsFrame(void);

int freeFinsFrame(struct finsFrame *f);

void cpy_fins_to_fins(struct finsFrame *src, struct finsFrame *dst);

void print_finsFrame(struct finsFrame *fins_in);

#endif /* QUEUEMODULE_H_ */
