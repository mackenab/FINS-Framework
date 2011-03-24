/**
 *  @file _finsframe.c
 *
 *  @date Nov 25, 2010
 *      @author Abdallah Abdallah
 */


#include <config.h>


#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include <gdsl.h>


#include "_finsframe.h"
#include "finstypes.h"
#include "finsdebug.h"

extern gdsl_element_t alloc_finsframe (void *elementP)
{
    struct finsFrame *ff = (struct finsFrame *) elementP;


    struct finsFrame *value = (struct finsFrame *) malloc(sizeof(struct finsFrame));



    assert (value != NULL);

    memcpy (value, ff, sizeof (struct finsFrame));
    // ToDo free the finsFrame which has been just copied
    return (gdsl_element_t) value;
}

extern void free_finsframe (gdsl_element_t e)
{
    free (e);
}
