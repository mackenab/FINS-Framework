/**
 *
 * @file fatal.h FOR COPYRIGHTS This code is a modified version from a code which
 * has been copied from an unknown code exists online. We dont claim the ownership of
 * the original code. But we claim the ownership of the modifications.
 *
 *
 */

#ifndef FATAL_H_
#define FATAL_H_

#include <stdio.h>
#include <stdlib.h>

#define Error( Str )       fprintf( stderr, "%s\n", Str )
#define FatalError( Str )   fprintf( stderr, "%s\n", Str ), exit( 1 )

#endif
