#include <stdio.h>
#include <stdlib.h>

#define Error( Str )       fprintf( stderr, "%s\n", Str )
#define FatalError( Str )   fprintf( stderr, "%s\n", Str ), exit( 1 )
