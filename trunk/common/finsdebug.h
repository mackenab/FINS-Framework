/*
 * finsdebug.h
 *
 *
 */

#ifndef FINSDEBUG_H_
#define FINSDEBUG_H_

#define DEBUG
#define ERROR

#ifdef DEBUG
#include <stdio.h>
#define PRINT_DEBUG(format, args...) printf("DEBUG(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout);
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef ERROR
#include <stdio.h>
#define PRINT_ERROR(format, args...) printf("ERROR(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout);
#else
#define PRINT_ERROR(format, args...)
#endif
#endif /* FINSDEBUG_H_ */
