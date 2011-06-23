/*
 * finsdebug.h
 *
 *
 */

#ifndef FINSDEBUG_H_
#define FINSDEBUG_H_

//#define DEBUG
#define ERROR

#ifdef DEBUG
#define PRINT_DEBUG(format, args...) printf("DEBUG(%s, %d):"format"\n",__FILE__, __LINE__, ##args);
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef ERROR
#define PRINT_ERROR(format, args...) printf("ERROR(%s, %d):"format"\n",__FILE__, __LINE__, ##args);
#else
#define PRINT_ERROR(format, args...)
#endif
#endif /* FINSDEBUG_H_ */

