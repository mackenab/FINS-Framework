/*
 * finsdebug.h
 *
 *
 */

#ifndef FINSDEBUG_H_
#define FINSDEBUG_H_

#define DEBUG
#define IMPORTANT
#define ERROR

#ifdef BUILD_FOR_ANDROID
#include <android/log.h>

//#define printf(...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", __VA_ARGS__);
//#define perror(...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", __VA_ARGS__);

#ifdef DEBUG
#define PRINT_DEBUG(format, args...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", "DEBUG(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef IMPORTANT
#define PRINT_IMPORTANT(format, args...) __android_log_print(ANDROID_LOG_INFO, "FINS", "IMPORTANT(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define PRINT_IMPORTANT(format, args...)
#endif

#ifdef ERROR
#define PRINT_ERROR(format, args...) __android_log_print(ANDROID_LOG_ERROR, "FINS", "ERROR(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define PRINT_ERROR(format, args...)
#endif

#else /* BUILD_FOR_ANDROID */
#include <stdio.h>

#ifdef DEBUG
#define PRINT_DEBUG(format, args...) printf("DEBUG(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef IMPORTANT
#define PRINT_IMPORTANT(format, args...) printf("IMPORTANT(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_IMPORTANT(format, args...)
#endif

#ifdef ERROR
#define PRINT_ERROR(format, args...) printf("ERROR(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_ERROR(format, args...)
#endif

#endif /* BUILD_FOR_ANDROID */

#endif /* FINSDEBUG_H_ */
