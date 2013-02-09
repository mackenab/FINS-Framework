/*
 * finsdebug.h
 *
 *
 */

#ifndef FINSDEBUG_H_
#define FINSDEBUG_H_

//#define DEBUG
#define CRITICAL
#define ERROR

#ifndef BUILD_FOR_ANDROID

#ifdef DEBUG
#include <stdio.h>
#define PRINT_DEBUG(format, args...) printf("DEBUG(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout);
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef CRITICAL
#include <stdio.h>
#define PRINT_CRITICAL(format, args...) printf("CRITICAL(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout);
#else
#define PRINT_CRITICAL(format, args...)
#endif

#ifdef ERROR
#include <stdio.h>
#define PRINT_ERROR(format, args...) printf("ERROR(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout);
#else
#define PRINT_ERROR(format, args...)
#endif

#endif



#ifdef BUILD_FOR_ANDROID
#include <android/log.h>
#warning "building in debugging for android"

#define printf(...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", __VA_ARGS__);
#define perror(...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", __VA_ARGS__);

#ifdef DEBUG
//#define PRINT_DEBUG(format, args...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", format);
#define PRINT_DEBUG(format, args...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", "DEBUG(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef CRITICAL
//#define PRINT_CRITICAL(format, args...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", format);
#define PRINT_CRITICAL(format, args...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", "CRITICAL(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);
#else
#define PRINT_CRITICAL(format, args...)
#endif

#ifdef ERROR
//#define PRINT_ERROR(format, args...) __android_log_print(ANDROID_LOG_ERROR, "FINS", format);
#define PRINT_ERROR(format, args...) __android_log_print(ANDROID_LOG_ERROR, "FINS", "ERROR(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);
#else
#define PRINT_ERROR(format, args...)
#endif

#endif /*BUILD_FOR_ANDROID*/


#endif /* FINSDEBUG_H_ */
