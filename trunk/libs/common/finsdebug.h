/*
 * finsdebug.h
 *
 * add verbose level?
 * debug - white - for tracing function calls (Entered/Exited function)
 * info - blue - human readable text that doesn't need context (resolved/didn't resolve MAC address)
 * warn - yellow - potentially bad occurrances but not errors (poll not finding initial call)
 * important - green - crucially important output (modules going up/down, console connecting)
 * error - red - fatal errors
 */

#ifndef FINSDEBUG_H_
#define FINSDEBUG_H_

//#define DEBUG
//#define INFO
#define WARN
#define IMPORTANT
#define ERROR

#ifdef BUILD_FOR_ANDROID
#include <android/log.h>
//#define printf(...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", __VA_ARGS__);

#ifdef DEBUG
#define PRINT_DEBUG(format, args...) __android_log_print(ANDROID_LOG_DEBUG, "FINS", "DEBUG(%s, %s, %d):"format"\n", __FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef INFO
#define PRINT_INFO(format, args...) __android_log_print(ANDROID_LOG_INFO, "FINS", "INFO(%s, %s, %d):"format"\n", __FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define PRINT_INFO(format, args...)
#endif

#ifdef WARN
#define PRINT_WARN(format, args...) __android_log_print(ANDROID_LOG_WARN, "FINS", "WARN(%s, %s, %d):"format"\n", __FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define PRINT_WARN(format, args...)
#endif

#ifdef IMPORTANT
#define PRINT_IMPORTANT(format, args...) __android_log_print(ANDROID_LOG_INFO, "FINS", "IMPORTANT(%s, %s, %d):"format"\n", __FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define PRINT_IMPORTANT(format, args...)
#endif

#ifdef ERROR
#define PRINT_ERROR(format, args...) __android_log_print(ANDROID_LOG_ERROR, "FINS", "ERROR(%s, %s, %d):"format"\n", __FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define PRINT_ERROR(format, args...)
#endif

#else //!BUILD_FOR_ANDROID
#include <stdio.h>
#include <errno.h>
#include <semaphore.h>
#include <sys/time.h>
#include <unistd.h>

struct timeval global_print_tv;

#ifdef DEBUG
//#define PRINT_DEBUG(format, args...) printf("\033[01;37mDEBUG(%s, %s, %d):"format"\n\033[01;37m",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#define PRINT_DEBUG(format, args...) gettimeofday(&global_print_tv, NULL);printf("\033[01;37m%12u.%06u:DEBUG(%s, %s, %d):"format"\n\033[01;37m", (uint32_t)global_print_tv.tv_sec, (uint32_t)global_print_tv.tv_usec, __FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef INFO
//#define PRINT_INFO(format, args...) printf("\033[01;34mINFO(%s, %s, %d):"format"\n\033[01;37m",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#define PRINT_INFO(format, args...) gettimeofday(&global_print_tv, NULL);printf("\033[01;34m%12u.%06u:INFO(%s, %s, %d):"format"\n\033[01;37m", (uint32_t)global_print_tv.tv_sec, (uint32_t)global_print_tv.tv_usec, __FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_INFO(format, args...)
#endif

#ifdef WARN
//#define PRINT_WARN(format, args...) printf("\033[01;33mWARN(%s, %s, %d):"format"\n\033[01;37m",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#define PRINT_WARN(format, args...) gettimeofday(&global_print_tv, NULL);printf("\033[01;33m%12u.%06u:WARN(%s, %s, %d):"format"\n\033[01;37m", (uint32_t)global_print_tv.tv_sec, (uint32_t)global_print_tv.tv_usec, __FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_WARN(format, args...)
#endif

#ifdef IMPORTANT
//#define PRINT_IMPORTANT(format, args...) printf("\033[01;32mIMPORTANT(%s, %s, %d):"format"\n\033[01;37m",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#define PRINT_IMPORTANT(format, args...) gettimeofday(&global_print_tv, NULL);printf("\033[01;32m%12u.%06u:IMPORTANT(%s, %s, %d):"format"\n\033[01;37m", (uint32_t)global_print_tv.tv_sec, (uint32_t)global_print_tv.tv_usec, __FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_IMPORTANT(format, args...)
#endif

#ifdef ERROR
//#define PRINT_ERROR(format, args...) printf("\033[01;31mERROR(%s, %s, %d):"format"\n\033[01;37m",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#define PRINT_ERROR(format, args...) gettimeofday(&global_print_tv, NULL);printf("\033[01;31m%12u.%06u:ERROR(%s, %s, %d):"format"\n\033[01;37m", (uint32_t)global_print_tv.tv_sec, (uint32_t)global_print_tv.tv_usec, __FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_ERROR(format, args...)
#endif

#endif //BUILD_FOR_ANDROID
#endif //FINSDEBUG_H_
