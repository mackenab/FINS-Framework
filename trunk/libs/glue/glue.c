#include "glue.h"

/*
typedef struct { 
  unsigned int quot; 
  unsigned int rem; 
} uidiv_return;

typedef struct  { 
  int quot;  
  int rem; 
} idiv_return;
*/

//extern uidiv_return __aeabi_uidivmod(unsigned int numerator, unsigned int denominator);
//extern idiv_return __aeabi_idivmod(int numerator, int denominator);
/*
unsigned int __aeabi_uidiv(unsigned int numerator, unsigned int denominator){
  //printf("numerator=%u, denominator=%u\n", numerator, denominator);
  if (numerator == 0) {
    return 0;
  } else if (denominator == 0) {
    exit(-1);
    return -1;
  } else {
    unsigned int count = 0;
    while (numerator > denominator) {
      numerator -= denominator;
      count++;
    }
    return count;
  }
}

int __aeabi_idiv(int numerator, int denominator){
  //printf("numerator=%u, denominator=%u\n", numerator, denominator);
    if (numerator == 0) {
    return 0;
  } else if (denominator == 0) {
    exit(-1);
    return -1;
  } else {
    int count = 0;
    if (numerator > 0) {
      if (denominator > 0) {
        while (numerator > denominator) {
          numerator -= denominator;
          count++;
        }
        return count;
      } else {
        denominator = -denominator;
        while (numerator > denominator) {
          numerator -= denominator;
          count--;
        }
        return count;
      }
    } else {
      if (denominator > 0) {
        numerator = -numerator;
        while (numerator > denominator) {
          numerator -= denominator;
          count--;
        }
        return count;
      } else {
        while (numerator < denominator) {
          numerator += denominator;
          count--;
        }
        return count;
      }
    }
  }
}
*/
int atexit (void (*func)(void)) {
  return 0;
}
