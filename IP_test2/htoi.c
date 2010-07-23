/**
 * @file htoi.c
 *
 * @date Jun 9, 2010
 * @brief This function htoi converts a byte of hexa decimal into into its corresponding integer value whose range (0-255).
 * @author: Abdallah Abdallah
 */






#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>

unsigned char htoi(unsigned char s[])
{
    unsigned char val = 0;
    int x = 0;

    if(s[x] == '0' && (s[x+1]=='x' || s[x+1]=='X')) x+=2;

    while(s[x]!='\0')
    {
       if(val > UINT_MAX) return 0;
       else if(s[x] >= '0' && s[x] <='9')
       {
          val = val * 16 + s[x] - '0';
       }
       else if(s[x]>='A' && s[x] <='F')
       {
          val = val * 16 + s[x] - 'A' + 10;
       }
       else if(s[x]>='a' && s[x] <='f')
       {
          val = val * 16 + s[x] - 'a' + 10;
       }
       else return 0;

       x++;
    }
    return val;
}
