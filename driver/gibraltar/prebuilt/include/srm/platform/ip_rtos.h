/** @file ip_rtos.h
 ****************************************************************************
 *
 * @brief
 *    This contains all the RTOS(like system calls) and environment      *
 *    related macro's and stub utilities which should be modified or     *
 *    filled in as suited to the customer environment. It is important   *
 *    that this customization or porting of the driver is done BEFORE    *
 *    making any attempt to compile or use the driver.                   *
 *
 ****************************************************************************
 * @author
 *    This file contains information that is proprietary and confidential to
 *    ABCD_CORP.
 *
 *    This file can be used under the terms of the ABCD_LICENSE
 *    Agreement. You should have received a copy of the license with this file,
 *    if not please contact your ABCD_SUPPORT staff.
 *
 *    Copyright (C) 2006-2021 ABCD_CORP, Inc. All rights reserved.
 *
 *    API Version Number: 0.33.0.1670
 ****************************************************************************/
#ifndef __IP_RTOS_H__
#define __IP_RTOS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "ip_types.h"
#include "ip_config.h"

#if (defined(_MSC_VER) || defined(__TINYC__)) && !defined(_WINDOWS)
   //We use _WINDOWS to signify tcc or msvc compilers
#  define _WINDOWS
#endif

#if defined(_WINDOWS)
#  include <windows.h>
#endif

/**********************************************************
 *         Input/Output Routines                          *
 **********************************************************/
#ifdef IP_DONT_USE_STDLIB
// You can either replace these with non-stdlib versions or remove them entirely
#  define IP_FPRINTF(...)
#  define IP_FLUSH()
#  define IP_FFLUSH(x)
#  define IP_PRINTF(...)
#  define IP_SNPRINTF(...)
#  define IP_STRNCAT(...)
#  define IP_NOTE(...)
#  define IP_WARN(...)
#  define IP_CRIT(...)
#  define IP_DEBUG(...)
#  define IP_FN_START(...)
#  define IP_RETURN(...) return __VA_ARGS__
#else
/* Include any necessary library files when building the driver */
#  include <stdlib.h>        /* for malloc(), free(), abs() */
#  include <string.h>        /* for memcpy()                */
#  include <stdarg.h>        /* for variable args           */
#  include <stdio.h>         /* for printf variants         */
#  include <time.h>          // For nanosleep
#    define IP_PRINTF(...)  srm_printf(PRINT, __VA_ARGS__);
#    define IP_FPRINTF(...) fprintf(__VA_ARGS__)
#  define IP_FLUSH()   fflush(stdout)
#  define IP_FFLUSH(x) fflush(x)
#  define IP_STRNCAT(...) strncat(__VA_ARGS__)
#  if !defined(__APPLE__) && !defined(_MSC_VER)
     int snprintf(char* s, size_t n, const char* format, ...);
#  endif /* __APPLE__ */
#  if defined(_MSC_VER)
     //MSVC does things differently...
#    define IP_SNPRINTF(...) _snprintf(__VA_ARGS__)
#  else
#    define IP_SNPRINTF(...) snprintf(__VA_ARGS__)
#  endif

   //logging functions, based on http://stackoverflow.com/a/1644898
   //To print out a 'note' message
#  define IP_NOTE(...) \
      do { if(IP_HAS_LOG_NOTE) { \
          srm_printf(PRINT, __VA_ARGS__); \
          } \
      } while(0) 
   //To print out a 'warning' message
#  define IP_WARN(...) \
      do { if(IP_HAS_LOG_WARN) { \
          srm_printf(WARN, __VA_ARGS__); \
          } \
      } while(0) 
          
   //To print out a 'critical' message
#  define IP_CRIT(...) \
      do { if(IP_HAS_LOG_CRIT) { \
          srm_printf(CRIT, __VA_ARGS__); \
          } \
      } while(0)

    //To print out a 'debug' message
#  define IP_DEBUG(...) \
      do { if(IP_HAS_LOG_DEBUG) { \
          srm_printf(DEBUG, __VA_ARGS__); \
          } \
      } while(0)

#endif /* IP_DONT_USE_STDLIB */

typedef enum {
    PRINT = 0,
    DEBUG,
    WARN,
    CRIT
} ip_log_level;

void srm_printf(ip_log_level log_type, const char* fmt, ...);

/**********************************************************
 *         Timer delay utilities                          *
 **********************************************************/
void IP_UDELAY(int usecs);
void IP_MDELAY(int msecs);

/**********************************************************
 *         Memory Handling                                *
 **********************************************************/
char *IP_STRNCPY(char *dest, const char *source, int count);
void *IP_MEMSET(void *dest, int ch, unsigned int count);
void *IP_MEMCPY(void *dest, const void *src, unsigned int count);

/**********************************************************
 *         Byte Swapping
 **********************************************************/
uint32_t IP_NTOHL(uint32_t data);

/**********************************************************
 *         Other utilities                                *
 **********************************************************/
unsigned int IP_ABS(int value);

/**
 * Calculates checksum on src data of given length
 *
 * Checksum is just a simple add and rotate
 *
 * @param src    [I] - Pointer to the source data
 * @param length [I] - Length of source data
 *
 * @return 32bit checksum
 */
uint32_t ip_checksum(const void *src, unsigned int length);

/* bit masks */
#define INBIT0  0x00000001
#define INBIT1  0x00000002
#define INBIT2  0x00000004
#define INBIT3  0x00000008
#define INBIT4  0x00000010
#define INBIT5  0x00000020
#define INBIT6  0x00000040
#define INBIT7  0x00000080

#define INBIT8  0x00000100
#define INBIT9  0x00000200
#define INBIT10 0x00000400
#define INBIT11 0x00000800
#define INBIT12 0x00001000
#define INBIT13 0x00002000
#define INBIT14 0x00004000
#define INBIT15 0x00008000

#define INBIT16 0x00010000 
#define INBIT17 0x00020000
#define INBIT18 0x00040000
#define INBIT19 0x00080000
#define INBIT20 0x00100000
#define INBIT21 0x00200000
#define INBIT22 0x00400000
#define INBIT23 0x00800000

#define INBIT24 0x01000000
#define INBIT25 0x02000000
#define INBIT26 0x04000000
#define INBIT27 0x08000000
#define INBIT28 0x10000000
#define INBIT29 0x20000000
#define INBIT30 0x40000000
#define INBIT31 0x80000000

/** Use this macro when assigning to a ip_boolean, 
 * since the inph_boolean is really an unsigned char
 * 
 * @example
 * valid == TRUE iff bit3 OR bit5 is set in reg_val:
 * cs_boolean valid = IP_IF_SET(reg_val,INBIT3|INBIT5);
 */
#define IP_IF_SET(val,mask) ( ((val) & (mask)) != 0 )

/** True iff all bits in mask are set */
#define IP_IF_ALL_SET(val,mask) ( ((val) & (mask)) == mask )

/** True iff all bits in mask are cleared */
#define IP_IF_CLR(val,mask) ( ((val) & (mask)) == 0 )

/** Set mask bits in val */
#define IP_SET(val,mask) ( ((val) | (mask)) )

/** Clear mask bits in val */
#define IP_CLR(val,mask) ( ((val) & ~(mask)) )

/** Toggle mask bits in val */
#define IP_TOGGLE(val,mask) ( ((val) ^ (mask)) )


/** Simple define to help stringify enums for translation */
#define IP_TRANS_ENUM(value) case value: return #value;

#ifdef __cplusplus
} /* closing brace for extern "C" */
#endif

#endif /* __IP_RTOS_H__ */

