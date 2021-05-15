/** @file ip_config.h
 ****************************************************************************
 *
 * @brief
 *     This module allows individual features in the API to be compiled
 *     in or out to manage code space.
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
 ***************************************************************************/
#ifndef __IP_CONFIG_H__
#define __IP_CONFIG_H__

#undef IP_HAS_FLOATING_POINT

// Set to 1 if to bundle the application firmware with
// the API for programming via vega_mcu_download_firmware()
#define IP_HAS_INLINE_APP_FW        1

// Set to 1 if you want to include support for downloading
// the firmware directly to the IRAM/DRAM 
#define IP_HAS_DIRECT_DOWNLOAD      1

// Set to 1 to include support for displaying diagnostic dumps
// This would only be useful on systems with some sort of console
// access.
#define IP_HAS_DIAGNOSTIC_DUMPS     1

// Set to 1 to include support for math.h
#define IP_HAS_MATH_DOT_H           1

// Set to 1 to include floating point math support
#define IP_HAS_FLOATING_POINT       1

// Turn on/off MCU diagnostic methods
#define IP_HAS_MCU_DIAGNOSTICS      1

// Turn on/off the eye monitor methods
#define IP_HAS_EYEMON               1

// Turn on/off conservative Inbound PIF reads.
// To speed up verifying the f/w image this
// can be set to 0.
#define IP_HAS_INBPIF_READ_POLLING  1

// Set the size of the verify buffer size
// when programming the firmware. This is
// a static buffer. Each entry in the array/buffer
// is 32b in size.
#define IP_UCODE_VERIFY_BUFFER_SIZE  64

// This is an optional define that is used
// to automatically bump the die parameter
// for channels 3/4 on STC.
#define IP_HAS_STC_CHANNEL_MAPPING 1

#define IP_HAS_LOG_NOTE 1
#define IP_HAS_LOG_WARN 1
#define IP_HAS_LOG_CRIT 1
#define IP_HAS_LOG_DEBUG 1

#if !defined(IP_DONT_USE_STDLIB)
#    if !defined(IP_HAS_FILESYSTEM)
#        define IP_HAS_FILESYSTEM 1
#    endif
#endif

#if defined(IP_DONT_USE_STDLIB)
#    undef IP_HAS_FILESYSTEM
#    undef IP_HAS_MATH_DOT_H
#    undef IP_HAS_DIAGNOSTIC_DUMPS
#    define IP_HAS_FILESYSTEM       0
#    define IP_HAS_MATH_DOT_H       0
#    define IP_HAS_DIAGNOSTIC_DUMPS 0
#endif

#endif /* __IP_CONFIG_H__ */
