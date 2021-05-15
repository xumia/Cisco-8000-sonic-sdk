// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#ifndef __CEM_TEST_IF_H__
#define __CEM_TEST_IF_H__

#ifdef TEST_MODE

/// @file
/// @brief Declarations for test interface utilities
///

// for printf
#include <stdio.h>

/// @brief Call to CEM stub to provide new command for execution or respond to one of UAUX requests.
/// @details The function is used in TEST_MODE instead of real polling to CEM HW.
void test_poll();

/// @brief ASSERT implementation in TEST MODE
void test_assert_brk();

//*************************
// MACROS TO BE PLACED IN CODE
//*************************
#define TEST_MODE_POLL() test_poll();
#define PRINT(...) printf(__VA_ARGS__)
#define STATIC_ASSERT(expr)                                                                                                        \
    {                                                                                                                              \
        const int size = 1 / (expr);                                                                                               \
        const int arr[size] = {1}; /* Static Assert */                                                                             \
    }
#define ASSERT(expr)                                                                                                               \
    if (!(expr)) {                                                                                                                 \
        test_assert_brk();                                                                                                         \
    }

#else // not TEST_MODE

//*************************
// MACROS TO BE PLACED IN CODE
//*************************
#define TEST_MODE_POLL()
#define PRINT(...)
#define STATIC_ASSERT(expr)
#define ASSERT(expr)

#endif // TEST_MODE

#endif // __CEM_TEST_IF_H__
