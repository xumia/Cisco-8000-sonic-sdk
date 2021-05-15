// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef _MODULES_H_
#define _MODULES_H_

#include <assert.h>

namespace npsuite
{

// clang-format off
typedef enum {
    APP = 0,
    NSIM_TABLE,
    NSIM_DEBUG,
    USER,
    NSIM_COUNTER,
    NUM_MODULES
} eModules;

static const char*
getModuleName(eModules module)
{
    static const char* names[] = {
        "APP",
        "NSIM_TABLE",
        "NSIM",
        "USER",
        "NSIM_COUNTER"
    };

    assert((sizeof(names) / sizeof(names[0]) == NUM_MODULES) && "Missing module name ?!?!");

    if ((module >= NUM_MODULES) || (module < 0)) {
        return "UNKNOWN";
    } else {
        return names[module];
    }
}
// clang-format on
}

#endif //_MODULES_H_
