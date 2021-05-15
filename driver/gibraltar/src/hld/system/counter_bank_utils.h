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

#ifndef __COUNTER_BANK_UTILS_H__
#define __COUNTER_BANK_UTILS_H__

#include "hld_types_fwd.h"
#include <cstdio>

namespace silicon_one
{

class la_device_impl;

enum counter_read_command_e {
    MAX_COUNTER_READ = 0,
    SPECIFIC_COUNTER_READ = 1,
};

class counter_bank_utils
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    counter_bank_utils() = default;
    //////////////////////////////
public:
    static void dispatch_read_counter_command(const la_device_impl_wptr& device,
                                              counter_read_command_e cmd,
                                              size_t counter_read_address);
};
} // namespace silicon_one
#endif // __COUNTER_BANK_UTILS_H__
