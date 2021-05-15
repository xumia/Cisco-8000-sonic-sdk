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

#ifndef __ARC_HANDLER_PACIFIC_H__
#define __ARC_HANDLER_PACIFIC_H__

#include "lld/lld_fwd.h"
#include "system/arc_handler_base.h"

namespace silicon_one
{

class la_device_impl;

class arc_handler_pacific : public arc_handler_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    arc_handler_pacific(const la_device_impl_wptr& device);
    ~arc_handler_pacific();

    // Disallow copy c'tor. Default construct is private, in order to support serialization
    arc_handler_pacific(const arc_handler_pacific&) = delete;

private:
    lld_memory_sptr get_mem_ptr();

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    arc_handler_pacific() = default;
};
} // namespace silicon_one

#endif // __ARC_HANDLER_PACIFIC_H__
