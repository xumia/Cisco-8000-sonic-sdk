// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __IFG_HANDLER_CIFG_H__
#define __IFG_HANDLER_CIFG_H__

#include "system/ifg_handler_base.h"

namespace silicon_one
{

class la_device_impl;

class ifg_handler_cifg : public ifg_handler_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    ifg_handler_cifg(const la_device_impl_wptr& device, la_slice_id_t slice_id, la_ifg_id_t ifg_id);
    ~ifg_handler_cifg() override;

protected:
    // For serialization purposes only
    ifg_handler_cifg() = default;
};
} // namespace silicon_one

#endif // __IFG_HANDLER_CIFG_H__
