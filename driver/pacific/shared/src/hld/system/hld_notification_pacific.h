// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __HLD_NOTIFICATION_PACIFIC_H__
#define __HLD_NOTIFICATION_PACIFIC_H__

#include "hld_notification_base.h"

namespace silicon_one
{

class la_device_impl;

class hld_notification_pacific : public hld_notification_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief c'tor
    hld_notification_pacific(const la_device_impl_wptr& device);

    /// @brief d'tor
    virtual ~hld_notification_pacific();

    /// @brief Initialize internal objects and load the interrupt tree
    ///
    /// @return     Status code.
    la_status initialize() override;

protected:
    bool is_msi_clear() override;

    void init_static_mapping(const la_device_impl_wptr& la_device, vector_alloc<lld_memory_scptr>& out_vect) const override;

private:
    // For serialization purposes only
    hld_notification_pacific() = default;
};

} // namespace silicon_one
#endif
