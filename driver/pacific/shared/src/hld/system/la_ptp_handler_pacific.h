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

#ifndef __LA_PTP_HANDLER_GIBRALTAR_H__
#define __LA_PTP_HANDLER_GIBRALTAR_H__

#include "la_ptp_handler_base.h"
#include "lld/pacific_tree.h"

#include "hld_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_device_impl;

class la_ptp_handler_pacific : public la_ptp_handler_base
{

    // CEREAL
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_ptp_handler_pacific(const la_device_impl_wptr& device);
    ~la_ptp_handler_pacific();

    la_status enable_load_event_generation(bool enabled) override;

    la_status set_pad_config(ptp_pads_config config) const override;
    la_status get_pad_config(ptp_pads_config& out_config) const override;

    la_status set_load_time_offset(la_uint64_t offset) const override;
    la_status get_load_time_offset(la_uint64_t& out_offset) const override;

private:
    pacific_tree_scptr m_pc_tree;

    la_ptp_handler_pacific() = default;
};
}

/// @}

#endif
