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
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "lld/lld_fwd.h"

#include "hld_types.h"
#include "hld_types_fwd.h"

namespace silicon_one
{

class la_device_impl;

class la_ptp_handler_gibraltar : public la_ptp_handler_base
{

    // CEREAL
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_ptp_handler_gibraltar(const la_device_impl_wptr& device);
    ~la_ptp_handler_gibraltar();

    la_status set_pad_config(ptp_pads_config config) const override;
    la_status get_pad_config(ptp_pads_config& out_config) const override;

    la_status set_load_time_offset(la_uint64_t offset) const override;
    la_status get_load_time_offset(la_uint64_t& out_offset) const override;

    la_status adjust_device_time(ptp_sw_tuning_config adjustment) const override;

    la_status load_new_time(ptp_time load_time) const override;
    la_status capture_time(ptp_time& out_load_time) const override;

    la_status load_new_time_unit(ptp_time_unit time_unit) const override;
    la_status get_time_unit(ptp_time_unit& out_time_unit) const override;

private:
    la_status send_cpu_device_time_load() const override;

    // helper methods
    la_status write_command(fte_commands command) const;
    la_status write_command_wait() const;

    gibraltar_tree_scptr m_gb_tree;

    la_ptp_handler_gibraltar() = default;
};
}

/// @}

#endif
