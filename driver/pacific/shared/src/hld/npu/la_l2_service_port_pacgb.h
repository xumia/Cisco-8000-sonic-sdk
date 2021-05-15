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

#ifndef __LA_L2_SERVICE_PORT_PACGB_H__
#define __LA_L2_SERVICE_PORT_PACGB_H__

#include "la_l2_service_port_base.h"

#include <sstream>

namespace silicon_one
{

class la_l2_service_port_pacgb : public la_l2_service_port_base
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    //////////////////////////////
public:
    explicit la_l2_service_port_pacgb(const la_device_impl_wptr& device);
    la_l2_service_port_pacgb() = default; // Needed for cereal
    ~la_l2_service_port_pacgb() override;

    lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const override;
    la_status populate_inject_up_port_parameters() override;
    la_status set_group_policy_encap(bool enabled) override;
    la_status get_group_policy_encap(bool& out_enabled) const override;

protected:
    la_status configure_service_lp_attributes_table(la_slice_id_t slice_idx,
                                                    npl_service_lp_attributes_table_entry_wptr_t& lp_attributes_entry) override;
};

} // namespace silicon_one

#endif // __LA_L2_SERVICE_PORT_PACGB_H__
