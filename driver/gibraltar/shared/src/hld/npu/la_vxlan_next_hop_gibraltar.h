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

#ifndef __LA_VXLAN_NEXT_HOP_GIBRALTAR_H__
#define __LA_VXLAN_NEXT_HOP_GIBRALTAR_H__

#include <vector>

#include "la_vxlan_next_hop_base.h"

namespace silicon_one
{

class la_device_impl;
class la_l3_fec_impl;
class la_svi_port_base;
class la_l2_service_port_base;

class la_vxlan_next_hop_gibraltar : public la_vxlan_next_hop_base
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    //////////////////////////////
public:
    explicit la_vxlan_next_hop_gibraltar(const la_device_impl_wptr& device);
    ~la_vxlan_next_hop_gibraltar() override;

    // Resolution API helpers
    lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const override;
    destination_id get_destination_id(resolution_step_e prev_step) const override;

protected:
    la_vxlan_next_hop_gibraltar() = default;

private:
    // Resolution API helpers
    // General functions
    resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const;
};

} // namesapce silicon_one

#endif // __LA_VXLAN_NEXT_HOP_GIBRALTAR_H__
