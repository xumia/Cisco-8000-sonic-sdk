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

#ifndef __LA_L2_MULTICAST_GROUP_PACIFIC_H__
#define __LA_L2_MULTICAST_GROUP_PACIFIC_H__

#include <map>
#include <vector>

#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l2_multicast_group.h"
#include "api/types/la_object.h"

#include "npu/la_l2_multicast_group_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_multicast_group_common_base.h"
#include "npu/la_multicast_group_common_pacific.h"
#include "npu/resolution_utils.h"

namespace silicon_one
{
class la_device_impl;

class la_l2_multicast_group_pacific : public la_l2_multicast_group_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    explicit la_l2_multicast_group_pacific(la_device_impl_wptr device);
    ~la_l2_multicast_group_pacific() override;

private:
    la_l2_multicast_group_pacific() = default;

    la_status get_mc_copy_id(const member_t& member,
                             const la_system_port_wcptr& dsp,
                             bool is_wide,
                             uint64_t& out_mc_copy_id) override;
    la_status release_mc_copy_id(const member_t& member, const la_system_port_wcptr& dsp) override;
    la_status add_to_mc_copy_id_table(const member_t& member, const la_system_port_wcptr& dsp) override;
    la_status remove_from_mc_copy_id_table(const member_t& member, const la_system_port_wcptr& dsp) override;
    la_status add(const la_l2_destination* vxlan_port, la_next_hop* next_hop, const la_system_port* dsp) override;
    la_status remove_cud_table_entry(const la_l2_destination* destination, const la_system_port_wcptr& dsp) override;
    la_status configure_stack_copy_cud_mapping(la_slice_id_t slice, uint64_t mc_copy_id) override;
};

} // namespace silicon_one

#endif // __LA_L2_MULTICAST_GROUP_PACIFIC_H__
