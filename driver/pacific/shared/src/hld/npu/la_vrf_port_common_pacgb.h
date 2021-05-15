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

// la_vrf_port_common_... models the shared part betweeen la_svi_port_base and la_l3_ac_port_impl, among others
//
#ifndef __LA_VRF_PORT_COMMON_PACGB_H__
#define __LA_VRF_PORT_COMMON_PACGB_H__

#include <array>
#include <bitset>
#include <map>
#include <vector>

#include "api/npu/la_acl.h"
#include "api/npu/la_svi_port.h"
#include "api/system/la_mirror_command.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "ifg_use_count.h"
#include "la_vrf_port_common_base.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_vrf_port_common_pacgb : public la_vrf_port_common_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    la_vrf_port_common_pacgb(const la_device_impl_wptr& device, la_l3_port_wptr parent);
    virtual ~la_vrf_port_common_pacgb();

    // IFG management
    la_status add_ifg(la_slice_ifg ifg) override;
    la_status remove_ifg(la_slice_ifg ifg) override;

    // l3_port API-s
    la_status set_active(bool active) override;
    la_status set_port_egress_mode(bool active) override;

    la_status set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile) override;

    la_status set_ecn_remark_enabled(bool enabled) override;
    la_status set_mac(const la_mac_addr_t& mac_addr) override;

    // Mirror Command API-s
    la_status set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status set_ecn_counting_enabled(bool enabled) override;

    la_status set_egress_vlan_tag(la_vlan_tag_t tag1, la_vlan_tag_t tag2) override;

    // Populate the given key
    la_status get_mac_termination_table_key(la_switch_gid_t sw_id, npl_mac_termination_em_table_key_t& out_key) const override;

    // Egress DHCP snooping
    la_status set_egress_dhcp_snooping_enabled(bool enabled) override;

protected:
    struct slice_pair_data {
        /// Address of entry of the l3-dlp table
        npl_l3_dlp_table_entry_wptr_t l3_dlp_table_entry = nullptr;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_pair_data)

    // Slice-pair data
    std::vector<slice_pair_data> m_slice_pair_data;

protected:
    la_vrf_port_common_pacgb() = default;
    // Manage the L3-DLP table
    la_status configure_l3_dlp_attributes(la_slice_pair_id_t pair_idx) override;
    la_status configure_l3_dlp_table(la_slice_pair_id_t pair_idx) override;
    la_status teardown_l3_dlp_table(la_slice_pair_id_t pair_idx) override;

    // Helper function for counter
    la_status configure_ingress_counter() override;
    la_status configure_egress_drop_counter_offset(size_t offset) override;
};

} // namespace silicon_one

#endif // __LA_VRF_PORT_COMMON_PACGB_H__
