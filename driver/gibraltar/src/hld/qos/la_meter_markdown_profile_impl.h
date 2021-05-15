// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_METER_MARKDOWN_PROFILE_IMPL_H__
#define __LA_METER_MARKDOWN_PROFILE_IMPL_H__

#include "api/qos/la_meter_markdown_profile.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"

namespace silicon_one
{

class la_device_impl;

class la_meter_markdown_profile_impl : public la_meter_markdown_profile
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_meter_markdown_profile_impl(const la_device_impl_wptr& device);
    ~la_meter_markdown_profile_impl() override;
    la_status initialize(la_object_id_t oid, la_meter_markdown_gid_t gid);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;
    la_meter_markdown_gid_t get_gid() const override;

    // la_meter_markdown_profile API-s
    la_status set_meter_markdown_mapping_pcpdei(la_qos_color_e color,
                                                la_vlan_pcpdei from_pcp,
                                                la_vlan_pcpdei markdown_pcp) override;

    la_status set_meter_markdown_mapping_dscp(la_qos_color_e color, la_ip_dscp from_dscp, la_ip_dscp markdown_dscp) override;

    la_status set_meter_markdown_mapping_mpls_tc(la_qos_color_e color,
                                                 la_mpls_tc from_mpls_tc,
                                                 la_mpls_tc markdown_mpls_tc) override;

    la_status set_meter_markdown_mapping_mpls_tc_encap(la_qos_color_e color,
                                                       la_mpls_tc from_encap_mpls_tc,
                                                       la_mpls_tc markdown_mpls_tc) override;

    la_status get_meter_markdown_mapping_pcpdei(la_qos_color_e color,
                                                la_vlan_pcpdei from_pcp,
                                                la_vlan_pcpdei& out_markdown_pcp) const override;

    la_status get_meter_markdown_mapping_dscp(la_qos_color_e color,
                                              la_ip_dscp from_dscp,
                                              la_ip_dscp& out_markdown_dscp) const override;

    la_status get_meter_markdown_mapping_mpls_tc(la_qos_color_e color,
                                                 la_mpls_tc from_mpls_tc,
                                                 la_mpls_tc& out_markdown_mpls_tc) const override;

    la_status get_meter_markdown_mapping_mpls_tc_encap(la_qos_color_e color,
                                                       la_mpls_tc from_encap_mpls_tc,
                                                       la_mpls_tc& out_markdown_mpls_tc) const override;

private:
    // Containing device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    /// Global ID given by the user
    la_meter_markdown_gid_t m_gid;

    la_status set_meter_markdown_default_mappings();

    la_meter_markdown_profile_impl() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif //  __LA_METER_MARKDOWN_PROFILE_IMPL_H__
