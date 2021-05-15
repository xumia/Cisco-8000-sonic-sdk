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

#ifndef __LA_EGRESS_QOS_PROFILE_IMPL__
#define __LA_EGRESS_QOS_PROFILE_IMPL__

#include <array>

#include "api/qos/la_egress_qos_profile.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"
namespace silicon_one
{

class la_device_impl;

class la_egress_qos_profile_impl : public la_egress_qos_profile, public dependency_listener
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_egress_qos_profile_impl(const la_device_impl_wptr& device);
    ~la_egress_qos_profile_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, la_egress_qos_marking_source_e marking_source);
    la_status destroy();

    // la_egress_qos_profile API-s

    // Marking source
    la_status get_marking_source(la_egress_qos_marking_source_e& marking_source) const override;

    // Ethernet forwarding QoS re/marking mapping
    la_status set_qos_tag_mapping_pcpdei(la_vlan_pcpdei egress_pcpdei_tag,
                                         la_vlan_pcpdei remark_pcpdei,
                                         encapsulating_headers_qos_values encap_qos_values) override;
    la_status get_qos_tag_mapping_pcpdei(la_vlan_pcpdei egress_pcpdei_tag,
                                         la_vlan_pcpdei& out_remark_pcpdei,
                                         encapsulating_headers_qos_values& out_encap_qos_values) const override;
    la_status set_qos_group_mapping_pcpdei(la_qos_group_t qos_group,
                                           la_vlan_pcpdei pcpdei,
                                           encapsulating_headers_qos_values encap_qos_values) override;
    la_status get_qos_group_mapping_pcpdei(la_qos_group_t qos_group,
                                           la_vlan_pcpdei& out_pcpdei,
                                           encapsulating_headers_qos_values& out_encap_qos_values) const override;

    // IP forwarding QoS re/marking mapping
    la_status set_qos_tag_mapping_dscp(la_ip_dscp egress_dscp_tag,
                                       la_ip_dscp remark_dscp,
                                       encapsulating_headers_qos_values encap_qos_values) override;
    la_status get_qos_tag_mapping_dscp(la_ip_dscp egress_dscp_tag,
                                       la_ip_dscp& out_remark_dscp,
                                       encapsulating_headers_qos_values& out_encap_qos_values) const override;
    la_status set_qos_group_mapping_dscp(la_qos_group_t qos_group,
                                         la_ip_dscp dscp,
                                         encapsulating_headers_qos_values encap_qos_values) override;
    la_status get_qos_group_mapping_dscp(la_qos_group_t qos_group,
                                         la_ip_dscp& out_dscp,
                                         encapsulating_headers_qos_values& out_encap_qos_values) const override;

    // MPLS forwarding QoS re/marking mapping
    la_status set_qos_tag_mapping_mpls_tc(la_mpls_tc egress_mpls_tc_tag,
                                          la_mpls_tc remark_mpls_tc,
                                          encapsulating_headers_qos_values encap_qos_values) override;
    la_status get_qos_tag_mapping_mpls_tc(la_mpls_tc egress_mpls_tc_tag,
                                          la_mpls_tc& out_remark_mpls_tc,
                                          encapsulating_headers_qos_values& out_encap_qos_values) const override;
    la_status set_qos_group_mapping_mpls_tc(la_qos_group_t qos_group,
                                            la_mpls_tc mpls_tc,
                                            encapsulating_headers_qos_values encap_qos_values) override;
    la_status get_qos_group_mapping_mpls_tc(la_qos_group_t qos_group,
                                            la_mpls_tc& out_mpls_tc,
                                            encapsulating_headers_qos_values& out_encap_qos_values) const override;

    la_status set_combined_qos_mapping(la_slice_pair_id_t slice_pair, la_acl_id_t qos_id, uint qos_tag);

    // Counter offset mapping
    la_status set_counter_offset_mapping(la_vlan_pcpdei pcpdei, la_uint8_t offset) override;
    la_status get_counter_offset_mapping(la_vlan_pcpdei pcpdei, la_uint8_t& out_offset) const override;
    la_status set_counter_offset_mapping(la_ip_dscp dscp, la_uint8_t offset) override;
    la_status get_counter_offset_mapping(la_ip_dscp dscp, la_uint8_t& out_offset) const override;
    la_status set_counter_offset_mapping(la_mpls_tc mpls_tc, la_uint8_t offset) override;
    la_status get_counter_offset_mapping(la_mpls_tc mpls_tc, la_uint8_t& out_offset) const override;
    la_status set_counter_offset_mapping(la_qos_group_t qos_group, la_uint8_t offset) override;
    la_status get_counter_offset_mapping(la_qos_group_t qos_group, la_uint8_t& out_offset) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    /// @brief Get profile ID.
    ///
    /// @return Profile ID in hardware.
    uint64_t get_id(la_slice_pair_id_t slice_pair) const;

    /// IFG management
    la_status notify_change(dependency_management_op op) override;
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);
    slice_ifg_vec_t get_ifgs() const;

private:
    // This flag need to be set for any egress QoS policy key for MPLS TC case.
    // NPL will check this flag to make sure incoming packet has MPLS label to pick inner MPLS EXP
    // from packet to do QoS policy match.
    static constexpr la_uint8_t IN_MPLS_EXP_VALID = 0x8;

    la_status set_marking_source(la_egress_qos_marking_source_e marking_source);

    /// Helper functions for writing to QoS mapping table

    la_status read_mac_qos_mapping_table_entry(la_uint8_t pcpdei_or_qos_group, npl_egress_qos_result_t& out_value) const;

    la_status write_mac_qos_mapping_table_entry(la_uint8_t pcpdei_or_qos_group, const npl_egress_qos_result_t& v);

    la_status read_ip_qos_mapping_table_entry(la_uint8_t dscp_or_qos_group, npl_egress_qos_result_t& out_value) const;

    la_status write_ip_qos_mapping_table_entry(la_uint8_t qos_tag_or_qos_group, const npl_egress_qos_result_t& v);

    la_status read_mpls_qos_mapping_table_entry(la_uint8_t mpls_tc_or_qos_group, npl_egress_qos_result_t& v) const;

    la_status write_mpls_qos_mapping_table_entry(la_uint8_t mpls_tc_or_qos_group, const npl_egress_qos_result_t& v);

    la_status set_mac_fwd_qos_mapping_table_entry(la_uint8_t pcpdei_or_qos_group,
                                                  la_vlan_pcpdei remark_pcpdei,
                                                  encapsulating_headers_qos_values encap_qos_values);
    la_status get_mac_fwd_qos_mapping_table_entry(la_uint8_t pcpdei_or_qos_group,
                                                  la_vlan_pcpdei& out_remark_dscp,
                                                  encapsulating_headers_qos_values& out_encap_qos_values) const;
    la_status set_ip_fwd_qos_mapping_table_entry(la_uint8_t dscp_or_qos_group,
                                                 la_ip_dscp remark_dscp,
                                                 encapsulating_headers_qos_values encap_qos_values);
    la_status get_ip_fwd_qos_mapping_table_entry(la_uint8_t dscp_or_qos_group,
                                                 la_ip_dscp& out_remark_dscp,
                                                 encapsulating_headers_qos_values& out_encap_qos_values) const;
    la_status set_mpls_fwd_qos_mapping_table_entry(la_uint8_t mpls_tc_or_qos_group,
                                                   encapsulating_headers_qos_values encap_qos_values);
    la_status get_mpls_fwd_qos_mapping_table_entry(la_uint8_t mpls_tc_or_qos_group,
                                                   encapsulating_headers_qos_values& out_encap_qos_values) const;
    la_status set_qos_mapping(la_slice_pair_id_t slice_pair, la_acl_id_t qos_id);

    /// Device this AC profle belongs to
    la_device_impl_wptr m_device;

    /// Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    struct slice_pair_data {
        /// Profile index
        la_acl_id_t qos_id = la_device_impl::NUM_EGRESS_QOS_PROFILES_PER_SLICE_PAIR;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_pair_data)

    std::array<slice_pair_data, NUM_SLICE_PAIRS_PER_DEVICE> m_slice_pair_data{{}};
    // qos map definitions
    std::array<npl_egress_qos_result_t, LA_MAX_QOS_GROUP> m_qos_map{{}};

    /// Marking source.
    la_egress_qos_marking_source_e m_marking_source;

    // IFG management
    ifg_use_count_uptr m_ifg_use_count;

    la_egress_qos_profile_impl() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __LA_EGRESS_QOS_PROFILE_IMPL__
