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

#ifndef __LA_INGRESS_QOS_PROFILE_IMPL__
#define __LA_INGRESS_QOS_PROFILE_IMPL__

#include <array>

#include "api/qos/la_ingress_qos_profile.h"
#include "api/types/la_qos_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"
#include "qos/la_meter_markdown_profile_impl.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

class la_device_impl;
class la_meter_markdown_profile_impl;

class la_ingress_qos_profile_impl : public la_ingress_qos_profile, public dependency_listener
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_ingress_qos_profile_impl(const la_device_impl_wptr& device);
    ~la_ingress_qos_profile_impl() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid);
    la_status destroy();

    // la_ingress_qos_profile API-s
    // Traffic class mapping
    la_status set_traffic_class_mapping(la_vlan_pcpdei pcpdei, la_traffic_class_t tc) override;
    la_status get_traffic_class_mapping(la_vlan_pcpdei pcpdei, la_traffic_class_t& out_tc) const override;
    la_status set_traffic_class_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_traffic_class_t tc) override;
    la_status get_traffic_class_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_traffic_class_t& out_tc) const override;
    la_status set_traffic_class_mapping(la_mpls_tc mpls_tc, la_traffic_class_t tc) override;
    la_status get_traffic_class_mapping(la_mpls_tc mpls_tc, la_traffic_class_t& out_tc) const override;

    // Color mapping
    la_status set_color_mapping(la_vlan_pcpdei pcpdei, la_qos_color_e color) override;
    la_status get_color_mapping(la_vlan_pcpdei pcpdei, la_qos_color_e& out_color) const override;
    la_status set_color_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_color_e color) override;
    la_status get_color_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_color_e& out_color) const override;
    la_status set_color_mapping(la_mpls_tc mpls_tc, la_qos_color_e color) override;
    la_status get_color_mapping(la_mpls_tc mpls_tc, la_qos_color_e& out_color) const override;

    // Meter/Counter offset mapping
    la_status set_meter_or_counter_offset_mapping(la_vlan_pcpdei pcpdei, la_uint8_t offset) override;
    la_status get_meter_or_counter_offset_mapping(la_vlan_pcpdei pcpdei, la_uint8_t& out_offset) const override;
    la_status set_meter_or_counter_offset_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_uint8_t offset) override;
    la_status get_meter_or_counter_offset_mapping(la_ip_version_e ip_version,
                                                  la_ip_dscp dscp,
                                                  la_uint8_t& out_offset) const override;
    la_status set_meter_or_counter_offset_mapping(la_mpls_tc mpls_tc, la_uint8_t offset) override;
    la_status get_meter_or_counter_offset_mapping(la_mpls_tc mpls_tc, la_uint8_t& out_offset) const override;

    // Meter or Counter selection mapping
    la_status set_metering_enabled_mapping(la_vlan_pcpdei pcpdei, bool enabled) override;
    la_status get_metering_enabled_mapping(la_vlan_pcpdei pcpdei, bool& out_enabled) const override;
    la_status set_metering_enabled_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, bool enabled) override;
    la_status get_metering_enabled_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, bool& out_enabled) const override;
    la_status set_metering_enabled_mapping(la_mpls_tc mpls_tc, bool enabled) override;
    la_status get_metering_enabled_mapping(la_mpls_tc mpls_tc, bool& out_enabled) const override;

    // Ingress QoS field mapping
    la_status set_qos_tag_mapping_pcpdei(la_vlan_pcpdei ingress_pcpdei, la_vlan_pcpdei mapped_pcpdei_tag) override;
    la_status get_qos_tag_mapping_pcpdei(la_vlan_pcpdei ingress_pcpdei, la_vlan_pcpdei& out_mapped_pcpdei_tag) const override;

    la_status set_qos_tag_mapping_dscp(la_ip_dscp ingress_dscp, la_ip_dscp mapped_dscp_tag) override;
    la_status set_qos_tag_mapping_dscp(la_ip_version_e ip_version, la_ip_dscp ingress_dscp, la_ip_dscp mapped_dscp_tag) override;
    la_status get_qos_tag_mapping_dscp(la_ip_version_e ip_version,
                                       la_ip_dscp ingress_dscp,
                                       la_ip_dscp& out_mapped_dscp_tag) const override;

    la_status set_qos_tag_mapping_mpls_tc(la_mpls_tc ingress_mpls_tc, la_mpls_tc mapped_mpls_tc_tag) override;
    la_status get_qos_tag_mapping_mpls_tc(la_mpls_tc ingress_mpls_tc, la_mpls_tc& out_mapped_mpls_tc_tag) const override;

    // MPLS EXP-imposition label traffic-class mapping
    la_status set_encap_qos_tag_mapping(la_vlan_pcpdei pcpdei, la_mpls_tc ingress_encap_qos_tag) override;
    la_status get_encap_qos_tag_mapping(la_vlan_pcpdei pcpdei, la_mpls_tc& out_ingress_encap_qos_tag) const override;
    la_status set_encap_qos_tag_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_mpls_tc ingress_encap_qos_tag) override;
    la_status get_encap_qos_tag_mapping(la_ip_version_e ip_version,
                                        la_ip_dscp dscp,
                                        la_mpls_tc& out_ingress_encap_qos_tag) const override;
    la_status set_encap_qos_tag_mapping(la_mpls_tc mpls_tc, la_mpls_tc ingress_encap_qos_tag) override;
    la_status get_encap_qos_tag_mapping(la_mpls_tc mpls_tc, la_mpls_tc& out_ingress_encap_qos_tag) const override;

    // QoS Group mapping
    la_status set_qos_group_mapping(la_vlan_pcpdei pcpdei, la_qos_group_t qos_group) override;
    la_status get_qos_group_mapping(la_vlan_pcpdei pcpdei, la_qos_group_t& out_qos_group) const override;
    la_status set_qos_group_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_group_t qos_group) override;
    la_status get_qos_group_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_group_t& out_qos_group) const override;
    la_status set_qos_group_mapping(la_mpls_tc mpls_tc, la_qos_group_t qos_group) override;
    la_status get_qos_group_mapping(la_mpls_tc mpls_tc, la_qos_group_t& out_qos_group) const override;

    // Meter markdown profile
    la_status set_meter_markdown_profile(const la_meter_markdown_profile* meter_markdown_profile) override;
    la_status get_meter_markdown_profile(const la_meter_markdown_profile*& out_meter_markdown_profile) const override;
    la_status clear_meter_markdown_profile() override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    la_status set_qos_tag_mapping_enabled(bool enabled) override;
    la_status get_qos_tag_mapping_enabled(bool& out_enabled) const override;

    /// @brief Get profile ID.
    ///
    /// @return Profile ID in hardware.
    uint64_t get_id(la_slice_pair_id_t slice_pair) const;

    /// IFG management
    la_status notify_change(dependency_management_op op) override;
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);
    slice_ifg_vec_t get_ifgs() const;

    /// Reserved meter markdown profile id.
    static constexpr uint8_t LA_RSVD_METER_MARKDOWN_PROFILE_ID = 15;

private:
    /// Helper functions for writing to QoS mapping tables
    la_status read_mac_qos_mapping_table_entry(la_vlan_pcpdei pcpdei, npl_mac_qos_mapping_table_t::value_type& out_value) const;
    la_status write_mac_qos_mapping_table_entry(la_vlan_pcpdei pcpdei, npl_mac_qos_mapping_table_t::value_type& v);
    la_status read_ip_qos_mapping_table_entry(la_ip_version_e ip_version,
                                              la_ip_dscp dscp,
                                              npl_ingress_ip_qos_mapping_table_t::value_type& out_value) const;
    la_status write_ip_qos_mapping_table_entry(la_ip_version_e ip_version,
                                               la_ip_dscp dscp,
                                               npl_ingress_ip_qos_mapping_table_t::value_type& v);
    la_status read_mpls_qos_mapping_table_entry(la_mpls_tc mpls_tc, npl_mpls_qos_mapping_table_t::value_type& out_value) const;
    la_status write_mpls_qos_mapping_table_entry(la_mpls_tc mpls_tc, npl_mpls_qos_mapping_table_t::value_type& v);

    la_status set_mac_qos_mapping_table_entry(la_vlan_pcpdei pcpdei, la_vlan_pcpdei mapped_pcpdei_tag);
    la_status get_mac_qos_mapping_table_entry(la_vlan_pcpdei pcpdei, la_vlan_pcpdei& out_mapped_pcpdei_tag) const;
    la_status set_ip_qos_mapping_table_entry(la_ip_version_e ip_version, la_ip_dscp dscp, la_ip_dscp mapped_dscp_tag);
    la_status get_ip_qos_mapping_table_entry(la_ip_version_e ip_version, la_ip_dscp dscp, la_ip_dscp& out_mapped_dscp_tag) const;
    la_status set_mpls_qos_mapping_table_entry(la_mpls_tc mpls_tc, la_mpls_tc mapped_mpls_tc_tag);
    la_status get_mpls_qos_mapping_table_entry(la_mpls_tc mpls_tc, la_mpls_tc& out_mapped_mpls_tc_tag) const;

    la_status set_mpls_qos_mapping_table(la_slice_pair_id_t slice_pair, la_acl_id_t qos_id, uint mpls_tc);
    la_status set_ip_qos_mapping_table(la_ip_version_e ip_version, la_slice_pair_id_t slice_pair, la_acl_id_t qos_id, uint dscp);
    la_status set_mac_qos_mapping_table(la_slice_pair_id_t slice_pair, la_acl_id_t qos_id, uint pcpdei);

    la_status set_mac_traffic_class_mapping(la_vlan_pcpdei pcpdei, la_traffic_class_t tc);
    la_status get_mac_traffic_class_mapping(la_vlan_pcpdei pcpdei, la_traffic_class_t& out_tc) const;
    la_status set_ip_traffic_class_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_traffic_class_t tc);
    la_status get_ip_traffic_class_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_traffic_class_t& out_tc) const;
    la_status set_mpls_traffic_class_mapping(la_mpls_tc mpls_tc, la_traffic_class_t tc);
    la_status get_mpls_traffic_class_mapping(la_mpls_tc mpls_tc, la_traffic_class_t& out_tc) const;

    la_status set_mac_metering_enabled_mapping(la_vlan_pcpdei pcpdei, bool enabled);
    la_status get_mac_metering_enabled_mapping(la_vlan_pcpdei pcpdei, bool& out_enabled) const;
    la_status set_ip_metering_enabled_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, bool enabled);
    la_status get_ip_metering_enabled_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, bool& out_enabled) const;
    la_status set_mpls_metering_enabled_mapping(la_mpls_tc mpls_tc, bool enabled);
    la_status get_mpls_metering_enabled_mapping(la_mpls_tc mpls_tc, bool& out_enabled) const;

    la_status set_mac_color_mapping(la_vlan_pcpdei pcpdei, la_qos_color_e color);
    la_status get_mac_color_mapping(la_vlan_pcpdei pcpdei, la_qos_color_e& out_color) const;
    la_status set_ip_color_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_color_e color);
    la_status get_ip_color_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_color_e& out_color) const;
    la_status set_mpls_color_mapping(la_mpls_tc mpls_tc, la_qos_color_e color);
    la_status get_mpls_color_mapping(la_mpls_tc mpls_tc, la_qos_color_e& out_color) const;

    la_status set_mac_encap_qos_tag_mapping(la_vlan_pcpdei pcpdei, la_mpls_tc encap_mpls_tc);
    la_status get_mac_encap_qos_tag_mapping(la_vlan_pcpdei pcpdei, la_mpls_tc& out_encap_mpls_tc) const;
    la_status set_ip_encap_qos_tag_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_mpls_tc encap_mpls_tc);
    la_status get_ip_encap_qos_tag_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_mpls_tc& out_encap_mpls_tc) const;
    la_status set_mpls_encap_qos_tag_mapping(la_mpls_tc mpls_tc, la_mpls_tc encap_mpls_tc);
    la_status get_mpls_encap_qos_tag_mapping(la_mpls_tc mpls_tc, la_mpls_tc& out_encap_mpls_tc) const;

    la_status set_mac_qos_group_mapping(la_vlan_pcpdei pcpdei, la_qos_group_t qos_group);
    la_status get_mac_qos_group_mapping(la_vlan_pcpdei pcpdei, la_qos_group_t& out_qos_group) const;
    la_status set_ip_qos_group_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_group_t qos_group);
    la_status get_ip_qos_group_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_group_t& out_qos_group) const;
    la_status set_mpls_qos_group_mapping(la_mpls_tc mpls_tc, la_qos_group_t qos_group);
    la_status get_mpls_qos_group_mapping(la_mpls_tc mpls_tc, la_qos_group_t& out_qos_group) const;

    la_status set_qos_mappings(la_slice_pair_id_t slice_pair, la_acl_id_t qos_id);

    /* Meter markdown profile APIs */
    la_status set_eth_meter_profile_mapping_table(la_slice_id_t slice_id, uint64_t qos_id, uint64_t profile_id);
    la_status set_ip_meter_profile_mapping_table(la_slice_id_t slice_id, uint64_t qos_id, uint64_t profile_id);
    la_status set_meter_markdown_profile_mapping(uint64_t profile_id);

    /// Device this AC profle belongs to
    la_device_impl_wptr m_device;

    /// Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    std::array<la_acl_delegate_wptr, (size_t)la_acl_key_type_e::LAST> m_acls{{}};

    /// Enable/disable ingress remarking
    bool m_enable_ingress_remark;

    // IFG management
    ifg_use_count_uptr m_ifg_use_count;

    la_meter_markdown_profile_impl_wcptr m_meter_markdown_profile;

    struct slice_pair_data {
        /// Profile index
        la_acl_id_t qos_id = la_device_impl::ACL_INVALID_ID;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_pair_data)

    std::array<slice_pair_data, NUM_SLICE_PAIRS_PER_DEVICE> m_slice_pair_data{{}};
    // qos map definitions
    std::array<npl_ingress_ip_qos_mapping_table_value_t, LA_MAX_DSCP> m_ip_qos_map{{}};
    std::array<npl_ingress_ip_qos_mapping_table_value_t, LA_MAX_DSCP> m_ipv6_qos_map{{}};
    std::array<npl_mac_qos_mapping_table_value_t, LA_MAX_PCPDEI> m_mac_qos_map{{}};
    std::array<npl_mpls_qos_mapping_table_value_t, LA_MAX_EXP> m_mpls_qos_map{{}};

    la_ingress_qos_profile_impl() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __LA_INGRESS_QOS_PROFILE_IMPL__
