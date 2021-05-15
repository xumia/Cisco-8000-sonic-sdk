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

#ifndef __LA_ETHERNET_PORT_BASE_H__
#define __LA_ETHERNET_PORT_BASE_H__

#include "api/npu/la_ethernet_port.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"

#include <vector>

namespace silicon_one
{

class la_ethernet_port_base : public la_ethernet_port, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    explicit la_ethernet_port_base(const la_device_impl_wptr& device);
    ~la_ethernet_port_base() override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, la_system_port_base* system_port, la_l2_port_gid_t port_gid, port_type_e type);
    la_status initialize(la_object_id_t oid, la_spa_port_base* spa_port, la_l2_port_gid_t port_gid, port_type_e type);
    la_status destroy();

    // la_l2_port API-s
    la_status set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile) override;
    la_status get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const override;
    la_status set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile) override;
    la_status get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const override;

    la_status set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group) override;
    la_status get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const override;
    la_status clear_acl_group(la_acl_direction_e dir) override;

    la_status set_meter(const la_meter_set* meter) override;
    la_status get_meter(const la_meter_set*& out_meter) const override;

    // Mirror command API-s
    la_status set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const override;
    la_status set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const override;

    // Counter API-s
    la_status set_ingress_counter(la_counter_set::type_e type, la_counter_set* counter) override;
    la_status get_ingress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const override;
    la_status set_egress_counter(la_counter_set::type_e type, la_counter_set* counter) override;
    la_status get_egress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const override;

    // la_ethernet_port API-s
    la_status get_port_type(port_type_e& out_type) const override;

    la_status get_allowed_vlans(la_vlan_set_t* out_allowed_vlans) override;
    la_status set_allowed_vlans(const la_vlan_set_t allowed_vlans) override;

    la_status get_security_mode(la_port_security_mode_e* out_security_mode) override;
    la_status set_security_mode(la_port_security_mode_e security_mode) override;

    la_status get_ac_profile(la_ac_profile*& out_profile) const override;
    la_status set_ac_profile(la_ac_profile* profile) override;

    la_status get_ac_port(la_vlan_id_t vid1, la_vlan_id_t vid2, const la_object*& out_object) const override;

    la_status get_transparent_ptp_enabled(bool& out_enabled) const override;
    la_status set_transparent_ptp_enabled(bool enabled) override;

    la_mtu_t get_mtu() const override;
    la_status set_mtu(la_mtu_t mtu) override;

    la_status get_service_mapping_type(service_mapping_type_e& out_type) const override;
    la_status set_service_mapping_type(service_mapping_type_e type) override;

    const la_system_port* get_system_port() const override;
    const la_spa_port* get_spa_port() const override;

    la_status get_svi_egress_tag_mode(svi_egress_tag_mode_e& out_mode) const override;
    la_status set_svi_egress_tag_mode(svi_egress_tag_mode_e mode) override;

    la_vlan_pcpdei get_ingress_default_pcpdei() const override;
    la_status set_ingress_default_pcpdei(la_vlan_pcpdei pcpdei) override;

    // Security Group API-s
    la_status set_security_group_tag(la_sgt_t sgt) override;
    la_status get_security_group_tag(la_sgt_t& out_sgt) const override;
    la_status set_security_group_policy_enforcement(bool enforcement) override;
    la_status get_security_group_policy_enforcement(bool& out_enforcement) const override;
    virtual la_status configure_security_group_policy_attributes() = 0;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_ethernet_port_base additional API-s
    la_l2_port_gid_t get_id() const;

    /// @brief Add an IFG user.
    ///
    /// Updates per-IFG use-count and properties for this counter.
    ///
    /// @param[in]  ifg         IFG usage being added.
    ///
    /// @retval     LA_STATUS_SUCCESS   Per-slice information initialized correctly.
    /// @retval     LA_STATUS_ERESOURCE Missing resources to complete configuration request.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status add_ifg(la_slice_ifg ifg);

    /// @brief Remove IFG user.
    ///
    /// @param[in]  ifg         IFG usage being removed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Per-slice information released correctly (if not in use by other objects).
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status remove_ifg(la_slice_ifg ifg);

    /// @brief Get a list of active IFGs
    ///
    /// @retval  A vector that holds the active IFGs
    slice_ifg_vec_t get_ifgs() const;

    /// @brief Set AC port according to VLAN ID's.
    ///
    /// @param[in] ac_port      AC port.
    /// @param[in] vid1         VLAN ID 1.
    /// @param[in] vid2         VLAN ID 2.
    void set_ac_port(la_vlan_id_t vid1, la_vlan_id_t vid2, la_object_wcptr ac_port);

    /// @brief Clear AC port associated with this ethernet port by VLAN ID's.
    ///
    /// @param[in] vid1         VLAN ID 1.
    /// @param[in] vid2         VLAN ID 2.
    void clear_ac_port(la_vlan_id_t vid1, la_vlan_id_t vid2);

    // True if ethport is on the system port
    bool is_member(const la_system_port_wcptr& system_port) const;

    // True if ethport is on a spa port
    bool is_aggregate() const;

    // Return the underlying port as la_object
    la_object* get_underlying_port() const;

    // Return the underlying port type
    la_object::object_type_e get_underlying_port_type() const;

    la_status get_port_vid(la_vlan_id_t& out_vid) const override;
    la_status set_port_vid(la_vlan_id_t out_vid) override;

    bool get_decrement_ttl() const override;
    la_status set_decrement_ttl(bool decrement_ttl) override;

    la_status set_stack_mc_prune(bool prune_enable) override;
    la_status get_stack_mc_prune(bool& prune_enabled) const override;

    la_status set_copc_profile(la_control_plane_classifier::ethernet_profile_id_t ethernet_profile_id) override;
    la_status get_copc_profile(la_control_plane_classifier::ethernet_profile_id_t& out_ethernet_profile_id) const override;
    la_status set_traffic_matrix_interface_type(traffic_matrix_type_e type) override;
    la_status get_traffic_matrix_interface_type(traffic_matrix_type_e& out_traffic_matrix_type) const override;

protected:
    la_ethernet_port_base() = default;

    using system_port_base_vec = std::vector<la_system_port_base_wptr>;

    la_status initialize_common();
    la_status destroy_common();

    la_status update_npp_attributes();
    la_status update_npp_sgt_attributes();
    la_status update_dsp_sgt_attributes();
    virtual la_status set_source_pif_entry(const la_ac_profile_impl* ac_profile) = 0;
    virtual la_status erase_source_pif_entry();
    la_status set_inject_up_entry(la_ac_profile_impl* ac_profile);
    la_status erase_inject_up_entry();
    la_status set_inject_up_entry(la_system_port_base* sys_port, la_ac_profile_impl* ac_profile);
    la_status erase_inject_up_entry(la_system_port_base* sys_port);
    la_status do_set_mtu();

    virtual npl_mac_af_npp_attributes_table_t::value_type populate_mac_af_npp_attributes() const = 0;
    npl_initial_pd_nw_rx_data_t populate_initial_pd_nw_rx_data(const la_ac_profile_impl* ac_profile) const;

    system_port_base_vec get_underlying_local_system_port_vec() const;

    /// Device this ethernet port belongs to
    la_device_impl_wptr m_device;

    // IFG manager
    ifg_use_count_uptr m_ifg_use_count;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    /// System port
    la_system_port_base_wptr m_system_port;

    /// SPA port
    la_spa_port_base_wptr m_spa_port;

    /// L2 port GID
    la_l2_port_gid_t m_id;

    /// Port type
    port_type_e m_port_type;

    /// AC port only: AC profile
    la_ac_profile_impl_wptr m_ac_profile;

    /// COPC profile value
    la_uint8_t m_copc_profile;

    // PTP transparent mode enabled on this port
    bool m_transparent_ptp_enabled;

    // SR DM accounting eligbility
    traffic_matrix_type_e m_traffic_matrix_type;

    // MTU value for this port
    la_mtu_t m_mtu;

    struct ac_port_key {
        la_vlan_id_t vid1;
        la_vlan_id_t vid2;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ac_port_key);

    struct ac_port_key_operator_less {
        bool operator()(const ac_port_key& lhs, const ac_port_key& rhs) const
        {
            if (lhs.vid1 != rhs.vid1) {
                return lhs.vid1 < rhs.vid1;
            }

            return lhs.vid2 < rhs.vid2;
        }
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ac_port_key_operator_less);

    std::map<ac_port_key, la_object_wcptr, ac_port_key_operator_less> m_ac_ports_entries;
    svi_egress_tag_mode_e m_svi_egress_tag_mode;

    /// Service mapping type
    service_mapping_type_e m_service_mapping_type;

    /// Port default vid
    la_vlan_id_t m_port_vid;

    /// Port default (PCP, DEI)
    la_vlan_pcpdei m_default_pcpdei;

    bool m_decrement_ttl;

    /// Security Group Tag
    la_sgt_t m_security_group_tag;

    /// Security Group Policy enforcement
    bool m_security_group_policy_enforcement;
};
}
/// @}

#endif
