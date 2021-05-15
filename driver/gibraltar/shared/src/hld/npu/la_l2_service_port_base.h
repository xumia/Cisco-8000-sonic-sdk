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

#ifndef __LEABA_LA_L2_SERVICE_PORT_BASE_H__
#define __LEABA_LA_L2_SERVICE_PORT_BASE_H__

#include <array>
#include <map>

#include "api/npu/la_ac_profile.h"
#include "api/npu/la_l2_service_port.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_mpls_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"
#include "npu/ipv4_sip_index_manager.h"
#include "npu/la_ac_port_common.h"
#include "npu/la_acl_group_base.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

class la_l2_service_port_base : public la_l2_service_port, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    explicit la_l2_service_port_base(const la_device_impl_wptr& device);
    ~la_l2_service_port_base() override;

    // Object life-cycle API-s

    la_status initialize_ac(la_object_id_t oid,
                            la_l2_port_gid_t port_gid,
                            const la_ethernet_port_base_wcptr& ethernet_port_impl,
                            la_vlan_id_t vid1,
                            la_vlan_id_t vid2,
                            const la_filter_group_impl_wcptr& filter_group,
                            const la_ingress_qos_profile_impl_wptr& ingress_qos_profile_impl,
                            const la_egress_qos_profile_impl_wptr& egress_qos_profile_impl);

    la_status initialize_pwe(la_object_id_t oid,
                             la_l2_port_gid_t port_gid,
                             la_mpls_label local_label,
                             la_mpls_label remote_label,
                             la_pwe_gid_t pwe_gid,
                             const la_l3_destination_wptr& destination,
                             const la_ingress_qos_profile_impl_wptr& ingress_qos_profile_impl,
                             const la_egress_qos_profile_impl_wptr& egress_qos_profile_impl);

    la_status initialize_pwe_tagged(la_object_id_t oid,
                                    la_l2_port_gid_t port_gid,
                                    la_mpls_label local_label,
                                    la_mpls_label remote_label,
                                    la_vlan_id_t vid1,
                                    const la_l3_destination_wptr& destination,
                                    const la_ingress_qos_profile_impl_wptr& ingress_qos_profile_impl,
                                    const la_egress_qos_profile_impl_wptr& egress_qos_profile_impl);

    la_status initialize_vxlan(la_object_id_t oid,
                               la_l2_port_gid_t port_gid,
                               la_ipv4_addr_t local_ip_addr,
                               la_ipv4_addr_t remote_ip_addr,
                               const la_vrf_wptr& vrf);

    la_status initialize_vxlan(la_object_id_t oid,
                               la_l2_port_gid_t port_gid,
                               la_ip_tunnel_mode_e tunnel_mode,
                               la_ipv4_prefix_t local_ip_prefix,
                               la_ipv4_addr_t remote_ip_addr,
                               const la_vrf_wptr& vrf);

    la_status destroy();

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    // la_l2_port API-s
    la_status set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile) override;
    la_status get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const override;
    la_status set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile) override;
    la_status get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const override;

    la_status set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group) override;
    la_status get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const override;
    la_status clear_acl_group(la_acl_direction_e dir) override;

    la_status get_mac_learning_mode(la_lp_mac_learning_mode_e& out_learning_mode) override;
    la_status set_mac_learning_mode(la_lp_mac_learning_mode_e learning_mode) override;

    la_status set_ingress_counter(la_counter_set::type_e type, la_counter_set* counter) override;
    la_status get_ingress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const override;
    la_status set_egress_counter(la_counter_set::type_e type, la_counter_set* counter) override;
    la_status get_egress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const override;
    la_status set_meter(const la_meter_set* meter) override;
    la_status get_meter(const la_meter_set*& out_meter) const override;
    la_status set_drop_counter_offset(la_stage_e stage, size_t offset) override;
    la_status get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const override;

    // Mirror command API-s
    la_status set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const override;
    la_status set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const override;

    // la_l2_service_port API-s
    la_status get_stp_state(la_port_stp_state_e& out_state) const override;
    template <class _EntryType>
    la_status do_set_stp_state(const weak_ptr_unsafe<_EntryType>& dlp_entry, bool state);
    la_status set_stp_state(la_port_stp_state_e state) override;

    la_status get_filter_group(const la_filter_group*& out_group) const override;
    template <class _EntryType>
    la_status do_set_filter_group(const weak_ptr_unsafe<_EntryType>& dlp_entry, uint64_t group_id);
    template <class _EntryType>
    la_status do_set_vxlan_filter_group(const weak_ptr_unsafe<_EntryType>& dlp_entry, uint64_t group_id);
    la_status set_filter_group(la_filter_group* group) override;

    template <class _EntryType>
    la_status do_set_egress_vlan_edit_command(const weak_ptr_unsafe<_EntryType>& dlp_entry,
                                              npl_ive_profile_and_data_t npl_edit_command);
    la_status get_egress_vlan_edit_command(la_vlan_edit_command& out_edit_command) const override;
    la_status set_egress_vlan_edit_command(const la_vlan_edit_command& edit_command) override;

    la_status get_event_enabled(la_event_e event, bool& out_enabled) const override;
    la_status set_event_enabled(la_event_e event, bool enabled) override;

    la_status get_ingress_vlan_edit_command(la_vlan_edit_command& out_edit_command) const override;
    la_status set_ingress_vlan_edit_command(const la_vlan_edit_command& edit_command) override;

    la_status attach_to_switch(const la_switch* sw) override;
    la_status get_attached_switch(const la_switch*& out_switch) const override;

    la_status get_destination(const la_l2_destination*& destination) const override;
    la_status set_destination(const la_l2_destination* out_destination) override;
    la_status get_destination(const la_l3_destination*& destination) const;

    la_status detach() override;

    la_status disable() override;
    // Function to disable Tx for a port
    template <class _EntryType>
    la_status do_set_port_egress_mode(const weak_ptr_unsafe<_EntryType>& dlp_entry, bool active);
    la_status set_port_egress_mode(bool active);

    la_status get_remote_ip_addr(la_ipv4_addr_t& out_remote_ip_addr) const override;
    la_status get_local_ip_addr(la_ipv4_addr_t& out_local_ip_addr) const override;
    la_status get_vrf(const la_vrf*& out_vrf) const override;
    la_status get_l3_destination(const la_l3_destination*& out_l3_destination) const override;
    la_status get_recycle_destination(const la_next_hop*& out_nh) const;
    la_status get_recycle_label(la_mpls_label& out_label) const;
    la_status set_encap_vni(const la_switch* sw, la_vni_t vni) override;
    la_status clear_encap_vni(const la_switch* sw) override;
    la_status get_encap_vni(const la_switch* sw, la_vni_t& out_vni) const override;
    uint64_t get_overlay_nh_id();
    la_status get_pwe_gid(la_pwe_gid_t& out_pwe_gid) const override;

    la_l2_port_gid_t get_gid() const override;
    port_type_e get_port_type() const override;
    la_status set_service_mapping_vids(la_vlan_id_t vid1, la_vlan_id_t vid2) override;
    la_status get_service_mapping_vids(la_vlan_id_t& out_vid1, la_vlan_id_t& out_vid2) const override;
    la_status add_service_mapping_vid(la_vlan_id_t vid) override;
    la_status remove_service_mapping_vid(la_vlan_id_t vid) override;
    la_status get_service_mapping_vid_list(la_vid_vec_t& out_mapped_vids) const override;

    la_status set_ingress_sflow_enabled(bool enabled) override;
    la_status get_ingress_sflow_enabled(bool& out_enabled) const override;
    la_status set_egress_sflow_enabled(bool enabled) override;
    la_status get_egress_sflow_enabled(bool& out_enabled) const override;
    la_status set_egress_feature_mode(egress_feature_mode_e mode) override;
    la_status get_egress_feature_mode(egress_feature_mode_e& out_mode) const override;

    la_status set_control_word_enabled(bool enabled) override;
    la_status get_control_word_enabled(bool& out_enabled) const override;
    la_status set_flow_label_enabled(bool enabled) override;
    la_status get_flow_label_enabled(bool& out_enabled) const override;

    la_status set_pwe_multicast_recycle_lsp_properties(la_mpls_label recycle_label, la_next_hop* recycle_destination) override;
    virtual void clear_ac_profile_for_pwe() = 0;

    la_status set_ttl_inheritance_mode(la_ttl_inheritance_mode_e ttl_mode) override;
    la_status get_ttl_inheritance_mode(la_ttl_inheritance_mode_e& out_ttl_mode) const override;
    la_status get_ttl(la_uint8_t& out_ttl) const override;
    la_status set_ttl(la_uint8_t ttl) override;

    la_status set_cfm_enabled(la_mep_direction_e mep_dir, la_uint8_t mep_lvl) override;
    la_status clear_cfm(la_mep_direction_e mep_dir) override;
    la_status get_cfm_mep(la_mep_direction_e mep_dir, la_uint8_t& mep_lvl) const override;

    // la_object API-s
    object_type_e type() const override;
    la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_l2_service_port_base API-s

    /// @brief Add object as user of given slice.

    /// @brief Add an IFG user.
    ///
    /// Updates per-IFG use-count and properties for this counter.
    ///
    /// @param[in]  ifg         IFG usage being added.
    ///
    /// @retval     LA_STATUS_SUCCESS   Per-slice information initialized correctly.
    /// @retval     LA_STATUS_ERESOURCE Missing resources to complete configuration request.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_ifg(la_slice_ifg ifg) = 0;

    /// @brief Remove IFG user.
    ///
    /// @param[in]  ifg         IFG usage being removed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Per-slice information released correctly (if not in use by other objects).
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove_ifg(la_slice_ifg ifg) = 0;

    /// @brief Get ethernet port associated with this service port.
    ///
    /// @ret Ethernet port associated with this service port.
    const la_ethernet_port_base_wcptr get_ethernet_port() const;

    la_status get_ethernet_port(const la_ethernet_port*& out_ethernet_port) const override;

    /// @brief Get a list of active IFGs
    ///
    /// @retval  A vector that holds the active IFGs
    slice_ifg_vec_t get_ifgs() const;

    egress_feature_mode_e get_egress_feature_mode() const;
    virtual la_status populate_inject_up_port_parameters() = 0;
    virtual la_status populate_nh_l2_payload(npl_nh_payload_t& out_nh_payload, la_slice_pair_id_t slice_pair_idx) const;

    virtual la_status update_l3_destination_for_l3vxlan(bool shared_overlay_nh) = 0;
    virtual lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const = 0;

    virtual la_status set_group_policy_encap(bool enabled) override;
    virtual la_status get_group_policy_encap(bool& out_enabled) const override;

    destination_id get_destination_id() const;

    enum {
        VXLAN_SHARED_OVERLAY_NH_ID = 0,
    };

    la_status set_acl_group_by_packet_format(la_acl_direction_e dir,
                                             la_acl_packet_format_e packet_format,
                                             const la_acl_group_wcptr& acl_group);
    la_status set_copc_profile(la_control_plane_classifier::l2_service_port_profile_id_t l2_service_port_profile_id) override;
    la_status get_copc_profile(
        la_control_plane_classifier::l2_service_port_profile_id_t& out_l2_service_port_profile_id) const override;

protected:
    la_l2_service_port_base() = default;

    virtual la_status configure_common_tables() = 0;
    virtual la_status teardown_tables() = 0;
    virtual la_status do_update_relay_id_in_pwe_tables(uint64_t relay_id) = 0;
    // Per-slice-pair configuration helpers
    la_status do_configure_l2_dlp_table(const npl_l2_dlp_table_sptr_t& table,
                                        la_slice_pair_id_t pair_idx,
                                        npl_l2_dlp_table_entry_wptr_t& l2_dlp_entry);
    la_status do_configure_vxlan_l2_dlp_table(const npl_vxlan_l2_dlp_table_sptr_t& table,
                                              la_slice_pair_id_t pair_idx,
                                              npl_vxlan_l2_dlp_table_entry_wptr_t& l2_dlp_entry);
    virtual la_status update_vxlan_group_policy_encap(npl_vxlan_l2_dlp_table_value_t& value) = 0;
    la_status configure_l2_dlp_table(la_slice_pair_id_t pair_idx);
    template <class _TableType>
    la_status do_teardown_l2_dlp_table(const std::shared_ptr<_TableType>& table, typename _TableType::entry_wptr_type& entry);
    la_status teardown_l2_dlp_table(la_slice_pair_id_t pair_idx);
    virtual la_status configure_service_lp_attributes_table(la_slice_id_t slice_idx,
                                                            npl_service_lp_attributes_table_entry_wptr_t& lp_attributes_entry)
        = 0;
    la_status teardown_service_lp_attributes_table(la_slice_id_t slice_idx,
                                                   npl_service_lp_attributes_table_entry_wptr_t& lp_attributes_entry);

    // Global configuration helpers
    virtual la_status configure_mpls_termination_table() = 0;
    virtual la_status teardown_mpls_termination_table() = 0;
    // PWE-tagged table is updated on all slices, even it's per-slice
    virtual la_status configure_pwe_port_tag_table() = 0;
    la_status teardown_pwe_port_tag_table();
    la_status do_detach();
    la_status do_initialize_pwe();
    la_status update_lp_attributes_destination_id(const la_l2_destination_wcptr& destination);
    la_status notify_pwe_l3_destination_attrib_change() const;

    virtual la_status configure_pwe_service_lp_attributes_table() = 0;
    virtual la_status teardown_pwe_service_lp_attributes_table() = 0;

    virtual la_status configure_pwe_encap_table() = 0;
    virtual la_status teardown_pwe_encap_table() = 0;

    virtual la_status configure_pwe_vpls_label_table() = 0;
    virtual la_status teardown_pwe_vpls_label_table() = 0;
    virtual la_status do_update_cw_fat_pwe_vpls(bool flow_label_enable, bool control_word_enable) = 0;
    virtual la_status configure_pwe_to_l3_dest_table() = 0;
    virtual la_status teardown_pwe_to_l3_dest_table() = 0;
    virtual la_status do_set_pwe_vpls_filter_group(la_slice_pair_id_t pair_idx, uint64_t group_id) = 0;
    virtual la_status instantiate_pwe_l3_destination(const la_l3_destination_wcptr& l3_destination) = 0;
    virtual la_status uninstantiate_pwe_l3_destination(const la_l3_destination_wcptr& l3_destination) = 0;
    virtual la_status get_attached_destination_id(const la_l2_destination_wcptr& destination, uint64_t& attached_dest_id) = 0;
    virtual la_status service_mapping_set_destination_p2p_pwe(const la_l2_destination_wcptr& destination) = 0;

    virtual la_status configure_txpp_dlp_profile_table(la_slice_pair_id_t slice_pair) = 0;
    virtual la_status teardown_txpp_dlp_profile_table(la_slice_pair_id_t slice_pair) = 0;

    /// @brief Setter for LP attributes.
    ///
    /// LP attributes are configured in 2 different tables depending on the port type. These
    /// functions assume that LP attributes are the same in all the slices. The only exception
    /// to this are the counter pointers. Updating the counters cannot be done with these
    /// functions!
    la_status update_lp_attributes_payload(npl_mac_lp_attributes_payload_t& payload);
    la_status update_lp_attributes_payload_pwe(npl_mac_lp_attributes_payload_t& payload);
    virtual la_status update_lp_attributes_payload_pwe_tagged(npl_mac_lp_attributes_payload_t& payload) = 0;
    virtual la_status update_lp_attributes_payload_lp(npl_mac_lp_attributes_payload_t& payload) = 0;

    // Helper function for populating the LP attributes payload structure
    void populate_lp_attributes_payload(npl_mac_lp_attributes_payload_t& out_payload);
    virtual void populate_payload_counters(npl_mac_lp_attributes_payload_t& payload, la_slice_id_t slice_idx) = 0;

    // Helper function for allocating PWE SLP ID-s
    virtual la_status allocate_pwe_slp_ids() = 0;
    virtual la_status deallocate_pwe_slp_ids() = 0;

    // Helper function for getting local SLP ID per slice
    virtual uint64_t get_local_slp_id(la_slice_id_t slice) const = 0;

    la_status set_switch(const la_switch_impl_wptr& sw);
    la_status pwe_set_switch(const la_switch_impl_wptr& sw);
    // Check pwe destination in switch
    virtual la_status pwe_sw_dest_in_use(const la_l3_destination_wcptr& l3_destination) = 0;

    la_status set_acl_id(la_acl::stage_e stage, la_acl_key_type_e key_type, const la_acl_delegate_wptr& acl_delegate);
    la_status update_ingress_acl_id();
    la_status update_egress_acl_id();
    la_status configure_mac_ingress_acl_select_table(la_slice_pair_id_t pair_idx,
                                                     bool is_udk,
                                                     bool is_v6,
                                                     la_acl_id_t acl_id,
                                                     const la_acl_wptr& acl);
    la_status erase_mac_ingress_acl_select_table(la_slice_pair_id_t pair_idx);

    la_status initialize_common(slice_ifg_vec_t& ifgs);

    // Calculate the learning type from the stp-state and learning-mode
    npl_learn_type_e get_npl_learn_type(la_port_stp_state_e stp_state, la_lp_mac_learning_mode_e learning_mode) const;

    // Helper function for counter
    la_status do_set_counter(const la_counter_set_impl_wptr& new_counter,
                             la_counter_set::type_e counter_type,
                             counter_direction_e direction);
    bool is_counter_set_size_valid(const la_counter_set_impl_wptr& counter, la_counter_set::type_e counter_type) const;
    la_status verify_set_counter_parameters(const la_counter_set_impl_wptr& new_counter, la_counter_set::type_e counter_type) const;
    bool need_aggregate_counter() const;
    la_status configure_ingress_counter();
    la_status configure_egress_counter();

    la_status vxlan_add_port(la_ipv4_prefix_t local_ip_prefix,
                             la_ipv4_addr_t remote_ip_addr,
                             const la_vrf_wptr& vrf,
                             const la_l2_service_port_wptr& port);
    la_status vxlan_remove_port(la_ipv4_prefix_t local_ip_prefix, la_ipv4_addr_t remote_ip_addr, const la_vrf_wptr& vrf);
    la_l2_service_port_wptr vxlan_lookup_port(la_ipv4_prefix_t local_ip_prefix,
                                              la_ipv4_addr_t remote_ip_addr,
                                              const la_vrf_wptr& vrf);

    la_status notify_l2_dlp_attrib_change() const;
    la_status validate_set_acl_group(la_acl_direction_e dir, const la_acl_group_wcptr& acl_group) const;
    la_status validate_direction(la_acl_direction_e dir, la_acl_direction_e acl_key_dir) const;
    virtual la_status map_vxlan_slp() = 0;
    virtual la_status unmap_vxlan_slp() = 0;
    virtual la_status map_mcast_vxlan_slp() = 0;
    virtual la_status unmap_mcast_vxlan_slp() = 0;
    la_status do_destroy_vxlan();
    la_status update_dependent_attributes(dependency_management_op op);
    la_status handle_acl_group_change(const la_object* changed_acl_group, la_acl_packet_format_e packet_format);

    // Helper function for populating cfm related attributes
    la_status set_cfm_attrib(la_mep_direction_e mep_dir, la_uint8_t mep_lvl, bool mep_enabled);

    // Helper function to determine if mirror_cmd's type is the intended one (second argument)
    la_status verify_matching_mirror_types(const la_mirror_command* mirror_cmd, mirror_type_e type);

protected:
    struct slice_data_base {
        // PWE service mapping table entry and location
        size_t pwe_port_tag_entry_location = -1;
        npl_service_mapping_tcam_pwe_tag_table_entry_wptr_t pwe_port_tag_entry;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_data_base);

    struct slice_pair_data_base {
        /// L2 DLP table entry
        npl_l2_dlp_table_entry_wptr_t l2_dlp_entry;
        npl_vxlan_l2_dlp_table_entry_wptr_t vxlan_l2_dlp_entry;
        profile_allocator<l2_slp_acl_info_t>::profile_ptr acl_profile;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_pair_data_base);

    /// Device this port belongs to
    la_device_impl_wptr m_device;

    // IFG manager
    ifg_use_count_uptr m_ifg_use_count;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    /// Port type
    port_type_e m_port_type;

    /// Port GID
    la_l2_port_gid_t m_port_gid;

    /// AC port only: Ethernet port used by this AC port
    la_ethernet_port_base_wptr m_ac_ethernet_port;

    // AC port only: egress VLAN edit command
    npl_ive_profile_and_data_t m_ac_npl_eve_command;

    // AC port only: ingress VLAN edit command
    npl_ive_profile_and_data_t m_ac_npl_ive_command;

    /// STP state
    la_port_stp_state_e m_stp_state;

    /// Learning mode
    la_lp_mac_learning_mode_e m_learning_mode;

    /// Ingress Mirror command
    la_mirror_command_wcptr m_ingress_mirror_cmd;

    /// Egress Mirror command
    la_mirror_command_wcptr m_egress_mirror_cmd;

    /// Ingress mirror type
    npl_port_mirror_type_e m_ingress_mirror_type;

    /// Egress mirror type
    npl_port_mirror_type_e m_egress_mirror_type;

    /// Attached switch
    la_switch_impl_wptr m_attached_switch;

    // Recycle label for pwe to send bum trarffic to recycle port
    la_mpls_label m_recycle_label;

    // Recycle desination (nh) for pwe to send bum trarffic to recycle port
    la_next_hop_wcptr m_recycle_destination;

    /// Attached destination
    la_l2_destination_wcptr m_attached_destination;

    /// Filter group
    la_filter_group_impl_wcptr m_filter_group;

    /// Per-slice data
    std::vector<slice_data_base> m_slice_data_b;

    /// Per-slice-pair data
    std::vector<slice_pair_data_base> m_slice_pair_data_b;

    /// Common AC port implementation object
    la_ac_port_common m_ac_port_common;

    // Security ACL -- for each stage
    la_acl_wptr m_acls[(int)la_acl::stage_e::LAST][(int)la_acl_key_type_e::LAST];

    // PWE labels
    la_mpls_label m_local_label;  // decap
    la_mpls_label m_remote_label; // encap

    // PWE ID
    la_pwe_gid_t m_pwe_gid;

    // PWE flow label and control word
    bool m_flow_label_enable;
    bool m_control_word_enable;

    // PWE & VXLAN L3 destination
    la_l3_destination_wcptr m_l3_destination;

    // Resolution table entries
    // npl_native_l2_lp_table_entry_wptr_t m_native_l2_table_entry;

    // P/Q counters associated with this port.
    std::array<la_counter_set_impl_wptr, COUNTER_DIRECTION_NUM> m_p_counter;
    std::array<la_counter_set_impl_wptr, COUNTER_DIRECTION_NUM> m_q_counter;

    // Meter associated with the port
    la_meter_set_impl_wptr m_meter;

    /// Ingress QoS profile
    la_ingress_qos_profile_impl_wptr m_ingress_qos_profile;

    /// Egress QoS profile
    la_egress_qos_profile_impl_wptr m_egress_qos_profile;

    /// ACL drop counter offset
    size_t m_drop_counter_offset;

    /// VXLAN local ip address
    la_ipv4_addr_t m_local_ip_addr;

    /// VXLAN local ip prefix
    la_ipv4_prefix_t m_local_ip_prefix;

    /// VXLAN remote ip address
    la_ipv4_addr_t m_remote_ip_addr;

    /// VXLAN VRF
    la_vrf_wptr m_vrf;

    // overlay next hop id
    uint64_t m_compressed_vxlan_dlp_id;
    uint64_t m_cur_ovl_nh_id;

    // local ip sip index profile
    ipv4_sip_index_manager::ipv4_sip_index_profile_t m_sip_index{};

    // sFlow
    bool m_ingress_sflow_enabled;

    egress_feature_mode_e m_egress_feature_mode;

    // TTL mode
    la_ttl_inheritance_mode_e m_ttl_mode;

    // TTL
    la_uint8_t m_ttl;

    /// Acls attached to ethernet/ipv4/ipv6 ingress/egress
    std::vector<la_acl_delegate_wptr> m_delegate_acls[(int)la_acl_packet_format_e::LAST][(int)la_acl_direction_e::LAST];

    la_acl_group_wptr m_ingress_acl_group;
    la_acl_group_wptr m_egress_acl_group;

    uint64_t m_rtf_conf_set_ptr;

    // CFM Down Mep attributes
    la_uint8_t m_down_mep_level;
    bool m_down_mep_enabled;

    // CFM Up Mep attributes
    la_uint8_t m_up_mep_level;
    bool m_up_mep_enabled;

    // Tunnel mode
    la_ip_tunnel_mode_e m_tunnel_mode;

    // VXLAN Group Policy Encap Flag
    bool m_group_policy_encap;

    // VXLAN encap VNI map
    std::map<la_switch_gid_t, la_vni_t> m_encap_vni_map;

    // COPC profile value
    la_uint8_t m_copc_profile;
};

/// @}
}

#endif
