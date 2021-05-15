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

#ifndef __LA_SWITCH_IMPL_H__
#define __LA_SWITCH_IMPL_H__

#include "api/npu/la_switch.h"
#include "api/types/la_ethernet_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_switch_impl : public la_switch, public dependency_listener
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_switch_impl() = default;
    //////////////////////////////
public:
    explicit la_switch_impl(const la_device_impl_wptr& device);
    ~la_switch_impl() override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    /// @brief Handle an attachment notification sent by the device when a port is attaching to the switch
    ///
    /// @param[in]  object      Attaching port
    la_status handle_new_attachment(const la_object* obj);

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

    /// @brief Get a list of active slices
    ///
    /// @retval  A vector that holds the active slices
    la_slice_id_vec_t get_slices() const;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, la_switch_gid_t switch_gid);
    la_status destroy();

    // Inherited API-s

    la_status get_mac_aging_time(la_mac_aging_time_t& out_aging_time) override;
    la_status set_mac_aging_time(la_mac_aging_time_t aging_time) override;

    la_status get_max_switch_mac_addresses(la_uint64_t& out_max_addresses) override;
    la_status set_max_switch_mac_addresses(la_uint64_t max_addresses) override;

    la_status get_max_port_mac_addresses(const la_l2_port* lport, la_uint64_t* out_max_addresses) override;
    la_status set_max_port_mac_addresses(const la_l2_port* lport, la_uint64_t max_addresses) override;

    la_status set_flood_destination(la_l2_destination* destination) override;
    la_status get_flood_destination(la_l2_destination*& out_destination) const override;

    la_status get_ipv4_local_multicast_destination(la_ipv4_addr_t gaddr, la_l2_destination*& out_dest) override;
    la_status set_ipv4_local_multicast_destination(la_ipv4_addr_t gaddr, la_l2_destination* destination) override;
    la_status delete_ipv4_local_multicast_destination(la_ipv4_addr_t gaddr) override;
    la_status clear_all_ipv4_local_multicast_destination() override;

    la_status get_ipv6_local_multicast_destination(la_ipv6_addr_t gaddr, la_l2_destination*& out_dest) override;
    la_status set_ipv6_local_multicast_destination(la_ipv6_addr_t gaddr, la_l2_destination* destination) override;
    la_status delete_ipv6_local_multicast_destination(la_ipv6_addr_t gaddr) override;
    la_status clear_all_ipv6_local_multicast_destination() override;

    la_status set_event_enabled(la_event_e event, bool enabled) override;
    la_status get_event_enabled(la_event_e event, bool& out_enabled) override;

    la_status set_mac_entry(la_mac_addr_t mac_addr, la_l2_destination* l2_destination, la_mac_aging_time_t mac_aging_time) override;
    la_status set_mac_entry(la_mac_addr_t mac_addr,
                            la_l2_destination* l2_destination,
                            la_mac_aging_time_t mac_aging_time,
                            la_class_id_t class_id) override;
    la_status set_mac_entry(la_mac_addr_t mac_addr,
                            la_l2_destination* l2_destination,
                            la_mac_aging_time_t mac_aging_time,
                            bool owner) override;

    la_status remove_mac_entry(la_mac_addr_t mac_addr) override;

    la_status get_mac_entry(la_mac_addr_t mac_addr,
                            la_l2_destination*& out_l2_destination,
                            la_mac_age_info_t& out_mac_entry_info) const override;
    la_status get_mac_entry(la_mac_addr_t mac_addr,
                            la_l2_destination*& out_l2_destination,
                            la_mac_age_info_t& out_mac_entry_info,
                            la_class_id_t& out_class_id) const override;
    la_status flush_mac_entries(bool dynamic_only, la_mac_entry_vec& out_mac_entries) override;

    la_status get_decap_vni(la_vni_t& vni) const override;
    la_status set_decap_vni(la_vni_t vni) override;
    la_status clear_decap_vni() override;

    la_status get_mac_entries_count(la_uint32_t& out_count) override;
    la_status get_mac_entries(la_mac_entry_vec& out_mac_entries) override;

    la_status get_vxlan_encap_counter(la_counter_set*& counter) const override;
    la_status set_vxlan_encap_counter(la_counter_set* counter) override;
    la_status remove_vxlan_encap_counter() override;
    la_status get_vxlan_decap_counter(la_counter_set*& counter) const override;
    la_status set_vxlan_decap_counter(la_counter_set* counter) override;
    la_status remove_vxlan_decap_counter() override;
    la_switch::vxlan_termination_mode_e get_decap_vni_profile() const override;
    la_status set_decap_vni_profile(vxlan_termination_mode_e vni_profile) override;
    la_status get_drop_unknown_uc_enabled(bool& out_drop_unknown_uc_enabled) const override;
    la_status set_drop_unknown_uc_enabled(bool drop_unknown_uc_enabled) override;
    la_status get_drop_unknown_mc_enabled(bool& out_drop_unknown_mc_enabled) const override;
    la_status set_drop_unknown_mc_enabled(bool drop_unknown_mc_enabled) override;
    la_status get_drop_unknown_bc_enabled(bool& out_drop_unknown_bc_enabled) const override;
    la_status set_drop_unknown_bc_enabled(bool drop_unknown_bc_enabled) override;

    la_status set_ipv4_multicast_enabled(bool enabled) override;
    la_status get_ipv4_multicast_enabled(bool& out_enabled) override;
    la_status set_ipv6_multicast_enabled(bool enabled) override;
    la_status get_ipv6_multicast_enabled(bool& out_enabled) override;

    la_status delete_ipv4_multicast_route(la_ipv4_addr_t gaddr) override;
    la_status get_ipv4_multicast_route(la_ipv4_addr_t gaddr, la_l2_mc_route_info& out_l2_mc_route_info) const override;
    la_status add_ipv4_multicast_route(la_ipv4_addr_t gaddr, la_l2_multicast_group* mcg) override;
    la_status delete_ipv6_multicast_route(la_ipv6_addr_t gaddr) override;
    la_status get_ipv6_multicast_route(la_ipv6_addr_t gaddr, la_l2_mc_route_info& out_l2_mc_route_info) const override;
    la_status add_ipv6_multicast_route(la_ipv6_addr_t gaddr, la_l2_multicast_group* mcg) override;

    la_switch_gid_t get_gid() const override;
    la_status set_is_svi_flag(bool is_svi);

    la_status update_all_ifgs(bool add);
    la_status get_encap_vni(la_vni_t& vni) const;
    la_status set_encap_vni(la_vni_t vni);
    la_status clear_encap_vni();
    la_status get_svi_port(la_svi_port_base*& svi_port);

    la_status get_copc_profile(la_control_plane_classifier::switch_profile_id_t& out_switch_profile_id) const override;
    la_status set_copc_profile(la_control_plane_classifier::switch_profile_id_t switch_profile_id) override;
    la_status set_force_flood_mode(bool enabled) override;

    la_status set_security_group_policy_enforcement(bool enforcement) override;
    la_status get_security_group_policy_enforcement(bool& out_enforcement) const override;

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    /// @brief Handle an attachment removal notification sent by the device when a port is detaching from the switch
    ///
    /// @param[in]  object      Attaching port
    la_status remove_attachment(const la_object* obj);

private:
    struct slice_data {
        npl_vni_table_entry_wptr_t vni_table_entry;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_data);

    struct slice_pair_data {
        // VXLAN counters
        npl_mac_relay_to_vni_table_entry_wptr_t mac_relay_to_vni_table_entry;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_pair_data);

    struct vni_profile_data {
        bool vni_profile_allocated;
        vxlan_termination_mode_e vni_profile;
        uint64_t vni_profile_index;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(vni_profile_data);

    // Device this switch belongs to
    la_device_impl_wptr m_device;

    // IFG manager
    ifg_use_count_uptr m_ifg_use_count;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // Attributes table entry
    npl_service_relay_attributes_table_entry_wptr_t m_relay_attributes_entry;

    // Max MACs connected to this switch
    la_uint64_t m_max_switch_mac_addresses;

    // VXLAN vni
    la_vni_t m_encap_vni;
    la_uint32_t m_encap_vni_use_count;
    la_vni_t m_decap_vni;
    la_counter_set_impl_wptr m_vxlan_encap_counter;
    la_counter_set_impl_wptr m_vxlan_decap_counter;
    struct vni_profile_data m_vni_profile_data;

    // Per-slice data
    std::vector<slice_data> m_slice_data;

    // Per-slice-pair data
    std::vector<slice_pair_data> m_slice_pair_data;

    la_status notify_mac_move(la_mac_addr_t mac_addr) const;
    la_status do_set_encap_vni(la_vni_t vni);
    la_status do_set_decap_vni(la_vni_t vni);
    la_status allocate_vni_profile(vxlan_termination_mode_e vni_profile);
    la_status release_vni_profile();

    // WA Temporary protection to disallow SWTICH_GIDs >= 12k:
    //
    // Global limit for SWITCH GID is 16k. Initializing a switch with GID >= 12k causes overflow
    // service_relay_attributes_table(12k entries) is extended with link_service_relay_attributes(4k entries).
    // Overflow to extension table is unmanaged.
    //
    // For a long-term solution and to remove this protection either:
    //
    // 1) To make SDK aware of the different config locations
    // 2) To encompass theese two table as a single logical one exposed to SDK, if possible
    //
    enum { SERVICE_RELAY_ATTRIBUTES_TABLE_ENTRIES = 3 * (1 << 12) };

    // IPv4 entries located in EM
    struct ipv4_less_op {
        inline bool operator()(const la_ipv4_addr_t& lhs, const la_ipv4_addr_t& rhs) const
        {
            return lhs.s_addr < rhs.s_addr;
        }
    };

    // IPv6 entries located in EM
    struct ipv6_less_op {
        inline bool operator()(const la_ipv6_addr_t& lhs, const la_ipv6_addr_t& rhs) const
        {
            return lhs.s_addr < rhs.s_addr;
        }
    };
    std::map<la_ipv4_addr_t, la_l2_multicast_group_wcptr, ipv4_less_op> m_ipv4_em_entries;
    std::map<la_ipv6_addr_t, la_l2_multicast_group_wcptr, ipv6_less_op> m_ipv6_em_entries;
};

} // namespace silicon_one

#endif
