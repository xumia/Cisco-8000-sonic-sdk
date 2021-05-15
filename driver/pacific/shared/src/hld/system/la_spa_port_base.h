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

#ifndef __LA_SPA_PORT_BASE_H__
#define __LA_SPA_PORT_BASE_H__

#include <memory>
#include <set>
#include <vector>

#include "api/system/la_spa_port.h"
#include "api/types/la_lb_types.h"
#include "common/transaction.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"

namespace silicon_one
{

class la_device_impl;
class la_system_port_base;

class la_spa_port_base : public la_spa_port, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    ~la_spa_port_base() override;

    // Object life-cycle API-s
    la_status initialize(la_object_id_t oid, la_spa_port_gid_t spa_port_gid);
    virtual la_status destroy() = 0;

    // Inherited API-s
    la_status get_member(size_t member_idx, const la_system_port*& out_system_port) const override;
    la_status get_members(system_port_vec_t& out_system_ports) const override;
    la_status get_transmit_enabled_members(system_port_vec_t& out_system_ports) const override;
    la_status get_dspa_table_members(system_port_vec_t& out_system_ports) const override;

    la_status set_member_transmit_enabled(const la_system_port* system_port, bool enabled) override;
    la_status get_member_transmit_enabled(const la_system_port* system_port, bool& out_enabled) const override;
    la_status set_member_receive_enabled(const la_system_port* system_port, bool enabled) override;
    la_status get_member_receive_enabled(const la_system_port* system_port, bool& out_enabled) const override;

    la_status set_representative_mc(la_multicast_group_gid_t mc_gid, la_system_port* system_port) override;
    la_status clear_representative_mc(la_multicast_group_gid_t mc_gid) override;

    la_spa_port_gid_t get_gid() const override;
    virtual la_status get_lb_resolution(const la_lb_pak_fields_vec& lb_vector,
                                        size_t& member,
                                        const la_object*& out_object) const = 0;

    // la_object API-s
    object_type_e type() const override;
    la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    /// @brief Get all IFGs used by this SPA port.
    ///
    /// @return Vector of IFGs used.
    slice_ifg_vec_t get_ifgs() const;

    /// @brief Add a system port as user of given slice.
    ///
    /// Notifies the SPA port that a given system port requires it to be initialized on a slice. If the slice is already
    /// configured, the system port's info of this SPA will be configured. If the requested slice is not configured yet,
    /// this method will configure it properly.
    ///
    /// @param[in]  system_port_base    System port requesting the slice to be initialized.
    ///
    /// @retval     LA_STATUS_SUCCESS   Per-slice information initialized correctly.
    /// @retval     LA_STATUS_ERESOURCE Missing resources to complete configuration request.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status add_ifg_user(const la_system_port_base_wptr& system_port_base);

    /// @brief Remove object as user of given slice.
    ///
    /// Notifies the port that given object no longer requires it to be initialized on given slice.
    ///
    /// @param[in]  system_port_base    System port associated with the slice.
    ///
    /// @retval     LA_STATUS_SUCCESS   Per-slice information released correctly (if not in use by other objects).
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status remove_ifg_user(const la_system_port_base_wptr& system_port_base);

    la_status set_mac_af_npp_attributes(const npl_mac_af_npp_attributes_table_value_t value);
    virtual la_status clear_source_pif() = 0;
    // True if spa_port has the system port
    bool is_member(const la_system_port_wcptr& system_port) const;

    la_mtu_t get_mtu() const;
    la_status set_mtu(la_mtu_t mtu);
    la_status set_mask_eve(bool mask_eve);

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    la_status set_decrement_ttl(bool decrement_ttl);
    bool get_decrement_ttl() const;

    la_status set_stack_prune(bool prune);
    la_status get_stack_prune(bool& prune) const;

protected:
    la_spa_port_base() = default; // Needed for cereal
    typedef std::vector<la_system_port_base_wptr> system_port_base_vec_t;

    struct system_port_base_data {
        la_system_port_base_wptr system_port;
        size_t num_of_dspa_table_entries;
        la_mac_port::port_speed_e underlying_port_speed;
        bool is_active;
        bool is_receive_enabled;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(system_port_base_data);
    using system_port_base_data_vec_t = std::vector<std::shared_ptr<system_port_base_data> >;

    explicit la_spa_port_base(const la_device_impl_wptr& device);
    // True if system port is enabled to transmit
    bool is_transmit_enabled(const la_system_port_wcptr& system_port) const;
    // True if system port is enabled to receive
    bool is_receive_enabled(const la_system_port_wcptr& system_port) const;
    virtual la_status configure_system_port_source_pif_table(const la_system_port* system_port, bool enabled) = 0;

    la_status add_transmit_enabled_member_to_dspa_table(std::shared_ptr<system_port_base_data>& sp_data_to_update);
    virtual la_status add_system_port_to_dspa_table(std::shared_ptr<system_port_base_data>& sp_data_to_update,
                                                    size_t num_of_entries_to_add,
                                                    transaction& txn)
        = 0;
    la_status remove_transmit_enabled_member_from_dspa_table(std::shared_ptr<system_port_base_data>& sp_data_to_update);
    la_status swap_to_index(const la_system_port_base_wptr& system_port_to_swap,
                            size_t num_of_entries,
                            size_t start_index,
                            transaction& txn,
                            bool swap_from_end);
    virtual la_status clear_table_tail(size_t start_index, transaction& txn) = 0;
    void recalculate_qu();

    la_status get_dspa_table_member(size_t member_idx, la_system_port_wcptr& out_system_port) const;

    /// Source PIF attributes for this SPA
    npl_mac_af_npp_attributes_table_value_t m_mac_af_npp_attributes_table_value;
    bool m_mac_af_npp_attributes_table_value_valid;

    virtual la_status init_port_dspa_group_size_table_entry() = 0;
    virtual la_status erase_port_dspa_group_size_table_entry() = 0;

    /// @brief Sets the given value in the port-DSPA-group-size resolution table.
    ///
    /// Sets the given group-size value in the port-DSPA-group-size resolution table.
    ///
    /// @param[in]  lbg_group_size      Group size to write.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_port_dspa_group_size_table_entry(size_t lbg_group_size) = 0;

    /// @brief Sets the given system port as a member of this SPA in the port-DSPA resolution table.
    ///
    /// Sets the given system port's GID as lbg_member_id-th member in the port-DSPA resolution table.
    ///
    /// @param[in]  system_port         System port to set as member.
    /// @param[in]  lbg_member_id       Member ID of the system port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_port_dspa_table_entry(const la_system_port_wcptr& system_port, size_t lbg_member_id) = 0;

    /// @brief Get underlying port's speed (Gbps)
    ///
    /// @param[in]  system_port         System port for which the underlying port's speed is fetched from.
    /// @param[out] out_port_speed      Underlying port's speed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    system_port type is invalid.
    la_status get_underlying_port_speed(const la_system_port_wcptr& system_port, la_mac_port::port_speed_e& out_port_speed);

    system_port_base_data_vec_t::iterator get_system_port_data_it(const la_system_port_wcptr& system_port);
    system_port_base_data_vec_t::const_iterator get_system_port_data_it(const la_system_port_wcptr& system_port) const;

    // Dependency management
    void register_attribute_dependency(const la_system_port_wcptr& system_port);
    void remove_attribute_dependency(const la_system_port_wcptr& system_port);

    // Attributes management
    la_status update_dependent_attributes(dependency_management_op op);
    la_status handle_speed_change(const la_object_wcptr& changed_port, la_mac_port::port_speed_e new_port_speed);
    la_status update_system_port_speed(std::shared_ptr<system_port_base_data>& sp_data_to_update,
                                       la_mac_port::port_speed_e new_port_speed);

    // Device this port belongs to
    la_device_impl_wptr m_device;

    // IFG management
    ifg_use_count_uptr m_ifg_use_count;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // Port GID
    la_spa_port_gid_t m_gid;

    // MTU value
    la_mtu_t m_mtu;

    // Quantization unit (effectively the gcd of all underlying sp's speed (in Gbps))
    uint32_t m_qu;

    // mask egress vlan editting
    bool m_mask_eve;

    // Resolution API helpers

    // Associative vector to map index to its corresponding (transmit enabled) system_port
    system_port_base_vec_t m_index_to_system_port;

    system_port_base_data_vec_t m_system_ports_data;

    bool m_decrement_ttl;

    bool m_stack_prune;
};
}

/// @}

#endif
