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

#ifndef __LA_COUNTER_SET_IMPL_H__
#define __LA_COUNTER_SET_IMPL_H__

#include <map>
#include <vector>

#include "api/npu/la_counter_set.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
#include "qos/la_meter_set_exact_impl.h"
#include "system/counter_manager.h"

namespace silicon_one
{
class slice_id_manager_base;
class la_counter_set_impl : public la_counter_set, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_counter_set_impl() = default; // Needed for cereal
public:
    explicit la_counter_set_impl(const la_device_impl_wptr& device);
    ~la_counter_set_impl() override;
    la_status initialize(la_object_id_t oid, size_t set_size);
    la_status destroy();

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    // la_object API-s
    object_type_e type() const override;
    la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_counter_set API-s
    size_t get_set_size() const override;
    la_status read(size_t counter_index, bool force_update, bool clear_on_read, size_t& out_packets, size_t& out_bytes) override;
    la_status read(la_slice_ifg ifg,
                   size_t counter_index,
                   bool force_update,
                   bool clear_on_read,
                   size_t& out_packets,
                   size_t& out_bytes) override;

    la_status read(la_slice_id_t slice_id,
                   size_t counter_index,
                   bool force_update,
                   bool clear_on_read,
                   size_t& out_packets,
                   size_t& out_bytes) override;

    /// @brief Get the counter's type.
    ///
    /// @retval     Counter's type.
    type_e get_type() const;

    /// @brief Get the counter's direction.
    ///
    /// @retval     Counter's direction.
    counter_direction_e get_direction() const;

    /// @brief Get the counter's counter_user_type.
    ///
    /// @retval     #silicon_one::counter_user_type describing the Counter's counter_user_type.
    la_status get_user_type(type_e counter_type, const la_object_wcptr& user, counter_user_type_e& out_user_type) const;

    /// @brief Return true if the counter is aggregated.
    ///
    /// @retval     Counter's aggregation state.
    bool get_aggregation() const;

    /// @brief Add a user to the counter.
    ///
    /// All users of the counter should have the same attributes,
    /// and should be in the same user type group.
    /// User type groups are -
    /// 1) L2 and L3 AC ports.
    /// 2) MPLS tunnel and PWE port (both tagged and un-tagged).
    /// 3) SVI and tunnel-next-hop.
    ///
    /// @param[in]  user                       The object using that counter. NULL for traps.
    /// @param[in]  direction                  Ingress/egress.
    /// @param[in]  is_aggregate               The user may span over several slices/IFGs.
    la_status add_pq_counter_user(const la_object_wcptr& user,
                                  type_e counter_type,
                                  counter_direction_e direction,
                                  bool is_aggregate);

    /// @brief Remove a user from the counter.
    ///
    /// @param[in]  user      The object using that counter. NULL for traps.
    la_status remove_pq_counter_user(const la_object_wcptr& user);

    /// @brief Add a global LSP prefix counter.
    la_status add_global_lsp_prefix_counter(type_e counter_type);

    /// @brief Remove a global LSP prefix counter.
    la_status remove_global_lsp_prefix_counter();

    /// @brief Attach ACE counter in a particular direction
    la_status add_ace_counter(counter_direction_e direction, const slice_ifg_vec_t& ifgs);

    /// @brief Remove ACE counter from a particular direction
    la_status remove_ace_counter(const slice_ifg_vec_t& ifgs);

    /// @brief Attach drop counter in a particular direction
    la_status add_drop_counter(counter_direction_e direction, const slice_ifg_vec_t& ifgs);

    /// @brief Remove drop counter from a particular direction
    la_status remove_drop_counter(const slice_ifg_vec_t& ifgs);

    /// @brief Add a trap counter in a particular direction.
    la_status add_trap_counter(counter_direction_e direction);

    /// @brief Remove a trap counter from a particular direction.
    la_status remove_trap_counter(counter_direction_e direction);

    /// @brief Add a mcg counter.
    la_status add_mcg_counter(la_slice_ifg& slice_ifg);

    /// @brief Remove a mcg counter.
    la_status remove_mcg_counter(const la_slice_ifg& slice_ifg);

    /// @brief Add a BFD counter.
    la_status add_bfd_counter();

    /// @brief Remove a BFD counter.
    la_status remove_bfd_counter();

    /// @brief Add a internal error counter.
    la_status add_internal_error_counter(counter_direction_e direction);

    /// @brief Add a ERSPAN session counter.
    la_status add_erspan_session_counter();

    /// @brief Remove a ERSPAN session counter.
    la_status remove_erspan_session_counter();

    /// @brief Add a MPLS decap counter.
    la_status add_mpls_decap_counter();

    /// @brief Remove a MPLS decap counter.
    la_status remove_mpls_decap_counter();

    /// @brief Add a VNI encap counter.
    la_status add_vni_encap_counter();

    /// @brief Remove a VNI encap counter.
    la_status remove_vni_encap_counter();

    /// @brief Add a VNI decap counter.
    la_status add_vni_decap_counter();

    /// @brief Remove a VNI decap counter.
    la_status remove_vni_decap_counter();

    /// @brief Add a ip tunnel transit counter.
    la_status add_ip_tunnel_transit_counter();

    /// @brief Remove a ip tunnel transit counter.
    la_status remove_ip_tunnel_transit_counter();

    /// @brief Add a Security Group Cell counter.
    la_status add_security_group_cell_counter();

    /// @brief Remove a Security Group Cell counter.
    la_status remove_security_group_cell_counter();

    /// @brief  Get the counter allocation for the given slice in the given direction.
    ///
    /// @param[in]  slice                    Target slice.
    /// @param[in]  direction                Ingress/egress.
    /// @param[out] out_allocation           Counter-allocation object to populate.
    ///
    /// @retval    LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval    LA_STATUS_ENOTFOUND       No allocation exists for the given slice.
    la_status get_allocation(la_slice_id_t slice, counter_direction_e direction, counter_allocation& out_allocation) const;

    /// @brief Add an IFG user.
    ///
    /// Updates per-IFG use-count and properties for this counter.
    ///
    /// @param[in]  ifg                 IFG usage being added.
    /// @param[in]  direction           Ingress/egress.
    ///
    /// @retval     LA_STATUS_SUCCESS   Per-slice information initialized correctly.
    /// @retval     LA_STATUS_ERESOURCE Missing resources to complete configuration request.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status add_ifg(la_slice_ifg ifg, counter_direction_e direction);

    /// @brief Remove IFG user.
    ///
    /// @param[in]  ifg                 IFG usage being removed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Per-slice information released correctly (if not in use by other objects).
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status remove_ifg(la_slice_ifg ifg, counter_direction_e direction);

    /// @brief Set VOQ base.
    void set_voq_base(la_voq_gid_t base_voq_id);

    bool is_using_meter() const;

private:
    struct allocation_desc {
        bool is_valid = false;
        counter_allocation allocation;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(allocation_desc)

    // Containing device
    la_device_impl_wptr m_device;

    slice_manager_smart_ptr m_slice_id_manager;

    // IFG use count
    ifg_use_count_uptr m_ifg_use_count[COUNTER_DIRECTION_NUM];

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Number of sub-counters
    size_t m_set_size;

    // The counter's direction
    counter_direction_e m_direction;

    // The counter's user-type
    counter_user_type_e m_user_type;

    // Counter type
    type_e m_counter_type;

    // Is the user object defined over port aggregation
    bool m_is_aggregate;

    // VOQ ID, valid only if m_counter_type is VOQ
    la_voq_gid_t m_base_voq;

    // Internal Meter for Ingress QoS Counter
    la_meter_set_exact_impl_wptr m_meter;

    // Physical counter descriptors, mapped by slice-pair-id
    typedef std::map<la_slice_pair_id_t, counter_allocation> allocation_map_t;
    allocation_map_t m_allocations[COUNTER_DIRECTION_NUM];

    // Count from removed IFGs
    std::vector<size_t> m_cached_packets;
    std::vector<size_t> m_cached_bytes;

    // Check if it's valid to add user
    la_status validate_pq_user_counter(const la_object_wcptr& user,
                                       type_e counter_type,
                                       counter_direction_e direction,
                                       bool is_aggregate) const;

    // Check if it's valid to add user
    void init_counter_data(size_t set_size, type_e counter_type, counter_direction_e direction, bool is_aggregate);

    // Check if it's valid to add user
    la_status validate_global_lsp_prefix_counter() const;
    la_status validate_ace_counter(counter_direction_e direction) const;
    la_status validate_drop_counter(counter_direction_e direction) const;
    la_status validate_trap_counter(counter_direction_e direction) const;
    la_status validate_mcg_counter() const;
    la_status validate_bfd_counter() const;
    la_status validate_ip_tunnel_transit_counter() const;
    la_status validate_voq_counter() const;
    la_status validate_erspan_session_counter() const;
    la_status validate_mpls_decap_counter() const;
    la_status validate_vni_counter() const;
    la_status validate_security_group_cell_counter() const;

    // Init the internal state of the counter set
    void init_counter_data(size_t set_size,
                           type_e counter_type,
                           counter_user_type_e user_type,
                           counter_direction_e direction,
                           bool is_aggregate);

    // Check whether a port counter's set-size is adequate
    bool is_valid_set_size() const;

    // Read VOQ-counter-set
    la_status read_voq_counter_set(size_t counter_index,
                                   bool force_update,
                                   bool clear_on_read,
                                   size_t& out_packets,
                                   size_t& out_bytes);

    // Compensate missing CRC header bytes for egress counters only
    size_t get_bytes_counter_adjustment(counter_direction_e direction, size_t packets);

    la_status destroy_internal_meter();
    la_status create_internal_meter(size_t size);
    bool is_counter_group_global(counter_user_type_e user_type, counter_direction_e direction);
};

} // namespace silicon_one

#endif //  __LA_COUNTER_SET_IMPL_H__
