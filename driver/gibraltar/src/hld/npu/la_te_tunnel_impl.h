// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_TE_TUNNEL_IMPL_H__
#define __LA_TE_TUNNEL_IMPL_H__

#include "api/npu/la_counter_set.h"
#include "api/npu/la_te_tunnel.h"
#include "api/types/la_lb_types.h"
#include "api/types/la_mpls_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"
#include <vector>

namespace silicon_one
{

class la_device_impl;
class la_next_hop_base;
class la_counter_set_impl;

class la_te_tunnel_impl : public la_te_tunnel, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_te_tunnel_impl(const la_device_impl_wptr& device);
    ~la_te_tunnel_impl() override;
    la_status initialize(la_object_id_t oid,
                         la_te_tunnel_gid_t te_tunnel_gid,
                         const la_l3_destination_wcptr& destination,
                         tunnel_type_e type);
    la_status destroy();
    la_status instantiate(resolution_step_e prev_step);
    la_status uninstantiate(resolution_step_e prev_step);

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    // la_object APIs
    const la_device* get_device() const override;
    object_type_e type() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;
    la_te_tunnel_gid_t get_gid() const override;

    /// @brief Get a list of active slice-pairs
    ///
    /// @retval  A vector that holds the active slice-pairs
    std::vector<la_slice_pair_id_t> get_slice_pairs(const la_next_hop_base_wcptr& next_hop) const;

    // la_te_tunnel APIs
    const la_l3_destination* get_destination() const override;
    la_status set_destination(const la_l3_destination* destination) override;
    la_status set_nh_lsp_properties(const la_next_hop* nh, const la_mpls_label_vec_t& labels, la_counter_set* counter) override;
    la_status get_nh_lsp_properties(const la_next_hop* nh,
                                    la_mpls_label_vec_t& out_labels,
                                    const la_counter_set*& out_counter) const override;
    la_status clear_nh_lsp_properties(const la_next_hop* nh) override;
    la_status get_tunnel_type(tunnel_type_e& out_type) const override;
    la_status set_tunnel_type(tunnel_type_e type) override;
    la_status get_ipv6_explicit_null_enabled(bool& out_enabled) const override;
    la_status set_ipv6_explicit_null_enabled(bool enabled) override;
    la_status get_lb_resolution(const la_lb_pak_fields_vec& lb_vector, size_t& member, const la_object*& out_object) const;

    // Resolution API helpers
    destination_id get_destination_id(resolution_step_e prev_step) const;
    // Hold tunnel-nh pair object
    class tunnel_nh_pair : public dependency_listener, public std::enable_shared_from_this<tunnel_nh_pair>
    {
        CEREAL_SUPPORT_PRIVATE_MEMBERS
    public:
        tunnel_nh_pair(const la_device_impl_wptr& device,
                       const la_te_tunnel_impl_wptr& tunnel,
                       const la_next_hop_base_wcptr& nh,
                       const la_counter_set_wptr& counter);
        ~tunnel_nh_pair();
        la_status initialize();
        la_status destroy();
        void set_counter(const la_counter_set_wptr& counter);
        const la_device_impl_wptr& get_device() const;
        la_status notify_change(dependency_management_op op) override;

    private:
        la_device_impl_wptr m_device;
        la_te_tunnel_impl_wptr m_tunnel;
        la_next_hop_base_wcptr m_nh;
        la_counter_set_impl_wptr m_counter;
        tunnel_nh_pair() = default; // For serialization purposes only.
    };

private:
    // Attributes management
    la_status update_dependent_attributes(dependency_management_op op);

    // Helper functions for adding/removing attribute dependency
    void register_attribute_dependency(const la_next_hop_base_wcptr& next_hop);
    void deregister_attribute_dependency(const la_next_hop_base_wcptr& next_hop);
    void add_dependency(const la_l3_destination_wcptr& destination);
    void remove_dependency(const la_l3_destination_wcptr& destination);

    // Creating device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Global ID
    la_te_tunnel_gid_t m_te_tunnel_gid;

    // Associated destination
    la_l3_destination_wcptr m_destination;

    // Tunnel type
    la_te_tunnel::tunnel_type_e m_tunnel_type;

    // IPv6 Explicit NULL Enabled
    bool m_ipv6_explicit_null_enabled;

    // Hold temporary lsp table configuration
    struct lsp_configuration_params {
        bool multi_counter_enabled;
        bool program_additional_labels_table;
        bool lsp_payload_with_3_labels;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(lsp_configuration_params);

    // Resolution related data
    struct resolution_data {
        resolution_data();
        la_uint_t users_for_step[RESOLUTION_STEP_LAST];
        resolution_table_index id_in_step[RESOLUTION_STEP_LAST];
    } m_resolution_data;
    CEREAL_SUPPORT_PRIVATE_CLASS(resolution_data);

    // Hold entry information
    struct te_em_info {
        la_mpls_label_vec_t labels;
        la_counter_set_wptr counter;
        bool more_labels_index_valid = false;
        uint64_t more_labels_index = 0;
        ifg_use_count_sptr ifgs;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(te_em_info);

    // EM-key to label stack and counter mapping
    typedef std::map<la_next_hop_base_wcptr, te_em_info> te_em_entry_map_t;
    te_em_entry_map_t m_te_em_entry_map;

    // Hold entry information
    struct ldp_over_te_em_info {
        la_mpls_label_vec_t labels;
        la_counter_set_wcptr counter = nullptr;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ldp_over_te_em_info);

    // EM-key to label stack and counter mapping
    typedef std::map<la_next_hop_base_wcptr, ldp_over_te_em_info> ldp_over_te_em_entry_map_t;
    ldp_over_te_em_entry_map_t m_ldp_over_te_em_entry_map;

    std::map<la_next_hop_base_wcptr, std::shared_ptr<tunnel_nh_pair> > m_tunnel_nh_pairs;

    ifg_use_count_uptr m_ifgs; // Union of IFGs used by all next-hops

    // Resolution API helpers
    // General functions
    resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const;

    // Helper functions for counter
    bool is_counter_set_size_valid(const la_counter_set_impl_wcptr& counter, la_counter_set::type_e counter_type);
    la_status allocate_counter(const la_next_hop_base_wcptr& next_hop,
                               const la_counter_set_wptr& new_counter,
                               la_counter_set::type_e counter_type,
                               counter_direction_e direction);
    la_status release_counter(const la_next_hop_base_wcptr& next_hop, const la_counter_set_wptr& curr_counter);

    // Manage the large_encap_te_he_tunnel_id Encap table configuration
    la_status set_nh_lsp_properties_mpls_he(const la_next_hop_base_wcptr& next_hop,
                                            const la_mpls_label_vec_t& labels,
                                            const la_counter_set_wptr& counter);
    la_status set_nh_lsp_properties_ldp_over_te(const la_next_hop_base_wcptr& next_hop,
                                                const la_mpls_label_vec_t& labels,
                                                const la_counter_set_wptr& counter);

    lsp_configuration_params get_lsp_configuration_params(const la_mpls_label_vec_t& labels,
                                                          const la_counter_set_wcptr& counter) const;
    void prepare_encap_te_he_nh_table(la_slice_pair_id_t pair_idx,
                                      const la_next_hop_base_wcptr& nh,
                                      const la_mpls_label_vec_t& labels,
                                      const la_counter_set_wcptr& counter,
                                      const uint64_t more_labels_index,
                                      const lsp_configuration_params& lsp_config,
                                      npl_lsp_encap_mapping_data_payload_t& payload);
    la_status configure_additional_labels_table_entry(la_slice_pair_id_t pair_idx,
                                                      const la_mpls_label_vec_t& labels,
                                                      const uint64_t more_labels_index);
    la_status teardown_additional_labels_table_entry(la_slice_pair_id_t pair_idx, const uint64_t more_labels_index);
    la_status configure_small_encap_mpls_he_te_table_entry(la_slice_pair_id_t pair_idx,
                                                           const la_next_hop_base_wcptr& nh,
                                                           const la_mpls_label_vec_t& labels,
                                                           const la_counter_set_wcptr& counter,
                                                           const uint64_t more_labels_index,
                                                           const lsp_configuration_params& lsp_config);
    la_status teardown_small_encap_mpls_he_te_table_entry(la_slice_pair_id_t pair_idx, const la_next_hop_base_wcptr& nh);
    la_status configure_large_encap_te_he_tunnel_id_table_entry(la_slice_pair_id_t pair_idx,
                                                                const la_next_hop_base_wcptr& nh,
                                                                const la_mpls_label_vec_t& labels,
                                                                const la_counter_set_wcptr& counter,
                                                                const uint64_t more_labels_index,
                                                                const lsp_configuration_params& lsp_config);
    la_status teardown_large_encap_te_he_tunnel_id_table_entry(la_slice_pair_id_t pair_idx, const la_next_hop_base_wcptr& next_hop);
    la_status configure_encap_te_he_nh_slice_pair_entry(la_slice_pair_id_t pair_idx,
                                                        const la_next_hop_base_wcptr& next_hop,
                                                        const la_mpls_label_vec_t& labels,
                                                        const la_counter_set_wcptr& counter,
                                                        bool& more_labels_index_valid,
                                                        uint64_t& more_labels_index);
    la_status teardown_encap_te_he_nh_slice_pair_entry(la_slice_pair_id_t pair_idx,
                                                       const la_next_hop_base_wcptr& next_hop,
                                                       const bool more_labels_index_valid,
                                                       const uint64_t more_labels_index);
    la_status teardown_encap_te_he_nh_slice_pairs(const la_next_hop_base_wcptr& next_hop,
                                                  bool& more_labels_index_valid,
                                                  uint64_t& more_labels_index);
    la_status teardown_encap_te_he_all_nh();
    la_status configure_small_encap_mpls_he_te_table();
    la_status teardown_small_encap_mpls_he_te_table();

    // Manage the ldp_over_te Encap table configuration
    la_status configure_ldp_over_te_table(la_slice_pair_id_t pair_idx,
                                          const la_next_hop_base_wcptr& nh,
                                          const la_mpls_label_vec_t& labels,
                                          const la_counter_set_wcptr& counter,
                                          const uint64_t more_labels_index);
    la_status teardown_ldp_over_te_table();
    la_status teardown_ldp_over_te_table_entry(la_slice_pair_id_t pair_idx, const la_next_hop_base_wcptr& next_hop);

    la_status instantiate_new_destination(const la_l3_destination_wcptr& destination);
    la_status uninstantiate_old_destination(const la_l3_destination_wcptr& destination);

    // API function body
    la_status do_get_nh_lsp_properties(const la_next_hop_wcptr& nh,
                                       la_mpls_label_vec_t& out_labels,
                                       const la_counter_set*& out_counter) const;

    /// IFG management
    la_status add_ifg(const la_next_hop_base_wcptr& nh, la_slice_ifg ifg);
    la_status remove_ifg(const la_next_hop_base_wcptr& nh, la_slice_ifg ifg);

    la_te_tunnel_impl() = default; // For serialization purposes only.
};

} // namespace silicon_one

#endif // __LA_TE_TUNNEL_IMPL_H__
