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

#ifndef __LA_PREFIX_OBJECT_BASE_H__
#define __LA_PREFIX_OBJECT_BASE_H__

#include "api/npu/la_counter_set.h"
#include "api/npu/la_prefix_object.h"
#include "api/npu/la_vrf.h"
#include "api/types/la_mpls_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_vrf_impl.h"
#include <vector>

namespace silicon_one
{
class la_prefix_object_base : public la_prefix_object, public dependency_listener
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    ~la_prefix_object_base() override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    la_status initialize(la_object_id_t oid,
                         la_l3_destination_gid_t prefix_gid,
                         const la_l3_destination_wcptr& destination,
                         la_prefix_object::prefix_type_e type);
    virtual la_status destroy() = 0;
    la_status instantiate(resolution_step_e prev_step);
    la_status uninstantiate(resolution_step_e prev_step);

    // la_object APIs
    const la_device* get_device() const override;
    object_type_e type() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;
    la_l3_destination_gid_t get_gid() const override;

    /// @brief Get a list of active slice-pairs
    ///
    /// @retval  A vector that holds the active slice-pairs
    std::vector<la_slice_pair_id_t> get_slice_pairs(const la_next_hop_base_wcptr& next_hop) const;

    // la_prefix_object APIs
    const la_l3_destination* get_destination() const override;
    la_status set_destination(const la_l3_destination* destination) override;
    la_status set_global_lsp_properties(const la_mpls_label_vec_t& labels,
                                        la_counter_set* counter,
                                        lsp_counter_mode_e counter_mode) override;
    la_status get_global_lsp_properties(la_mpls_label_vec_t& out_labels,
                                        const la_counter_set*& out_counter,
                                        lsp_counter_mode_e& out_counter_mode) const override;
    la_status clear_global_lsp_properties() override;
    la_status get_prefix_type(prefix_type_e& out_type) const override;
    la_status set_nh_lsp_properties(const la_next_hop* nh,
                                    const la_mpls_label_vec_t& labels,
                                    la_counter_set* counter,
                                    lsp_counter_mode_e counter_mode) override;
    la_status get_nh_lsp_properties(const la_next_hop* nh,
                                    la_mpls_label_vec_t& out_labels,
                                    const la_counter_set*& out_counter,
                                    lsp_counter_mode_e& out_counter_mode) const override;
    la_status clear_nh_lsp_properties(const la_next_hop* nh) override;

    la_status set_vrf_properties(const la_vrf* vrf, la_ip_version_e ip_version, const la_mpls_label_vec_t& labels) override;
    la_status get_vrf_properties(const la_vrf* vrf, la_ip_version_e ip_version, la_mpls_label_vec_t& out_labels) const override;
    la_status clear_vrf_properties(const la_vrf* vrf, la_ip_version_e ip_version) override;

    la_status set_te_tunnel_lsp_properties(const la_te_tunnel* te_tunnel,
                                           const la_mpls_label_vec_t& labels,
                                           la_counter_set* counter) override;
    la_status get_te_tunnel_lsp_properties(const la_te_tunnel* te_tunnel,
                                           la_mpls_label_vec_t& out_labels,
                                           const la_counter_set*& out_counter) const override;
    la_status clear_te_tunnel_lsp_properties(const la_te_tunnel* te_tunnel) override;
    la_status get_ipv6_explicit_null_enabled(bool& out_enabled) const override;
    la_status set_ipv6_explicit_null_enabled(bool enabled) override;

    // Resolution API helpers
    lpm_destination_id get_lpm_destination_id(resolution_step_e prev_step) const;
    virtual destination_id get_destination_id(resolution_step_e prev_step) const = 0;

    la_status register_asbr_lsp_next_hop(const la_next_hop_wcptr& nh);
    la_status deregister_asbr_lsp_next_hop(const la_next_hop_wcptr& nh);

    // True if resolution-forwardable
    bool is_resolution_forwarding_supported() const;

    // True if it can be a pbts member
    bool is_pbts_eligible() const;

    // Hold prefix-nh pair object
    class prefix_nh_pair : public dependency_listener, public std::enable_shared_from_this<prefix_nh_pair>
    {
        CEREAL_SUPPORT_PRIVATE_MEMBERS
    public:
        explicit prefix_nh_pair(const la_device_impl_wptr& device,
                                const la_prefix_object_base_wptr& prefix,
                                const la_next_hop_base_wcptr& nh,
                                const la_counter_set_wptr& counter);
        ~prefix_nh_pair();
        prefix_nh_pair() = default; // For serialization purposes only.
        la_status initialize();
        la_status destroy();
        la_status notify_change(dependency_management_op op) override;
        void set_counter(const la_counter_set_wptr& counter);
        const la_device_impl_wptr& get_device() const;

    private:
        la_device_impl_wptr m_device;
        la_prefix_object_base_wptr m_prefix;
        const la_next_hop_base_wcptr m_nh;
        la_counter_set_impl_wptr m_counter;
    };

protected:
    explicit la_prefix_object_base(const la_device_impl_wptr& device);
    la_prefix_object_base() = default; // For serialization purpose only

    // Creating device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;

    // Global ID
    la_l3_destination_gid_t m_prefix_gid;

    // Associated destination
    la_l3_destination_wcptr m_destination;

    // Attributes management
    virtual la_status update_dependent_attributes(dependency_management_op op) = 0;

    virtual la_status update_destination(const la_l3_destination_wcptr& destination, bool is_global, bool is_init) = 0;
    la_status validate_new_destination_for_global_lsp(const la_l3_destination_wcptr& destination);

    // Helper functions for adding/removing attribute dependency
    void add_dependency(const la_l3_destination_wcptr& destination);
    void remove_dependency(const la_l3_destination_wcptr& destination);
    virtual void register_attribute_dependency(const la_l3_destination_wcptr& destination) = 0;
    virtual void deregister_attribute_dependency(const la_l3_destination_wcptr& destination) = 0;

    virtual la_status do_clear_nh_lsp_properties(const la_next_hop_wcptr& nh) = 0;
    virtual la_status do_set_nh_lsp_properties(const la_next_hop_wcptr& nh,
                                               const la_mpls_label_vec_t& labels,
                                               const la_counter_set_wptr& counter,
                                               lsp_counter_mode_e counter_mode)
        = 0;
    virtual la_status do_clear_vrf_properties(const la_vrf_wcptr& vrf, la_ip_version_e ip_version) = 0;
    virtual la_status do_set_vrf_properties(const la_vrf_wcptr& vrf, la_ip_version_e ip_version, const la_mpls_label_vec_t& labels)
        = 0;

    la_status do_clear_te_tunnel_lsp_properties(const la_te_tunnel_wcptr& te_tunnel);

    // Hold entry information
    struct mpls_em_info {
        size_t use_count = 0;
        bool more_labels_index_valid = false;
        uint64_t more_labels_index = 0;
        la_mpls_label_vec_t labels;
        la_counter_set_wptr counter;
        lsp_counter_mode_e counter_mode;
        ifg_use_count_sptr ifgs;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(mpls_em_info)

    // Hold temporary lsp table configuration
    struct lsp_configuration_params {
        bool multi_counter_enabled;
        bool sr_dm_accounting_enabled;
        bool program_additional_labels_table;
        bool lsp_payload_with_3_labels;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(lsp_configuration_params)

    lsp_configuration_params get_lsp_configuration_params(const la_mpls_label_vec_t& labels,
                                                          const la_counter_set_wcptr& counter) const;
    void prepare_lsp_table_payload(npl_lsp_encap_mapping_data_payload_t& payload,
                                   const la_mpls_label_vec_t& labels,
                                   la_slice_pair_id_t pair_idx,
                                   const la_counter_set_wcptr& counter,
                                   const lsp_configuration_params& lsp_config,
                                   const bool ipv6_explicit_null_enabled,
                                   uint64_t more_labels_index) const;
    void prepare_tunnel_lsp_table_payload(npl_large_em_label_encap_data_and_counter_ptr_t& payload,
                                          const la_mpls_label_vec_t& labels,
                                          la_slice_pair_id_t pair_idx,
                                          const la_counter_set_wcptr& counter,
                                          const lsp_configuration_params& lsp_config,
                                          bool ipv6_explicit_null_enabled,
                                          uint64_t more_labels_index) const;

    // EM-key to label stack and counter mapping
    typedef std::map<la_next_hop_base_wcptr, mpls_em_info> mpls_em_entry_map_t;

    mpls_em_entry_map_t m_mpls_em_entry_map;

    // Hold entry information
    struct mpls_global_em_info {
        mpls_em_info em_info;
        bool entry_present = false;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(mpls_global_em_info)

    mpls_global_em_info m_global_lsp_prefix_info;

    // Hold entry information
    struct te_pfx_obj_em_info {
        la_mpls_label_vec_t labels;
        la_counter_set_wptr counter = nullptr;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(te_pfx_obj_em_info)

    // EM-key to label stack and counter mapping
    typedef std::map<la_te_tunnel_impl_wcptr, te_pfx_obj_em_info> te_pfx_obj_em_entry_map_t;

    te_pfx_obj_em_entry_map_t m_te_pfx_obj_em_entry_map;

    // Hold entry information
    struct vpn_info {
        la_mpls_label_vec_t ipv4_labels;
        bool ipv4_valid = false;
        la_mpls_label_vec_t ipv6_labels;
        bool ipv6_valid = false;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(vpn_info)

    // EM-key to VPN label mapping
    typedef std::map<la_vrf_impl_wcptr, vpn_info> vpn_entry_map_t;

    vpn_entry_map_t m_vpn_entry_map;

    bool m_vpn_enabled;

    bool m_global_lsp_prefix;

    // IPv6 Explicit NULL Enabled
    bool m_ipv6_explicit_null_enabled;

    std::map<la_next_hop_base_wcptr, std::shared_ptr<prefix_nh_pair> > m_prefix_nh_pairs;

    ifg_use_count_uptr m_ifgs; // Union of IFGs used by all next-hops

    // Resolution API helpers
    // General functions
    virtual resolution_step_e get_next_resolution_step(resolution_step_e prev_step) const = 0;

    // Helper functions for counter
    bool is_counter_set_size_valid(const la_counter_set_impl_wcptr& counter,
                                   lsp_counter_mode_e counter_mode,
                                   const la_next_hop_base_wcptr& next_hop);
    la_counter_set::type_e lsp_counter_mode_get_counter_type(lsp_counter_mode_e counter_mode);
    la_status allocate_counter(const la_next_hop_base_wcptr& next_hop,
                               const la_counter_set_wptr& new_counter,
                               lsp_counter_mode_e counter_mode,
                               counter_direction_e direction);
    la_status release_counter(const la_next_hop_base_wcptr& next_hop, const la_counter_set_wptr& curr_counter);

    // Manage the MPLS headend Large Encap table configuration
    la_status configure_large_encap_mpls_he_no_ldp_table(la_slice_pair_id_t pair_idx,
                                                         const la_next_hop_base_wcptr& nh,
                                                         const la_mpls_label_vec_t& labels,
                                                         const la_counter_set_wcptr& counter);
    la_status teardown_large_encap_mpls_he_no_ldp_table();
    la_status teardown_large_encap_mpls_he_no_ldp_table_entry(la_slice_pair_id_t pair_idx, const la_next_hop_base_wcptr& next_hop);

    // Manage the MPLS headend Small Encap table configuration
    virtual la_status configure_small_encap_mpls_he_asbr_table(la_slice_pair_id_t pair_idx,
                                                               const la_next_hop_base_wcptr& nh,
                                                               const la_mpls_label_vec_t& labels,
                                                               const la_counter_set_wcptr& counter)
        = 0;
    la_status teardown_small_encap_mpls_he_asbr_table_entry(la_slice_pair_id_t pair_idx, const la_next_hop_base_wcptr& next_hop);

    la_status configure_large_encap_global_lsp_prefix_table(la_slice_pair_id_t pair_idx,
                                                            const la_mpls_label_vec_t& labels,
                                                            const la_counter_set_wcptr& counter);
    la_status teardown_large_encap_global_lsp_prefix_table();
    la_status teardown_large_encap_global_lsp_prefix_table_entry(la_slice_pair_id_t pair_idx);
    la_status teardown_encap_additional_labels_table_entry(la_slice_pair_id_t pair_idx);

    // Manage the VPN Encap table configuration
    la_status configure_per_pe_and_vrf_vpn_key_large_table(const la_vrf_impl_wcptr& vrf,
                                                           la_ip_version_e ip_version,
                                                           vpn_info& map_entry,
                                                           const la_mpls_label_vec_t& labels);
    la_status teardown_per_pe_and_vrf_vpn_key_large_table();
    la_status teardown_per_pe_and_vrf_vpn_key_large_table_entry(const la_vrf_impl_wcptr& vrf);

    // Manage the large_encap_mpls_ldp_over_te Encap table configuration
    la_status configure_large_encap_mpls_ldp_over_te_table(const la_te_tunnel_impl_wcptr& te_tunnel_impl,
                                                           const la_mpls_label_vec_t& labels,
                                                           const la_counter_set_wcptr& counter);
    la_status teardown_large_encap_mpls_ldp_over_te_table();
    la_status teardown_large_encap_mpls_ldp_over_te_table_entry(const la_te_tunnel_impl_wcptr& te_tunnel);

    // API function body
    la_status do_get_nh_lsp_properties(const la_next_hop_wcptr& nh,
                                       la_mpls_label_vec_t& out_labels,
                                       la_counter_set_wcptr& out_counter,
                                       lsp_counter_mode_e& out_counter_mode) const;

    /// IFG management
    la_status add_ifg(const la_next_hop_base_wcptr& nh, la_slice_ifg ifg);
    la_status remove_ifg(const la_next_hop_base_wcptr& nh, la_slice_ifg ifg);
};

} // namespace silicon_one

#endif // __LA_PREFIX_OBJECT_BASE_H__
